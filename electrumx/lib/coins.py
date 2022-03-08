# Copyright (c) 2016-2017, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''Module providing coin abstraction.

Anything coin-specific should go in this file and be subclassed where
necessary for appropriate handling.
'''
import re
import struct
from dataclasses import dataclass
from decimal import Decimal
from functools import partial
from hashlib import sha256
from typing import Sequence, Tuple

import electrumx.lib.util as util
from electrumx.lib.hash import Base58, double_sha256, hash_to_hex_str
from electrumx.lib.hash import HASHX_LEN, hex_str_to_hash
from electrumx.lib.script import (_match_ops, Script, ScriptError,
                                  ScriptPubKey, OpCodes)
import electrumx.lib.tx as lib_tx
from electrumx.lib.tx import Tx
import electrumx.server.block_processor as block_proc
import electrumx.server.daemon as daemon
from electrumx.server.session import (ElectrumX)


@dataclass
class Block:
    __slots__ = "raw", "header", "transactions"
    raw: bytes
    header: bytes
    transactions: Sequence[Tuple[Tx, bytes]]


class CoinError(Exception):
    '''Exception raised for coin-related errors.'''


class Coin:
    '''Base class of coin hierarchy.'''

    REORG_LIMIT = 200
    # Not sure if these are coin-specific
    RPC_URL_REGEX = re.compile('.+@(\\[[0-9a-fA-F:]+\\]|[^:]+)(:[0-9]+)?')
    VALUE_PER_COIN = 100000000
    CHUNK_SIZE = 2016
    BASIC_HEADER_SIZE = 80
    STATIC_BLOCK_HEADERS = True
    SESSIONCLS = ElectrumX
    DEFAULT_MAX_SEND = 1000000
    DESERIALIZER = lib_tx.Deserializer
    DAEMON = daemon.Daemon
    BLOCK_PROCESSOR = block_proc.BlockProcessor
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root', 'timestamp',
                     'bits', 'nonce')
    HEADER_UNPACK = struct.Struct('< I 32s 32s I I I').unpack_from
    MEMPOOL_HISTOGRAM_REFRESH_SECS = 500
    P2PKH_VERBYTE = bytes.fromhex("00")
    P2SH_VERBYTES = (bytes.fromhex("05"),)
    XPUB_VERBYTES = bytes('????', 'utf-8')
    XPRV_VERBYTES = bytes('????', 'utf-8')
    WIF_BYTE = bytes.fromhex("80")
    ENCODE_CHECK = Base58.encode_check
    DECODE_CHECK = Base58.decode_check
    GENESIS_HASH = ('000000000019d6689c085ae165831e93'
                    '4ff763ae46a2a6c172b3f1b60a8ce26f')
    GENESIS_ACTIVATION = 100_000_000
    # Peer discovery
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    PEERS = []
    CRASH_CLIENT_VER = None
    BLACKLIST_URL = None
    ESTIMATEFEE_MODES = (None, 'CONSERVATIVE', 'ECONOMICAL')

    RPC_PORT: int
    NAME: str
    NET: str

    # only used for initial db sync ETAs:
    TX_COUNT_HEIGHT: int  # at a given snapshot of the chain,
    TX_COUNT: int         # there have been this many txs so far,
    TX_PER_BLOCK: int     # and from that height onwards, we guess this many txs per block

    @classmethod
    def lookup_coin_class(cls, name, net):
        '''Return a coin class given name and network.

        Raise an exception if unrecognised.'''
        req_attrs = ('TX_COUNT', 'TX_COUNT_HEIGHT', 'TX_PER_BLOCK')
        for coin in util.subclasses(Coin):
            if (coin.NAME.lower() == name.lower() and
                    coin.NET.lower() == net.lower()):
                missing = [
                    attr
                    for attr in req_attrs
                    if not hasattr(coin, attr)
                ]
                if missing:
                    raise CoinError(
                        f'coin {name} missing {missing} attributes'
                    )
                return coin
        raise CoinError(f'unknown coin {name} and network {net} combination')

    @classmethod
    def sanitize_url(cls, url):
        # Remove surrounding ws and trailing /s
        url = url.strip().rstrip('/')
        match = cls.RPC_URL_REGEX.match(url)
        if not match:
            raise CoinError(f'invalid daemon URL: "{url}"')
        if match.groups()[1] is None:
            url = f'{url}:{cls.RPC_PORT:d}'
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
        return url + '/'

    @classmethod
    def max_fetch_blocks(cls, height):
        if height < 130000:
            return 1000
        return 100

    @classmethod
    def genesis_block(cls, block):
        '''Check the Genesis block is the right one for this coin.

        Return the block less its unspendable coinbase.
        '''
        header = cls.block_header(block, 0)
        header_hex_hash = hash_to_hex_str(cls.header_hash(header))
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError(f'genesis block has hash {header_hex_hash} '
                            f'expected {cls.GENESIS_HASH}')

        return header + b'\0'

    @classmethod
    def hashX_from_script(cls, script):
        '''Returns a hashX from a script.'''
        return sha256(script).digest()[:HASHX_LEN]

    @staticmethod
    def lookup_xverbytes(verbytes):
        '''Return a (is_xpub, coin_class) pair given xpub/xprv verbytes.'''
        # Order means BTC testnet will override NMC testnet
        for coin in util.subclasses(Coin):
            if verbytes == coin.XPUB_VERBYTES:
                return True, coin
            if verbytes == coin.XPRV_VERBYTES:
                return False, coin
        raise CoinError('version bytes unrecognised')

    @classmethod
    def address_to_hashX(cls, address):
        '''Return a hashX given a coin address.'''
        return cls.hashX_from_script(cls.pay_to_address_script(address))

    @classmethod
    def hash160_to_P2PKH_script(cls, hash160):
        return ScriptPubKey.P2PKH_script(hash160)

    @classmethod
    def hash160_to_P2PKH_hashX(cls, hash160):
        return cls.hashX_from_script(cls.hash160_to_P2PKH_script(hash160))

    @classmethod
    def pay_to_address_script(cls, address):
        '''Return a pubkey script that pays to a pubkey hash.

        Pass the address (either P2PKH or P2SH) in base58 form.
        '''
        raw = cls.DECODE_CHECK(address)

        # Require version byte(s) plus hash160.
        verbyte = -1
        verlen = len(raw) - 20
        if verlen > 0:
            verbyte, hash160 = raw[:verlen], raw[verlen:]

        if verbyte == cls.P2PKH_VERBYTE:
            return cls.hash160_to_P2PKH_script(hash160)
        if verbyte in cls.P2SH_VERBYTES:
            return ScriptPubKey.P2SH_script(hash160)

        raise CoinError(f'invalid address: {address}')

    @classmethod
    def privkey_WIF(cls, privkey_bytes, compressed):
        '''Return the private key encoded in Wallet Import Format.'''
        payload = bytearray(cls.WIF_BYTE + privkey_bytes)
        if compressed:
            payload.append(0x01)
        return cls.ENCODE_CHECK(payload)

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header)

    @classmethod
    def header_prevhash(cls, header):
        '''Given a header return previous hash'''
        return header[4:36]

    @classmethod
    def static_header_offset(cls, height):
        '''Given a header height return its offset in the headers file.

        If header sizes change at some point, this is the only code
        that needs updating.'''
        assert cls.STATIC_BLOCK_HEADERS
        return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def static_header_len(cls, height):
        '''Given a header height return its length.'''
        return (cls.static_header_offset(height + 1)
                - cls.static_header_offset(height))

    @classmethod
    def block_header(cls, block, height):
        '''Returns the block header given a block and its height.'''
        return block[:cls.static_header_len(height)]

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block namedtuple given a raw block and its height.'''
        header = cls.block_header(raw_block, height)
        txs = cls.DESERIALIZER(raw_block, start=len(header)).read_tx_block()
        return Block(raw_block, header, txs)

    @classmethod
    def decimal_value(cls, value):
        '''Return the number of standard coin units as a Decimal given a
        quantity of smallest units.

        For example 1 BTC is returned for 100 million satoshis.
        '''
        return Decimal(value) / cls.VALUE_PER_COIN

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, _client_ver):
        return False

    @classmethod
    def bucket_estimatefee_block_target(cls, n: int) -> int:
        '''For caching purposes, it might be desirable to restrict the
        set of values that can be queried as an estimatefee block target.
        '''
        return n


class BitcoinMixin:
    SHORTNAME = "BTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    RPC_PORT = 8332


class NameMixin:
    DATA_PUSH_MULTIPLE = -2

    @classmethod
    def interpret_name_prefix(cls, script, possible_ops):
        """Interprets a potential name prefix
        Checks if the given script has a name prefix.  If it has, the
        name prefix is split off the actual address script, and its parsed
        fields (e.g. the name) returned.
        possible_ops must be an array of arrays, defining the structures
        of name prefixes to look out for.  Each array can consist of
        actual opcodes, -1 for ignored data placeholders, -2 for
        multiple ignored data placeholders and strings for named placeholders.
        Whenever a data push matches a named placeholder,
        the corresponding value is put into a dictionary the placeholder name
        as key, and the dictionary of matches is returned."""

        try:
            ops = Script.get_ops(script)
        except ScriptError:
            return None, script

        name_op_count = None
        for pops in possible_ops:
            # Start by translating named placeholders to -1 values, and
            # keeping track of which op they corresponded to.
            template = []
            named_index = {}

            n = len(pops)
            offset = 0
            for i, op in enumerate(pops):
                if op == cls.DATA_PUSH_MULTIPLE:
                    # Emercoin stores value in multiple placeholders
                    # Script structure: https://git.io/fjuRu
                    added, template = cls._add_data_placeholders_to_template(
                        ops[i:], template)
                    offset += added - 1  # subtract the "DATA_PUSH_MULTIPLE" opcode
                elif type(op) == str:
                    template.append(-1)
                    named_index[op] = i + offset
                else:
                    template.append(op)
            n += offset

            if not _match_ops(ops[:n], template):
                continue

            name_op_count = n
            named_values = {key: ops[named_index[key]] for key in named_index}
            break

        if name_op_count is None:
            return None, script

        name_end_pos = cls.find_end_position_of_name(script, name_op_count)

        address_script = script[name_end_pos:]
        return named_values, address_script

    @classmethod
    def _add_data_placeholders_to_template(cls, opcodes, template):
        num_dp = cls._read_data_placeholders_count(opcodes)
        num_2drop = num_dp // 2
        num_drop = num_dp % 2

        two_drops = [OpCodes.OP_2DROP] * num_2drop
        one_drops = [OpCodes.OP_DROP] * num_drop

        elements_added = num_dp + num_2drop + num_drop
        placeholders = [-1] * num_dp
        drops = two_drops + one_drops

        return elements_added, template + placeholders + drops

    @classmethod
    def _read_data_placeholders_count(cls, opcodes):
        data_placeholders = 0

        for opcode in opcodes:
            if type(opcode) == tuple:
                data_placeholders += 1
            else:
                break

        return data_placeholders

    @staticmethod
    def find_end_position_of_name(script, length):
        """Finds the end position of the name data
        Given the number of opcodes in the name prefix (length), returns the
        index into the byte array of where the name prefix ends."""
        n = 0
        for _i in range(length):
            # Content of this loop is copied from Script.get_ops's loop
            op = script[n]
            n += 1

            if op <= OpCodes.OP_PUSHDATA4:
                # Raw bytes follow
                if op < OpCodes.OP_PUSHDATA1:
                    dlen = op
                elif op == OpCodes.OP_PUSHDATA1:
                    dlen = script[n]
                    n += 1
                elif op == OpCodes.OP_PUSHDATA2:
                    dlen, = struct.unpack('<H', script[n: n + 2])
                    n += 2
                else:
                    dlen, = struct.unpack('<I', script[n: n + 4])
                    n += 4
                if n + dlen > len(script):
                    raise IndexError
                n += dlen

        return n


class NameIndexMixin(NameMixin):
    """Shared definitions for coins that have a name index
    This class defines common functions and logic for coins that have
    a name index in addition to the index by address / script."""

    BLOCK_PROCESSOR = block_proc.NameIndexBlockProcessor

    @classmethod
    def build_name_index_script(cls, name):
        """Returns the script by which names are indexed"""

        from electrumx.lib.script import Script

        res = bytearray()
        res.append(cls.OP_NAME_UPDATE)
        res += Script.push_data(name)
        res += Script.push_data(b'')
        res.append(OpCodes.OP_2DROP)
        res.append(OpCodes.OP_DROP)
        res.append(OpCodes.OP_RETURN)

        return bytes(res)

    @classmethod
    def split_name_script(cls, script):
        named_values, address_script = cls.interpret_name_prefix(
            script, cls.NAME_OPERATIONS)
        if named_values is None or "name" not in named_values:
            return None, address_script

        name_index_script = cls.build_name_index_script(
            named_values["name"][1])
        return name_index_script, address_script

    @classmethod
    def hashX_from_script(cls, script):
        _, address_script = cls.split_name_script(script)
        return super().hashX_from_script(address_script)

    @classmethod
    def address_from_script(cls, script):
        _, address_script = cls.split_name_script(script)
        return super().address_from_script(address_script)

    @classmethod
    def name_hashX_from_script(cls, script):
        name_index_script, _ = cls.split_name_script(script)
        if name_index_script is None:
            return None

        return super().hashX_from_script(name_index_script)


class Bitcoin(BitcoinMixin, Coin):
    NAME = "Bitcoin"
    DESERIALIZER = lib_tx.DeserializerSegWit
    MEMPOOL_HISTOGRAM_REFRESH_SECS = 120
    TX_COUNT = 565436782
    TX_COUNT_HEIGHT = 646855
    TX_PER_BLOCK = 2200
    CRASH_CLIENT_VER = (3, 2, 3)
    BLACKLIST_URL = 'https://electrum.org/blacklist.json'
    PEERS = [
        'electrum.vom-stausee.de s t',
        'electrum.hsmiths.com s t',
        'helicarrier.bauerj.eu s t',
        'hsmiths4fyqlw5xw.onion s t',
        'ozahtqwp25chjdjd.onion s t',
        'electrum.hodlister.co s',
        'electrum3.hodlister.co s',
        'btc.usebsv.com s50006',
        'fortress.qtornado.com s443 t',
        'ecdsa.net s110 t',
        'e2.keff.org s t',
        'currentlane.lovebitco.in s t',
        'electrum.jochen-hoenicke.de s50005 t50003',
        'vps5.hsmiths.com s',
        'electrum.emzy.de s',
    ]

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 3):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electrum.<br/>'
                    'Download the new version from the usual place:<br/>'
                    'https://electrum.org/'
                    '<br/><br/>')
        return False

    @classmethod
    def bucket_estimatefee_block_target(cls, n: int) -> int:
        # values based on https://github.com/bitcoin/bitcoin/blob/af05bd9e1e362c3148e3b434b7fac96a9a5155a1/src/policy/fees.h#L131  # noqa
        if n <= 1:
            return 1
        if n <= 12:
            return n
        if n == 25:  # so common that we make an exception for it
            return n
        if n <= 48:
            return n // 2 * 2
        if n <= 1008:
            return n // 24 * 24
        return 1008


class BitcoinSegwit(Bitcoin):
    NAME = "BitcoinSegwit"  # support legacy name


class BitcoinTestnetMixin:
    SHORTNAME = "XTN"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = (bytes.fromhex("c4"),)
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('000000000933ea01ad0ee984209779ba'
                    'aec3ced90fa3f408719526f8d77f4943')
    REORG_LIMIT = 8000
    TX_COUNT = 12242438
    TX_COUNT_HEIGHT = 1035428
    TX_PER_BLOCK = 21
    RPC_PORT = 18332
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}


class BitcoinTestnet(BitcoinTestnetMixin, Coin):
    '''Bitcoin Testnet for Core bitcoind >= 0.13.1.'''
    NAME = "Bitcoin"
    DESERIALIZER = lib_tx.DeserializerSegWit
    CRASH_CLIENT_VER = (3, 2, 3)
    PEERS = [
        'testnet.hsmiths.com t53011 s53012',
        'hsmithsxurybd7uh.onion t53011 s53012',
        'testnet.qtornado.com s t',
        'testnet1.bauerj.eu t50001 s50002',
        'tn.not.fyi t55001 s55002',
        'bitcoin.cluelessperson.com s t',
    ]

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 3):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electrum.<br/>'
                    'Download the new version from the usual place:<br/>'
                    'https://electrum.org/'
                    '<br/><br/>')
        return False


class BitcoinSegwitTestnet(BitcoinTestnet):
    NAME = "BitcoinSegwit"  # support legacy name


class BitcoinRegtest(BitcoinTestnet):
    NAME = "Bitcoin"
    NET = "regtest"
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1


class BitcoinSegwitRegtest(BitcoinRegtest):
    NAME = "BitcoinSegwit"  # support legacy name


class BitcoinSignet(BitcoinTestnet):
    NAME = "Bitcoin"
    NET = "signet"
    GENESIS_HASH = ('00000008819873e925422c1ff0f99f7c'
                    'c9bbb232af63a077a480a3633bee1ef6')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1


class BitcoinSegwitSignet(BitcoinSignet):
    NAME = "BitcoinSegwit"  # support legacy name
