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
# and warranty status of this software.

import pytest

import electrumx.lib.coins as coins

addresses = [
    (coins.Bitcoin, "13xDKJbjh4acmLpNVr6Lc9hFcXRr9fyt4x",
     "206168f5322583ff37f8e55665a4789ae8963532", "b8cb80b26e8932f5b12a7e"),
    (coins.Bitcoin, "3GxRZWkJufR5XA8hnNJgQ2gkASSheoBcmW",
     "a773db925b09add367dcc253c1f9bbc1d11ec6fd", "062d8515e50cb92b8a3a73"),
]


@pytest.fixture(params=addresses)
def address(request):
    return request.param


def test_address_to_hashX(address):
    coin, addr, _, hashX = address
    assert coin.address_to_hashX(addr).hex() == hashX
