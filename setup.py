import setuptools
version = '1.16.0'

setuptools.setup(
    name='e-x',
    version=version,
    scripts=['electrumx_server', 'electrumx_rpc', 'electrumx_compact_history'],
    python_requires='>=3.8',
    install_requires=['aiorpcX[ws]>=0.22.0,<0.23', 'attrs',
                      'plyvel', 'pylru', 'aiohttp>=3.3,<4'],
    extras_require={
        'rapidjson': ['python-rapidjson>=0.4.1,<2.0'],
        'rocksdb': ['python-rocksdb>=0.6.9'],
        'ujson': ['ujson>=2.0.0,<4.0.0'],
        'uvloop': ['uvloop>=0.14'],
    },
    packages=setuptools.find_packages(include=('electrumx*',)),
    description='ElectrumX Server',
    author='Electrum developers',
    author_email='electrumdev@gmail.com',
    license='MIT Licence',
    url='https://github.com/spesmilo/electrumx',
    long_description='Server implementation for the Electrum protocol',
    download_url=('https://github.com/spesmilo/electrumX/archive/'
                  f'{version}.tar.gz'),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Framework :: AsyncIO',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Unix',
        "Programming Language :: Python :: 3.8",
        "Topic :: Database",
        'Topic :: Internet',
    ],
)
