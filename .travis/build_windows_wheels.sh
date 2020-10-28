#!/bin/bash

set -e -x

build_dll() {
    ./autogen.sh
    echo "LDFLAGS = -no-undefined" >> Makefile.am
    ./configure --host=$1 --enable-module-recovery --enable-experimental --enable-module-ecdh --enable-endomorphism --disable-jni --disable-openssl-tests --with-bignum=no --enable-module-ed25519 --enable-module-generator --enable-module-dleag --enable-module-ecdsaotves
    make
}

cd ..
#git clone https://github.com/bitcoin-core/secp256k1.git
#mv secp256k1 64bit
wget -O secp256k1_anonswap.zip https://github.com/tecnovert/secp256k1/archive/anonswap.zip
unzip secp256k1_anonswap.zip
mv secp256k1-anonswap 64bit

cp 64bit 32bit -R

cd 64bit
build_dll x86_64-w64-mingw32
mv .libs/libsecp256k1-0.dll ../clean/coincurve/libsecp256k1.dll
cd ../clean
python setup.py bdist_wheel --universal --plat-name=win_amd64
rm coincurve/libsecp256k1.dll

cd ../32bit
build_dll i686-w64-mingw32
mv .libs/libsecp256k1-0.dll ../clean/coincurve/libsecp256k1.dll
cd ../clean
python setup.py bdist_wheel --universal --plat-name=win32

mv dist/* ../coincurve/dist/
cd ../coincurve
