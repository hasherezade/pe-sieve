#!/bin/sh

set -e

cmake . \
    -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
    -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
    -DCMAKE_SYSTEM_NAME=Windows-GNU \
    -DPESIEVE_AS_DLL=0 \
    -DPESIEVE_AS_STATIC_LIB=0 \
    -DLINK_STATICALLY=1

make
