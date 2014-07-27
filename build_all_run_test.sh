#!/bin/bash
LIB_FOLDER=`pwd`/libc
SRC_FOLDER=$LIB_FOLDER/SRC
BUILD_FOLDER=$LIB_FOLDER/BUILD
LIBC_PREFIX=$LIB_FOLDER/install

GLIBC_FOLDER=$SRC_FOLDER/glibc
LINUX_HEADERS_FOLDER=$SRC_FOLDER/linux-headers-for-nacl
ZRT_FOLDER=$SRC_FOLDER/zrt

GLIBC_REPO=https://github.com/zerovm/glibc.git
LINUX_HEADERS_REPO=https://github.com/zerovm/linux-headers-for-nacl.git
ZRT_REPO=https://github.com/zerovm/zrt.git
mkdir -p $SRC_FOLDER $INSTALL_FOLDER

#ensure glibc repo is exist
if [[ ! -d $GLIBC_FOLDER ]] ; then \
  git clone $GLIBC_REPO ; \
fi

#ensure linux-headers repo is exist
if [[ ! -d $LINUX_HEADERS_FOLDER ]] ; then \
  git clone $LINUX_HEADERS_REPO ; \
fi

#ensure linux-headers repo is exist
if [[ ! -d $ZRT_FOLDER ]] ; then \
  git clone $ZRT_REPO ; \
fi

#setup environemnt
export __ZRT_HOST=something; 
export ZVM_PREFIX=$LIBC_PREFIX;
export ZRT_ROOT=$ZRT_FOLDER;

#patch libc before build
cp patch_files/elf_Versions $GLIBC_FOLDER/elf/Versions -p

rm $BUILD_FOLDER $SECCOMP_PREFIX -rf
#build libc install to the $SECCOMP_PREFIX
make -Clibc

cd $GLIBC_FOLDER
make -j4
cd ..
cd testlib
make clean zrt
./zrt

