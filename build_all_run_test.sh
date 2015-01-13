#!/bin/bash

PATCH_FOLDER=`pwd`/patch_files
LIB_FOLDER=`pwd`/libc
LIBS_FOLDER=`pwd`/libs

SRC_FOLDER=$LIB_FOLDER/SRC
BUILD_FOLDER=$LIB_FOLDER/BUILD
LIBC_PREFIX=$LIB_FOLDER/install

ZVM_FOLDER=`pwd`/zerovm
GLIBC_FOLDER=$SRC_FOLDER/glibc
LINUX_HEADERS_FOLDER=$SRC_FOLDER/linux-headers-for-nacl
ZRT_FOLDER=$SRC_FOLDER/zrt

ZVM_REPO=https://github.com/YaroslavLitvinov/zerovm.git
GLIBC_REPO=https://github.com/zerovm/glibc.git
LINUX_HEADERS_REPO=https://github.com/zerovm/linux-headers-for-nacl.git
ZRT_REPO=https://github.com/YaroslavLitvinov/zrt.git
mkdir -p $SRC_FOLDER $INSTALL_FOLDER

#ensure zerovm repo is exist
if [[ ! -d $ZVM_FOLDER ]] ; then \
  git clone $ZVM_REPO ; \
  cd $ZVM_FOLDER; \
  git checkout so; \
  cd $SRC_FOLDER; \
fi

cd $SRC_FOLDER

#ensure glibc repo is exist
if [[ ! -d $GLIBC_FOLDER ]] ; then \
  git clone $GLIBC_REPO ; \
  cd $GLIBC_FOLDER; \
  git checkout; \
  cd $SRC_FOLDER; \
fi

#ensure linux-headers repo is exist
if [[ ! -d $LINUX_HEADERS_FOLDER ]] ; then \
  git clone $LINUX_HEADERS_REPO ; \
fi

#ensure zrt repo is exist
if [[ ! -d $ZRT_FOLDER ]] ; then \
  git clone $ZRT_REPO ; \
  cd $ZRT_FOLDER; \
  git checkout dev; \
  cd $SRC_FOLDER; \
fi

cd `pwd`



#patch libc before build
cp $PATCH_FOLDER/elf_Versions $GLIBC_FOLDER/elf/Versions -p
#patch zrt before build
cp $PATCH_FOLDER/zvm.h $ZRT_FOLDER/lib/

rm $BUILD_FOLDER $LIBC_PREFIX -rf

#build libc install to the $LIBZRT_PREFIX
export __ZRT_HOST=something; export ZVM_PREFIX=$LIBC_PREFIX; export ZRT_ROOT=$ZRT_FOLDER;
export LIBZRT_PREFIX=$ZVM_PREFIX; export LIBZRT_ROOT=$ZRT_ROOT;
make -j4 -C$LIB_FOLDER || exit 1

make -C$LIBS_FOLDER clean all || exit 1

cd $LIBS_FOLDER
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:`pwd`;
MANIFEST_PATH=dyn-zrt-main.manifest.temp LD_PRELOAD=libzrt.so ./dyn-zrt-main
cd `pwd`

