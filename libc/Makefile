# Copyright (c) 2012 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# Copyright (c) 2013 LiteStack, Inc. All rights reserved.

##############################################################################
# Helper script for NaCl toolchain development workflow.
#
# Buildbots:
# - Sync needed sources at pinned revision and build newlib-based toolchain:
#     make buildbot-build-with-newlib TOOLCHAINLOC=<where-to-install-the-toolchain>
#  or
#     make buildbot-build-with-glibc TOOLCHAINLOC=<where-to-install-the-toolchain>
#
# Development:
# - Sync all sources at pinned revision:
#     make sync-pinned
# - Sync all sources at most recent revision:
#     make sync
# - Build newlib-based toolchain from current sources:
#     make build-with-newlib TOOLCHAINLOC=<where-to-install-the-toolchain>
# - Build glibc-based toolchain from current sources:
#     make build-with-glibc TOOLCHAINLOC=<where-to-install-the-toolchain>
#
##############################################################################

PREFIX?=$(LIBZRT_PREFIX)

default:  install-glibc

# Delete the target file if the recipe fails after beginning to change the file
# http://www.gnu.org/software/make/manual/make.html#Errors (Errors in Recipes)
.DELETE_ON_ERROR: ;

THISMAKEFILE := $(lastword $(MAKEFILE_LIST))

SHELL = /bin/bash

CROSSARCH = x86_64
define PREFIX_ERR

endef
ifndef LIBZRT_PREFIX
$(error $(PREFIX_ERR))
endif
define ZRT_ERR

endef
ifndef LIBZRT_ROOT
$(error $(ZRT_ERR))
endif
SDKROOT ?= $(abspath $(LIBZRT_PREFIX))
#SDKROOT ?= $(SDKLOC)/$(SDKNAME)
DESTDIR ?=

# We can't use CFLAGS and LDFLAGS since they are passed to sub-makes and
# those override configure parameters.
USER_CFLAGS = -O2 -g
USER_LDFLAGS = -s

# By default all toolchain executables are x86-32 executables, use
# HOST_TOOLCHAIN_BITS=64 to make them x86-64 executables.
HOST_TOOLCHAIN_BITS = 32

# Convert CROSSARCH (nacl or nacl64) to (32 or 64).
BITSPLATFORM = 64

LINUX_HEADERS = "$(abspath $(dir $(THISMAKEFILE)))/SRC/linux-headers-for-nacl/include"

BUILDPATH = $(DESTDIR)$(PREFIX)/bin:$(PATH)
PREFIX_NATIVE = $(DESTDIR)$(PREFIX)

# Create the build directories for compiled binaries.
BUILD:
	mkdir BUILD

##################################################################
# glibc:
##################################################################

# Build directory for glibc.
GLIBC_BUILD_DIR = BUILD/build-glibc-$(CROSSARCH)

# Glibc is built with pregcc.
GLIBC_CC = gcc -D__ZRT_HOST -D__ZRT_SO -U_FORTIFY_SOURCE -fPIC 
# issue a warning whenever a value is implicitly converted (truncated)
# from a 64-bit type to a 32-bit type
#GLIBC_CC += -Wconversion

# CFLAGS for building glibc.
#switch off HP_TIMING
GLIBC_CFLAGS += -O2 -g #-fno-stack-protector #-UHP_SMALL_TIMING_AVAIL

ARCH_DEST = $(DESTDIR)$(PREFIX)/$(CROSSARCH)
ARCH_DEST_INC_NATIVE = $(PREFIX_NATIVE)/$(CROSSARCH)/include

# LIB_BITS is used with different values to execute targets in this Makefile for
# different architectures (32, 64) when building libraries (glibc and nacl).
# CROSSARCH and BITSPLATFORM could be used for this, but we better avoid
# redefining variables with recursive $(MAKE) calls.
LIB_BITS ?= 64
ARCH_DEST_LIB_NATIVE = $(PREFIX_NATIVE)/$(CROSSARCH)/$(if $(filter 32,$(LIB_BITS)),lib32,lib)

BUILD/stamp-glibc64: SRC/glibc glibc-adhoc-files zrt-stub64
	if [[ ! -d $(LINUX_HEADERS) ]] ; then \
	  $(MAKE) -f $(THISMAKEFILE) SRC/linux-headers-for-nacl ; \
	fi
	rm -rf BUILD/build-glibc64
	mkdir -p BUILD/build-glibc64
	cd BUILD/build-glibc64 && ../../SRC/glibc/configure \
	    ZRT_ROOT="$(LIBZRT_ROOT)" \
	    BUILD_CC="gcc -O2 -g" \
	    CC="$(GLIBC_CC) -m64" \
	    CFLAGS="-pipe -fno-strict-aliasing -mno-tls-direct-seg-refs $(GLIBC_CFLAGS)" \
	    libc_cv_forced_unwind=yes \
	    libc_cv_c_cleanup=yes \
	    libc_cv_slibdir=/lib \
	    --prefix= \
	    --libdir=/lib \
	    --host=x86_64-linux-gnu \
	    --with-headers=$(LINUX_HEADERS) \
	    --enable-shared=no \
	    --enable-kernel=2.6.18 \
	    --with-zrt=forhost \
	    --with-selinux=no 
	ZRT_ROOT=$(LIBZRT_ROOT) $(MAKE) -C BUILD/build-glibc64
	ZRT_ROOT=$(LIBZRT_ROOT) $(MAKE) -C BUILD/build-glibc64 install_root=$(DESTDIR)$(PREFIX)/$(CROSSARCH) install
	touch $@

# Can be used to make a glibc archive separately from the main install tree.
# Used, i.e., on buildbots.
INST_GLIBC_PREFIX ?= $(PREFIX)
.PHONY: install-glibc
install-glibc: build-with-glibc
#	rm -rf "$(INST_GLIBC_PREFIX)"
#	mkdir "$(INST_GLIBC_PREFIX)"
	$(MAKE) -f $(THISMAKEFILE) -C BUILD/build-glibc64 \
	  install_root="$(INST_GLIBC_PREFIX)/$(CROSSARCH)" install
#build zrt and replace zrt-stub by real implementation
	export __ZRT_NOCPP=something; export __ZRT_HOST=something; export ZVM_PREFIX=$(LIBZRT_PREFIX); export ZRT_ROOT=$(LIBZRT_ROOT);
	make -C$(LIBZRT_ROOT) clean build install

##################################################################
# Build the entire toolchain.
##################################################################

ZRT_CFLAGS=-DZLIBC_STUB -pipe -fno-strict-aliasing -mno-tls-direct-seg-refs
ZRT_BUILD_OBJ=$(ZRT_CFLAGS) -c -o $(LIBZRT_ROOT)/lib/zrt.o $(LIBZRT_ROOT)/lib/zrt.c

zrt-stub64:
	rm -f $(LIBZRT_ROOT)/lib/zrt.o
	$(GLIBC_CC) -m64 $(ZRT_BUILD_OBJ)

# On platforms where glibc build is slow or unavailable you can specify
# glibc_download.sh (or any other program) to download glibc
INST_GLIBC_PROGRAM ?= none
.PHONY: build-with-glibc
build-with-glibc: BUILD/stamp-glibc64


##################################################################
# selection of NaCl headers for GCC.
##################################################################
.PHONY: glibc-adhoc-files
glibc-adhoc-files: | SRC/glibc
	if [[ ! -d $(LINUX_HEADERS) ]] ; then \
	  $(MAKE) -f $(THISMAKEFILE) SRC/linux-headers-for-nacl ; \
	fi
	mkdir -p $(ARCH_DEST)/include/{sys,machine,bits}
	cp -rf $(LINUX_HEADERS)/{asm*,linux} $(ARCH_DEST)/include

##################################################################
# Remove the BUILD directory.
# Library builds are maintained by scons.
##################################################################

.PHONY: clean
clean:
	rm -rf BUILD/*
	export __ZRT_HOST=something; export ZVM_PREFIX=$(LIBZRT_PREFIX); export ZRT_ROOT=$(LIBZRT_ROOT);
	make -C$(LIBZRT_ROOT) clean
