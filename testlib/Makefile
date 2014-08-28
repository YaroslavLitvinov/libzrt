ZRT_SO=libzrt.so
ZVM_SO=libzvm3.so
ZVM_PATH=../zerovm
EXECUTABLES= $(ZVM_SO) $(ZRT_SO) dyn-zrt-main
CFLAGS=-g -Wall -O0 -fPIC -I./bpf
CLIB_PATH=./override_libc

ARCH=x86_64
ZRT_CFLAGS= -I$(ZRT_ROOT)/lib/zcalls -I$(ZRT_ROOT)/lib/helpers -I$(ZRT_ROOT)/lib \
-I$(ZVM_PREFIX)/$(ARCH)/include
ZRT_STATIC_LIBS= -Wl,--start-group \
$(CLIB_PATH)/libzrt.a $(CLIB_PATH)/libnetworking.a $(CLIB_PATH)/libmapreduce.a $(CLIB_PATH)/libtar.a \
$(CLIB_PATH)/libc.a $(CLIB_PATH)/librt.a $(CLIB_PATH)/libcrypt.a $(CLIB_PATH)/libnss_files.a \
$(CLIB_PATH)/libnss_dns.a $(CLIB_PATH)/libresolv.a $(CLIB_PATH)/libpthread.a -Wl,--end-group 

all: $(EXECUTABLES)

bpf/simple-seccomp.o: bpf/simple-seccomp.c
	$(CC) -c -g -O0 $^ -o $@ -I. -fPIC
zrt-syscalls.o: zrt-syscalls.c
	$(CC) -c -g -O0 $^ -o $@ -I. -fPIC

$(ZVM_SO):
	mkdir $(ZVM_PATH)/obj -p
	make -C$(ZVM_PATH) clean $(ZVM_SO)
	cp $(ZVM_PATH)/libzvm3.so .

$(ZRT_SO): 
$(ZRT_SO): CFLAGS = -Wall -g -Werror -fPIC $(ZRT_CFLAGS)  -DPREFIX_ZRT_SYMBOLS -I$(ZVM_PATH) -I. `pkg-config --cflags glib-2.0`
$(ZRT_SO): CFLAGS += -I$(ZVM_PREFIX)/$(ARCH)/include
$(ZRT_SO): bpf/simple-seccomp.o libzrt.o zvm.o zrt-syscalls.o
$(ZRT_SO): override_libc
	export LD_LIBRARY_PATH=$(CURDIR)
	gcc -m64 -g -shared -o $(ZRT_SO) libzrt.o zvm.o zrt-syscalls.o  bpf/simple-seccomp.o \
	-Wl,--whole-archive -Wl,-static $(ZRT_STATIC_LIBS) -Wl,--no-whole-archive \
	-Wl,-Bdynamic -L$(CURDIR) -lzvm3
#	-L$(ZVM_PREFIX)/$(ARCH)/lib -Wl,--whole-archive -lbfd -liberty -Wl,--no-whole-archive 
#-Wl,--version-script=Versions -nostdlib 

dyn-zrt-main: 
	gcc -Wall -g dyn-zrt-main.c -o $@ #-L. -lzrt -ldl
#genmanifest
	MEMORY=33554432 \
	TIMEOUT=20 \
	ABS_PATH=$(CURDIR) \
	NAME=$@ \
	CHANNELS_INCLUDE=channels.manifest.include \
	./template.sh manifest.template > $@.manifest.temp

override_libc:
	rm -fr override_libc
	mkdir -p override_libc
	`find $(ZVM_PREFIX)/$(ARCH)/lib -name "*.a" | xargs cp -t ./override_libc`
	`find ./override_libc -type f \( -iname "*.a" ! -iname "libbfd.a" ! -iname "libiberty.a" \) | xargs -l objcopy --localize-symbol=fstatat --prefix-symbols=__zrt_ `
	`find ./override_libc -name '*.a' | xargs -l objcopy \
	--redefine-sym __zrt__GLOBAL_OFFSET_TABLE_=_GLOBAL_OFFSET_TABLE_ \
	--redefine-sym __zrt_zvm_pwrite=zvm_pwrite \
	--redefine-sym __zrt_zvm_pread=zvm_pread \
	--redefine-sym __zrt_zvm_exit=zvm_exit \
	--redefine-sym __zrt_prepare_zrt_host=prepare_zrt_host \
	--redefine-sym __zrt_extern_manifest=extern_manifest  `

clean:
	rm -rf override_libc bpf/*.o *.o $(ZRT_SO) $(EXECUTABLES) tarimage.tar *.temp