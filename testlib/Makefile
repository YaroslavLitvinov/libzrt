ZRT_SO=libzrt.so
EXECUTABLES= $(ZRT_SO) dyn-zrt-main
CFLAGS=-g -Wall -O0 -fPIC -I./bpf

ARCH=x86_64
ZRT_CFLAGS= -I$(ZRT_ROOT)/lib/zcalls -I$(ZRT_ROOT)/lib/helpers -I$(ZRT_ROOT)/lib \
-I$(ZVM_PREFIX)/$(ARCH)/include
ZRT_STATIC_LIBS= -Wl,--start-group \
-lzrt -lnetworking -lmapreduce -ltar \
-lc -lrt -lcrypt -lnss_files -lnss_dns -lresolv -lpthread -Wl,--end-group 

all: $(EXECUTABLES)

bpf/simple-seccomp.o: bpf/simple-seccomp.c
	$(CC) -c -g -O0 $^ -o $@ -I. -fPIC
zrt-syscalls.o: zrt-syscalls.c
	$(CC) -c -g -O0 $^ -o $@ -I. -fPIC

$(ZRT_SO): CLIB_PATH=./override_libc
$(ZRT_SO): CFLAGS = -Wall -g -Werror -fPIC $(ZRT_CFLAGS)  -DPREFIX_ZRT_SYMBOLS
$(ZRT_SO): bpf/simple-seccomp.o 
$(ZRT_SO): libzrt.o zvm.o zrt-syscalls.o override_libc
	gcc -m64 -g -shared -o $(ZRT_SO) libzrt.o zvm.o zrt-syscalls.o bpf/simple-seccomp.o -L$(CLIB_PATH) \
	-Wl,--whole-archive  $(ZRT_STATIC_LIBS) -Wl,--no-whole-archive -Wl,--version-script=Versions -nostdlib

dyn-zrt-main: 
	gcc -Wall -g dyn-zrt-main.c -o $@ -L. -lzrt
	tar -cf zrt.import.tar ../libc

override_libc:
	rm -fr override_libc
	mkdir -p override_libc
	`find $(ZVM_PREFIX)/$(ARCH)/lib -name "*.a" | xargs cp -t ./override_libc`
	`find ./override_libc -name '*.a' | xargs -l objcopy --localize-symbol=fstatat --prefix-symbols=__zrt_ `
	`find ./override_libc -name '*.a' | xargs -l objcopy \
	--redefine-sym __zrt___gcc_personality_v0=__gcc_personality_v0 \
	--redefine-sym __zrt__GLOBAL_OFFSET_TABLE_=_GLOBAL_OFFSET_TABLE_ \
	--redefine-sym __zrt__Unwind_GetIP=_Unwind_GetIP \
	--redefine-sym __zrt__Unwind_Resume=_Unwind_Resume \
	--redefine-sym __zrt_zvm_pwrite=zvm_pwrite \
	--redefine-sym __zrt_zvm_pread=zvm_pread \
	--redefine-sym __zrt_zvm_exit=zvm_exit \
	--redefine-sym __zrt___fdelt_chk=__fdelt_chk \
	--redefine-sym __zrt_prepare_zrt_host=prepare_zrt_host \
	--redefine-sym __zrt_extern_manifest=extern_manifest \
	--redefine-sym __zrt__Unwind_Backtrace=_Unwind_Backtrace `

clean:
	rm -rf override_libc bpf/*.o *.o $(ZRT_SO) $(EXECUTABLES) tarimage.tar 