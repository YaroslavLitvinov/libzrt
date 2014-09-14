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
$(CLIB_PATH)/libnss_dns.a $(CLIB_PATH)/libresolv.a $(CLIB_PATH)/libpthread.a \
-Wl,--end-group 
#$(CLIB_PATH)/libfs.a

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
	export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):$(CURDIR)
	gcc -m64 -g -shared -o $(ZRT_SO) libzrt.o zvm.o zrt-syscalls.o  bpf/simple-seccomp.o \
	-Wl,--whole-archive -Wl,-static $(ZRT_STATIC_LIBS) -Wl,--no-whole-archive \
	-Wl,-Bdynamic -L$(CURDIR) -lzvm3 -lstdc++ -ldl

dyn-zrt-main: 
	g++ -Wall -g dyn-zrt-main.c -o $@ #-L. -lzrt -lzvm3
	tar -cf $@.import.tar.temp ../zerovm
#genmanifest
	MEMORY=4294967296 \
	TIMEOUT=20 \
	ABS_PATH=$(CURDIR) \
	NAME=$@ \
	CHANNELS_INCLUDE=channels.manifest.include \
	./template.sh manifest.template > $@.manifest.temp

override_libc:
	rm -fr override_libc symbols_replace
	mkdir -p override_libc
	`find $(ZVM_PREFIX)/$(ARCH)/lib -name "*.a" | xargs cp -t ./override_libc`
	`find ./override_libc -name "*.a" | xargs nm -A \
	| awk '{if ($$2 != "U") {print $$0}}' \
	| awk '{ print $$3, "__zrt_"$$3 }' | sort | uniq > symbols_replace`
	`find ./override_libc -name "*.a" | xargs -l objcopy --redefine-syms=symbols_replace `

clean:
	rm -rf override_libc symbols_replace bpf/*.o *.o $(ZRT_SO) $(EXECUTABLES) tarimage.tar *.temp

#grep -in -e " t " -e " d " -e " w " -e " c " -e " b " -e " v "
