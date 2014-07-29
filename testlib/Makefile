EXECUTABLES= zrt
CFLAGS=-g -O0 -static -fPIC -I./bpf
ZRT_SO=libzrt.so

ARCH=x86_64
ZRT_CFLAGS= -I$(ZRT_ROOT)/lib/zcalls -I$(ZRT_ROOT)/lib/helpers -I$(ZRT_ROOT)/lib \
-I$(ZVM_PREFIX)/$(ARCH)/include
ZRT_STATIC_LIBS= -L$(ZVM_PREFIX)/$(ARCH)/lib -L$(ZRT_ROOT)/lib \
-Wl,--start-group \
-lzrt -lnetworking -lmapreduce -ltar -lfs \
-lc -lrt -ldl -lm -lcrypt -lnss_files -lnss_dns -lresolv -Wl,--end-group \
-lstdc++ 

all: $(EXECUTABLES)

bpf/bpf-helper.o: bpf/bpf-helper.c
	$(CC) -c -g -O0 $^ -o $@
bpf/bpf-zrt.o: bpf/bpf-zrt.c
	$(CC) -c -g -O0 $^ -o $@

zrt: bpf/bpf-helper.o bpf/bpf-zrt.o
zrt: CFLAGS += -static $(ZRT_CFLAGS)
zrt: LDFLAGS += -static zvm.o bpf/bpf-zrt.o bpf/bpf-helper.o $(ZRT_STATIC_LIBS)
zrt: zrt.o zvm.o
	$(CC) -o $@ $@.o $(LDFLAGS)
	tar -cf tarimage.tar ../libc

$(ZRT_SO): CFLAGS += -static $(ZRT_CFLAGS)
$(ZRT_SO):
	gcc -c -Wall -Werror -fPIC $(ZRT_CFLAGS) libzrt.c
	gcc -shared -o $(ZRT_SO) libzrt.o $(ZRT_STATIC_LIBS) -Wl,--version-script=Versions
	gcc -Wall dyn-zrt-main.c -o dyn-zrt-main -L. -lzrt

clean:
	rm -f bpf/*.o *.o $(ZRT_SO) $(EXECUTABLES) tarimage.tar