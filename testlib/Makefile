EXECUTABLES= zrt
CFLAGS=-g -O0 -static

ARCH=x86_64
ZRT_CFLAGS= -I$(ZRT_ROOT)/lib/zcalls -I$(ZRT_ROOT)/lib/helpers -I$(ZRT_ROOT)/lib \
-I$(ZVM_PREFIX)/$(ARCH)/include
ZRT_STATIC_LIBS= -L$(ZVM_PREFIX)/$(ARCH)/lib -L$(ZRT_ROOT)/lib \
-Wl,--start-group \
-lzrt -lnetworking -lmapreduce -ltar -lfs \
-lc -lrt -ldl -lm -lcrypt -lnss_files -lnss_dns -lresolv -Wl,--end-group \
-lstdc++ 

all: $(EXECUTABLES)

zrt: CFLAGS += -static $(ZRT_CFLAGS)
zrt: LDFLAGS += -static zvm.o $(ZRT_STATIC_LIBS)
zrt: zrt.o zvm.o
	$(CC) -o $@ $@.o $(LDFLAGS)
	tar -cf tarimage.tar ../libc

clean:
	rm -f *.o $(EXECUTABLES) tarimage.tar