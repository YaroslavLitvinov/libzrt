EXECUTABLES= zrt
CFLAGS=-g -O0 -static

ARCH=x86_64
ZRT_ROOT=../seccomp-zrt2
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

so_test: 
	gcc -c -Wall -Werror -fPIC so_test.c
	gcc -shared -o lib_test.so so_test.o
	gcc -L$(CURDIR) -Wall so_user.c -o so_user -l_test

dyn-zrt: 
	gcc -c -Wall -Werror -fPIC $(ZRT_CFLAGS) dyn-zrt.c
	gcc -shared -o 	libdyn-zrt.so -Wl,--whole-archive  $(ZRT_STATIC_LIBS) -Wl,--no-whole-archive
	gcc -L$(CURDIR) -Wall dyn-zrt-main.c -o dyn-zrt-main -ldyn-zrt

clean:
	rm -f *.o $(EXECUTABLES) 