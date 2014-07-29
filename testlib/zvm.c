# define _GNU_SOURCE         /* See feature_test_macros(7) */
# include <unistd.h>
# include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "memory/memory_syscall_handlers.h"

#include "zvm.h"

#define ZRT_HEAP_START 0xffffffff /*be determined at runtime*/
#define ZRT_HEAP_SIZE 1024*1024*1024

/*channels: stdin, stdout, stderr, nvram*/
#define ZRT_DEBUG_FNAME "zrt.debug"
#define ZRT_NVRAM_FNAME "zrt.nvram"
#define ZRT_TARIMPORT_FNAME "tarimage.tar"
#define ZRT_TAREXPORT_FNAME "zrt.export.tar"
#define ZRT_CHANNELS_COUNT 7

#define CHANNEL_SIZE_LIMIT 999999999
#define CHANNEL_OPS_LIMIT  999999999
#define MANIFEST_CHANNELS {						\
	{{CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT, 0, 0},	0,SGetSPut,"/dev/stdin"}, \
	    {{0, 0, CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT},	0,SGetSPut,"/dev/stdout"}, \
		{{0, 0, CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT},	0,SGetSPut,"/dev/stderr"}, \
		    {{0, 0, CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT},	0,SGetSPut,"/dev/debug"}, \
			{{CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT, 0, 0},	0,RGetSPut,"/dev/nvram"}, \
			    {{CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT, 0, 0},	0,RGetSPut, \
										    "/dev/mount/import.tar"}, \
				{{CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT, CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT},	0,RGetRPut, "/dev/mount/export.tar"} \
    } 
#define MANIFEST_DEFAULTS(channels) {(void *)ZRT_HEAP_START, ZRT_HEAP_SIZE, 0, ZRT_CHANNELS_COUNT, channels }


extern int* s_zrt_filetable;


/****************** static zvm-emulated data*/
/*extern variables*/
int *s_zrt_filetable;
int s_zrt_filetable_[10];

struct ZVMChannel s_channels[] = MANIFEST_CHANNELS;
struct UserManifest s_zrt_manifest = MANIFEST_DEFAULTS( s_channels );
struct UserManifest* extern_manifest = &s_zrt_manifest;

/****************** */

static void* syscall6(int nr, void* arg0, size_t arg1,
		      int arg2, int arg3, int arg4, unsigned long arg5)
{
    register unsigned long r10 asm("r10") = r10;
    register unsigned long r8 asm("r8") = r8;
    register unsigned long r9 asm("r9") = r9;
    void* ret;
    
    r10 = arg3;
    r8 = arg4;
    r9 = arg5;
    asm volatile("syscall"
		 : "=a" (ret)
		 : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		 : "memory");
    return ret;
}

void prepare_zrt_host(){
    /*Emulate hypervisor. Initialize heap*/
    /*set start heap address and allocate*/

    extern_manifest->heap_size = 1024*1024*1024;
    void * heap = syscall6(__NR_mmap, NULL, extern_manifest->heap_size,
			   PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
    if ( heap == MAP_FAILED )
	abort();
    extern_manifest->heap_ptr = heap;
    extern_manifest->heap_ptr = (void*)ROUND_UP((intptr_t)heap, PAGE_SIZE);
    /*if heap start adress is aligned on pagesize then decremant heap size on pagesize's value*/
    if ( heap != extern_manifest->heap_ptr )
	extern_manifest->heap_size -= PAGE_SIZE;

    /*Emulate channels preopening*/
    int nvram_fd;
    asm volatile ("syscall"
		  : "=a" (nvram_fd)
		  : "0" (__NR_open),
		    "D" (ZRT_NVRAM_FNAME),
		    "S" (O_RDONLY)
		  : "memory");
    if (nvram_fd <0) abort();

    int debug_fd;
    asm volatile ("syscall"
		  : "=a" (debug_fd)
		  : "0" (__NR_open),
		    "D" (ZRT_DEBUG_FNAME),
		    "S" (O_CREAT|O_WRONLY),
		    "d" (0666)
		  : "memory");
    if (debug_fd < 0) abort();

    int import_fd;
    asm volatile ("syscall"
		  : "=a" (import_fd)
		  : "0" (__NR_open),
		    "D" (ZRT_TARIMPORT_FNAME),
		    "S" (O_RDONLY)
		  : "memory");
    if (import_fd < 0) abort();

    int export_fd;
    asm volatile ("syscall"
		  : "=a" (export_fd)
		  : "0" (__NR_open),
		    "D" (ZRT_TAREXPORT_FNAME),
		    "S" (O_CREAT|O_RDWR),
		    "d" (0666)
		  : "memory");
    if (export_fd < 0) abort();

    s_zrt_filetable = (int*)s_zrt_filetable_;

    /*preopen files*/
    int i=0;
    s_zrt_filetable[i++] = 0; //stdin
    s_zrt_filetable[i++] = 1; //stdout
    s_zrt_filetable[i++] = 2; //stderr
    s_zrt_filetable[i++] = debug_fd; //debug
    s_zrt_filetable[i++] = nvram_fd; //nvram
    s_zrt_filetable[i++] = import_fd; //import
    s_zrt_filetable[i++] = export_fd; //export
}

ssize_t zvm_pread (int fd, void *buf, size_t nbytes, off_t offset){
    ssize_t ret;
    if ( fd == 0 ){
	zvm_read_write(ret, __NR_read, fd, buf, nbytes);
    }
    else
	zvm_pread_pwrite(ret, __NR_pread, fd, buf, nbytes, offset);
    return ret;
}

ssize_t zvm_pwrite (int fd, const void *buf, size_t n, off_t offset){
    ssize_t ret;
    if ( fd == 1 || fd == 2 ){
	zvm_read_write(ret, __NR_write, fd, buf, n);
    }
    else
	zvm_pread_pwrite(ret, __NR_pwrite, fd, buf, n, offset);
    return ret;
}


