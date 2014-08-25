# define _GNU_SOURCE         /* See feature_test_macros(7) */
# include <unistd.h>
# include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include "memory/memory_syscall_handlers.h"

#include "zvm.h"

#define ZRT_HEAP_SIZE 1024*1024*1024

/*channels: stdin, stdout, stderr, nvram*/
#define ZRT_DEBUG_FNAME "zrt.debug"
#define ZRT_NVRAM_FNAME "zrt.nvram"
#define ZRT_TARIMPORT_FNAME "zrt.import.tar"
#define ZRT_TAREXPORT_FNAME "zrt.export.tar"

#define CHANNEL_SIZE_LIMIT 999999999
#define CHANNEL_OPS_LIMIT  999999999
#define CHANNEL_STDIN {{CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT, 0, 0},	0,SGetSPut,"/dev/stdin"}
#define CHANNEL_STDOUT {{0, 0, CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT},	0,SGetSPut,"/dev/stdout"}
#define CHANNEL_STDERR {{0, 0, CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT},	0,SGetSPut,"/dev/stderr"}
#define CHANNEL_DEBUG  {{0, 0, CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT},	0,SGetSPut,"/dev/debug"}
#define CHANNEL_NVRAM  {{CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT, 0, 0},	1000,RGetSPut,"/dev/nvram"}
#define CHANNEL_TARIMPORT {{CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT, 0, 0}, 0,RGetSPut, "/dev/mount/import.tar"}
#define CHANNEL_TAREXPORT {{CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT, CHANNEL_OPS_LIMIT, CHANNEL_SIZE_LIMIT},0,RGetRPut, "/dev/mount/export.tar"}
#define MAX_CHANNELS_COUNT 10
extern int* s_zrt_filetable;


/****************** static zvm-emulated data*/
/*extern variables*/
int *s_zrt_filetable;
int s_zrt_filetable_[MAX_CHANNELS_COUNT];

struct ZVMChannel s_channels[MAX_CHANNELS_COUNT];
struct UserManifest s_zrt_manifest;
struct UserManifest* extern_manifest = &s_zrt_manifest;

/****************** */

struct ZVMChannel *open_channels_create_list(int32_t *count){
    /*preopen files*/
    int32_t channels_count = 0;

    struct ZVMChannel stdin_chan = CHANNEL_STDIN;
    struct ZVMChannel stdout_chan = CHANNEL_STDOUT;
    struct ZVMChannel stderr_chan = CHANNEL_STDERR;
    struct ZVMChannel nvram_chan = CHANNEL_NVRAM;
    struct ZVMChannel debug_chan = CHANNEL_DEBUG;
    struct ZVMChannel import_chan = CHANNEL_TARIMPORT;
    struct ZVMChannel export_chan = CHANNEL_TAREXPORT;

    /*add standard files*/
    s_channels[channels_count] = stdin_chan;
    s_zrt_filetable_[channels_count++] = 0; //stdin

    s_channels[channels_count] = stdout_chan;
    s_zrt_filetable_[channels_count++] = 1; //stdout

    s_channels[channels_count] = stderr_chan;
    s_zrt_filetable_[channels_count++] = 2; //stderr

    /*Emulate channels preopening*/
    int nvram_fd = open(ZRT_NVRAM_FNAME, O_RDONLY, 0);
    if (nvram_fd <0){ perror(ZRT_NVRAM_FNAME); abort();}
    s_channels[channels_count] = nvram_chan;
    s_zrt_filetable_[channels_count++] = nvram_fd;

    int debug_fd = open(ZRT_DEBUG_FNAME, O_CREAT|O_WRONLY, 0666);
    if (debug_fd < 0) {perror(ZRT_DEBUG_FNAME); abort();}
    s_channels[channels_count] = debug_chan;
    s_zrt_filetable_[channels_count++] = debug_fd;

    int import_fd = open(ZRT_TARIMPORT_FNAME, O_RDONLY, 0);
    if (import_fd < 0) {perror(ZRT_TARIMPORT_FNAME); abort();}
    s_channels[channels_count] = import_chan;
    s_zrt_filetable_[channels_count++] = import_fd;

    int export_fd = open(ZRT_TAREXPORT_FNAME, O_CREAT|O_RDWR, 0666);
    if (export_fd < 0) {perror(ZRT_TAREXPORT_FNAME); abort();}
    s_channels[channels_count] = export_chan;
    s_zrt_filetable_[channels_count++] = export_fd;

    s_zrt_filetable = (int*)s_zrt_filetable_;

    *count = channels_count;
    return s_channels;
}


void prepare_zrt_host(){
    /*Emulate hypervisor. do all initializations*/

    int32_t channels_count=0;
    struct ZVMChannel *channels = open_channels_create_list(&channels_count);

    uint32_t heap_size = ZRT_HEAP_SIZE;
    heap_size *= 6;

    /*allocate heap*/
    void *heap = mmap(NULL, heap_size,
		      PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if ( heap == MAP_FAILED )
	perror("heap create FAILED");

#define ALIGN(k, v) (((k)+((v)-1))&(~((v)-1)))
    /*align heap on zrt's pagesize*/    
    s_zrt_manifest.heap_ptr = (void*)ALIGN((intptr_t)heap, PAGE_SIZE);
    /*if heap start adress is aligned on linux pagesize then decrement
      heap size on zrt's pagesize value*/
    s_zrt_manifest.heap_size = 
	heap!=s_zrt_manifest.heap_ptr?heap_size-PAGE_SIZE:heap_size;
    s_zrt_manifest.stack_size = 0;
    s_zrt_manifest.channels_count = channels_count;
    s_zrt_manifest.channels = channels;
}

ssize_t zvm_pread (int fd, void *buf, size_t nbytes, off_t offset){
    ssize_t ret;
    int chantype = extern_manifest->channels[fd].type;
    fd = s_zrt_filetable[fd];
    if ( chantype == SGetSPut || chantype == SGetRPut ){
	ret = read(fd, buf, nbytes);
    }
    else
	ret = pread(fd, buf, nbytes, offset);
    return ret;
}

ssize_t zvm_pwrite(int fd, const void *buf, size_t n, off_t offset){
    ssize_t ret;
    int chantype = extern_manifest->channels[fd].type;
    fd = s_zrt_filetable[fd];
    if ( chantype == SGetSPut || chantype == RGetSPut ){
	ret = write(fd, buf, n);
    }
    else
	ret = pwrite(fd, buf, n, offset);
    return ret;
}

void zvm_exit(int code){

}

