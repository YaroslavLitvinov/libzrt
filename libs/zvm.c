# define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#include "zvminit.h"

#define ZVMSO
#include "src/main/manifest.h"
#include "src/channels/channel.h"
#include "memory/memory_syscall_handlers.h"
#include "zvm.h"

#define ALIGN(k, v) (((k)+((v)-1))&(~((v)-1)))

struct UserManifest s_user_manifest;
struct UserManifest *extern_manifest=NULL;
struct Manifest *s_system_manifest=NULL;

/****************** */
struct ZVMChannel *open_channels_create_list(struct Manifest *manifest){
    struct ZVMChannel *channels = (struct ZVMChannel *)malloc(sizeof(struct ZVMChannel)*manifest->channels->len);
    int i;
    for( i=0; i < manifest->channels->len; i++ ){
	struct ChannelDesc* channel_desc = GetChannel(manifest, i);
	memcpy(channels[i].limits, channel_desc->limits, sizeof(int64_t)*LimitsNumber);
	channels[i].size = channel_desc->size;
	channels[i].type = channel_desc->type;
	channels[i].name = channel_desc->alias;
    }
    return channels;
}

struct UserManifest* setup_user_manifest(struct UserManifest* user_manifest,
					 void* heap_ptr, size_t heap_size, 
					 struct ZVMChannel *channels, int channels_count){
    /*align heap on zrt's pagesize*/    
    user_manifest->heap_ptr = (void*)ALIGN((intptr_t)heap_ptr, PAGE_SIZE);
    /*if heap start adress is aligned on linux pagesize then decrement
      heap size on zrt's pagesize value*/
    user_manifest->heap_size = 
	heap_ptr!=user_manifest->heap_ptr?heap_size-PAGE_SIZE:heap_size;
    user_manifest->stack_size = 0;
    user_manifest->channels_count = channels_count;
    user_manifest->channels = channels;
    return user_manifest;
}

void zvm_session_init(const char *manifest_path ){
    /*Emulate hypervisor. do all initializations*/

    if ( manifest_path == NULL ){
	fprintf(stderr, "environment variable MANIFEST_PATH not specified\n");
	exit(1);
    }
    s_system_manifest = ManifestCtor(manifest_path);
    if (s_system_manifest != NULL){	
	ChannelsCtor(s_system_manifest);

#ifdef USE_MMAP_MEMORY_LIBZRT
	/*allocate heap using mmap*/
	void *heap = mmap(NULL, s_system_manifest->mem_size,
			  PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if ( heap == MAP_FAILED ){
	    perror("heap create FAILED by mmap");
	    exit(1);
	}
#else
	void *heap = sbrk(0);
	void *heap_brk = heap+s_system_manifest->mem_size;
	extern void *__curbrk;
	printf("before heap_ptr=%p\n", heap);fflush(0);
	if ( brk(heap_brk) != 0 ){
	    perror("heap create FAILED by brk");
	    exit(1);
	}
	__curbrk = heap_brk;
#endif //USE_MMAP_MEMORY_LIBZRT

	extern_manifest = setup_user_manifest(&s_user_manifest,
					      heap, s_system_manifest->mem_size, 
					      open_channels_create_list(s_system_manifest),
					      s_system_manifest->channels->len );
    }
}

ssize_t zvm_pread (int fd, void *buf, size_t nbytes, off_t offset){
    ssize_t ret;
    if ( fd >= 0 && fd < s_system_manifest->channels->len ){
	struct ChannelDesc *chan_desc = GetChannel(s_system_manifest, fd);
	fd = (int64_t)chan_desc->handle;
	int chantype = chan_desc->type;
	if ( chantype == SGetSPut || chantype == SGetRPut ){
	    ret = read(fd, buf, nbytes);
	}
	else
	    ret = pread(fd, buf, nbytes, offset);
    }
    else{
	ret = -EBADF;
    }
    return ret;
}

ssize_t zvm_pwrite(int fd, const void *buf, size_t n, off_t offset){
    ssize_t ret;
    if ( fd >= 0 && fd < s_system_manifest->channels->len ){
	struct ChannelDesc *chan_desc = GetChannel(s_system_manifest, fd);
	fd = (int64_t)chan_desc->handle;
	int chantype = chan_desc->type;
	if ( chantype == SGetSPut || chantype == RGetSPut ){
	    ret = write(fd, buf, n);
	}
	else
	    ret = pwrite(fd, buf, n, offset);
    }
    else{
	ret = -EBADF;
    }
    return ret;
}

void zvm_exit(int code){

}

