# define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#define ZVMSO
#include "src/main/manifest.h"
#include "src/channels/channel.h"
#include "memory/memory_syscall_handlers.h"
#include "zvm.h"

#define ALIGN(k, v) (((k)+((v)-1))&(~((v)-1)))

struct UserManifest s_user_manifest;
struct UserManifest *extern_manifest=NULL;
struct Manifest *s_system_manifest=NULL;

/****************** static zvm-emulated data*/
/* struct ZVMChannel s_channels[MAX_CHANNELS_COUNT]; */


/*dl zvm3.so functions*/
/* void *f_ManifestCtor; */
/* void *f_ManifestDtor; */
/* void *f_GetChannel; */
/* void *f_ChannelsCtor; */

//struct Manifest *(*ManifestCtor)(const char *);
//void (*ManifestDtor)(struct Manifest *);
//struct ChannelDesc* (*GetChannel)(struct Manifest *manifest, int index);
//void (*ChannelsCtor)(struct Manifest *manifest);


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

void prepare_zrt_host(){
    /*Emulate hypervisor. do all initializations*/

    /**/
    /* void *libhdl = dlopen( "./libzvm3.so", RTLD_NOW|RTLD_DEEPBIND); */
    /* if (!libhdl) */
    /* 	{ */
    /* 	    fprintf(stderr, "Problem with loading SO: %s\n", */
    /* 		    dlerror()); */
    /* 	    exit(1); */
    /* 	} */
    /* f_ManifestCtor = (struct Manifest *(*)(const char *))dlsym(libhdl, "ManifestCtor"); */
    /* f_ManifestDtor = (void (*)(struct Manifest *))dlsym(libhdl, "ManifestDtor"); */
    /* f_GetChannel = (struct ChannelDesc* (*)(struct Manifest *manifest, int index))dlsym(libhdl, "GetChannel"); */
    /* f_ChannelsCtor = (void (*)(struct Manifest *manifest))dlsym(libhdl, "ChannelsCtor"); */

    /* if (!ManifestCtor || !ManifestDtor) */
    /* 	fprintf(stderr, "Problem loading symbol: %s\n", dlerror()); */

    char *manifest_path = getenv("MANIFEST_PATH");
    if ( manifest_path == NULL ){
	fprintf(stderr, "environment variable MANIFEST_PATH not specified\n");
	exit(1);
    }
    s_system_manifest = ManifestCtor(manifest_path);
    if (s_system_manifest != NULL){	
	ChannelsCtor(s_system_manifest);

	/*allocate heap*/
	void *heap = mmap(NULL, s_system_manifest->mem_size,
			  PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if ( heap == MAP_FAILED ){
	    perror("heap create FAILED");
	    exit(1);
	}

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

