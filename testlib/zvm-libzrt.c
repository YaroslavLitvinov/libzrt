#include <unistd.h>

struct UserManifest* extern_manifest;

/*do nothing*/
void prepare_zrt_host(){
}

/*Always successfull*/
ssize_t zvm_pread (int fd, void *buf, size_t nbytes, off_t offset){
    return nbytes;
}

/*Always successfull*/
ssize_t zvm_pwrite (int fd, const void *buf, size_t n, off_t offset){
    return n;
}


