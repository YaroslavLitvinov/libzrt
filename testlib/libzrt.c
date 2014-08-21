
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include "zrt.h"
#include "libzrt.h"
#include "libzrt_externs.h"

extern int LIBZRT_SYMBOL(errno);
#define SET_ZRT_ERRNO zrt_errno = LIBZRT_SYMBOL(errno)

int zrt_errno;

/*not for export.*/
int LIBZRT_SYMBOL(init)(int argc, char **argv, char **nvram_envp){  
    /*keep original argv from linux, alter environment by envp from zrt*/
    int i;
    while(*nvram_envp != NULL){
	i=0;
	while( (*nvram_envp)[i]!='\0'&& (*nvram_envp)[i]!='=' ) ++i;
	/*if valid token key=value and key has not zero length*/
	if ((*nvram_envp)[i]=='=' && i>0){
	    (*nvram_envp)[i] = '\0'; //split one string into two null terminated string
	    if ( setenv(*nvram_envp, &(*nvram_envp)[i+1], 1) == -1 ){
		perror("wrong setenv args\n");
	    }
	    nvram_envp++;
	}
    }
    return 0;
}

/*not for export.  It's uses as callback from zrt__start, when
 initialization is completed and nvram's args,envs are ready to
 consume. */
int LIBZRT_SYMBOL(main)(int nvram_argc, char **nvram_argv, char **nvram_envp){  

    /*run eluexec*/
    return 0;
}

/*use inside of libzrt original args get with executable*/
void zrt__start (int argc, char **argv){
    LIBZRT_SYMBOL(__libc_start_main)(&LIBZRT_SYMBOL(main), argc, argv,
				     (void (*)(void))LIBZRT_SYMBOL(init), 
				     NULL, 
				     NULL,
				     __builtin_frame_address(0));
    SET_ZRT_ERRNO;
}

ssize_t zrt_read(int fd, void *buf, size_t count){
    ssize_t ret = LIBZRT_SYMBOL(read)(fd, buf, count);
    SET_ZRT_ERRNO;
    return ret;
}

ssize_t zrt_write(int fd, const void *buf, size_t count){
    ssize_t ret = LIBZRT_SYMBOL(write)(fd, buf, count);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_open(const char *filename, int flags, int mode){
    int ret = LIBZRT_SYMBOL(open)(filename, flags, (mode_t)mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_close(int fd){
    int ret = LIBZRT_SYMBOL(close)(fd);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_creat(const char *pathname, int mode){
    int ret = LIBZRT_SYMBOL(creat)(pathname, (mode_t)mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_link(const char *oldpath, const char *newpath){
    int ret = LIBZRT_SYMBOL(link)(oldpath, newpath);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_unlink(const char *pathname){
    int ret = LIBZRT_SYMBOL(unlink)(pathname);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_chdir(const char *filename){
    int ret = LIBZRT_SYMBOL(chdir)(filename);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_fchdir(int fd){
    int ret = LIBZRT_SYMBOL(fchdir)(fd);
    SET_ZRT_ERRNO;
    return ret;
}

time_t zrt_time(time_t *t){
    time_t ret = LIBZRT_SYMBOL(time)(t);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_chmod(const char *path, mode_t mode){
    int ret = LIBZRT_SYMBOL(chmod)(path, mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_fchmod(int fd, mode_t mode){
    int ret = LIBZRT_SYMBOL(fchmod)(fd, mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_lchown(const char *path, uid_t owner, gid_t group){
    int ret = LIBZRT_SYMBOL(lchown)(path, owner, group);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_stat(const char *path, struct stat *buf){
    int ret = LIBZRT_SYMBOL(stat)(path, buf);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_fstat(int fd, struct stat *buf){
    int ret = LIBZRT_SYMBOL(fstat)(fd, buf);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_lstat(const char *pathname, struct stat *buf){
    int ret = LIBZRT_SYMBOL(stat)(pathname, buf);
    SET_ZRT_ERRNO;
    return ret;
}

off_t zrt_lseek(int fd, off_t offset, int whence){
    int ret = LIBZRT_SYMBOL(lseek)(fd, offset, whence);
    SET_ZRT_ERRNO;
    return ret;
}

pid_t zrt_getpid(void){
    return 1;
}

uid_t zrt_getuid(void){
    uid_t ret = LIBZRT_SYMBOL(getuid)();
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_access(const char *pathname, int mode){
    int ret = LIBZRT_SYMBOL(access)(pathname, mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_rename(const char *oldpath, const char *newpath){
    int ret = LIBZRT_SYMBOL(rename)(oldpath, newpath);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_mkdir(const char *pathname, mode_t mode){
    int ret = LIBZRT_SYMBOL(mkdir)(pathname, mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_rmdir(const char *pathname){
    int ret = LIBZRT_SYMBOL(rmdir)(pathname);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_dup(int oldfd){
    int ret = LIBZRT_SYMBOL(dup)(oldfd);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_dup2(int oldfd, int newfd){
    int ret = LIBZRT_SYMBOL(dup2)(oldfd, newfd);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_gettimeofday(struct timeval *tv, struct timezone *tz){
    int ret = LIBZRT_SYMBOL(gettimeofday)(tv, tz);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_settimeofday(const struct timeval *tv, const struct timezone *tz){
    int ret = LIBZRT_SYMBOL(settimeofday)(tv, tz);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_clock_gettime(clockid_t clk_id, struct timespec *tp){
    int ret = LIBZRT_SYMBOL(clock_gettime)(clk_id, tp);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_clock_nanosleep(clockid_t clock_id, int flags, 
			const struct timespec *request,
			struct timespec *remain){
    int ret = LIBZRT_SYMBOL(clock_nanosleep)(clock_id, flags, request, remain);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_nanosleep(const struct timespec *request,
		  struct timespec *remain){
    int ret = LIBZRT_SYMBOL(nanosleep)(request, remain);
    SET_ZRT_ERRNO;
    return ret;
}

ssize_t zrt_pread(int fd, void *buf, size_t count, off_t offset){
    int nbytes;
    int ret = LIBZRT_SYMBOL(__nacl_irt_pread)(fd, buf, count, offset, &nbytes);
    SET_ZRT_ERRNO;
    if (ret==0)
	return nbytes;
    else
	return ret;    
}

ssize_t zrt_pwrite(int fd, const void *buf, size_t count, off_t offset){
    int nbytes;
    int ret = LIBZRT_SYMBOL(__nacl_irt_pwrite)(fd, buf, count, offset, &nbytes);
    SET_ZRT_ERRNO;
    if (ret==0)
	return nbytes;
    else
	return ret;    
}

void* zrt_sysbrk(void *addr){
    int ret = LIBZRT_SYMBOL(zrt_zcall_prolog_sysbrk)(&addr);
    SET_ZRT_ERRNO;
    if ( ret == 0 )
	return addr;
    else
	return (void*)-1;
}

void *zrt_mmap(void *addr, size_t length, int prot, int flags,
	   int fd, off_t offset){
    void *ret = LIBZRT_SYMBOL(mmap)(addr, length, prot, flags, fd, offset);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_munmap(void *addr, size_t length){
    int ret = LIBZRT_SYMBOL(munmap)(addr, length);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_truncate(const char *path, off_t length){
    int ret = LIBZRT_SYMBOL(truncate)(path, length);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_ftruncate(int fd, off_t length){
    int ret = LIBZRT_SYMBOL(ftruncate)(fd, length);
    SET_ZRT_ERRNO;
    return ret;
}

char *zrt_getcwd(char *buf, size_t size){
    char *ret = LIBZRT_SYMBOL(getcwd)(buf, size);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_getdents(unsigned int fd, struct dirent *dirp,
		 unsigned int count){
    int ret = LIBZRT_SYMBOL(__getdents)(fd, (char*)dirp, count);
    SET_ZRT_ERRNO;
    return ret;
}

/*statvfs doesn't exist in linux syscalls table*/
int zrt_statvfs(const char *path, struct statvfs *buf){
    int ret = LIBZRT_SYMBOL(statvfs)(path, buf);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_fcntl(int fd, int cmd, ... /* arg */ ){
    int ret=-1;
    errno = EINVAL;
    va_list args;
    va_start(args, cmd);
    if ( cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK ){
	struct flock* input_lock = va_arg(args, struct flock*);
	ret = LIBZRT_SYMBOL(fcntl)(fd, cmd, input_lock);
    }
    else if ( cmd == F_GETFL ){
	ret = LIBZRT_SYMBOL(fcntl)(fd, cmd);
    }
    else if ( cmd == F_SETFL ){
	long flags = va_arg(args, long);
	ret = LIBZRT_SYMBOL(fcntl)(fd, cmd, flags);
    }
    va_end(args);

    SET_ZRT_ERRNO;
    return ret;
}

int zrt_symlink(const char *target, const char *linkpath){
    int ret = LIBZRT_SYMBOL(symlink)(target, linkpath);
    SET_ZRT_ERRNO;
    return ret;
}

ssize_t zrt_readlink(const char *pathname, char *buf, size_t bufsiz){
    ssize_t ret = LIBZRT_SYMBOL(readlink)(pathname, buf, bufsiz);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_openat(int dfd, const char *filename, int flags, int mode){
    int ret =  LIBZRT_SYMBOL(__openat_nocancel)(dfd, filename, flags, mode);
    SET_ZRT_ERRNO;
    return ret;
}


/*stubs*/
void LIBZRT_SYMBOL(pthread_detach)(void){}
void LIBZRT_SYMBOL(__pthread_unregister_cancel)(){}
void LIBZRT_SYMBOL(pthread_barrier_init)(){}
void LIBZRT_SYMBOL(__pthread_register_cancel)(){}
void LIBZRT_SYMBOL(_dl_num_cache_relocations)(){}
void LIBZRT_SYMBOL(pthread_barrier_wait)(){}
