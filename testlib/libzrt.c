
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include "zrt.h"

#define SET_ZRT_ERRNO zrt_errno = errno

extern void _start (uint32_t *info);
extern ssize_t __getdents (int fd, char *buf, size_t nbytes);

int zrt_errno;

void zrt__start (uint32_t *info){
    _start(info);
    SET_ZRT_ERRNO;
}

ssize_t zrt_read(int fd, void *buf, size_t count){
    ssize_t ret = read(fd, buf, count);
    SET_ZRT_ERRNO;
    return ret;
}

ssize_t zrt_write(int fd, const void *buf, size_t count){
    ssize_t ret = write(fd, buf, count);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_open(const char *filename, int flags, int mode){
    int ret = open(filename, flags, (mode_t)mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_close(int fd){
    int ret = close(fd);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_creat(const char *pathname, int mode){
    int ret = creat(pathname, (mode_t)mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_link(const char *oldpath, const char *newpath){
    int ret = link(oldpath, newpath);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_unlink(const char *pathname){
    int ret = unlink(pathname);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_chdir(const char *filename){
    int ret = chdir(filename);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_fchdir(int fd){
    int ret = fchdir(fd);
    SET_ZRT_ERRNO;
    return ret;
}

time_t zrt_time(time_t *t){
    time_t ret = time(t);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_chmod(const char *path, mode_t mode){
    int ret = chmod(path, mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_fchmod(int fd, mode_t mode){
    int ret = fchmod(fd, mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_lchown(const char *path, uid_t owner, gid_t group){
    int ret = lchown(path, owner, group);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_stat(const char *path, struct stat *buf){
    int ret = stat(path, buf);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_fstat(int fd, struct stat *buf){
    int ret = fstat(fd, buf);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_lstat(const char *pathname, struct stat *buf){
    int ret = stat(pathname, buf);
    SET_ZRT_ERRNO;
    return ret;
}

off_t zrt_lseek(int fd, off_t offset, int whence){
    int ret = lseek(fd, offset, whence);
    SET_ZRT_ERRNO;
    return ret;
}

pid_t zrt_getpid(void){
    return 1;
}

uid_t zrt_getuid(void){
    uid_t ret = getuid();
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_access(const char *pathname, int mode){
    int ret = access(pathname, mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_rename(const char *oldpath, const char *newpath){
    int ret = rename(oldpath, newpath);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_mkdir(const char *pathname, mode_t mode){
    int ret = mkdir(pathname, mode);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_rmdir(const char *pathname){
    int ret = rmdir(pathname);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_dup(int oldfd){
    int ret = dup(oldfd);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_dup2(int oldfd, int newfd){
    int ret = dup2(oldfd, newfd);
    SET_ZRT_ERRNO;
    return ret;
}



int zrt_gettimeofday(struct timeval *tv, struct timezone *tz){
    int ret = gettimeofday(tv, tz);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_settimeofday(const struct timeval *tv, const struct timezone *tz){
    int ret = settimeofday(tv, tz);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_clock_gettime(clockid_t clk_id, struct timespec *tp){
    int ret = clock_gettime(clk_id, tp);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_clock_nanosleep(clockid_t clock_id, int flags, 
			const struct timespec *request,
			struct timespec *remain){
    int ret = clock_nanosleep(clock_id, flags, request, remain);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_nanosleep(const struct timespec *request,
		  struct timespec *remain){
    int ret = nanosleep(request, remain);
    SET_ZRT_ERRNO;
    return ret;
}

ssize_t zrt_pread(int fd, void *buf, size_t count, off_t offset){
    int nbytes;
    int ret = __nacl_irt_pread(fd, buf, count, offset, &nbytes);
    SET_ZRT_ERRNO;
    if (ret==0)
	return nbytes;
    else
	return ret;    
}

ssize_t zrt_pwrite(int fd, const void *buf, size_t count, off_t offset){
    int nbytes;
    int ret = __nacl_irt_pwrite(fd, buf, count, offset, &nbytes);
    SET_ZRT_ERRNO;
    if (ret==0)
	return nbytes;
    else
	return ret;    
}

int zrt_brk(void *addr){
    int ret = brk( addr );
    SET_ZRT_ERRNO;
    return ret;
}

void *zrt_mmap(void *addr, size_t length, int prot, int flags,
	   int fd, off_t offset){
    void *ret = mmap(addr, length, prot, flags, fd, offset);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_munmap(void *addr, size_t length){
    int ret = munmap(addr, length);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_truncate(const char *path, off_t length){
    int ret = truncate(path, length);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_ftruncate(int fd, off_t length){
    int ret = ftruncate(fd, length);
    SET_ZRT_ERRNO;
    return ret;
}

char *zrt_getcwd(char *buf, size_t size){
    char *ret = getcwd(buf, size);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_getdents(unsigned int fd, struct dirent *dirp,
		 unsigned int count){
    int ret = __getdents(fd, (char*)dirp, count);
    SET_ZRT_ERRNO;
    return ret;
}

int zrt_statvfs(const char *path, struct statvfs *buf){
    int ret = statvfs(path, buf);
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
	ret = fcntl(fd, cmd, input_lock);
    }
    else if ( cmd == F_GETFL ){
	ret = fcntl(fd, cmd);
    }
    else if ( cmd == F_SETFL ){
	long flags = va_arg(args, long);
	ret = fcntl(fd, cmd, flags);
    }
    va_end(args);

    SET_ZRT_ERRNO;
    return ret;
}

int zrt_symlink(const char *target, const char *linkpath){
    int ret = symlink(target, linkpath);
    SET_ZRT_ERRNO;
    return ret;
}

ssize_t zrt_readlink(const char *pathname, char *buf, size_t bufsiz){
    ssize_t ret = readlink(pathname, buf, bufsiz);
    SET_ZRT_ERRNO;
    return ret;
}

