#ifndef __LIBZRT_H__
#define __LIBZRT_H__

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <sys/time.h>
#include <dirent.h>

#define MANIFEST_PATH getenv("MANIFEST_PATH")

void zrt_seccomp_setup();

void zrt__start (int argc, char **argv);

ssize_t zrt_read(int fd, void *buf, size_t count);

ssize_t zrt_write(int fd, const void *buf, size_t count);

int zrt_open(const char *filename, int flags, int mode);

int zrt_close(int fd);

int zrt_creat(const char *pathname, int mode);

int zrt_link(const char *oldpath, const char *newpath);

int zrt_unlink(const char *pathname);

int zrt_chdir(const char *filename);

int zrt_fchdir(int fd);

time_t zrt_time(time_t *t);

int zrt_chmod(const char *path, mode_t mode);

int zrt_fchmod(int fd, mode_t mode);

int zrt_lchown(const char *path, uid_t owner, gid_t group);

int zrt_stat(const char *path, struct stat *buf);

int zrt_fstat(int fd, struct stat *buf);

int zrt_lstat(const char *pathname, struct stat *buf);

off_t zrt_lseek(int fd, off_t offset, int whence);

pid_t zrt_getpid(void);

uid_t zrt_getuid(void);

int zrt_access(const char *pathname, int mode);

int zrt_rename(const char *oldpath, const char *newpath);

int zrt_mkdir(const char *pathname, mode_t mode);

int zrt_rmdir(const char *pathname);

int zrt_dup(int oldfd);

int zrt_dup2(int oldfd, int newfd);

int zrt_gettimeofday(struct timeval *tv, struct timezone *tz);

int zrt_settimeofday(const struct timeval *tv, const struct timezone *tz);

int zrt_clock_gettime(clockid_t clk_id, struct timespec *tp);

int zrt_clock_nanosleep(clockid_t clock_id, int flags, 
			const struct timespec *request,
			struct timespec *remain);

int zrt_nanosleep(const struct timespec *request,
		  struct timespec *remain);

ssize_t zrt_pread(int fd, void *buf, size_t count, off_t offset);

ssize_t zrt_pwrite(int fd, const void *buf, size_t count, off_t offset);

void* zrt_sysbrk(void *addr);

void *zrt_mmap(void *addr, size_t length, int prot, int flags,
	       int fd, off_t offset);

int zrt_munmap(void *addr, size_t length);

int zrt_truncate(const char *path, off_t length);

int zrt_ftruncate(int fd, off_t length);

char *zrt_getcwd(char *buf, size_t size);

int zrt_getdents(unsigned int fd, struct dirent *dirp,
		 unsigned int count);

int zrt_statvfs(const char *path, struct statvfs *buf);

int zrt_fcntl(int fd, int cmd, ... /* arg */ );

int zrt_symlink(const char *target, const char *linkpath);

ssize_t zrt_readlink(const char *pathname, char *buf, size_t bufsiz);

int zrt_openat(int dfd, const char *filename, int flags, int mode);

#endif //__LIBZRT_H__
