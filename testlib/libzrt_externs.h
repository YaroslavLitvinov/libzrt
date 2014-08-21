#ifndef __LIBZRT_EXTERNS_H__
#define __LIBZRT_EXTERNS_H__

#ifdef PREFIX_ZRT_SYMBOLS
#define LIBZRT_SYMBOL(name) __zrt_##name
#else
#define LIBZRT_SYMBOL(name) name
#endif

extern intptr_t (*s_zrt_calls[])();
extern int LIBZRT_SYMBOL(errno);
extern intptr_t* LIBZRT_SYMBOL(__libc_stack_end);
extern intptr_t* __libc_stack_end;
extern int LIBZRT_SYMBOL(__libc_start_main) (int (*main) (int, char **, char **),
					     int ,
					     char **,
					     void (*init) (void),
					     void (*fini) (void),
					     void (*rtld_fini) (void),
					     void *stack_end);
extern ssize_t LIBZRT_SYMBOL(__getdents)(int __fd, char *__buf, size_t __nbytes);


#ifdef PREFIX_ZRT_SYMBOLS
extern ssize_t LIBZRT_SYMBOL(read)(int fd, void *buf, size_t count);
extern ssize_t LIBZRT_SYMBOL(write)(int fd, const void *buf, size_t count);
extern int LIBZRT_SYMBOL(open)(const char *filename, int flags, int mode);
extern int LIBZRT_SYMBOL(close)(int fd);
extern int LIBZRT_SYMBOL(creat)(const char *pathname, int mode);
extern int LIBZRT_SYMBOL(link)(const char *oldpath, const char *newpath);
extern int LIBZRT_SYMBOL(unlink)(const char *pathname);
extern int LIBZRT_SYMBOL(chdir)(const char *filename);
extern int LIBZRT_SYMBOL(fchdir)(int fd);
extern time_t LIBZRT_SYMBOL(time)(time_t *t);
extern int LIBZRT_SYMBOL(chmod)(const char *path, mode_t mode);
extern int LIBZRT_SYMBOL(fchmod)(int fd, mode_t mode);
extern int LIBZRT_SYMBOL(lchown)(const char *path, uid_t owner, gid_t group);
extern int LIBZRT_SYMBOL(stat)(const char *path, struct stat *buf);
extern int LIBZRT_SYMBOL(fstat)(int fd, struct stat *buf);
extern int LIBZRT_SYMBOL(lstat)(const char *pathname, struct stat *buf);
extern off_t LIBZRT_SYMBOL(lseek)(int fd, off_t offset, int whence);
extern pid_t LIBZRT_SYMBOL(getpid)(void);
extern uid_t LIBZRT_SYMBOL(getuid)(void);
extern int LIBZRT_SYMBOL(access)(const char *pathname, int mode);
extern int LIBZRT_SYMBOL(rename)(const char *oldpath, const char *newpath);
extern int LIBZRT_SYMBOL(mkdir)(const char *pathname, mode_t mode);
extern int LIBZRT_SYMBOL(rmdir)(const char *pathname);
extern int LIBZRT_SYMBOL(dup)(int oldfd);
extern int LIBZRT_SYMBOL(dup2)(int oldfd, int newfd);
extern int LIBZRT_SYMBOL(gettimeofday)(struct timeval *tv, struct timezone *tz);
extern int LIBZRT_SYMBOL(settimeofday)(const struct timeval *tv, const struct timezone *tz);
extern int LIBZRT_SYMBOL(clock_gettime)(clockid_t clk_id, struct timespec *tp);
extern int LIBZRT_SYMBOL(clock_nanosleep)(clockid_t clock_id, int flags, 
			const struct timespec *request,
					  struct timespec *remain);
extern int LIBZRT_SYMBOL(nanosleep)(const struct timespec *request,
				    struct timespec *remain);
extern int LIBZRT_SYMBOL(__nacl_irt_pread)(int fd, void *buf, int count, long long offset, int *nread);
extern int LIBZRT_SYMBOL(__nacl_irt_pwrite)(int fd, const void *buf, int count, long long offset, int *nwrote);
extern int LIBZRT_SYMBOL(zrt_zcall_prolog_sysbrk)(void *addr);
extern void *LIBZRT_SYMBOL(mmap)(void *addr, size_t length, int prot, int flags,
				 int fd, off_t offset);
extern int LIBZRT_SYMBOL(munmap)(void *addr, size_t length);
extern int LIBZRT_SYMBOL(truncate)(const char *path, off_t length);
extern int LIBZRT_SYMBOL(ftruncate)(int fd, off_t length);
extern char *LIBZRT_SYMBOL(getcwd)(char *buf, size_t size);
extern int LIBZRT_SYMBOL(statvfs)(const char *path, struct statvfs *buf);
extern int LIBZRT_SYMBOL(fcntl)(int fd, int cmd, ... /* arg */ );
extern int LIBZRT_SYMBOL(symlink)(const char *target, const char *linkpath);
extern ssize_t LIBZRT_SYMBOL(readlink)(const char *pathname, char *buf, size_t bufsiz);
extern int LIBZRT_SYMBOL(__openat_nocancel)(int dfd, const char *filename, int flags, int mode);

#endif //#ifdef PREFIX_ZRT_SYMBOLS

#endif //__LIBZRT_EXTERNS_H__

