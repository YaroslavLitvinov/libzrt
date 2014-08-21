/*
 * Seccomp filter example for x86 (32-bit and 64-bit) with BPF macros
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Author: Will Drewry <wad@chromium.org>
 *
 * The code may be used by anyone for any purpose,
 * and can serve as a starting point for developing
 * applications using prctl(PR_SET_SECCOMP, 2, ...).
 */
#if defined(__i386__) || defined(__x86_64__)
#define SUPPORTED_ARCH 1
#endif
 
#if defined(SUPPORTED_ARCH)
#define __USE_GNU 1
#define _GNU_SOURCE 1
 
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <errno.h>

#include <sys/syscall.h>   /* For SYS_xxx definitions */

#include "libzrt_externs.h"
 
#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define syscall_nr (offsetof(struct seccomp_data, nr))
 
#if defined(__i386__)
#define REG_RESULT      REG_EAX
#define REG_SYSCALL     REG_EAX
#define REG_ARG0        REG_EBX
#define REG_ARG1        REG_ECX
#define REG_ARG2        REG_EDX
#define REG_ARG3        REG_ESI
#define REG_ARG4        REG_EDI
#define REG_ARG5        REG_EBP
#elif defined(__x86_64__)
#define REG_RESULT      REG_RAX
#define REG_SYSCALL     REG_RAX
#define REG_ARG0        REG_RDI
#define REG_ARG1        REG_RSI
#define REG_ARG2        REG_RDX
#define REG_ARG3        REG_R10
#define REG_ARG4        REG_R8
#define REG_ARG5        REG_R9
#endif
 
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
 
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

#define ZSYSNUM  ctx->uc_mcontext.gregs[REG_SYSCALL]
#define ZSYSRES  ctx->uc_mcontext.gregs[REG_RESULT]
#define ZARG0 ctx->uc_mcontext.gregs[REG_ARG0]
#define ZARG1 ctx->uc_mcontext.gregs[REG_ARG1]
#define ZARG2 ctx->uc_mcontext.gregs[REG_ARG2]
#define ZARG3 ctx->uc_mcontext.gregs[REG_ARG3]
#define ZARG4 ctx->uc_mcontext.gregs[REG_ARG4]
#define ZARG5 ctx->uc_mcontext.gregs[REG_ARG5]

static void emulator(int nr, siginfo_t *info, void *void_context)
{
        ucontext_t *ctx = (ucontext_t *)(void_context);
 
        if (info->si_code != SYS_SECCOMP)
                return;
        if (!ctx)
                return;
	int sysnum = ZSYSNUM;

        /* Redirect stderr messages to stdout. Doesn't handle EINTR, etc */
        char buffer[32];
	int l=snprintf(buffer, 32, "%d\n", sysnum);
        syscall(__NR_write, STDOUT_FILENO, buffer, l);

	if ( sysnum >= 0 ){
	    switch(sysnum){
		/*0 arguments*/
	    case __NR_sched_yield:
	    case __NR_pause:
	    case __NR_getpid:
	    case __NR_fork:
	    case __NR_vfork:
	    case __NR_fsync:
	    case __NR_fdatasync:
	    case __NR_chdir:
	    case __NR_fchdir:
	    case __NR_rmdir:
	    case __NR_unlink:
	    case __NR_umask:
	    case __NR_sysinfo:
	    case __NR_times:
	    case __NR_setuid:
	    case __NR_setgid:
	    case __NR_getpgid:
	    case __NR_setfsuid:
	    case __NR_setfsgid:
	    case __NR_getsid:
	    case __NR_personality:
	    case __NR_sched_getscheduler:
	    case __NR_sched_get_priority_max:
	    case __NR_sched_get_priority_min:
	    case __NR_mlockall:
	    case __NR__sysctl:
	    case __NR_adjtimex:
	    case __NR_chroot:
	    case __NR_acct:
	    case __NR_swapoff:
	    case __NR_time:
	    case __NR_io_destroy:
	    case __NR_epoll_create:
	    case __NR_set_tid_address:
	    case __NR_timer_getoverrun:
	    case __NR_timer_delete:
	    case __NR_exit_group:
	    case __NR_mq_unlink:
	    case __NR_eventfd:
	    case __NR_syncfs:
	    case __NR_inotify_init:
	    case __NR_uselib:
		ZSYSRES = s_zrt_calls[sysnum]();
		break;

		/*1 argument */
	    case __NR_inotify_init1:
	    case __NR_epoll_create1:
	    case __NR_close:
	    case __NR_brk:
	    case __NR_pipe:
	    case __NR_rt_sigreturn:
	    case __NR_dup:
	    case __NR_alarm:
	    case __NR_exit:
	    case __NR_uname:
	    case __NR_shmdt:
	    case __NR_getuid:
	    case __NR_getgid:
	    case __NR_geteuid:
	    case __NR_getegid:
	    case __NR_getppid:
	    case __NR_getpgrp:
	    case __NR_setsid:
	    case __NR_munlockall:
	    case __NR_vhangup:
	    case __NR_sync:
	    case __NR_gettid:
	    case __NR_restart_syscall:
	    case __NR_unshare:
		ZSYSRES = s_zrt_calls[sysnum](ZARG0);
		break;

		/*2 arguments */
	    case __NR_stat:
	    case __NR_fstat:
	    case __NR_lstat:
	    case __NR_munmap:
	    case __NR_access:
	    case __NR_mprotect:
	    case __NR_dup2:
	    case __NR_nanosleep:
	    case __NR_getitimer:
	    case __NR_shutdown:
	    case __NR_listen:
	    case __NR_kill:
	    case __NR_msgget:
	    case __NR_clock_adjtime:
	    case __NR_setns:
	    case __NR_fanotify_init:
	    case __NR_pipe2:
	    case __NR_eventfd2:
	    case __NR_timerfd_gettime:
	    case __NR_set_robust_list:
	    case __NR_flock:
	    case  __NR_getrlimit:
	    case __NR_getrusage:
	    case __NR_setpgid:
	    case __NR_setreuid:
	    case __NR_setregid:
	    case __NR_getgroups:
	    case __NR_setgroups:
	    case __NR_capget:
	    case __NR_capset:
	    case __NR_rt_sigpending:
	    case __NR_rt_sigsuspend:
	    case __NR_sigaltstack:
	    case __NR_utime:
		ZSYSRES = s_zrt_calls[sysnum](ZARG0, ZARG1);
		break;

		/*3 arguments */
	    case __NR_read:
	    case __NR_write:
	    case __NR_open:
	    case __NR_poll:
	    case __NR_lseek:
	    case __NR_ioctl:
	    case __NR_readv:
	    case __NR_writev:
	    case __NR_msync:
	    case __NR_mincore:
	    case __NR_madvise:
	    case __NR_shmget:
	    case __NR_shmat:
	    case __NR_shmctl:
	    case __NR_setitimer:
	    case __NR_socket:
	    case __NR_connect:
	    case __NR_accept:
	    case __NR_sendmsg:
	    case __NR_recvmsg:
	    case __NR_bind:
	    case __NR_getsockname:
	    case __NR_getpeername:
	    case __NR_execve:
	    case __NR_semget:
	    case __NR_semop:
	    case __NR_msgctl:
	    case __NR_fcntl:
	    case __NR_getdents:
	    case __NR_readlink:
	    case __NR_chown:
	    case __NR_fchown:
	    case __NR_lchown:
	    case __NR_syslog:
	    case __NR_setresuid:
	    case __NR_getresuid:
	    case __NR_setresgid:
	    case __NR_getresgid:
	    case __NR_rt_sigqueueinfo:
	    case __NR_mknod:
	    case __NR_sysfs:
	    case __NR_setpriority:
	    case __NR_sched_setscheduler:
	    case __NR_modify_ldt:
	    case __NR_arch_prctl:
	    case __NR_ioperm:
	    case __NR_init_module:
	    case __NR_readahead:
	    case __NR_listxattr:
	    case __NR_llistxattr:
	    case __NR_flistxattr:
	    case __NR_sched_setaffinity:
	    case __NR_sched_getaffinity:
	    case __NR_io_submit:
	    case __NR_io_cancel:
	    case __NR_lookup_dcookie:
	    case __NR_getdents64:
	    case __NR_timer_create:
	    case __NR_tgkill:
	    case __NR_set_mempolicy:
	    case __NR_mq_getsetattr:
	    case __NR_ioprio_set:
	    case __NR_inotify_add_watch:
	    case __NR_mkdirat:
	    case __NR_unlinkat:
	    case __NR_symlinkat:
	    case __NR_fchmodat:
	    case __NR_faccessat:
	    case __NR_get_robust_list:
	    case __NR_signalfd:
	    case __NR_dup3:
	    case __NR_getcpu:
		ZSYSRES = s_zrt_calls[sysnum](ZARG0, ZARG1, ZARG2);
		break;

		/*4 arguments */
	    case __NR_pread64:
	    case __NR_pwrite64:
	    case __NR_rt_sigaction:
	    case __NR_rt_sigprocmask:
	    case __NR_mremap:
	    case __NR_sendfile:
	    case __NR_socketpair:
	    case __NR_clone:
	    case __NR_wait4:
	    case __NR_semctl:
	    case __NR_msgsnd:
	    case __NR_ptrace:
	    case __NR_rt_sigtimedwait:
	    case __NR_reboot:
	    case __NR_quotactl:
	    case __NR_getxattr:
	    case __NR_lgetxattr:
	    case __NR_fgetxattr:
	    case __NR_io_getevents:
	    case __NR_semtimedop:
	    case __NR_fadvise64:
	    case __NR_timer_settime:
	    case __NR_clock_nanosleep:
	    case __NR_epoll_wait:
	    case __NR_epoll_ctl:
	    case __NR_mq_open:
	    case __NR_kexec_load:
	    case __NR_add_key:
	    case __NR_request_key:
	    case __NR_migrate_pages:
	    case __NR_openat:
	    case __NR_mknodat:
	    case __NR_newfstatat:
	    case __NR_renameat:
	    case __NR_readlinkat:
	    case __NR_tee:
	    case __NR_sync_file_range:
	    case __NR_vmsplice:
	    case __NR_utimensat:
	    case __NR_fallocate:
	    case __NR_timerfd_settime:
	    case __NR_accept4:
	    case __NR_signalfd4:
	    case __NR_rt_tgsigqueueinfo:
	    case __NR_prlimit64:
	    case __NR_sendmmsg:
		ZSYSRES = s_zrt_calls[sysnum](ZARG0, ZARG1, ZARG2, ZARG3);
		break;

		/*5 arguments*/
	    case __NR_select:
	    case __NR_setsockopt:
	    case __NR_getsockopt:
	    case __NR_msgrcv:
	    case __NR_prctl:
	    case __NR_mount:
	    case __NR_setxattr:
	    case __NR_lsetxattr:
	    case __NR_fsetxattr:
	    case __NR_remap_file_pages:
	    case __NR_get_mempolicy:
	    case __NR_mq_timedsend:
	    case __NR_mq_timedreceive:
	    case __NR_waitid:
	    case __NR_keyctl:
	    case __NR_fchownat:
	    case __NR_linkat:
	    case __NR_ppoll:
	    case __NR_preadv:
	    case __NR_pwritev:
	    case __NR_perf_event_open:
	    case __NR_recvmmsg:
	    case __NR_fanotify_mark:
	    case __NR_name_to_handle_at:
	    case __NR_open_by_handle_at:
		ZSYSRES = s_zrt_calls[sysnum](ZARG0, ZARG1, ZARG2, ZARG3, ZARG4);
		break;

		    /*6 arguments */
	    case __NR_mmap:
	    case __NR_sendto:
	    case __NR_recvfrom:
	    case __NR_futex:
	    case __NR_mbind:
	    case __NR_pselect6:
	    case __NR_splice:
	    case __NR_move_pages:
	    case __NR_epoll_pwait:
	    case __NR_process_vm_readv:
	    case __NR_process_vm_writev:
		ZSYSRES = s_zrt_calls[sysnum](ZARG0, ZARG1, ZARG2, ZARG3, ZARG4, ZARG5);
		break;

	    default:
		break;
	    }
	}
	else{
	    errno = EFAULT;
	    ZSYSRES= -1;
	}
        return;
}
 
static int install_emulator(void)
{
        struct sigaction act;
        sigset_t mask;
        memset(&act, 0, sizeof(act));
        sigemptyset(&mask);
        sigaddset(&mask, SIGSYS);
 
        act.sa_sigaction = &emulator;
        act.sa_flags = SA_SIGINFO;
        if (sigaction(SIGSYS, &act, NULL) < 0) {
                perror("sigaction");
                return -1;
        }
        if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
                perror("sigprocmask");
                return -1;
        }
        return 0;
}
 
static int install_filter(void)
{
        struct sock_filter filter[] = {
                /* Grab the system call number */
                BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
                /* Jump table for the allowed syscalls */
                BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_rt_sigreturn, 0, 1),
                BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
#ifdef __NR_sigreturn
                BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_sigreturn, 0, 1),
                BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
#endif
                BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit_group, 0, 1),
                BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
                BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit, 0, 1),
                BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
                BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_write, 0, 1),
                BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
                BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_read, 0, 1),
                BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
               
                BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),
                BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
        };
        struct sock_fprog prog = {
                .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
                .filter = filter,
        };
 
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
                perror("prctl(NO_NEW_PRIVS)");
                return 1;
        }
 
 
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
                perror("prctl");
                return 1;
        }
        return 0;
}
 
void zrt_seccomp_setup(){
    if (install_emulator()){
	perror("install_emulator error");
	return;
    }
    if (install_filter()){
	perror("install_emulator error");
	return;
    }
}
#else   /* SUPPORTED_ARCH */
/*
 * This sample is x86-only.  Since kernel samples are compiled with the
 * host toolchain, a non-x86 host will result in using only the main()
 * below.
 */
void zrt_seccomp_setup(){}
#endif  /* SUPPORTED_ARCH */
