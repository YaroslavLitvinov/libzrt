#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <stdint.h>
#include <errno.h>

#include "libzrt.h"

#define SYSCALL_STUB(args_count) zrt_not_implemented##args_count

static intptr_t SYSCALL_STUB(0)(){
    errno=ENOSYS;
    return -1;
}
static intptr_t SYSCALL_STUB(1)(){
    errno=ENOSYS;
    return -1;
}
static intptr_t SYSCALL_STUB(2)(){
    errno=ENOSYS;
    return -1;
}
static intptr_t SYSCALL_STUB(3)(){
    errno=ENOSYS;
    return -1;
}
static intptr_t SYSCALL_STUB(4)(){
    errno=ENOSYS;
    return -1;
}
static intptr_t SYSCALL_STUB(5)(){
    errno=ENOSYS;
    return -1;
}
static intptr_t SYSCALL_STUB(6)(){
    errno=ENOSYS;
    return -1;
}
static intptr_t zrt_not_implemented() {
    return 0;
}


intptr_t (*s_zrt_calls[])(intptr_t*) = {
    (intptr_t (*)(intptr_t*))zrt_read,   /*0 __NR_read*/
    (intptr_t (*)(intptr_t*))zrt_write,  /*1 __NR_write*/
    (intptr_t (*)(intptr_t*))zrt_open,   /*2 __NR_open*/
    (intptr_t (*)(intptr_t*))zrt_close,  /*3 __NR_close*/
    (intptr_t (*)(intptr_t*))zrt_stat,   /*4 __NR_stat*/
    (intptr_t (*)(intptr_t*))zrt_fstat,  /*5 __NR_fstat*/
    (intptr_t (*)(intptr_t*))zrt_lstat,  /*6 __NR_lstat*/  
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*7 __NR_poll*/  

    (intptr_t (*)(intptr_t*))zrt_lseek,  /*8 __NR_lseek*/  
    (intptr_t (*)(intptr_t*))zrt_mmap,   /*9 __NR_mmap*/  
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*10 __NR_mprotect*/  
    (intptr_t (*)(intptr_t*))zrt_munmap, /*11 __NR_munmap*/  
    (intptr_t (*)(intptr_t*))zrt_sysbrk,    /*12 __NR_brk*/  
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*13 __NR_rt_sigaction*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*14 __NR_rt_sigprocmask*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*15 __NR_rt_sigreturn*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*16 __NR_ioctl*/
    (intptr_t (*)(intptr_t*))zrt_pread,  /*17 __NR_pread64*/
    (intptr_t (*)(intptr_t*))zrt_pwrite, /*18 __NR_pwrite64*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*19 __NR_readv*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*20 __NR_writev*/
    (intptr_t (*)(intptr_t*))zrt_access,  /*21 __NR_access*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*22 __NR_pipe*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*23 __NR_select*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*24 __NR_sched_yield*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*25 __NR_mremap*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*26 __NR_msync*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*27 __NR_mincore*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*28 __NR_madvise*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*29 __NR_shmget*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*30 __NR_shmat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*31 __NR_shmctl*/

    (intptr_t (*)(intptr_t*))zrt_dup, /*32 __NR_dup*/
    (intptr_t (*)(intptr_t*))zrt_dup2, /*33 __NR_dup2*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*34 __NR_pause*/
    (intptr_t (*)(intptr_t*))zrt_nanosleep, /*35 __NR_nanosleep*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*36 __NR_getitimer*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*37 __NR_alarm*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*38 __NR_setitimer*/
    (intptr_t (*)(intptr_t*))zrt_getpid, /*39 __NR_getpid*/
    
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*40 __NR_sendfile*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*41 __NR_socket*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*42 __NR_connect*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*43 __NR_accept*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(6), /*44 __NR_sendto*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(6), /*45 __NR_recvfrom*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*46 __NR_sendmsg*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*47 __NR_recvmsg*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*48 __NR_shutdown*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*49 __NR_bind*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*50 __NR_listen*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*51 __NR_getsockname*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*52 __NR_getpeername*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*53 __NR_socketpair*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*54 __NR_setsockopt*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*55 __NR_getsockopt*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*56 __NR_clone*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*57 __NR_fork*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*58 __NR_vfork*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*59 __NR_execve*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*60 __NR_exit*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*61 __NR_wait4*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*62 __NR_kill*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*63 __NR_uname*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*64 __NR_semget*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*65 __NR_semop*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*66 __NR_semctl*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*67 __NR_shmdt*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*68 __NR_msgget*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*69 __NR_msgsnd*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*70 __NR_msgrcv*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*71 __NR_msgctl*/

    (intptr_t (*)(intptr_t*))zrt_fcntl, /*72 __NR_fcntl*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*73 __NR_flock*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*74 __NR_fsync*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*75 __NR_fdatasync*/
    (intptr_t (*)(intptr_t*))zrt_truncate, /*76 __NR_truncate*/
    (intptr_t (*)(intptr_t*))zrt_ftruncate, /*77 __NR_ftruncate*/
    (intptr_t (*)(intptr_t*))zrt_getdents, /*78 __NR_getdents*/
    (intptr_t (*)(intptr_t*))zrt_getcwd, /*79 __NR_getcwd*/

    (intptr_t (*)(intptr_t*))zrt_chdir, /*80 __NR_chdir*/
    (intptr_t (*)(intptr_t*))zrt_fchdir, /*81 __NR_fchdir*/
    (intptr_t (*)(intptr_t*))zrt_rename, /*82 __NR_rename*/
    (intptr_t (*)(intptr_t*))zrt_mkdir, /*83 __NR_mkdir*/
    (intptr_t (*)(intptr_t*))zrt_rmdir, /*84 __NR_rmdir*/
    (intptr_t (*)(intptr_t*))zrt_creat, /*85 __NR_creat*/
    (intptr_t (*)(intptr_t*))zrt_link, /*86 __NR_link*/
    (intptr_t (*)(intptr_t*))zrt_unlink, /*87 __NR_unlink*/

    (intptr_t (*)(intptr_t*))zrt_symlink, /*88 __NR_symlink*/
    (intptr_t (*)(intptr_t*))zrt_readlink, /*89 __NR_readlink*/
    (intptr_t (*)(intptr_t*))zrt_chmod, /*90 __NR_chmod*/
    (intptr_t (*)(intptr_t*))zrt_fchmod, /*91 __NR_fchmod*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*92 __NR_chown*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*93 __NR_fchown*/
    (intptr_t (*)(intptr_t*))zrt_lchown, /*94 __NR_lchown*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*95 __NR_umask*/

    (intptr_t (*)(intptr_t*))zrt_gettimeofday, /*96__NR_gettimeofday */
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*97 __NR_getrlimit*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*98 __NR_getrusage*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*99 __NR_sysinfo*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*100 __NR_times*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*101 __NR_ptrace*/
    (intptr_t (*)(intptr_t*))zrt_getuid, /*102 __NR_getuid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*103 __NR_syslog*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*104 __NR_getgid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*105 __NR_setuid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*106 __NR_setgid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*107 __NR_geteuid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*108 __NR_getegid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*109 __NR_setpgid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*110 __NR_getppid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*111 __NR_getpgrp*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*112 __NR_setsid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*113 __NR_setreuid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*114 __NR_setregid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*115 __NR_getgroups*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*116 __NR_setgroups*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*117 __NR_setresuid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*118 __NR_getresuid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*119 __NR_setresgid*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*120 __NR_getresgid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*121 __NR_getpgid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*122 __NR_setfsuid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*123 __NR_setfsgid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*124 __NR_getsid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*125 __NR_capget*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*126 __NR_capset*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*127 __NR_rt_sigpending*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*128 __NR_rt_sigtimedwait*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*129 __NR_rt_sigqueueinfo*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*130 __NR_rt_sigsuspend*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*131 __NR_sigaltstack*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*132 __NR_utime*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*133 __NR_mknod*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*134 __NR_uselib*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*135 __NR_personality*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*136 __NR_ustat*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*137 __NR_statfs*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*138 __NR_fstatfs*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*139 __NR_sysfs*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*140 __NR_getpriority*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*141 __NR_setpriority*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*142 __NR_sched_setparam*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*143 __NR_sched_getparam*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*144 __NR_sched_setscheduler*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*145 __NR_sched_getscheduler*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*146 __NR_sched_get_priority_max*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*147 __NR_sched_get_priority_min*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*148 __NR_sched_rr_get_interval*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*149 __NR_mlock*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*150 __NR_munlock*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*151 __NR_mlockall*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*152 __NR_munlockall*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*153 __NR_vhangup*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*154 __NR_modify_ldt*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*155 __NR_pivot_root*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*156 __NR__sysctl*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*157 __NR_prctl*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*158 __NR_arch_prctl*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*159 __NR_adjtimex*/

    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*160 __NR_setrlimit*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*161 __NR_chroot*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*162 __NR_sync*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*163 __NR_acct*/
    (intptr_t (*)(intptr_t*))zrt_settimeofday, /*164 __NR_settimeofday*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*165 __NR_mount*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*166 __NR_umount2*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*167 __NR_swapon*/

    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*168 __NR_swapoff*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*169 __NR_reboot*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*170 __NR_sethostname*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*171 __NR_setdomainname*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*172 __NR_iopl*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*173 __NR_ioperm*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*174 __NR_create_module*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*175 __NR_init_module*/

    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*176 __NR_delete_module*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*177 __NR_get_kernel_syms*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*178 __NR_query_module*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*179 __NR_quotactl*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*180 __NR_nfsservctl*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*181 __NR_getpmsg*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*182 __NR_putpmsg*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*183 __NR_afs_syscall*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*184 __NR_tuxcall*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*185 __NR_security*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*186 __NR_gettid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*187 __NR_readahead*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*188 __NR_setxattr*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*189 __NR_lsetxattr*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*190 __NR_fsetxattr*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*191 __NR_getxattr*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*192 __NR_lgetxattr*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*193 __NR_fgetxattr*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*194 __NR_listxattr*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*195 __NR_llistxattr*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*196 __NR_flistxattr*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*197 __NR_removexattr*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*198 __NR_lremovexattr*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*199 __NR_fremovexattr*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*200 __NR_tkill*/
    (intptr_t (*)(intptr_t*))zrt_time, /*201 __NR_time*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(6), /*202 __NR_futex*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*203 __NR_sched_setaffinity*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*204 __NR_sched_getaffinity*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*205 __NR_set_thread_area*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*206 __NR_io_setup*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*207 __NR_io_destroy*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*208 __NR_io_getevents*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*209 __NR_io_submit*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*210 __NR_io_cancel*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*211 __NR_get_thread_area*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*212 __NR_lookup_dcookie*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*213 __NR_epoll_create*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*214 __NR_epoll_ctl_old*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*215 __NR_epoll_wait_old*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*216 __NR_remap_file_pages*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*217 __NR_getdents64*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*218 __NR_set_tid_address*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*219 __NR_restart_syscall*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*220 __NR_semtimedop*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*221 __NR_fadvise64*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*222 __NR_timer_create*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*223 __NR_timer_settime*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*224 __NR_timer_gettime*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*225 __NR_timer_getoverrun*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*226 __NR_timer_delete*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*227 __NR_clock_settime*/
    (intptr_t (*)(intptr_t*))zrt_clock_gettime, /*228 __NR_clock_gettime*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*229 __NR_clock_getres*/
    (intptr_t (*)(intptr_t*))zrt_clock_nanosleep, /*230 __NR_clock_nanosleep*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*231 __NR_exit_group*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*232 __NR_epoll_wait*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*233 __NR_epoll_ctl*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*234 __NR_tgkill*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*235 __NR_utimes*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*236 __NR_vserver*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(6), /*237 __NR_mbind*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*238 __NR_set_mempolicy*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*239 __NR_get_mempolicy*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*240 __NR_mq_open*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*241 __NR_mq_unlink*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*242 __NR_mq_timedsend*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*243 __NR_mq_timedreceive*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*244 __NR_mq_notify*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*245 __NR_mq_getsetattr*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*246 __NR_kexec_load*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*247 __NR_waitid*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*248 __NR_add_key*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*249 __NR_request_key*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*250 __NR_keyctl*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*251 __NR_ioprio_set*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*252 __NR_ioprio_get*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*253 __NR_inotify_init*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*254 __NR_inotify_add_watch*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*255 __NR_inotify_rm_watch*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*256 __NR_migrate_pages*/
    (intptr_t (*)(intptr_t*))zrt_openat, /*257 __NR_openat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*258 __NR_mkdirat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*259 __NR_mknodat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*260 __NR_fchownat*/
    (intptr_t (*)(intptr_t*))zrt_not_implemented, /*261 __NR_futimesat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*262 __NR_newfstatat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*263 __NR_unlinkat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*264 __NR_renameat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*265 __NR_linkat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*266 __NR_symlinkat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*267 __NR_readlinkat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*268 __NR_fchmodat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*269 __NR_faccessat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(6), /*270 __NR_pselect6*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*271 __NR_ppoll*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*272 __NR_unshare*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*273 __NR_set_robust_list*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*274 __NR_get_robust_list*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(6), /*275 __NR_splice*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*276 __NR_tee*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*277 __NR_sync_file_range*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*278 __NR_vmsplice*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(6), /*279 __NR_move_pages*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*280 __NR_utimensat*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(6), /*281 __NR_epoll_pwait*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*282 __NR_signalfd*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*283 __NR_timerfd_create*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*284 __NR_eventfd*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*285 __NR_fallocate*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*286 __NR_timerfd_settime*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*287 __NR_timerfd_gettime*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*288 __NR_accept4*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*289 __NR_signalfd4*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*290 __NR_eventfd2*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*291 __NR_epoll_create1*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*292 __NR_dup3*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*293 __NR_pipe2*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(1), /*294 __NR_inotify_init1*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*295 __NR_preadv*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*296 __NR_pwritev*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*297 __NR_rt_tgsigqueueinfo*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*298 __NR_perf_event_open*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*299 __NR_recvmmsg*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*300 __NR_fanotify_init*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*301 __NR_fanotify_mark*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*302 __NR_prlimit64*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*303 __NR_name_to_handle_at*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(5), /*304 __NR_open_by_handle_at*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*305 __NR_clock_adjtime*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(0), /*306 __NR_syncfs*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(4), /*307 __NR_sendmmsg*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(2), /*308 __NR_setns*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(3), /*309 __NR_getcpu*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(6), /*310 __NR_process_vm_readv*/
    (intptr_t (*)(intptr_t*))SYSCALL_STUB(6), /*311 __NR_process_vm_writev*/
};

