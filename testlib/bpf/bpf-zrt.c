/*
 * Seccomp BPF example using a macro-based generator.
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Author: Will Drewry <wad@chromium.org>
 *
 * The code may be used by anyone for any purpose,
 * and can serve as a starting point for developing
 * applications using prctl(PR_ATTACH_SECCOMP_FILTER).
 */

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include "bpf-helper.h"

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

extern int switch_on_seccomp_bpf();
int switch_on_seccomp_bpf()
{
	struct bpf_labels l;
	char buf[256];
	struct sock_filter filter[] = {
		/* TODO: LOAD_SYSCALL_NR(arch) and enforce an arch */
		LOAD_SYSCALL_NR,
		SYSCALL(__NR_exit, ALLOW),
		SYSCALL(__NR_exit_group, ALLOW),
		SYSCALL(__NR_write, ALLOW),
		SYSCALL(__NR_read, ALLOW),
		SYSCALL(__NR_pwrite64, ALLOW),
		SYSCALL(__NR_pread64, ALLOW),
		DENY,  /* Don't passthrough into a label */
	};
	struct sock_fprog prog = {
		.filter = filter,
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
	};

	/**********setup zrt***********/
	ssize_t bytes;
	bpf_resolve_jumps(&l, filter, sizeof(filter)/sizeof(*filter));

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		return 1;
	}

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		return 1;
	}
	return 0;
}
