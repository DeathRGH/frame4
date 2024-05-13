#ifndef _AFR_H
#define _AFR_H

#include <ksdk.h>

struct syscall_open {
	const char *path;
	int flags;
	int mode;
}  __attribute__((packed));
struct syscall_openat {
	int fd;
	const char *path;
	int flags;
	int mode;
}  __attribute__((packed));
struct syscall_stat {
	const char *path;
	void *sb;
}  __attribute__((packed));
struct hook_data {
	short cachedFw;
	char data_path[100];
	char cusa[5];
	char print_debug1[100];
	char print_debug2[100];
	struct syscall_stat *statData;
	struct syscall_stat *statData_at;
};

int sys_open_hook(struct thread *td, struct syscall_open *args);
int sys_openat_hook(struct thread *td, struct syscall_openat *args);

int install_afr_hooks();

#endif
