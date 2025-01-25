#ifndef _HOOKS_H
#define _HOOKS_H

#include <ksdk.h>
#include "proc.h"
#include "elf.h"

// custom syscall 107
struct proc_list_entry {
    char p_comm[32];
    int pid;
}  __attribute__((packed));

struct sys_proc_list_args {
    struct proc_list_entry *procs;
    uint64_t *num;
} __attribute__((packed));
int sys_proc_list(struct thread *td, struct sys_proc_list_args *uap);

// custom syscall 108
struct sys_proc_rw_args {
    uint64_t pid;
    uint64_t address;
    void *data;
    uint64_t length;
    uint64_t write;
} __attribute__((packed));
int sys_proc_rw(struct thread *td, struct sys_proc_rw_args *uap);

// custom syscall 109
#define SYS_PROC_ALLOC      1
#define SYS_PROC_FREE       2
#define SYS_PROC_PROTECT    3
#define SYS_PROC_VM_MAP     4
#define SYS_PROC_INSTALL    5
#define SYS_PROC_CALL       6
#define SYS_PROC_ELF        7
#define SYS_PROC_INFO       8
#define SYS_PROC_THRINFO    9
#define SYS_PROC_PRX_LIST   10
struct sys_proc_alloc_args {
    uint64_t address;
    uint64_t length;
} __attribute__((packed));
struct sys_proc_free_args {
    uint64_t address;
    uint64_t length;
} __attribute__((packed));
struct sys_proc_protect_args {
    uint64_t address;
    uint64_t length;
    uint64_t prot;
} __attribute__((packed));
struct sys_proc_vm_map_args {
    struct proc_vm_map_entry *maps;
    uint64_t num;
} __attribute__((packed));
struct sys_proc_install_args {
    uint64_t stubentryaddr;
} __attribute__((packed));
struct sys_proc_call_args {
    uint32_t pid;
    uint64_t rpcstub;
    uint64_t rax;
    uint64_t rip;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t r8;
    uint64_t r9;
} __attribute__((packed));
struct sys_proc_elf_args {
    void *elf;
    uint64_t entry;
} __attribute__((packed));
struct sys_proc_info_args {
    int pid;
    char name[40];
    char path[64];
    char titleid[16];
    char contentid[64];
} __attribute__((packed));
struct sys_proc_thrinfo_args {
    uint32_t lwpid;
    uint32_t priority;
    char name[32];
} __attribute__((packed));
struct prx_list_entry {
    uint32_t handle;
    char name[256];
    uint64_t text_address;
    uint32_t text_size;
    uint64_t data_address;
    uint32_t data_size;
}  __attribute__((packed));
struct sys_proc_prx_list_args {
    struct prx_list_entry *entries;
    uint64_t num;
} __attribute__((packed));
struct sys_proc_cmd_args {
    uint64_t pid;
    uint64_t cmd;
    void *data;
} __attribute__((packed));
int sys_proc_cmd(struct thread *td, struct sys_proc_cmd_args *uap);

// custom syscall 110
struct sys_kern_base_args {
    uint64_t *kbase;
} __attribute__((packed));
int sys_kern_base(struct thread *td, struct sys_kern_base_args *uap);

// custom syscall 111
struct sys_kern_rw_args {
    uint64_t address;
    void *data;
    uint64_t length;
    uint64_t write;
} __attribute__((packed));
int sys_kern_rw(struct thread *td, struct sys_kern_rw_args *uap);

// custom syscall 112
#define SYS_CONSOLE_CMD_REBOOT       1
#define SYS_CONSOLE_CMD_PRINT        2
#define SYS_CONSOLE_CMD_JAILBREAK    3
struct sys_console_cmd_args {
    uint64_t cmd;
    void *data;
} __attribute__((packed));
int sys_console_cmd(struct thread *td, struct sys_console_cmd_args *uap);

int install_hooks();

#endif
