#ifndef _INSTALLER_H
#define _INSTALLER_H

#include <ksdk.h>
#include "proc.h"

#define PAYLOAD_BASE 0x926600000
#define PAYLOAD_SIZE 0x400000

// shared
struct sys_proc_vm_map_args {
    struct proc_vm_map_entry *maps;
    uint64_t num;
} __attribute__((packed));

int runinstaller();

#endif
