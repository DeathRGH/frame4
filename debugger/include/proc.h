#ifndef _PROC_H
#define _PROC_H

#include <ps4.h>
#include <stdbool.h>
#include "protocol.h"
#include "net.h"

struct proc_vm_map_entry {
    char name[32];
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint16_t prot;
} __attribute__((packed));

int proc_handle(int fd, struct cmd_packet *packet);

#endif
