#ifndef _KERN_H
#define _KERN_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"

struct cmd_kern_read_packet {
    uint64_t address;
    uint32_t length;
} __attribute__((packed));

struct cmd_kern_write_packet {
    uint64_t address;
    uint32_t length;
} __attribute__((packed));

struct cmd_kern_rdmsr_packet {
    uint32_t reg;
} __attribute__((packed));

struct cmd_kern_phys_read_packet {
    uint64_t address;
    uint32_t length;
} __attribute__((packed));

struct cmd_kern_phys_write_packet {
    uint64_t address;
    uint32_t length;
} __attribute__((packed));

int kern_handle(int fd, struct cmd_packet *packet);

#endif
