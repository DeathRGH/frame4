#ifndef _KERN_H
#define _KERN_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"

struct cmd_kern_read_packet {
    uint64_t address;
    uint32_t length;
} __attribute__((packed));
#define CMD_KERN_READ_PACKET_SIZE 12

struct cmd_kern_write_packet {
    uint64_t address;
    uint32_t length;
} __attribute__((packed));
#define CMD_KERN_WRITE_PACKET_SIZE 12

int kern_handle(int fd, struct cmd_packet *packet);

#endif
