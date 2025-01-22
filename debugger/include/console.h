#ifndef _CONSOLE_H
#define _CONSOLE_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"
#include "debug.h"

struct cmd_console_print_packet {
    uint32_t length;
} __attribute__((packed));

struct cmd_console_notify_packet {
    uint32_t messageType;
    uint32_t length;
} __attribute__((packed));

struct cmd_console_info_response {
    char kern_ostype[50];
    char kern_osrelease[50];
    int kern_osrev;
    char kern_version[100];
    char hw_model[100];
    int hw_ncpu;
} __attribute__((packed));
#define CMD_CONSOLE_INFO_RESPONSE_SIZE 308

struct cmd_console_fanthreshold_packet {
    uint8_t temperature;
} __attribute__((packed));

int console_handle(int fd, struct cmd_packet *packet);

#endif
