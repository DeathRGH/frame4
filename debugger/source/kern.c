#include "kern.h"

int kern_base_handle(int fd, struct cmd_packet *packet) {
    uint64_t kernbase;

    sys_kern_base(&kernbase);

    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &kernbase, sizeof(uint64_t));

    return 0;
}

int kern_read_handle(int fd, struct cmd_packet *packet) {
    struct cmd_kern_read_packet *rp;
    void *data;
    uint64_t left;
    uint64_t address;

    rp = (struct cmd_kern_read_packet *)packet->data;

    if (rp) {
        data = pfmalloc(NET_MAX_LENGTH);
        if (!data) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        net_send_status(fd, CMD_SUCCESS);

        left = rp->length;
        address = rp->address;

        while (left > 0) {
            memset(data, NULL, NET_MAX_LENGTH);

            if (left > NET_MAX_LENGTH) {
                sys_kern_rw(address, data, NET_MAX_LENGTH, 0);
                net_send_data(fd, data, NET_MAX_LENGTH);

                address += NET_MAX_LENGTH;
                left -= NET_MAX_LENGTH;
            }
            else {
                sys_kern_rw(address, data, left, 0);
                net_send_data(fd, data, left);

                address += left;
                left -= left;
            }
        }

        free(data);
        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);
    return 1;
}

int kern_write_handle(int fd, struct cmd_packet *packet) {
    struct cmd_kern_write_packet *wp;
    void *data;
    uint64_t left;
    uint64_t address;

    wp = (struct cmd_kern_write_packet *)packet->data;

    if(wp) {
        data = pfmalloc(NET_MAX_LENGTH);
        if (!data) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        net_send_status(fd, CMD_SUCCESS);

        left = wp->length;
        address = wp->address;

        while (left > 0) {
            if (left > NET_MAX_LENGTH) {
                net_recv_data(fd, data, NET_MAX_LENGTH, 1);
                sys_kern_rw(address, data, NET_MAX_LENGTH, 1);

                address += NET_MAX_LENGTH;
                left -= NET_MAX_LENGTH;
            }
            else {
                net_recv_data(fd, data, left, 1);
                sys_kern_rw(address, data, left, 1);

                address += left;
                left -= left;
            }
        }

        net_send_status(fd, CMD_SUCCESS);

        free(data);
        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);
    return 1;
}

int kern_handle(int fd, struct cmd_packet *packet) {
    switch (packet->cmd) {
        case CMD_KERN_BASE:
            return kern_base_handle(fd, packet);
        case CMD_KERN_READ:
            return kern_read_handle(fd, packet);
        case CMD_KERN_WRITE:
            return kern_write_handle(fd, packet);
    }

    return 1;
}
