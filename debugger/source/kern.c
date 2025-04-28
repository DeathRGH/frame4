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

    if (wp) {
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

int kern_vm_map_handle(int fd, struct cmd_packet *packet) {
    struct sys_kern_vm_map_args args;
    uint32_t size;

    memset(&args, NULL, sizeof(args));

    if (sys_kern_cmd(SYS_KERN_CMD_VM_MAP, &args)) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    size = args.num * sizeof(struct kern_vm_map_entry);

    args.maps = (struct kern_vm_map_entry *)pfmalloc(size); // need to chunk this
    if (!args.maps) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if (sys_kern_cmd(SYS_KERN_CMD_VM_MAP, &args)) {
        free(args.maps);
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &args.num, sizeof(uint32_t));
    net_send_data(fd, args.maps, size);

    free(args.maps);
    return 0;
}

int kern_rdmsr_handle(int fd, struct cmd_packet *packet) {
    struct sys_kern_rdmsr_args args;
    struct cmd_kern_rdmsr_packet *rd;

    rd = (struct cmd_kern_rdmsr_packet *)packet->data;

    args.reg = rd->reg;
    if (sys_kern_cmd(SYS_KERN_CMD_RDMSR, &args)) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &args.msr, sizeof(uint64_t));

    return 0;
}

int kern_phys_read_handle(int fd, struct cmd_packet *packet) {
    struct sys_kern_phys_rw_args args;
    struct cmd_kern_phys_read_packet *rp;
    void *data;
    uint64_t left;
    uint64_t address;

    rp = (struct cmd_kern_phys_read_packet *)packet->data;

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
                args.address = address;
                args.data = data;
                args.length = NET_MAX_LENGTH;
                args.write = 0;
                sys_kern_cmd(SYS_KERN_CMD_PHYS_RW, &args);
                net_send_data(fd, data, NET_MAX_LENGTH);

                address += NET_MAX_LENGTH;
                left -= NET_MAX_LENGTH;
            }
            else {
                args.address = address;
                args.data = data;
                args.length = left;
                args.write = 0;
                sys_kern_cmd(SYS_KERN_CMD_PHYS_RW, &args);
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

int kern_phys_write_handle(int fd, struct cmd_packet *packet) {
    struct sys_kern_phys_rw_args args;
    struct cmd_kern_write_packet *wp;
    void *data;
    uint64_t left;
    uint64_t address;

    wp = (struct cmd_kern_write_packet *)packet->data;

    if (wp) {
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
                args.address = address;
                args.data = data;
                args.length = NET_MAX_LENGTH;
                args.write = 1;
                sys_kern_cmd(SYS_KERN_CMD_PHYS_RW, &args);

                address += NET_MAX_LENGTH;
                left -= NET_MAX_LENGTH;
            }
            else {
                net_recv_data(fd, data, left, 1);
                args.address = address;
                args.data = data;
                args.length = left;
                args.write = 1;
                sys_kern_cmd(SYS_KERN_CMD_PHYS_RW, &args);

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
        case CMD_KERN_VM_MAP:
            return kern_vm_map_handle(fd, packet);
        case CMD_KERN_RDMSR:
            return kern_rdmsr_handle(fd, packet);
        case CMD_KERN_PHYS_READ:
            return kern_phys_read_handle(fd, packet);
        case CMD_KERN_PHYS_WRITE:
            return kern_phys_write_handle(fd, packet);
    }

    return 1;
}
