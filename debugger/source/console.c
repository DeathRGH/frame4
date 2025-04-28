#include "console.h"

int console_reboot_handle(int fd, struct cmd_packet *packet) {
    if (g_debugging) {
        debug_cleanup(curdbgctx);

        // close the socket, we are not about to call free_client
        // this is a little hacky but meh
        sceNetSocketClose(fd);
    }

    sys_console_cmd(SYS_CONSOLE_CMD_REBOOT, NULL);
    return 1;
}

int console_print_handle(int fd, struct cmd_packet *packet) {
    struct cmd_console_print_packet *pp;
    void *data;

    pp = (struct cmd_console_print_packet *)packet->data;

    if (pp) {
        data = pfmalloc(pp->length);
        if (!data) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        memset(data, NULL, pp->length);
        
        net_recv_data(fd, data, pp->length, 1);
        
        sys_console_cmd(SYS_CONSOLE_CMD_PRINT, data);
        net_send_status(fd, CMD_SUCCESS);

        free(data);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);
    return 1;
}

int console_notify_handle(int fd, struct cmd_packet *packet) {
    struct cmd_console_notify_packet *np;
    void *data;

    np = (struct cmd_console_notify_packet *)packet->data;

    if (np) {
        data = pfmalloc(np->length);
        if (!data) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        memset(data, NULL, np->length);
        
        net_recv_data(fd, data, np->length, 1);
        
        sceSysUtilSendSystemNotificationWithText(np->messageType, data);
        net_send_status(fd, CMD_SUCCESS);
        
        free(data);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);
    return 1;
}

int console_info_handle(int fd, struct cmd_packet *packet) {
    size_t len;
    struct cmd_console_info_response resp;

    memset((void *)resp.psid, NULL, sizeof(resp.psid));
    len = 16;
    sysctlbyname("machdep.openpsid", &resp.psid, &len, NULL, 0);

    resp.upd_version = 0;
    len = 4;
    sysctlbyname("machdep.upd_version", &resp.upd_version, &len, NULL, 0);

    resp.sdk_version = 0;
    len = 4;
    sysctlbyname("kern.sdk_version", &resp.sdk_version, &len, NULL, 0);

    int mib[2];

    memset((void *)resp.kern_ostype, NULL, sizeof(resp.kern_ostype));
    mib[0] = 1; // CTL_KERN
    mib[1] = 1; // KERN_OSTYPE
    syscall(202, mib, 2, NULL, &len, NULL, 0);
    syscall(202, mib, 2, (void *)resp.kern_ostype, &len, NULL, 0);

    memset((void *)resp.kern_osrelease, NULL, sizeof(resp.kern_osrelease));
    mib[0] = 1; // CTL_KERN
    mib[1] = 2; // KERN_OSRELEASE
    syscall(202, mib, 2, NULL, &len, NULL, 0);
    syscall(202, mib, 2, (void *)resp.kern_osrelease, &len, NULL, 0);

    len = sizeof(resp.kern_osrev);
    mib[0] = 1; // CTL_KERN
    mib[1] = 3; // KERN_OSREV
    syscall(202, mib, 2, &resp.kern_osrev, &len, NULL, 0);

    memset((void *)resp.kern_version, NULL, sizeof(resp.kern_version));
    mib[0] = 1; // CTL_KERN
    mib[1] = 4; // KERN_VERSION
    syscall(202, mib, 2, NULL, &len, NULL, 0);
    syscall(202, mib, 2, (void *)resp.kern_version, &len, NULL, 0);

    memset((void *)resp.hw_model, NULL, sizeof(resp.hw_model));
    mib[0] = 6; // CTL_HW
    mib[1] = 2; // HW_MODEL
    syscall(202, mib, 2, NULL, &len, NULL, 0);
    syscall(202, mib, 2, (void *)resp.hw_model, &len, NULL, 0);

    len = sizeof(resp.hw_ncpu);
    mib[0] = 6; // CTL_HW
    mib[1] = 3; // HW_NCPU
    syscall(202, mib, 2, &resp.hw_ncpu, &len, NULL, 0);
    
    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &resp, CMD_CONSOLE_INFO_RESPONSE_SIZE);

    return 0;
}

int console_fanthreshold_handle(int fd, struct cmd_packet *packet) {
    struct cmd_console_fanthreshold_packet *fp;

    fp = (struct cmd_console_fanthreshold_packet *)packet->data;
    if (fp) {
        uint8_t temp_temperature = fp->temperature > 80 ? 80 : fp->temperature;

        int fd2 = open("/dev/icc_fan", O_RDONLY, 0);
        if (!fd2) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }

        char data[10] = {0x00, 0x00, 0x00, 0x00, 0x00, temp_temperature, 0x00, 0x00, 0x00, 0x00};
        ioctl(fd2, 0xC01C8F07, data);
        close(fd2);

        net_send_status(fd, CMD_SUCCESS);

        float fahrenheit = (temp_temperature * 1.8f) + 32;

        char notifyBuffer[100];
        snprintf(notifyBuffer, sizeof(notifyBuffer), "Frame4 - Fan Threshold set to %i°C / %i°F!", temp_temperature, (int)fahrenheit);
        sceSysUtilSendSystemNotificationWithText(222, notifyBuffer);
        
        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);
    return 1;
}

int console_handle(int fd, struct cmd_packet *packet) {
    switch (packet->cmd) {
        case CMD_CONSOLE_REBOOT:
            return console_reboot_handle(fd, packet);
        case CMD_CONSOLE_END:
            return 1;
        case CMD_CONSOLE_PRINT:
            return console_print_handle(fd, packet);
        case CMD_CONSOLE_NOTIFY:
            return console_notify_handle(fd, packet);
        case CMD_CONSOLE_INFO:
            return console_info_handle(fd, packet);
        case CMD_CONSOLE_FANTHRESHOLD:
            return console_fanthreshold_handle(fd, packet);
    }

    return 0;
}
