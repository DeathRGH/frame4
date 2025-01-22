#include <ps4.h>
#include "server.h"

bool unload_cmd_sent = false;
int broadcastServerSocketId = 0;
int logDevice = 0; // uart server

struct server_client servclients[SERVER_MAXCLIENTS];
struct uart_server_client uartservclients[UART_SERVER_MAXCLIENTS];

struct server_client *alloc_client() {
    for (int i = 0; i < SERVER_MAXCLIENTS; i++) {
        if (servclients[i].id == 0) {
            servclients[i].id = i + 1;
            return &servclients[i];
        }
    }

    return NULL;
}

void free_client(struct server_client *svc) {
    svc->id = 0;
    sceNetSocketClose(svc->fd);

    if (svc->debugging) {
        debug_cleanup(&svc->dbgctx);
    }

    memset(svc, NULL, sizeof(struct server_client));
}

struct uart_server_client *alloc_uart_client() {
    for (int i = 0; i < UART_SERVER_MAXCLIENTS; i++) {
        if (uartservclients[i].id == 0) {
            uartservclients[i].id = i + 1;
            return &uartservclients[i];
        }
    }

    return NULL;
}

void free_uart_client(struct uart_server_client *svc) {
    svc->id = 0;
    sceNetSocketClose(svc->fd);

    memset(svc, NULL, sizeof(struct uart_server_client));
}

int handle_version(int fd, struct cmd_packet *packet) {
    uint32_t len = strlen(PACKET_VERSION);
    net_send_data(fd, &len, sizeof(uint32_t));
    net_send_data(fd, PACKET_VERSION, len);
    return 0;
}

// tested it again (0.2.6) and could not find any issue
int unload_handle(int fd, struct cmd_packet *packet) {
    unload_cmd_sent = true;
    uprintf("Unloading Frame4, wait 5 Seconds for all threads to end...");
    sceKernelSleep(1);
    uprintf("Unloading Frame4... 4");
    sceKernelSleep(1);
    uprintf("Unloading Frame4... 3");
    sceKernelSleep(1);
    uprintf("Unloading Frame4... 2");
    sceKernelSleep(1);
    uprintf("Unloading Frame4... 1");
    sceKernelSleep(1);

    uprintf("Unloading complete!");
    return 0;
}

int cmd_handler(int fd, struct cmd_packet *packet) {
    if (!VALID_CMD(packet->cmd)) {
        return 1;
    }

    if (packet->cmd == CMD_VERSION) {
        return handle_version(fd, packet);
    }
    if (packet->cmd == CMD_UNLOAD) {
        return unload_handle(fd, packet);
    }
    if (VALID_PROC_CMD(packet->cmd)) {
        return proc_handle(fd, packet);
    }
    else if (VALID_DEBUG_CMD(packet->cmd)) {
        return debug_handle(fd, packet);
    }
    else if (VALID_KERN_CMD(packet->cmd)) {
        return kern_handle(fd, packet);
    }
    else if (VALID_CONSOLE_CMD(packet->cmd)) {
        return console_handle(fd, packet);
    }

    return 0;
}

int check_debug_interrupt() {
    struct debug_interrupt_packet resp;
    struct debug_breakpoint *breakpoint;
    struct ptrace_lwpinfo *lwpinfo;
    uint8_t int3;
    int status;
    int signal;
    int r;

    r = wait4(curdbgctx->pid, &status, WNOHANG, NULL);
    if (!r) {
        return 0;
    }

    signal = WSTOPSIG(status);

    // ##########################################################################
    //uint64_t num;
    //sys_proc_list(NULL, &num);
    //
    //if (num <= 0) {
    //    uprintf("check_debug_interrupt - could not get proc list (num <= 0)");
    //    return 1;
    //}

    //struct proc_list_entry entry[num];
    //sys_proc_list(entry, &num);

    //int foundProc = 0;
    //for (int i = 0; i < num; i++) {
    //    if (entry[i].pid == curdbgctx->pid) {
    //        foundProc = 1;
    //        break;
    //    }
    //}

    //if (!foundProc) {
    //    uprintf("check_debug_interrupt - could not find proc [%i] in list", curdbgctx->pid);
    //    return 1;
    //}

    // ##########################################################################

    if (signal == SIGSTOP) {
        uprintf("passed on a SIGSTOP");
        return 0;
    }
    else if (signal == SIGKILL) {
        debug_cleanup(curdbgctx);

        // the process will die
        ptrace(PT_CONTINUE, curdbgctx->pid, (void *)1, SIGKILL);

        uprintf("sent final SIGKILL");
        return 0;
    }

    // If lwpinfo is on the stack it fails, maybe I should patch ptrace? idk
    lwpinfo = (struct ptrace_lwpinfo *)pfmalloc(sizeof(struct ptrace_lwpinfo));
    if (!lwpinfo) {
        uprintf("could not allocate memory for thread information");
        return 1;
    }

    // grab interrupt data
    r = ptrace(PT_LWPINFO, curdbgctx->pid, lwpinfo, sizeof(struct ptrace_lwpinfo));
    if (r) {
        uprintf("could not get lwpinfo errno %i", errno);
        debug_cleanup(curdbgctx);
        return 0;
    }

    // fill response
    memset(&resp, NULL, DEBUG_INTERRUPT_PACKET_SIZE);
    resp.lwpid = lwpinfo->pl_lwpid;
    resp.status = status;

    // TODO: fix size mismatch with these fields
    memcpy(resp.tdname, lwpinfo->pl_tdname, sizeof(lwpinfo->pl_tdname));

    r = ptrace(PT_GETREGS, resp.lwpid, &resp.reg64, NULL);
    if (r) {
        uprintf("could not get registers errno %i", errno);
        debug_cleanup(curdbgctx);
        return 0;
    }

    r = ptrace(PT_GETFPREGS, resp.lwpid, &resp.savefpu, NULL);
    if (r) {
        uprintf("could not get float registers errno %i", errno);
        debug_cleanup(curdbgctx);
        return 0;
    }

    r = ptrace(PT_GETDBREGS, resp.lwpid, &resp.dbreg64, NULL);
    if (r) {
        uprintf("could not get debug registers errno %i", errno);
        debug_cleanup(curdbgctx);
        return 0;
    }

    // if it is a software breakpoint we need to handle it accordingly
    breakpoint = NULL;
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        if (curdbgctx->breakpoints[i].address == resp.reg64.r_rip - 1) {
            breakpoint = &curdbgctx->breakpoints[i];
            break;
        }
    }

    if (breakpoint) {
        // write old instruction
        sys_proc_rw(curdbgctx->pid, breakpoint->address, &breakpoint->original, 1, 1);

        // backstep 1 instruction
        resp.reg64.r_rip -= 1;
        ptrace(PT_SETREGS, resp.lwpid, &resp.reg64, NULL);

        // single step over the instruction
        ptrace(PT_STEP, resp.lwpid, (void *)1, NULL);
        while (!wait4(curdbgctx->pid, &status, WNOHANG, NULL)) {
            sceKernelUsleep(4000);
        }

        // set breakpoint again
        int3 = 0xCC;
        sys_proc_rw(curdbgctx->pid, breakpoint->address, &int3, 1, 1);
    }
    else {
        uprintf("dealing with hardware breakpoint");
    }

    r = net_send_data(curdbgctx->dbgfd, &resp, DEBUG_INTERRUPT_PACKET_SIZE);
    if (r != DEBUG_INTERRUPT_PACKET_SIZE) {
        uprintf("net_send_data failed %i %i", r, errno);
    }

    free(lwpinfo);

    return 0;
}

int handle_socket_client(struct server_client *svc) {
    struct cmd_packet packet;
    uint32_t rsize;
    uint32_t length;
    void *data;
    int fd;
    int r;

    fd = svc->fd;

    // setup time val for select
    struct timeval tv;
    memset(&tv, NULL, sizeof(tv));
    tv.tv_usec = 1000;

    while (true) {
        if (unload_cmd_sent) {
            break;
        }

        // do a select
        fd_set sfd;
        FD_ZERO(&sfd);
        FD_SET(fd, &sfd);
        errno = NULL;
        net_select(FD_SETSIZE, &sfd, NULL, NULL, &tv);

        // check if we can recieve
        if (FD_ISSET(fd, &sfd)) {
            // zero out
            memset(&packet, NULL, CMD_PACKET_SIZE);

            // recieve our data
            rsize = net_recv_data(fd, &packet, CMD_PACKET_SIZE, 0);

            // if we didnt recieve hmm
            if (rsize <= 0) {
                goto error;
            }

            // check if disconnected
            if (errno == ECONNRESET) {
                goto error;
            }
        }
        else {
            // if we have a valid debugger context then check for interrupt
            // this does not block, as wait is called with option WNOHANG
            if (svc->debugging) {
                if (check_debug_interrupt()) {
                    goto error;
                }
            }

            // check if disconnected
            if (errno == ECONNRESET) {
                goto error;
            }

            // time the handler sleeps in between packets
            // tested with 1ms but gave inconsistency
            // if this causes issue on wifi set it higher
            sceKernelUsleep(2000); // was 25000
            continue;
        }

        // invalid packet
        if (packet.magic != PACKET_MAGIC) {
            uprintf("invalid packet magic %X!", packet.magic);
            continue;
        }

        // mismatch received size
        if (rsize != CMD_PACKET_SIZE) {
            uprintf("invalid recieve size %i!", rsize);
            continue;
        }

        length = packet.datalen;
        if (length) {
            // allocate data
            data = pfmalloc(length);
            if (!data) {
                goto error;
            }

            // recv data
            r = net_recv_data(fd, data, length, 1);
            if (!r) {
                goto error;
            }

            // set data
            packet.data = data;
        }
        else
            packet.data = NULL;

        // special case when attaching
        // if we are debugging then the handler for CMD_DEBUG_ATTACH will send back the right error
        if (!g_debugging && packet.cmd == CMD_DEBUG_ATTACH) {
            curdbgcli = svc;
            curdbgctx = &svc->dbgctx;
        }

        // handle the packet
        r = cmd_handler(fd, &packet);

        if (data) {
            free(data);
            data = NULL;
        }

        // check cmd handler error
        if (r) {
            goto error;
        }
    }

error:
    uprintf("client disconnected");
    free_client(svc);

    return 0;
}


void configure_socket(int fd) {
    int flag;

    flag = 1;
    sceNetSetsockopt(fd, SOL_SOCKET, SO_NBIO, (char *)&flag, sizeof(flag));

    flag = 1;
    sceNetSetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));

    flag = 1;
    sceNetSetsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (char *)&flag, sizeof(flag));
}

void *broadcast_thread(void *arg) {
    struct sockaddr_in server;
    struct sockaddr_in client;
    unsigned int clisize;
    int serv;
    int flag;
    int r;
    uint32_t magic;

    uprintf("broadcast server started");

    // setup server
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = IN_ADDR_ANY;
    server.sin_port = sceNetHtons(BROADCAST_SERVER_PORT);
    memset(server.sin_zero, NULL, sizeof(server.sin_zero));

    serv = sceNetSocket("broadsock", AF_INET, SOCK_DGRAM, 0);
    broadcastServerSocketId = serv;
    if (serv < 0) {
        uprintf("failed to create broadcast server");
        return NULL;
    }

    flag = 1;
    sceNetSetsockopt(serv, SOL_SOCKET, SO_BROADCAST, (char *)&flag, sizeof(flag));

    r = sceNetBind(serv, (struct sockaddr *)&server, sizeof(server));
    if (r) {
        uprintf("failed to bind broadcast server");
        return NULL;
    }

    // TODO: XXX: clean this up, but meh not too dirty? is it? hmmm
    int libNet = sceKernelLoadStartModule("libSceNet.sprx", 0, NULL, 0, 0, 0);
    int (*sceNetRecvfrom)(int s, void *buf, unsigned int len, int flags, struct sockaddr *from, unsigned int *fromlen);
    int (*sceNetSendto)(int s, void *msg, unsigned int len, int flags, struct sockaddr *to, unsigned int tolen);
    RESOLVE(libNet, sceNetRecvfrom);
    RESOLVE(libNet, sceNetSendto);

    while (true) {
        if (unload_cmd_sent) {
            break;
        }

        scePthreadYield();

        magic = 0;
        clisize = sizeof(client);
        r = sceNetRecvfrom(serv, &magic, sizeof(uint32_t), 0, (struct sockaddr *)&client, &clisize);

        if (r >= 0) {
            uprintf("broadcast server received a message");
            if (magic == BROADCAST_MAGIC) {
                sceNetSendto(serv, &magic, sizeof(uint32_t), 0, (struct sockaddr *)&client, clisize);
            }
        }
        else {
            uprintf("sceNetRecvfrom failed");
        }

        sceKernelSleep(1);
    }

    sceNetSocketClose(serv);
    uprintf("broadcast_thread() has ended!");
    return NULL;
}

int start_server() {
    struct sockaddr_in server;
    struct sockaddr_in client;
    struct server_client *svc;
    unsigned int len = sizeof(client);
    int serv, fd;
    int r;

    uprintf("Frame4 " PACKET_VERSION " server started");

    // server structure
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = IN_ADDR_ANY;
    server.sin_port = sceNetHtons(SOCK_SERVER_PORT);
    memset(server.sin_zero, NULL, sizeof(server.sin_zero));

    // start up server
    serv = sceNetSocket("debugserver", AF_INET, SOCK_STREAM, 0);
    if (serv < 0) {
        uprintf("could not create socket!");
        return 1;
    }

    configure_socket(serv);

    r = sceNetBind(serv, (struct sockaddr *)&server, sizeof(server));
    if (r) {
        uprintf("bind failed!");
        return 1;
    }

    r = sceNetListen(serv, SERVER_MAXCLIENTS * 2);
    if (r) {
        uprintf("listen failed!");
        return 1;
    }

    // reset clients
    memset(servclients, NULL, sizeof(struct server_client) * SERVER_MAXCLIENTS);

    // reset debugging stuff
    g_debugging = 0;
    curdbgcli = NULL;
    curdbgctx = NULL;

    while (true) {
        if (unload_cmd_sent) {
            break;
        }

        scePthreadYield();

        errno = NULL;
        fd = sceNetAccept(serv, (struct sockaddr *)&client, &len);
        if (fd > -1 && !errno) {
            uprintf("accepted a new client");

            svc = alloc_client();
            if (!svc) {
                uprintf("server can not accept anymore clients");
                continue;
            }

            configure_socket(fd);

            svc->fd = fd;
            svc->debugging = 0;
            memcpy(&svc->client, &client, sizeof(svc->client));
            memset(&svc->dbgctx, NULL, sizeof(svc->dbgctx));

            ScePthread thread;
            scePthreadCreate(&thread, NULL, (void *)handle_socket_client, (void *)svc, "clienthandler");
        }

        // this is the time we sleep in between adding clients
        // was 2 seconds which felt unresponsive at times
        sceKernelUsleep(1000 * 250); //sceKernelSleep(2);
    }

    sceNetSocketAbort(0, serv);
    sceNetSocketClose(serv);
    uprintf("Server thread has ended!");
    return 0;
}

void send_web_data(int fd, const char *data, bool success) {
    int size = strlen(data);

    if (success) {
        fd_printf(fd, "HTTP/1.1 200 OK\r\n");
    }
    else {
        fd_printf(fd, "HTTP/1.1 400 Bad Request\r\n");
    }

    fd_printf(fd, "Content-Type: application/json\r\n");
    fd_printf(fd, "Access-Control-Allow-Origin: *\r\n");
    fd_printf(fd, "Content-Length: %d\r\n\r\n", size);

    ssize_t bytes_sent;
    while (size > 0) {
        bytes_sent = write(fd, data, size);
        if (bytes_sent < 0) {
            return;
        }

        size -= bytes_sent;
        data += bytes_sent;
    }
}

void handle_web_allocate_memory(int fd, char *query) {
    char *fixedChar = query + 1;
    char *pidQuery = strtok(fixedChar, "&");
    char *lengthQuery = strtok(NULL, "&");
    char *pidParam = pidQuery + 4;
    char *lengthParam = lengthQuery + 7;
    // if (!strstr(pidQuery, "pid=") || !strstr(lengthQuery, "length=")) {
    //     send_web_data(fd, "{\"message\": \"Invalid params.\"}", false);
    //     return;
    // }
    char *pidEnd;
    char *lengthEnd;
    uint64_t pid = strtoull(pidParam, &pidEnd, 10);
    uint64_t length = strtoull(lengthParam, &lengthEnd, 16);
    struct sys_proc_alloc_args args;
    args.length = length;
    sys_proc_cmd(pid, SYS_PROC_ALLOC, &args);
    char responseJson[1000];
    *(char *)responseJson = 0;
    snprintf(responseJson, sizeof(responseJson), "{\"success\": true,\"allocated_address\": \"0x%llX\"}", args.address);
    send_web_data(fd, responseJson, true);
}

void handle_web_free_meory(int fd, char *query) {
    char *fixedChar = query + 1;
    char *pidQuery = strtok(fixedChar, "&");
    char *addressQuery = strtok(NULL, "&");
    char *lengthQuery = strtok(NULL, "&");
    char *pidParam = pidQuery + 4;
    char *addressParam = addressQuery + 8;
    char *lengthParam = lengthQuery + 7;
    // if (!strstr(pidQuery, "pid=") || !strstr(addressQuery, "address=") || !strstr(lengthQuery, "length=")) {
    //     send_web_data(fd, "{\"message\": \"Invalid params.\"}", false);
    //     return;
    // }
    char *pidEnd;
    char *addressEnd;
    char *lengthEnd;
    uint64_t pid = strtoull(pidParam, &pidEnd, 10);
    uint64_t address = strtoull(addressParam, &addressEnd, 16);
    uint64_t length = strtoull(lengthParam, &lengthEnd, 16);
    struct sys_proc_free_args args;
    args.address = address;
    args.length = length;
    sys_proc_cmd(pid, SYS_PROC_FREE, &args);
    send_web_data(fd, "{\"success\":true}", true);
}

void handle_web_get_process_info(int fd, char *query) {
    char *pidParam = query + 5;
    struct sys_proc_info_args args;
    char *pidEnd;
    uint64_t pid = strtoull(pidParam, &pidEnd, 10);
    sys_proc_cmd(pid, SYS_PROC_INFO, &args);
    
    char responseJson[1000];
    *(char *)responseJson = 0;
    snprintf(responseJson, sizeof(responseJson), "{\"pid\":%i,\"name\":\"%s\",\"path\":\"%s\",\"title_id\":\"%s\",\"content_id\":\"%s\"}", args.pid, args.name, args.path, args.titleid, args.contentid);
    send_web_data(fd, responseJson, true);
}

void handle_web_process_maps(int fd, char *query) {
    char *pidParam = query + 5;
    char *pidEnd;
    uint64_t pid = strtoull(pidParam, &pidEnd, 10);

    struct sys_proc_vm_map_args args;
    uint32_t size;
    memset(&args, NULL, sizeof(args));

    if (sys_proc_cmd(pid, SYS_PROC_VM_MAP, &args)) {
        send_web_data(fd, "{\"message\":\"SYS_PROC_VM_MAP returned error\"}", false);
        return;
    }

    size = args.num * sizeof(struct proc_vm_map_entry);
    args.maps = (struct proc_vm_map_entry *)pfmalloc(size);
    if (!args.maps) {
        free(args.maps);
        send_web_data(fd, "{\"message\":\"pfmalloc returned error\"}", false);
        return;
    }

    if (sys_proc_cmd(pid, SYS_PROC_VM_MAP, &args)) {
        free(args.maps);
        send_web_data(fd, "{\"message\":\"SYS_PROC_VM_MAP returned error\"}", false);
        return;
    }

    char responseJson[0x100000]; // needs to be even bigger for games like bo3
    *(char *)responseJson = 0;
    for (int entryIndex = 0; entryIndex < args.num; entryIndex++) {
        char tempBuf[1000];
        snprintf(tempBuf, sizeof(tempBuf), "%s{\"name\":\"%s\",\"start\":\"0x%llX\",\"end\":\"0x%llX\",\"offset\":\"0x%llx\",\"prot\":\"%i\"}", entryIndex == 0 ? "[" : ",", args.maps[entryIndex].name, args.maps[entryIndex].start, args.maps[entryIndex].end, args.maps[entryIndex].offset, args.maps[entryIndex].prot);
        strcat(responseJson, tempBuf);
    }
    strcat(responseJson, "]\n");
    send_web_data(fd, responseJson, true);
    free(args.maps);
}

void handle_web_process_list(int fd) {
    void *data;
    uint64_t num;
    uint32_t length;

    sys_proc_list(NULL, &num);

    if (num > 0) {
        length = sizeof(struct proc_list_entry) * num;
        data = pfmalloc(length);
        if (!data) {
            return;
        }
            
        sys_proc_list(data, &num);
        struct proc_list_entry *entries = (struct proc_list_entry *)((struct proc_list_entry **)data);
        char responseJson[0x20000];
        *(char *)responseJson = 0;
        for(int entryIndex = 0; entryIndex < num; entryIndex++) {
            char tempBuf[1000];
            snprintf(tempBuf, sizeof(tempBuf), "%s{\"name\":\"%s\",\"pid\":%i }", entryIndex == 0 ? "[" : ",", entries[entryIndex].p_comm, entries[entryIndex].pid);
            strcat(responseJson, tempBuf);
        }
        strcat(responseJson, "]\n");
        send_web_data(fd, responseJson, true);
        free(data);

        return;
    }
    else {
        send_web_data(fd, "{\"message\": \"Could not get list of processes.\"}\n", false);
        return;
    }
}

void handle_web_notify(int fd, char *query) {
    char *fixedChar = query + 1;
    char *messageTypeQuery = strtok(fixedChar, "&");
    char *messageQuery = strtok(NULL, "&");
    char *messageTypeParam = messageTypeQuery + 12;
    char *messageParam = messageQuery + 8;
    char *messageTypeEnd;
    int messageType = (int)strtoull(messageTypeParam, &messageTypeEnd, 10);
    size_t decodedMessageLength;
    unsigned char *message = base64_decode((const unsigned char *)messageParam, strlen(messageParam), &decodedMessageLength);
    void *data = pfmalloc(decodedMessageLength + 1);
    strcpy(data, (const char *)message);
    sceSysUtilSendSystemNotificationWithText(messageType, data);
    free(data);
    send_web_data(fd, "{\"success\": true}\n", true);
}

void handle_web_write_memory(int fd, char *query) {
    char *fixedChar = query + 1;
    char *pidQuery = strtok(fixedChar, "&");
    char *addressQuery = strtok(NULL, "&");
    char *bytesQuery = strtok(NULL, "&");
    char *pidParam = pidQuery + 4;
    char *address = addressQuery + 8;
    char *bytes = bytesQuery + 6;
    // if (!strstr(pidQuery, "pid=") || !strstr(addressQuery, "address=") || !strstr(bytesQuery, "bytes=")) {
    //     send_web_data(fd, "{\"message\": \"Invalid params.\"}", false);
    //     return;
    // }
    char *pidEnd;
    uint64_t pid = strtoull(pidParam, &pidEnd, 10);
    char *memoryEnd;
    uint64_t memoryAddress = strtoull(address, &memoryEnd, 16);
    int bytesLength = strlen(bytes) / 2;
    char *byteData = pfmalloc(bytesLength);
    for(int i = 0; i < bytesLength; i++) {
        char tempBuffer[3];
        char *dummy;
        strncpy(tempBuffer, bytes + (i * 2), 2);
        unsigned long long tempChar = strtoull(tempBuffer, &dummy, 16);
        *(unsigned char *)(byteData + i) = (unsigned char)tempChar;
    }
    sys_proc_rw(pid, memoryAddress, byteData, bytesLength, 1);

    free(byteData);

    send_web_data(fd, "{\"success\": true}\n", true);
}

void handle_web_read_memory(int fd, char *query) {
    char *fixedChar = query + 1;
    char *pidQuery = strtok(fixedChar, "&");
    char *addressQuery = strtok(NULL, "&");
    char *lengthQuery = strtok(NULL, "&");
    char *pidParam = pidQuery + 4;
    char *addressParam = addressQuery + 8;
    char *lengthParam = lengthQuery + 7;
    char *pidEnd;
    uint64_t pid = strtoull(pidParam, &pidEnd, 10);
    char *addressEnd;
    uint64_t address = strtoull(addressParam, &addressEnd, 16);
    char *lengthEnd;
    uint64_t length = strtoull(lengthParam, &lengthEnd, 16);
    void *data = pfmalloc(length + 1);
    if (!data) {
        send_web_data(fd, "{\"message\":\"pfmalloc returned error\"}", false);
        return;
    }
    memset(data, NULL, length);
    sys_proc_rw(pid, address, data, length, 0);
    char bytesString[0x20000];
    *(char *)bytesString = 0;
    unsigned char *ptr = data;
    for(int i = 0; i < length; i++) {
        char tempBuf[4];
        snprintf(tempBuf, sizeof(tempBuf), "%s%02X", (i == 0 ? "" : " "), (int)ptr[i]);
        strcat(bytesString, tempBuf);
    }
    char responseJson[0x20000];
    *(char *)responseJson = 0;
    snprintf(responseJson, sizeof(responseJson), "{\"bytes\": \"%s\"}", bytesString);
    send_web_data(fd, responseJson, true);
    free(data);
}

void handle_web_client(int fd) {
    char headerBuffer[4096] = {0};
    read(fd, headerBuffer, 4096);
    char *requestHeader = strtok(headerBuffer, "\r\n");

    char *requestHeaderPart = strtok(requestHeader, " ");
    while (requestHeaderPart != NULL) {
        if (strstr(requestHeaderPart, "/") != NULL) {
            break;
        }
        
        requestHeaderPart = strtok(NULL, " ");
    }
    char *dummyHost = "localhost:2812";
    char buffer[1000];
    snprintf(buffer, sizeof(buffer), "%s%s", dummyHost, requestHeaderPart);
    int ret;
    void *pool;
    size_t mallocSize, useSize;
    struct SceHttpUriElement element;

    ret = sceHttpUriParse(NULL, buffer, NULL, &mallocSize, 0);
    if (ret < 0) {
        return;
    }

    pool = malloc(mallocSize);
    if (pool == NULL) {
        return;
    }

    ret = sceHttpUriParse(&element, buffer, pool, &useSize, mallocSize);
    if (ret < 0) {
        // is it fine if this fails? ~DeathRGH 2022/02/17
    }

    if (!strcmp(element.path, "/write-memory")) {
        handle_web_write_memory(fd, element.query);
        return;
    }
    if (!strcmp(element.path, "/read-memory")) {
        handle_web_read_memory(fd, element.query);
        return;
    }
    if (!strcmp(element.path, "/allocate-memory")) {
        handle_web_allocate_memory(fd, element.query);
        return;
    }
    if (!strcmp(element.path, "/free-memory")) {
        handle_web_free_meory(fd, element.query);
        return;
    }
    if (!strcmp(element.path, "/notify")) {
        handle_web_notify(fd, element.query);
        return;
    }
    if (!strcmp(element.path, "/process-list")) {
        handle_web_process_list(fd);
        return;
    }
    if (!strcmp(element.path, "/process-info")) {
        handle_web_get_process_info(fd, element.query);
        return;
    }
    if (!strcmp(element.path, "/process-maps")) {
        handle_web_process_maps(fd, element.query);
        return;
    }
    send_web_data(fd, "{\"message\": \"Default Server\"}\n", true);
}

int start_http() {
    struct sockaddr_in serverAddress;
    struct sockaddr_in clientAddress;
    unsigned int clientAddressLength = sizeof(clientAddress);
    int server;
    int clientSocket;

    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = IN_ADDR_ANY;
    serverAddress.sin_port = sceNetHtons(HTTP_SERVER_PORT);

    server = sceNetSocket("httpserver", AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        return 1;
    }
    
    int flag = 1;
    sceNetSetsockopt(server, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

    int nbFlag = 1;
    sceNetSetsockopt(server, SOL_SOCKET, SCE_NET_SO_NBIO, &nbFlag, sizeof(nbFlag));

    int bindResponse = sceNetBind(server, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
    if (bindResponse) {
        return 1;
    }

    int listenResponse = sceNetListen(server, SERVER_MAXCLIENTS * 2);
    if (listenResponse) {
        return 1;
    }

    while (true) {
        if (unload_cmd_sent) {
            break;
        }
        clientSocket = sceNetAccept(server, (struct sockaddr*)&clientAddress, &clientAddressLength);
        if (clientSocket > -1) {
            handle_web_client(clientSocket);
            sceNetSocketClose(clientSocket);
        }
    }

    sceNetSocketAbort(0, server);
    sceNetSocketClose(server);
    sceKernelUsleep(10000);
    uprintf("Http server thread has ended!");
    return 0;
}

int read_kernel_for_client(struct uart_server_client *svc) {
    char s_Buffer[100];
    int bytesRead = 0;
    while (true) {
        if (unload_cmd_sent) {
            break;
        }
        bytesRead = sceKernelRead(logDevice, s_Buffer, 16);
        if (bytesRead > 0) {
            if (write(svc->fd, s_Buffer, strlen(s_Buffer)) <= 0) {
                break;
            }
        }
        memset(s_Buffer, 0, sizeof(s_Buffer));
    }

    uprintf("uart client disconnected");
    free_uart_client(svc);
    return 0;
}

int start_uart_server() {
    struct sockaddr_in server;
    struct sockaddr_in client;
    struct uart_server_client *svc;
    unsigned int len = sizeof(client);
    int serv, fd;
    int r;

    logDevice = sceKernelOpen("/dev/klog", 0x00, 0);

    uprintf("<TTYRedirector> server started");

    // server structure
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = IN_ADDR_ANY;
    server.sin_port = sceNetHtons(UART_SERVER_PORT);
    memset(server.sin_zero, NULL, sizeof(server.sin_zero));

    // start up server
    serv = sceNetSocket("ttyserver", AF_INET, SOCK_STREAM, 0);
    if (serv < 0) {
        uprintf("<TTYRedirector> could not create socket!");
        return 1;
    }

    configure_socket(serv);

    r = sceNetBind(serv, (struct sockaddr *)&server, sizeof(server));
    if (r) {
        uprintf("<TTYRedirector> bind failed!");
        return 1;
    }

    r = sceNetListen(serv, UART_SERVER_MAXCLIENTS * 2);
    if (r) {
        uprintf("<TTYRedirector> listen failed!");
        return 1;
    }

    // reset clients
    memset(uartservclients, NULL, sizeof(struct uart_server_client) * UART_SERVER_MAXCLIENTS);

    while (true) {
        if (unload_cmd_sent) {
            break;
        }
        scePthreadYield();

        errno = NULL;
        fd = sceNetAccept(serv, (struct sockaddr *)&client, &len);
        if (fd > -1 && !errno) {
            uprintf("<TTYRedirector> accepted a new uart client");

            svc = alloc_uart_client();
            if (!svc) {
                uprintf("<TTYRedirector> server can not accept anymore uart clients");
                continue;
            }

            configure_socket(fd);

            svc->fd = fd;
            memcpy(&svc->client, &client, sizeof(svc->client));

            ScePthread thread;
            scePthreadCreate(&thread, NULL, (void *)read_kernel_for_client, (void *)svc, "uart_clienthandler");
        }

        sceKernelSleep(2);
    }
    sceNetSocketAbort(0, serv);
    sceNetSocketClose(serv);
    uprintf("UART server thread has ended!");
    return 0;
}
