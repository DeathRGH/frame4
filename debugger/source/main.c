#include <ps4.h>
#include "ptrace.h"
#include "server.h"
#include "debug.h"
#include "protocol.h"

int _main(void) {
    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    initSysUtil();

    // sleep a few seconds
    // maybe lower our thread priority?
    sceKernelSleep(2);

    // just a little notify
    char notifyBuffer[100];
    snprintf(notifyBuffer, sizeof(notifyBuffer), "Frame4 loaded!\nUpdate %s", PACKET_VERSION);
    sceSysUtilSendSystemNotificationWithText(222, notifyBuffer);

    // jailbreak current thread
    sys_console_cmd(SYS_CONSOLE_CMD_JAILBREAK, NULL);

    // updates
    mkdir("/update/PS4UPDATE.PUP", 0777);
    mkdir("/update/PS4UPDATE.PUP.net.temp", 0777);

    // create folders for scanner
    mkdir("/data/scan_temp", 0777);
    mkdir("/data/scan_temp/init", 0777);
    mkdir("/data/scan_temp/cur", 0777);
    mkdir("/data/scan_temp/old", 0777);

    // start the http server
    ScePthread socketServerThread;
    scePthreadCreate(&socketServerThread, NULL, (void *)start_http, NULL, "http_server_thread");

    // start the uart socket
    ScePthread uartServerThread;
    scePthreadCreate(&uartServerThread, NULL, (void*)start_uart_server, NULL, "uart_server_thread");

    // start the socket server - this will block
    start_server();

    return 0;
}
