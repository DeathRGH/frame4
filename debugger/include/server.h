#ifndef _SERVER_H
#define _SERVER_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"

#include "proc.h"
#include "debug.h"
#include "kern.h"
#include "console.h"

#define SOCK_SERVER_PORT        2811
#define UART_SERVER_PORT        3321
#define HTTP_SERVER_PORT        2812
#define SERVER_MAXCLIENTS       8
#define UART_SERVER_MAXCLIENTS  1

#define BROADCAST_SERVER_PORT   2813
#define BROADCAST_MAGIC         0xFFFFAAAA

extern struct server_client servclients[SERVER_MAXCLIENTS];
extern struct uart_server_client uartservclients[UART_SERVER_MAXCLIENTS];

struct server_client *alloc_client();
void free_client(struct server_client *svc);

struct uart_server_client *alloc_uart_client();
void free_uart_client(struct uart_server_client *svc);

int handle_version(int fd, struct cmd_packet *packet);
int cmd_handler(int fd, struct cmd_packet *packet);
int check_debug_interrupt();
int handle_socket_client(struct server_client *svc);
void handle_web_client(int fd);

void configure_socket(int fd);
void *broadcast_thread(void *arg);
int start_server();
int start_http();
int start_uart_server();

#endif
