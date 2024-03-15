#pragma once
#include <errno.h>
#include <fcntl.h>
#include<stdlib.h>
#include<memory.h>
#include <sys/ioctl.h> 
#include <sys/types.h>
#include <sys/socket.h>
#include<unistd.h>
#include <linux/if.h>
#include <openssl/err.h>
#include <linux/if_tun.h>
#include<stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include"rsa.h"
#define UDP_CONN_PORT 1234
#define UDP_CONN_PORT_PEER 1234
#define TCP_CONN_PORT_PEER 1234 
// 此端为client
class Connect
{
    public:
    void init();
    void process_udp_read(int fd);
    void process_ctl_read();
    int udp_fd=0;
    int tcp_ctl_fd=0;
    private:
        void udp_init();
        void tcp_ctl_init();
        void swap_key();
};
