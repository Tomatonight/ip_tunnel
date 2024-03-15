#pragma once
#include <errno.h>
#include <fcntl.h>
#include<stdlib.h>
#include<memory.h>
#include <sys/ioctl.h> /* ioctl() */
/* includes for struct ifreq, etc */
#include <sys/types.h>
#include <sys/socket.h>
#include<unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
/* networking */
#include<stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include"rsa.h"
class tun_dev
{
    public:
    void tun_open();
    void route_init();
    void process_read(int udp_fd,class rsa* rsa);
    int tun_fd=0;
};