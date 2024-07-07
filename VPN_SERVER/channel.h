#pragma once
#include<openssl/ssl.h>
enum channel_state
{
    wait_tcp_ssl = 1,
    wait_for_msg,
    transmit_data,
    tun,
};
class channel
{
public:
    channel(int fd) : tcp_fd(fd){};
    channel_state state = wait_tcp_ssl;
    int tcp_fd;
    uint32_t alloced_ip=0;
    SSL *ssl;
};