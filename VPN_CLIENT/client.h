#pragma once
#include <stdio.h>
#include <iostream>
#include <regex>
#include <unistd.h>
#include <linux/if.h>
#include <openssl/err.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/socket.h>
#include<sys/select.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include"msg.h"
#define CONFIGURE_FILE "configure"
#define CTX_FILE "ssl/client.crt"
uint32_t u32_to_mask(int mask);
class client
{
public:
    void init();
    void loop();
private:
    void parse_configure();
    void connect_init();
    void openssl_init();
    void tun_init();
    uint32_t tun_ip;
    uint32_t tun_ip_mask;
    uint32_t route_ip;
    uint32_t route_ip_mask;
    sockaddr_in server_addr;
    std::string tun_name;
    int tcp_fd;
    int tun_fd;
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL* ssl;
    fd_set read_set,tmp_set;
};