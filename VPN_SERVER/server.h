#pragma once
#include <unistd.h>
#include <fcntl.h>
#include <linux/if.h>
#include <openssl/err.h>
#include <linux/if_tun.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <openssl/ssl.h>
#include "channel.h"
#include"msg.h"
#include<linux/ip.h>
#include "address_pool.h"
#include "forward_entry.h"
#define CONFIGURE_FILE "configure"
#define KEY_FILE "ssl/server.key"
#define CTX_FILE "ssl/server.crt"
class server
{
public:
    void init();
    void loop();

private:
    void process_channel(int fd);
    void erase_channel(channel *channel_);
    void parse_configure();
    void create_tun();
    void openssl_init();
    void start_listen();
    forward_entry forward;
    address_pool addr_pool;
    fd_set read_fds, tmp_fds;
    int listen_tcp_fd;
    uint16_t listen_tcp_port;
    sockaddr_in tcp_listen_addr;
    std::string tun_name;
    int tun_fd;
    uint32_t private_net; // host
    uint32_t private_net_mask;
    std::unordered_map<int, channel *> channels;
    SSL_CTX *ctx;
    const SSL_METHOD *method;
};