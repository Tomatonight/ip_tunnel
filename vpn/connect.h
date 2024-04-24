#include <linux/if_tun.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "rsa.h"
class Connect
{
public:
    void init();
    void process_udp_read(int fd);
    void process_ctl_read();
    void set_bind_netdev(int sock_fd,char *netdev_name);
    int udp_fd = 0;
    int tcp_ctl_fd = 0;
    int peer_tcp_fd=0;
private:
    void udp_init();
    void tcp_ctl_init();
    void swap_key();
};
