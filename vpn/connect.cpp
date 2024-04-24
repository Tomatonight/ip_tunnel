#include "connect.h"
#include <iostream>
#include "msg.h"
#include <unistd.h>
extern char *dest_ip;
extern char *local_ip;
extern class rsa *rsa;
extern bool server_or_client;
extern bool signup_or_encrypt;
extern char *dest_port;
extern char *local_port;
extern char *tun_dev_name;
extern char* real_dev_name;
void Connect::init()
{
    udp_init();
    tcp_ctl_init();
    swap_key();
}
void Connect::process_udp_read(int fd)
{
    char buffer[1600] = {0};
    int re = read(udp_fd, buffer, 1600);
    if (re < 0)
    {
        printf("udp read error\n");
        exit(-1);
    }
    if (re < EVP_PKEY_size(rsa->key))
    {
        printf("lost sign\n");
        return;
    }
    char *out_buffer = new char[re];
    int len = rsa->decrypt(buffer, re, out_buffer);
    int flag = rsa->test_sign(out_buffer, len - EVP_PKEY_size(rsa->key), out_buffer + len - EVP_PKEY_size(rsa->key), EVP_PKEY_size(rsa->key));
    int ret = 0;
    if (flag == 1)
        ret = write(fd, out_buffer, len);
    else
    {
        printf("sign vertify fault\n");
    }
    delete[] out_buffer;
    if (ret < 0)
    {
        printf("tun send error %d %s\n", len, strerror(errno));
    }
}

void Connect::udp_init()
{

    udp_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd < 0)
    {
        printf("create udp fd error\n");
        exit(-1);
    }
    sockaddr_in addr_d, addr_s;
    memset(&addr_d, 0, sizeof(sockaddr_in));
    addr_d.sin_family = AF_INET;
    addr_d.sin_port = htons(atoi(dest_port));
    addr_d.sin_addr.s_addr = inet_addr(dest_ip);
    memset(&addr_s, 0, sizeof(sockaddr_in));
    addr_s.sin_family = AF_INET;
    addr_s.sin_port = htons(atoi(local_port));
    addr_s.sin_addr.s_addr = inet_addr(local_ip);
    if (bind(udp_fd, (sockaddr *)(&addr_s), sizeof(sockaddr)) < 0)
    {
        printf("bind udp fd error\n");
        exit(-1);
    }
    if (connect(udp_fd, (sockaddr *)(&addr_d), sizeof(sockaddr)) < 0)
    {
        printf("connect udp fd error\n");
        exit(-1);
    }
    if (signup_or_encrypt)
    {
        set_bind_netdev(udp_fd, real_dev_name);
    }
}
void Connect::tcp_ctl_init()
{
    if (!server_or_client)
    {
        tcp_ctl_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        int opt = 1;
        setsockopt(tcp_ctl_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt));
        if (tcp_ctl_fd < 0)
        {
            printf("tcp ctl init error\n");
            exit(-1);
        }
        sockaddr_in addr_s;
        memset(&addr_s, 0, sizeof(sockaddr_in));
        addr_s.sin_family = AF_INET;
        addr_s.sin_port = htons(atoi(local_port));
        addr_s.sin_addr.s_addr = inet_addr(local_ip);
        if (bind(tcp_ctl_fd, (sockaddr *)(&addr_s), sizeof(sockaddr)) < 0)
        {
            printf("tcp ctl bind error\n");
            exit(-1);
        }
        if (listen(tcp_ctl_fd, 5) < 0)
        {
            printf("tcp listen error\n");
            exit(-1);
        }
        peer_tcp_fd = accept(tcp_ctl_fd, NULL, NULL);
        close(tcp_ctl_fd);
        tcp_ctl_fd = peer_tcp_fd;
    }
    else
    {
        
        tcp_ctl_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (tcp_ctl_fd < 0)
        {
            printf("tcp ctl init error\n");
            exit(-1);
        }
        sockaddr_in addr_d,addr_s;
        memset(&addr_d, 0, sizeof(sockaddr_in));
        addr_d.sin_family = AF_INET;
        addr_d.sin_port = htons(atoi(dest_port));
        addr_d.sin_addr.s_addr = inet_addr(dest_ip);
        memset(&addr_s, 0, sizeof(sockaddr_in));
        addr_s.sin_family = AF_INET;
        addr_s.sin_port = htons(atoi(local_port));
        addr_s.sin_addr.s_addr = inet_addr(local_ip);
        if(bind(tcp_ctl_fd,(sockaddr*)&addr_s,sizeof(sockaddr))<0)
        {
            printf("tcp ctl bind error\n");
            exit(-1);
        }
        if (connect(tcp_ctl_fd, (sockaddr *)(&addr_d), sizeof(sockaddr)) < 0)
        {
            printf("tcp ctl connect error\n");
            exit(-1);
        }
    }
    if (signup_or_encrypt)
    {
        set_bind_netdev(tcp_ctl_fd, real_dev_name);
    }
}
void Connect::swap_key()
{

    if (!server_or_client)
    {
        ctl_msg msg;
        int read_len = 0;
        while (read_len < sizeof(ctl_msg))
        {
            int re = read(peer_tcp_fd, ((char *)(&msg)) + read_len, sizeof(ctl_msg) - read_len);
            if (re < 0 && errno & EAGAIN)
            {
                continue;
            }
            else if (re < 0)
            {
                printf("msg write error\n");
                exit(-1);
            }
            else
                read_len += re;
        }
        rsa->recv_rsa = RSA_new();
        BIGNUM *recv_n = BN_bin2bn((const unsigned char *)(msg.data_n), msg.len_n, NULL);
        BIGNUM *recv_e = BN_bin2bn((const unsigned char *)(msg.data_e), msg.len_e, NULL);
        if (RSA_set0_key(rsa->recv_rsa, recv_n, recv_e, NULL) == 0)
        {
            printf("rsa set error\n");
            exit(-1);
        }
        ctl_msg *send_msg = create_transmit_key_msg(RSA_get0_n((const RSA *)rsa->rsa), RSA_get0_e((const RSA *)rsa->rsa));
        int len = sizeof(ctl_msg);
        int write_sum = 0;
        printf("read\n");
        while (len > write_sum)
        {
            int re = write(peer_tcp_fd, (char *)send_msg + write_sum, sizeof(ctl_msg) - write_sum);
            if (re < 0 && errno & EAGAIN)
            {
                continue;
            }
            else if (re < 0)
            {
                printf("msg write error\n");
                exit(-1);
            }
            else
                write_sum += re;
        }
        delete send_msg;
    }
    else
    {
         ctl_msg *msg = create_transmit_key_msg(RSA_get0_n((const RSA *)rsa->rsa), RSA_get0_e((const RSA *)rsa->rsa));
        int len = sizeof(ctl_msg);
        int write_sum = 0;
        while (len > write_sum)
        {
            int re = write(tcp_ctl_fd, (char *)msg + write_sum, sizeof(ctl_msg) - write_sum);
            if (re < 0 && errno & EAGAIN)
            {
                continue;
            }
            else if (re < 0)
            {
                printf("msg write error\n");
                exit(-1);
            }
            else
                write_sum += re;
        }
        int read_len = 0;
        while (read_len < len)
        {
            int re = read(tcp_ctl_fd, (char *)msg + read_len, sizeof(ctl_msg) - read_len);
            if (re < 0 && errno & EAGAIN)
            {
                continue;
            }
            else if (re < 0)
            {
                printf("msg write error\n");
                exit(-1);
            }
            else
                read_len += re;
        }
        rsa->recv_rsa = RSA_new();
        BIGNUM *recv_n = BN_bin2bn((const unsigned char *)(msg->data_n), msg->len_n, NULL);
        BIGNUM *recv_e = BN_bin2bn((const unsigned char *)(msg->data_e), msg->len_e, NULL);
        if (RSA_set0_key(rsa->recv_rsa, recv_n, recv_e, NULL) == 0)
        {
            printf("rsa set error\n");
            exit(-1);
        }
        delete msg;
    }
    printf("key received\n");
}
void Connect::process_ctl_read()
{
    char buffer[1024] = {0};
    int re = read(tcp_ctl_fd, buffer, 1024);
    if (re == 0)
    {
        printf("peer close\n");
        exit(-1);
    }
    else if (re < 0)
    {
        printf("ctl conn error\n");
        exit(-1);
    }
    else
    {
        exit(-1);
    }
}
void Connect::set_bind_netdev(int sock_fd,char *netdev_name)
{
    if (setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, netdev_name, strlen(netdev_name)) < 0)
    {
        printf("bind netdev error\n");
        exit(-1);
    }
}