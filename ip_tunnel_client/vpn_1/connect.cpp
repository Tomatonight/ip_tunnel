#include "connect.h"
#include <iostream>
#include"msg.h"
extern char *dest_server;
extern char *local_ip;
extern class rsa* rsa;
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
    if(re<EVP_PKEY_size(rsa->key))
    {
        printf("lost sign\n");
        return;
    }
    char* out_buffer=new char[re];
    int len=rsa->decrypt(buffer,re,out_buffer);
    int flag=rsa->test_sign(out_buffer,len-EVP_PKEY_size(rsa->key),out_buffer+len-EVP_PKEY_size(rsa->key),EVP_PKEY_size(rsa->key));
    int ret=0;
    if(flag==1)
    ret = write(fd, out_buffer, len);
    else
    {
        printf("sign vertify fault\n");
    }
    delete [] out_buffer;
    if (ret < 0)
    {
        printf("tun send error %d %s\n",len,strerror(errno));
    }
}
void Connect::process_ctl_read()
{
    char buffer[1024]={0};
    int re=read(tcp_ctl_fd,buffer,1024);
    if(re==0)
    {
        printf("server close\n");
        exit(-1);
    }
    else if(re<0)
    {
        printf("ctl conn error\n");
        exit(-1);
    }
    else 
    {
        exit(-1);
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
    addr_d.sin_port = htons(UDP_CONN_PORT_PEER);
    addr_d.sin_addr.s_addr = inet_addr(dest_server);
    memset(&addr_s, 0, sizeof(sockaddr_in));
    addr_s.sin_family = AF_INET;
    addr_s.sin_port = htons(UDP_CONN_PORT);
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
}
void Connect::tcp_ctl_init()
{
    tcp_ctl_fd=socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(tcp_ctl_fd<0)
    {
        printf("tcp ctl init error\n");
        exit(-1);
    }
    sockaddr_in  addr_d;
    memset(&addr_d, 0, sizeof(sockaddr_in));
    addr_d.sin_family = AF_INET;
    addr_d.sin_port = htons(TCP_CONN_PORT_PEER);
    addr_d.sin_addr.s_addr = inet_addr(dest_server);
    if(connect(tcp_ctl_fd,(sockaddr*)(&addr_d),sizeof(sockaddr))<0)
    {
        printf("tcp ctl connect error\n");
        exit(-1);
    }
    printf("tcp init\n");
}
void Connect::swap_key()
{
    ctl_msg *msg=create_transmit_key_msg(RSA_get0_n((const RSA*)rsa->rsa),RSA_get0_e((const RSA*)rsa->rsa));
    int len=sizeof(ctl_msg);
    int write_sum=0;
    while(len>write_sum)
    {
        int re=write(tcp_ctl_fd,(char*)msg+write_sum,sizeof(ctl_msg)-write_sum);
        if(re<0&&errno&EAGAIN)
        {
            continue;
        }
        else if(re<0)
        {
            printf("msg write error\n");
            exit(-1);
        }
        else 
        write_sum+=re;
    }
    int read_len=0;
    while(read_len<len)
    {
        int re=read(tcp_ctl_fd,(char*)msg+read_len,sizeof(ctl_msg)-read_len);
        if(re<0&&errno&EAGAIN)
        {
            continue;
        }
        else if(re<0)
        {
            printf("msg write error\n");
            exit(-1);
        }
        else 
        read_len+=re;
    }
    rsa->recv_rsa=RSA_new();
    BIGNUM *recv_n=BN_bin2bn((const unsigned char*)(msg->data_n),msg->len_n,NULL);
    BIGNUM *recv_e=BN_bin2bn((const unsigned char*)(msg->data_e),msg->len_e,NULL);
    if(RSA_set0_key(rsa->recv_rsa,recv_n,recv_e,NULL)==0)
    {
        printf("rsa set error\n");
        exit(-1);
    }
    delete msg;
    printf("key received\n");
}