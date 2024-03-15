#include "tun.h"
extern char *tun_dev_name;
extern char *tun_ip;
void tun_dev::tun_open()
{
    ifreq ifr;
    tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd <= 0)
    {
        printf("open tun error\n");
        exit(-1);
    }
    memset(&ifr, 0, sizeof(ifreq));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_UP;
    strncpy(ifr.ifr_name, tun_dev_name, IFNAMSIZ);
    if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        printf("ioctl tun error\n");
        exit(-1);
    }
    char buffer[100] = {0};
    sprintf(buffer, "sudo ifconfig %s %s/24", tun_dev_name, tun_ip);
    printf("%s\n", buffer);
    system(buffer);
    sprintf(buffer, "sudo ifconfig %s up", tun_dev_name);
    printf("%s\n", buffer);
    system(buffer);
    // memset(buffer,0,100);
    // sprintf(buffer, "sudo route add default tun0");
    // printf("%s\n",buffer);
    // system(buffer);
}
void tun_dev::process_read(int fd, rsa *rsa)
{
    char buffer[1500+EVP_PKEY_size(rsa->key)] = {0};
    int re = read(tun_fd, buffer, 1500);
    if (re < 0)
    {
        printf("tun read error\n");
    }
    rsa->generate_sign(buffer,re,buffer+re);
    re+=EVP_PKEY_size(rsa->key);
    char *out_buffer = new char[re * 2];
    int out_len = rsa->encrypt(buffer, re, out_buffer);
    int ret = write(fd, out_buffer, out_len);
    delete[] out_buffer;
    if (ret < 0)
    {
        printf("udp send error\n");
    }
};