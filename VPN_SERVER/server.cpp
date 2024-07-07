#include "server.h"
#include <string>
#include <regex>
uint32_t int2mask(int mask)
{
    uint32_t re = 0;
    while (mask--)
    {
        re = (re >> 1) | (0x80000000);
    }
    return re;
}
void server::parse_configure()
{
    int file_fd = open(CONFIGURE_FILE, O_RDONLY);
    if (file_fd < 0)
    {
        printf("open file err\n");
        exit(-1);
    }
    char buffer[1024] = {0};
    int re = read(file_fd, buffer, 1023);
    if (re < 0)
    {
        close(file_fd);
        printf("read file err\n");
        exit(-1);
    }
    close(file_fd);
    /*     private_net:10.0.0.1/24
    address_pool:192.168.71.1/24
    tcp_listen_port:1234
    tcp_listen_ip:192.168.72.140*/

    std::cmatch match;
    std::regex reg("private_net:([^ ]*)/([0-9]*)\naddress_pool:([^ ]*)/([0-9]*)\ntcp_listen_port:([0-9]*)\ntcp_listen_ip:([^ ]*)\ntun_name:([^ ]*)[ \n]*");
    if (std::regex_search(buffer, match, reg))
    {
        std::string str_1 = match[1];
        std::string str_2 = match[2];
        std::string str_3 = match[3];
        std::string str_4 = match[4];
        std::string str_5 = match[5];
        std::string str_6 = match[6];
        tun_name=std::string(match[7]);
        private_net = ntohl(inet_addr(str_1.data()));
        private_net_mask = (atoi(str_2.data()));
        uint32_t tmp, tmp_mask;
        tmp = ntohl(inet_addr(str_3.data()));
        tmp_mask = (atoi(str_4.data()));
        addr_pool.init(tmp, tmp_mask);
        tcp_listen_addr.sin_port = htons(atoi(str_5.data()));
        tcp_listen_addr.sin_addr.s_addr = inet_addr(str_6.data());
        //    printf("%d %d\n",private_net_mask,tmp_mask);
    }
    else
    {
        printf("configure err\n");
        exit(-1);
    }
}
void server::init()
{
    parse_configure();
    printf("configure done\n");
    create_tun();
    printf("create tun done\n");
    openssl_init();
    printf("openssl done\n");
    start_listen();
    printf("start listen done\n");
};

void server::loop()
{
    FD_ZERO(&read_fds);
    FD_ZERO(&tmp_fds);
    FD_SET(tun_fd, &read_fds);
    FD_SET(listen_tcp_fd, &read_fds);
    while (true)
    {
        tmp_fds = read_fds;
        int ret = select(FD_SETSIZE, &tmp_fds, nullptr, nullptr, 0);
        if (ret <= 0)
        {
            printf("select err\n");
            exit(-1);
        }
        for (int i = 0; i < FD_SETSIZE; i++)
        {
            if (FD_ISSET(i, &tmp_fds))
            {
                if (i == listen_tcp_fd)
                {
                    int new_fd = accept(listen_tcp_fd, nullptr, nullptr);
                    channel *new_channel = new channel(new_fd);
                    channels[new_fd] = new_channel;
                    new_channel->ssl = SSL_new(ctx);
                    FD_SET(new_fd, &read_fds);
                }
                else
                {
                    process_channel(i);
                }
            }
        }
    }
}
void server::create_tun()
{
    ifreq ifr;
    tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd <= 0)
    {
        printf("open tun err\n");
        exit(-1);
    }
    memset(&ifr, 0, sizeof(ifreq));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_UP;
    strncpy(ifr.ifr_name, tun_name.data(), IFNAMSIZ);
    if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        printf("ioctl tun err\n");
        exit(-1);
    }
    // set tun ip
    char buffer[100] = {0};
    in_addr addr = {.s_addr = htonl(addr_pool.ip)};
    in_addr mask = {.s_addr = htonl(addr_pool.ip_mask)};
    //  sudo ip addr add 192.168.71.1/24 dev my_tun
    sprintf(buffer, "sudo ip addr add %s/%d dev %s", inet_ntoa(addr), addr_pool.ip_mask,tun_name.data());
    system(buffer);
    bzero(buffer,100);
    sprintf(buffer,"sudo ifconfig %s up",tun_name.data());
    system(buffer);
    channel *tun_channel = new channel(tun_fd);
    channels[tun_fd] = tun_channel;
    tun_channel->state = tun;
}
void server::start_listen()
{
    listen_tcp_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_tcp_fd < 0)
    {
        printf("create tcp socket err\n");
        exit(-1);
    }
    int opt = 1;
    setsockopt(listen_tcp_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt));
    tcp_listen_addr.sin_family = AF_INET;
    // printf("%d\n",ntohs(tcp_listen_addr.sin_port));
    if (bind(listen_tcp_fd, (sockaddr *)&tcp_listen_addr, sizeof(sockaddr)) < 0)
    {
        printf("bind saddr err\n");
        exit(-1);
    }
    if (listen(listen_tcp_fd, 20) < 0)
    {
        printf("tcp listen err\n");
        exit(-1);
    }
}
void server::openssl_init()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    method = TLSv1_2_method();
    ctx = SSL_CTX_new(method);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    //  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    //  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    if (!ctx)
    {
        printf("Unable to create SSL context");
        exit(-1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_certificate_file(ctx, CTX_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
void server::process_channel(int fd)
{

    class channel *channel = channels[fd];
    if (!channel)
    {
        printf("process channel err\n");
        exit(-1);
    }
    switch (channel->state)
    {
    case wait_tcp_ssl:
    {

        SSL_set_fd(channel->ssl, channel->tcp_fd);
        if (SSL_accept(channel->ssl) <= 0)
        {
            erase_channel(channel);
            return;
        }
        channel->state = wait_for_msg;
        break;
    }
    case wait_for_msg:
    {
        msg recv_m;
        msg send_m;
        bzero(&send_m, sizeof(msg));
        int re = SSL_read(channel->ssl, &recv_m, sizeof(msg));
        if (re <= 0)
        {

            printf("msg size err %d %s\n", re, ERR_error_string(ERR_get_error(), NULL));
            erase_channel(channel);
            return;
        }
        if (recv_m.type != request)
        {
            printf("msg type err\n");
            erase_channel(channel);
            return;
        }
        send_m.type = response;
        msg_response *response = (msg_response *)send_m.data;
        response->alloced_ip = addr_pool.alloc_address();
        if (!response->alloced_ip)
        {
            printf("ip pool loss\n");
            erase_channel(channel);
            return;
        }
        response->alloced_ip_mask = addr_pool.ip_mask;
        response->route_ip = private_net;
        response->route_mask = private_net_mask;
        channel->alloced_ip = response->alloced_ip;
        if (SSL_write(channel->ssl, &send_m, sizeof(msg)) != sizeof(msg))
        {
            printf("msg write err\n");
            erase_channel(channel);
            return;
        }
        channel->state = transmit_data;
        forward.add_entry(response->alloced_ip, 0xffffffff, channel->tcp_fd);
        break;
    }
    case transmit_data:
    {

        char buffer[2048];
        int re = SSL_read(channel->ssl, buffer, sizeof(int));
        if (re <= 0)
        {
            erase_channel(channel);
            return;
        }
        int pkt_len = *((int *)buffer);
        re = SSL_read(channel->ssl, buffer + sizeof(int), pkt_len);
        if (re <= 0 || re != pkt_len)
        {
            erase_channel(channel);
            return;
        }
        if (write(tun_fd, buffer + sizeof(int), re) <= 0)
        {
            printf("write tun err\n");
        }
        break;
    }
    case tun:
    {

        char buffer[2048];
        int re = read(tun_fd, buffer + sizeof(int), 2048 - sizeof(int));
        if (re <= 0)
        {
            printf("tun read err\n");
            exit(-1);
        }
        *((int *)buffer) = re;
        iphdr *ip = (iphdr *)(buffer + sizeof(int));
        uint32_t dest_ip = ntohl(ip->daddr);
        int to_fd = forward.search_entry(dest_ip);
        if (to_fd < 0)
        {

            return;
        }
        class channel *to_channel = channels[to_fd];
        if (!to_channel)
        {
            printf("find to channel err\n");
            exit(-1);
        }

        if (SSL_write(to_channel->ssl, buffer, re + sizeof(int)) <= 0)
        {
            printf("ssl write err\n");
            erase_channel(channel);
            return;
        }
        break;
    }
    default:
        printf("channel state err\n");
        break;
    }
}
void server::erase_channel(channel *channel_)
{
    channels.erase(channel_->tcp_fd);
    if (channel_->alloced_ip)
        addr_pool.free_address(channel_->alloced_ip);
    FD_CLR(channel_->tcp_fd, &read_fds);
    //  if (channel_->state != wait_tcp_ssl)
    SSL_shutdown(channel_->ssl);
    SSL_free(channel_->ssl);
    if (channel_->state == transmit_data)
        forward.erase_entry(channel_->tcp_fd);
    close(channel_->tcp_fd);
    delete channel_;
}