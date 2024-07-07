#include "client.h"

static int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{

    // 检查预验证结果
    if (preverify_ok == 1)
    {
        // 预验证成功
        printf("verification success!\n");
    }
    else
    {
        // 预验证失败
        int err = X509_STORE_CTX_get_error(x509_ctx);
        printf("Certificate verification failed: %s.\n",
               X509_verify_cert_error_string(err));
    }

    return preverify_ok;
}
void client::parse_configure()
{
    int file_fd = open(CONFIGURE_FILE, O_RDONLY);
    if (file_fd < 0)
    {
        printf("open file err\n");
        exit(-1);
    }
    char buffer[1024] = {0};
    int re = read(file_fd, buffer, 1024);
    if (re < 0)
    {
        close(file_fd);
        printf("read file err\n");
        exit(-1);
    }
    close(file_fd);
    std::cmatch match;
    /*
    server_ip:192.168.72.140
    server_port:1234
 */
    std::regex reg("server_ip:([^ ]*)\nserver_port:([0-9]*)\ntun_name:([^ ]*)[ \n]*");
    if (std::regex_match(buffer, match, reg))
    {
        std::string str_1 = match[1];
        std::string str_2 = match[2];
        tun_name=match[3];
        server_addr.sin_port = htons(atoi(str_2.data()));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr(str_1.data());
    }
    else
    {
        printf("parse configure err\n");
        exit(-1);
    }
}
void client::init()
{
    parse_configure();
    printf("configure done\n");
    openssl_init();
    printf("openssl init done\n");
    connect_init();
    printf("connect init done\n");
    tun_init();
    printf("tun init done\n");
    loop();
}
void client::connect_init()
{
    tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0)
    {
        printf("create socket err\n");
        exit(-1);
    }
    if (connect(tcp_fd, (sockaddr *)&server_addr, sizeof(sockaddr)) < 0)
    {
        printf("connect err\n");
        exit(-1);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, tcp_fd);

    if (SSL_connect(ssl) < 1)
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    msg m;
    m.type = request;
    int re = SSL_write(ssl, &m, sizeof(msg));
    if (re <= 0)
    {
        printf("msg write err\n");
        exit(-1);
    }

    re = SSL_read(ssl, &m, sizeof(msg));
    if (re <= 0)
    {
        printf("msg read err");
        exit(-1);
    }

    if (m.type != response)
    {
        printf("msg type err\n");
        exit(-1);
    }
    msg_response *response = (msg_response *)(m.data);
    tun_ip = response->alloced_ip;
    tun_ip_mask = response->alloced_ip_mask;
    route_ip = response->route_ip;
    route_ip_mask = response->route_mask;
}
void client::tun_init()
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

    // set tun ip sudo ip addr add 192.168.71.1/24 dev tun0
    char buffer[100] = {0};
    sprintf(buffer,"sudo ifconfig %s up",tun_name.data());
    printf("%s\n", buffer);
    system(buffer);
    memset(buffer, 0, 100);
    in_addr addr = {.s_addr = htonl(tun_ip)};
    sprintf(buffer, "sudo ip addr add %s/%d dev %s", inet_ntoa(addr),tun_ip_mask,tun_name.data());
    printf("%s\n", buffer);
    system(buffer);
    memset(buffer, 0, 100);
    // set route sudo ip route add 192.168.72.0/24 via 192.168.71.1 dev tun0

    addr = {.s_addr = htonl(route_ip&u32_to_mask(route_ip_mask))};
    
    sprintf(buffer, "sudo ip route add  %s/%d  dev %s", inet_ntoa(addr),route_ip_mask,tun_name.data());
    //  addr.s_addr = route_ip_mask;
    // sprintf(buffer + strlen(buffer), "/%d dev my_tun", inet_ntoa(addr));
    printf("%s\n", buffer);
    system(buffer);
}
void client::loop()
{
    FD_ZERO(&read_set);
    FD_ZERO(&tmp_set);
    FD_SET(tcp_fd, &read_set);
    FD_SET(tun_fd, &read_set);
    while (true)
    {
        tmp_set = read_set;
        int ret = select(FD_SETSIZE, &tmp_set, nullptr, nullptr, 0);
        if (ret <= 0)
        {
            printf("select err\n");
            exit(-1);
        }
        for (int i = 0; i < FD_SETSIZE; i++)
        {
            if (FD_ISSET(i, &tmp_set))
            {
                if (i == tun_fd)
                {
                  // printf("tun read\n");
                    char buffer[2048];
                    int re = read(tun_fd, buffer+sizeof(int), 2048-sizeof(int));
                    if (re <= 0)
                    {
                        printf("tun read err\n");
                        exit(-1);
                    }
                    *((int*)buffer)=re;
                    re = SSL_write(ssl, buffer, re+sizeof(int));
                    if (re <= 0)
                    {
                        printf("ssl write err\n");
                        exit(-1);
                    }
                }
                else if (i == tcp_fd)
                {
                 //   printf("tcp read\n");
                    char buffer[2048];
                    int re = SSL_read(ssl, buffer, sizeof(int));
                    if (re <= 0)
                    {
                        printf("ssl connect closed\n");
                        exit(-1);
                    }
                    int pkt_len=*((int*)buffer);
                    re= SSL_read(ssl, buffer+sizeof(int), pkt_len);
                    if(re<=0||re!=pkt_len)
                    {
                        printf("tcp read err\n");
                        exit(-1);
                    }

                    re = write(tun_fd, buffer+sizeof(int), re);
                    if (re <= 0)
                    {
                        printf("tun write closed\n");
                        exit(-1);
                    }
                }
                else
                {
                    printf("fd err\n");
                }
            }
        }
    }
}
void client::openssl_init()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    method = TLSv1_2_method();
    ctx = SSL_CTX_new(method);
    if (!ctx || !method)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_load_verify_locations(ctx, "ssl/client.crt", nullptr))
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
}
uint32_t u32_to_mask(int mask)
{
    uint32_t re=0;
    while(mask--)
    {
        re=re>>1|0x80000000;
    }
    return re;
}