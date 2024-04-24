#include "tun.h"
#include "connect.h"
#include "rsa.h"
#include <algorithm>
#include <regex>
char *tun_dev_name;
char *dest_ip;
char *local_ip;
char *tun_ip;
char *dest_port;
char *local_port;
char* real_dev_name;
bool server_or_client;
bool signup_or_encrypt;
tun_dev *tun;
Connect *con;
class rsa *rsa;
std::regex reg;
std::cmatch match;
char configure_buffer[200];
void parse_configure()
{
    int file_fd = open("configure.txt", O_RDONLY);
    if (file_fd < 0)
    {
        printf("open configure file err\n");
        exit(-1);
    }
    int re = read(file_fd, configure_buffer, 199);
    if (re < 0)
    {
        printf("read configure file err\n");
        exit(-1);
    }
    reg = ("tun_ip:([^\n]*)\nlocal_ip:([^\n]*)\nlocal_port:([^\n]*)\ndest_ip:([^\n]*)\ndest_port:([^\n]*)\nreal_dev_name:([^\n]*)\ntun_name:([^\n]*)\n([^\n]*)\n([^\n]*)");
    if (std::regex_search(configure_buffer, match, reg))
    {
        std::string *t1 = new std::string(match[1]);
        tun_ip = t1->data();
        std::string *t2 = new std::string(match[2]);
        local_ip = t2->data();
        std::string *t3 = new std::string(match[3]);
        local_port = t3->data();
        std::string *t4 = new std::string(match[4]);
        dest_ip = t4->data();
        std::string *t5 = new std::string(match[5]);
        dest_port = t5->data();
        std::string *t6=new std::string(match[6]);
        real_dev_name=t6->data();
        std::string *t7 = new std::string(match[7]);
        tun_dev_name = t7->data();
        if ((match[8].str() != "server" && match[8].str() != "client") || (match[9].str() != "encrypt" && match[9].str() != "sign_up"))
        {
            printf("configure file err %s %s\n", match[8].str().data(), match[9].str().data());
            exit(-1);
        }
        if (match[8].str() == "client")
        {
            server_or_client = true;
        }
        if (match[9].str() == "encrypt")
        {
            signup_or_encrypt = true;
        }
    }
    else
    {
        printf("search configure file err\n");
        exit(-1);
    }
    printf("parse configure file success\n");
}
int main()
{
    parse_configure();
    tun = new tun_dev;
    con = new Connect;
    rsa = new class rsa;
    rsa->rsa_init();
    con->init();
    tun->tun_open();
    rsa->sign_init();
    int max_fd = std::max(tun->tun_fd, std::max(con->tcp_ctl_fd, con->udp_fd));
    while (true)
    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(tun->tun_fd, &fds);
        FD_SET(con->udp_fd, &fds);
        FD_SET(con->tcp_ctl_fd, &fds);
        int ret = select(max_fd + 1, &fds, nullptr, nullptr, 0);
        if (ret < 0 && errno == EINTR)
            continue;
        if (ret < 0)
        {
            printf("select error\n");
            exit(-1);
        }
        if (FD_ISSET(con->tcp_ctl_fd, &fds))
        {
            con->process_ctl_read();
        }
        if (FD_ISSET(tun->tun_fd, &fds))
        {
            tun->process_read(con->udp_fd, rsa);
        }
        if (FD_ISSET(con->udp_fd, &fds))
        {
            con->process_udp_read(tun->tun_fd);
        }
    }
    return 0;
};