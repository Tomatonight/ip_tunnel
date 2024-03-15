#include "tun.h"
#include "connect.h"
#include "rsa.h"
#include <algorithm>
char *tun_dev_name = "tun0";
char *dest_server = "192.168.72.129";
char *local_ip = "192.168.72.143";
char *tun_ip = "10.0.0.2";
tun_dev *tun;
Connect *con;
class rsa *rsa;
int main()
{
    tun = new tun_dev;
    con = new Connect;
    rsa = new class rsa;
    rsa->rsa_init();
    tun->tun_open();
    con->init();
    rsa->sign_init();
    tun->route_init();
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