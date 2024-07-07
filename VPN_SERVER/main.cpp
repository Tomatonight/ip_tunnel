#include"server.h"
int main()
{
    server* ser=new server;
    ser->init();
    ser->loop();
    return 0;
}