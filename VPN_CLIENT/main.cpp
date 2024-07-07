#include"client.h"
int main()
{
    client* cl=new client;
    cl->init();
    cl->loop();
    return 0;
}