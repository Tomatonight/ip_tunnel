#include "forward_entry.h"
void forward_entry::add_entry(uint32_t dest_ip, uint32_t mask,int fd)
{
    entrys.push_back({dest_ip,mask,fd});
}
int forward_entry::search_entry(uint32_t dest_ip)
{
    for(auto &entry:entrys)
    {
        if((entry.dest_ip&entry.mask)==(dest_ip&entry.mask))
        return entry.forward_fd;
    }
    return -1;
}
void forward_entry::erase_entry(int fd)
{
    for(auto it=entrys.begin();it!=entrys.end();it++)
    {
        if(it->forward_fd==fd)
        {
            entrys.erase(it);
            return;
        }
    }
}