#pragma once
#include<vector>
#include<iostream>
struct entry
{
    uint32_t dest_ip;
    uint32_t mask;
    int forward_fd;
};
class forward_entry
{
    public:
    void add_entry(uint32_t dest_ip,uint32_t mask,int fd);
    int search_entry(uint32_t dest_ip);
    void erase_entry(int fd);
    private:
    std::vector<entry> entrys;
};
