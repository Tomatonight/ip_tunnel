#pragma once
#include<iostream>
#include<vector>
#include<math.h>
extern uint32_t int2mask(int mask);
class address_pool
{
    public:
    void init(uint32_t ip_,uint32_t ip_mask_)
    {
        ip=ip_;
        ip_mask=ip_mask_;
        int t=32-ip_mask;
        mask=int2mask(ip_mask);
        int pool_nb=pow(2,t)-2;\
        pool=std::move(std::vector<bool>(pool_nb,0));
        pool[0]=1;
        pool[1]=1;
    }
    uint32_t alloc_address()
    {
        for(int i=0;i<pool.size();i++)
        {
            if(!pool[i])
            {
                pool[i]=true;
                return (ip&mask)+i;
            }
        }
        return 0;
    }
    void free_address(uint32_t ip_)
    {
        pool[(ip_&(~mask))]=false;
    }
    uint32_t ip;
    uint32_t ip_mask;
    uint32_t mask;
    private:
    std::vector<bool> pool; 
};