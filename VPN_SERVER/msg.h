#pragma once
#include<iostream>
#define MAX_DATA_SIZE 100
enum msg_type
{
    request=1,
    response,
};
struct msg_response
{
    uint32_t alloced_ip;
    uint32_t alloced_ip_mask;
    uint32_t route_ip;
    uint32_t route_mask;

};
struct msg_request
{
/* char user_name[20];
char user_password[20]; */
};
struct  msg
{
    msg_type type;
    uint8_t data[MAX_DATA_SIZE];
}__attribute__((packed));
