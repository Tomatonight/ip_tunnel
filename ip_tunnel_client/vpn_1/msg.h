#pragma once
#include <openssl/rsa.h>
#include <memory.h>
enum MSG_TYPE
{
    TRANSMIT_PUBLIC_KEY = 1,
};
struct ctl_msg
{
    MSG_TYPE type;
    int len_n=0;
    int len_e=0;
    char data_n[256] = {0};
    char data_e[256] = {0};
};
static inline ctl_msg *create_transmit_key_msg(const BIGNUM *n,const  BIGNUM *e)
{
    ctl_msg *msg = new ctl_msg;
    msg->type = TRANSMIT_PUBLIC_KEY;
    msg->len_n=BN_bn2bin((const BIGNUM*)n,(unsigned char *)(&msg->data_n));
    msg->len_e=BN_bn2bin((const BIGNUM*)e,(unsigned char *)(&msg->data_e));
    return msg;
};
