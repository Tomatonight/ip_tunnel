#include "rsa.h"
void rsa::rsa_init()
{
    int bits = 512;
    e = BN_new();
    rsa = RSA_new();
    BN_set_word(e, RSA_F4);
    if (RSA_generate_key_ex(rsa, bits, e, NULL) < 0)
    {
        printf("gernerate rsa error\n");
        exit(-1);
    }
    const BIGNUM *n = RSA_get0_n(rsa);
    const BIGNUM *d = RSA_get0_d(rsa);
    /*
    printf("generate public key:(n,e) private key:(n,d)\n");
    printf("n:\n");
    print(n);
    printf("e:\n");
    print(e);
    printf("d:\n");
    print(d);*/
}
int rsa::encrypt(char *buffer, int len, char *out_buffer)
{
    int sum = 0;
    int read_len = RSA_size(rsa) - RSA_PKCS1_PADDING_SIZE;
    for (int i = 0; i < len; i += read_len)
    {
        if (i + read_len >= len)
        {
            read_len = len - i;
        }
        int re = RSA_public_encrypt(read_len, (const unsigned char *)(buffer + i), (unsigned char *)(out_buffer + sum), recv_rsa, RSA_PKCS1_PADDING);
        if (re < 0)
        {
            printf("rsa encrypt error\n");
            exit(-1);
        }
        sum += re;
    }
    return sum;
}
int rsa::decrypt(char *buffer, int len, char *out_buffer)
{
    int sum = 0;
    int read_len = RSA_size(rsa);
    for (int i = 0; i < len; i += read_len)
    {
        int re = RSA_private_decrypt(read_len, (unsigned char *)(buffer + i), (unsigned char *)(out_buffer + sum), rsa, RSA_PKCS1_PADDING);
        if (re < 0)
        {
            printf("rsa decrypt error\n");
        }
        sum += re;
    }
    return sum;
}
void rsa::print(const BIGNUM *num)
{
    uint8_t buffer[256] = {0};
    BN_bn2bin(num, buffer);
    int len = BN_num_bytes(num);
    for (int i = 0; i < len; i++)
    {
        printf("%0x2", buffer[i]);
    }
    printf("\n");
}
void rsa::sign_init()
{
    key = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(key, rsa);
    ctx = EVP_PKEY_CTX_new(key, NULL);
    md_ctx = EVP_MD_CTX_new();
    EVP_SignInit(md_ctx, EVP_sha224());
    peer_key = EVP_PKEY_new();
    
    EVP_PKEY_set1_RSA(peer_key, recv_rsa);
    peer_ctx = EVP_PKEY_CTX_new(peer_key, NULL);
    peer_md_ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(peer_md_ctx, EVP_sha224());
  //   printf("sign init end\n");
}
int rsa::generate_sign(char *buffer, int len, char *out_buffer)
{
    EVP_SignUpdate(md_ctx, buffer, len);
    unsigned int re = 0;
    if(!EVP_SignFinal(md_ctx, (unsigned char *)out_buffer, &re, key))
    {
        printf("generate sign error\n");
    }
    return re;
}
int rsa::test_sign(char *buffer, int len, char *sign_buffer, int sign_len)
{
      EVP_VerifyUpdate(peer_md_ctx, buffer, len);
      return EVP_VerifyFinal(peer_md_ctx,(unsigned char*)sign_buffer,(unsigned int)sign_len,peer_key);
}