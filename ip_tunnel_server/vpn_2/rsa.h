#pragma once
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include<openssl/evp.h>
class rsa
{
public:
    void rsa_init();
    void sign_init();
    int encrypt(char *buffer, int len, char *out_buffer);
    int decrypt(char *buffer, int len, char *out_buffer);
    int generate_sign(char *buffer, int len, char *out_buffer);
    int test_sign(char *buffer, int len, char *sign_buffer, int sign_len);
    RSA *recv_rsa;
    RSA *rsa;
    EVP_PKEY *key;
    EVP_PKEY *peer_key;
private:
    
    EVP_PKEY_CTX *ctx;
    EVP_MD_CTX *md_ctx;
    //*******
    
    EVP_PKEY_CTX *peer_ctx;
    EVP_MD_CTX *peer_md_ctx;
    BIGNUM *e;
    void print(const BIGNUM *bum);
};