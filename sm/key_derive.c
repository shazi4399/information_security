// ECDH密钥协商，EC是"elliptic curves"的意思，DH是"Diffie-Hellman"的意思。不安全已经废弃,使用ECDHE代替（E：临时）
#define DEBUG
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdio.h>

#include "comm.h"

/**
 * @brief 根据公私钥对和对端公钥生成协商共享秘钥
 * 
 * intput:
 * @param priv_key pkey 己端私钥
 * @param peer_pub_key peer_pub_key 对端公钥
 * output:
 * @param skey skey 共享秘钥
 * @param skeylen skeylen 共享秘钥长度
 * @return int 
 */
int gen_share_key(EVP_PKEY* priv_key, EVP_PKEY* peer_pub_key,
                   unsigned char* skey, size_t* skeylen)
{
    EVP_PKEY_CTX* ctx;
    int ret = 0;
    ctx     = EVP_PKEY_CTX_new(priv_key, NULL);

    ret     = EVP_PKEY_derive_init(ctx);
    
    ret = EVP_PKEY_derive_set_peer(ctx, peer_pub_key);
    
    EVP_PKEY_derive(ctx, NULL, skeylen);
    
    skey = realloc(skey, *skeylen);
    
    ret = EVP_PKEY_derive(ctx, skey, skeylen);
    
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int main(int argc, char const* argv[])
{

    const char* hostA_pub = "../keys/hostA_pub_key.pem";
    const char* hostA_pri = "../keys/hostA_pri_key.pem";
    const char* hostB_pub = "../keys/hostB_pub_key.pem";
    const char* hostB_pri = "../keys/hostB_pri_key.pem";
    gen_key(hostA_pri, hostA_pub);
    gen_key(hostB_pri, hostB_pub);

    EVP_PKEY* hostA_pub_key = read_key_bio(hostA_pub, 0);
    EVP_PKEY* hostA_pri_key = read_key_bio(hostA_pri, 1);
    EVP_PKEY* hostB_pub_key = read_key_bio(hostB_pub, 0);
    EVP_PKEY* hostB_pri_key = read_key_bio(hostB_pri, 1);

    unsigned char* skey = malloc(BUFSIZ);
    size_t skey_len;
    // host A generate key
    // 根据B的私钥和A的公钥生成共享秘钥。
    gen_share_key(hostA_pri_key, hostB_pub_key, skey, &skey_len);
    printf("host A gen key len=%ld, data=", skey_len);
    for (size_t i = 0; i < skey_len; i++) {
        printf("%2X", skey[i]);
    }

    // host B generate key
    // 根据B的私钥和A的公钥生成共享秘钥。
    gen_share_key(hostB_pri_key, hostA_pub_key, skey, &skey_len);
    printf("\nhost B gen key len=%ld, data=", skey_len);
    for (size_t i = 0; i < skey_len; i++) {
        printf("%2X", skey[i]);
    }
    printf("\n");

    free(skey);
    EVP_PKEY_free(hostA_pub_key);
    EVP_PKEY_free(hostB_pub_key);
    EVP_PKEY_free(hostA_pri_key);
    EVP_PKEY_free(hostB_pri_key);
    return 0;
}
