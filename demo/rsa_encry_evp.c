#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "comm.h"


// 使用接收者公钥加密，只能用接收者的私钥加密
size_t pkey_encrypt(EVP_PKEY* pubkey, const unsigned char* in,
                    unsigned char* out)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (ctx == NULL) {
        print("EVP_PKEY_CTX_new failed \n");
        exit(1);
    }
    if (!EVP_PKEY_encrypt_init(ctx)) {
        print("EVP_PKEY_encrypt_init failed.\n");
        goto err;
    }
    size_t outlen;
    if (!EVP_PKEY_encrypt(ctx, out, &outlen, in, strlen((const char*)in))) {
        print("EVP_PKEY_encrypt failed.\n");
        goto err;
    }

    EVP_PKEY_CTX_free(ctx);
    return outlen;
err:
    EVP_PKEY_CTX_free(ctx);
    exit(1);
}

// 私钥解密
size_t pkey_decrypt(EVP_PKEY* prikey, const unsigned char* in,
                    const size_t inlen, unsigned char* out)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(prikey, NULL);
    EVP_PKEY_decrypt_init(ctx);

    size_t outlen;
    EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen);

    return outlen;
}

int main(int argc, char const* argv[])
{
    const char* pubkey_file     = "/tmp/pubkey_file";
    const char* prikey_file     = "/tmp/prikey_file";
    const char* passwd = "123";
    // 生成密钥对
    generate_key_file(pubkey_file, prikey_file, (unsigned char*)passwd);
    print("generate key file.\n");

    // 读取公钥和密钥
    EVP_PKEY* pubkey = read_pubkey(pubkey_file);
    EVP_PKEY* prikey = read_prikey(prikey_file);
    print("read key.\n");

    unsigned char txt[] = "hello world !";
    unsigned char buf[BUFSIZ];
    printf("src = %s\n", txt);

    // 加密
    size_t ret;
    ret = pkey_encrypt(pubkey, txt, buf);
    printf("enc = %s\n", buf);

    // 解密
    unsigned char decrypt_ret[BUFSIZ] = {0};
    pkey_decrypt(prikey, buf, ret, decrypt_ret);
    printf("dec:%s\n", decrypt_ret);

    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(prikey);
    print("free key.\n");

    return 0;
}
