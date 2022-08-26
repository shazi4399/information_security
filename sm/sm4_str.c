// sm4_str.c
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief 加密或解密数据
 *
 * @param in 输入数据
 * @param inl 输入数据的长度
 * @param out 输出数据
 * @param do_encrypt 1-加密，0-解密
 * @return void 
 */
void do_crypt(const unsigned char* in, const unsigned int inlen,
             unsigned char* out, int do_encrypt, const unsigned char* key)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, key, NULL, do_encrypt);
    EVP_Cipher(ctx, out, in, inlen);
    EVP_CIPHER_CTX_free(ctx);
    return;
}

int main(int argc, char const* argv[])
{
    unsigned char key[] = {0, 1, 2,  3,  4,  5,  6,  7,
                           8, 9, 10, 11, 12, 13, 14, 15};
    const char* str     = "hello world";
    printf("origin data= %s\n", str);

    // encrypt
    unsigned char buf[BUFSIZ] = {0};
    do_crypt((const unsigned char*)str, strlen(str), buf, 1, key);
    printf("after encrypt str(hex)= ");
    for (int i = 0; i < 12; i++) {
        printf("%2X", buf[i]);
    }

    // decrypt
    unsigned char bufout[BUFSIZ] = {0};
    do_crypt(buf, strlen((const char*)buf), bufout, 0, key);
    printf("\nafter decrypt data= %s\n", bufout);
    return 0;
}
