#include "comm.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>


void handleErrors()
{
    printf("error ocurr.\n");
    exit(0);
}
/**
 * @brief 加密信封
 *
 * intput:
 * @param pub_key 公钥
 * @param plaintext 明文
 * @param plaintext_len 明文长度
 * @param encrypted_key 对称秘钥
 * @param encrypted_key_len 对称秘钥长度
 * @param iv 初始化向量
 * output:
 * @param ciphertext 密文
 * @return int 密文长度
 */
int envelope_seal(EVP_PKEY* pub_key, unsigned char* plaintext,
                  int plaintext_len, unsigned char* encrypted_key,
                  int* encrypted_key_len, unsigned char* iv,
                  unsigned char* ciphertext)
{
    EVP_CIPHER_CTX* ctx;
    int ciphertext_len;
    int len;
    /* 创建并初始化上下文 */
    if (!(ctx = EVP_CIPHER_CTX_new())) print("3");
    print("test\n");
    /* 初始化信封加密操作。根据密码生成秘钥，然后对秘钥多次加密。
    在这里只加密一次，这个操作还会生成一个IV并至于iv中 */
    if (1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), &encrypted_key,
                          encrypted_key_len, iv, &pub_key, 1))
        print("1");

    /* 对消息进行加密并获得输出的密文，如果需要可以调用多次。
     */
    if (1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        print("2");
    ciphertext_len = len;

    /* 结束加密，其他密文在这一步写入。 */
    if (1 != EVP_SealFinal(ctx, ciphertext + len, &len)) print("3");
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


/**
 * @brief 打开信封
 *
 * input:
 * @param priv_key  私钥
 * @param ciphertext 密文
 * @param ciphertext_len 密文长度
 * @param encrypted_key 对称秘钥
 * @param encrypted_key_len 对称秘钥长度
 * @param iv 初始化向量
 * output:
 * @param plaintext 明文
 * @return int 明文长度
 */
int envelope_open(EVP_PKEY* priv_key, unsigned char* ciphertext,
                  int ciphertext_len, unsigned char* encrypted_key,
                  int encrypted_key_len, unsigned char* iv,
                  unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
                          encrypted_key_len, iv, priv_key))
        handleErrors();

    if (1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_OpenFinal(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main(int argc, char const* argv[])
{
    const char* pubkey_file = "/tmp/pubkey_file";
    const char* prikey_file = "/tmp/prikey_file";
    const char* passwd   = "123";
    // 生成密钥对
    generate_key_file(pubkey_file, prikey_file, (unsigned char*)passwd);
    print("generate key file.\n");

    // 读取公钥和密钥
    EVP_PKEY* pubkey = read_pubkey(pubkey_file);
    EVP_PKEY* prikey = read_prikey(prikey_file);
    print("read key.\n");

    unsigned char* encrypted_key = OPENSSL_zalloc(EVP_PKEY_size(pubkey));
    int encrypted_key_len;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    unsigned char txt[] = "hello world !";
    printf("src = %s\n", txt);

    int ciphertext_len               = 0;
    unsigned char ciphertext[BUFSIZ] = {0};
    ciphertext_len = envelope_seal(pubkey, txt, strlen((const char*)txt), encrypted_key,
                                   &encrypted_key_len, iv, ciphertext);

    printf("enc_len= %d ,key_len= %d, enc_data=%s\n", ciphertext_len, encrypted_key_len, ciphertext);

    unsigned char plaintext[BUFSIZ] = {0};
    int plaintext_len               = 0;
    plaintext_len =
        envelope_open(prikey, ciphertext, ciphertext_len, encrypted_key,
                      encrypted_key_len, iv, plaintext);
    printf("plaintext_len=%d, key_len= %d, dec_data=%s\n", plaintext_len, encrypted_key_len, plaintext);

    EVP_PKEY_free(prikey);
    EVP_PKEY_free(pubkey);
    OPENSSL_free(encrypted_key);
    print("free key.\n");
    return 0;
}
