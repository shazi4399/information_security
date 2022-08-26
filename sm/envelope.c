#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>

#include "comm.h"

/**
 * @brief 加密信封
 *
 * intput:
 * @param pub_key 公钥
 * @param plaintext 明文
 * @param plaintext_len 明文长度
 * output:
 * @param encrypted_key 被公钥加密了的对称秘钥
 * @param encrypted_key_len 被公钥加密了的对称秘钥长度
 * @param iv 初始化向量
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
    ctx = EVP_CIPHER_CTX_new();
    /* 初始化信封加密操作。根据密码生成秘钥，然后对秘钥多次加密。
    在这里只加密一次，这个操作还会生成一个IV并至于iv中*/
    EVP_SealInit(ctx, EVP_sm4_ecb(), &encrypted_key,
                          encrypted_key_len, iv, &pub_key, 1);
    /* 对消息进行加密并获得输出的密文，如果需要可以调用多次。 */
    EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    // EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    ciphertext_len = len;

    /* 结束加密，其他密文在这一步写入。 */
    EVP_SealFinal(ctx, ciphertext + len, &len);

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
 * @param encrypted_key 被公钥加密了的对称秘钥
 * @param encrypted_key_len 被公钥加密了的对称秘钥长度
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
    ctx = EVP_CIPHER_CTX_new();
    EVP_OpenInit(ctx, EVP_sm4_ecb(), encrypted_key, encrypted_key_len, iv,
                 priv_key);
    EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;
    EVP_OpenFinal(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main(int argc, char const* argv[])
{
    // const char* pub_file = "../keys/pub-key_sm2.pem";
    // const char* pri_file = "../keys/pri-key_sm2.pem";
    // // 生成密钥对
    // gen_key(pri_file, pub_file);

    // // 读取公钥和私钥
    // EVP_PKEY* pub_key = read_key_bio(pub_file, 0);
    // EVP_PKEY* pri_key = read_key_bio(pri_file, 1);

    // SM2好像不支持数字信封？？？，这里用RSA代替
    EVP_PKEY* pub_key = load_example_rsa_key();

    unsigned char* encrypted_key = OPENSSL_zalloc(EVP_PKEY_size(pub_key));
    int encrypted_key_len;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    unsigned char txt[] = "hello world !";
    printf("src = %s\n", txt);

    int ciphertext_len               = 0;
    unsigned char ciphertext[BUFSIZ] = {0};
    ciphertext_len =
        envelope_seal(pub_key, txt, strlen((const char*)txt), encrypted_key,
                      &encrypted_key_len, iv, ciphertext);

    printf("enc_len= %d, enc_data=%s\n", ciphertext_len, ciphertext);

    // ciphertext[2] = 'c'; // 测试修改密文

    unsigned char plaintext[BUFSIZ] = {0};
    int plaintext_len               = 0;
    plaintext_len =
        envelope_open(pub_key, ciphertext, ciphertext_len, encrypted_key,
                      encrypted_key_len, iv, plaintext);
    printf("plaintext_len=%d, dec_data=%s\n", plaintext_len, plaintext);

    EVP_PKEY_free(pub_key);
    // EVP_PKEY_free(pri_key);
    OPENSSL_free(encrypted_key);
    print("free key.\n");
    return 0;
}

