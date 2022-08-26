#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief 生成SM2公钥和私钥文件
 *
 * @param pri_file 私钥文件名
 * @param pub_file 公钥文件名
 * @return int 成功返回0，否则返回-1
 */
int gen_key(const char* pri_file, const char* pub_file);

/**
 * @brief 从文件中读取秘钥。
 *
 * @param key_file 公钥或私钥文件名
 * @param type 0读取公钥，1读取私钥
 * @return EVP_PKEY* 成功返回相应的秘钥，失败返回NULL
 */
EVP_PKEY* read_key_bio(const char* key_file, const int type);

/**
 * @brief 加密数据
 *
 * @param key 加密公钥
 * @param out 加密密文
 * @param in 要加密的数据
 * @param inlen 数据长度
 * @return size_t 密文长度
 */
size_t do_encrypt(EVP_PKEY* key, unsigned char* out, const unsigned char* in,
                  size_t inlen);

/**
 * @brief 解密数据
 *
 * @param key 解密私钥
 * @param out 解密后的数据
 * @param in 要解密的数据
 * @param inlen 数据长度
 * @return size_t 解密后的数据长度
 */
size_t do_decrypt(EVP_PKEY* key, unsigned char* out, const unsigned char* in,
                  size_t inlen);

int main(int argc, char const* argv[])
{
    size_t ret;

    const char* pub_file = "/tmp/pub_key.pem";
    const char* pri_file = "/tmp/pri_key.pem";
    // 生成公钥和私钥并写入文件中
    if (gen_key(pri_file, pub_file)) {
        printf("gen key failed.");
        exit(1);
    }
    // 读取公钥和私钥
    EVP_PKEY* pub_key = read_key_bio(pub_file, 0);
    EVP_PKEY* pri_key = read_key_bio(pri_file, 1);

    unsigned char data[]          = "hello world !";
    unsigned char enc_txt[BUFSIZ] = {0};
    unsigned char dec_txt[BUFSIZ] = {0};
    printf("data= %s\n", data);

    // 公钥加密
    ret = do_encrypt(pub_key, enc_txt, data, strlen((const char*)data));
    printf("ret=%ld, enc= ", ret);
    for (size_t i = 0; i < ret; i++){
        printf("%2X", enc_txt[i]);
    }
    
    // 私钥解密
    ret = do_decrypt(pri_key, dec_txt, enc_txt, ret);
    dec_txt[ret] = 0;
    printf("\nret=%ld, dec= %s\n", ret, dec_txt);

    EVP_PKEY_free(pub_key);
    EVP_PKEY_free(pri_key);
    return 0;
}

int gen_key(const char* pri_file, const char* pub_file)
{
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_sm2);

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
    EC_KEY_set_group(eckey, group);

    BIO* param = BIO_new_file("/tmp/param.cache", "w");
    PEM_write_bio_ECPKParameters(param, group);

    EC_KEY_generate_key(eckey);

    BIO* prikey = BIO_new_file(pri_file, "w");
    BIO* pubkey = BIO_new_file(pub_file, "w");

    PEM_write_bio_ECPrivateKey(prikey, eckey, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(pubkey, eckey);

    BIO_free(param);
    BIO_free(prikey);
    BIO_free(pubkey);
    return 0;
}

EVP_PKEY* read_key_bio(const char* key_file, const int type)
{
    BIO* bio = BIO_new_file(key_file, "r");

    EVP_PKEY* key = EVP_PKEY_new();
    if (0 == type) {
        key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    } else {
        key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    }

    EVP_PKEY_set_alias_type(key, EVP_PKEY_SM2);
    BIO_free(bio);
    return key;
}

size_t do_encrypt(EVP_PKEY* key, unsigned char* out, const unsigned char* in,
                  size_t inlen)
{
    size_t ret        = 0;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_encrypt(ctx, out, &ret, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

size_t do_decrypt(EVP_PKEY* key, unsigned char* out, const unsigned char* in,
                  size_t inlen)
{
    size_t ret        = inlen;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_decrypt(ctx, out, &ret, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}
