// sm2_ds_file.c
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char sm2_id[]  = "614837785@qq.com";
unsigned int sm2_id_len = sizeof(sm2_id);

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
 * @brief 对数据进行签名
 *
 * @param pkey 签名私钥
 * @param message 数据
 * @param message_len 数据长度
 * @param sig 签名值
 * @param sig_len 签名值长度
 * @return int 0
 */
int ds_sign(EVP_PKEY* pkey, FILE* fp, unsigned char* sig, size_t* sig_len);

/**
 * @brief 对签名数据进行验证
 *
 * @param pkey 公钥验证
 * @param message 签名数据
 * @param message_len 签名数据长度
 * @param sig 签名值
 * @param sig_len 签名值
 * @return int 0
 */
int ds_verify(EVP_PKEY* pkey, FILE* fp, unsigned char* sig, size_t sig_len);

int main(int argc, char const* argv[])
{
    if (argc < 2) {
        printf("usage: %s <file name>\n", argv[0]);
        return 0;
    }

    FILE* fp           = fopen(argv[1], "r");
    unsigned char* sig = malloc(BUFSIZ);
    size_t sig_len     = 0;

    const char* pub_file = "/tmp/pub-key_sm2.pem";
    const char* pri_file = "/tmp/pri-key_sm2.pem";
    // 生成密钥对
    gen_key(pri_file, pub_file);

    // 读取公钥和私钥
    EVP_PKEY* pub_key = read_key_bio(pub_file, 0);
    EVP_PKEY* pri_key = read_key_bio(pri_file, 1);
    ds_sign(pri_key, fp, sig, &sig_len);
    ds_verify(pub_key, fp, sig, sig_len);

    EVP_PKEY_free(pri_key);
    EVP_PKEY_free(pub_key);
    if (sig) {
        free(sig);
    }
    fclose(fp);
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

int ds_sign(EVP_PKEY* pkey, FILE* fp, unsigned char* sig, size_t* sig_len)
{
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* sctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(sctx, sm2_id, sm2_id_len);
    EVP_MD_CTX_set_pkey_ctx(md_ctx, sctx);

    EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey);

    size_t nread              = 0;
    unsigned char buf[BUFSIZ] = {0};
    while ((nread = fread(buf, 1, BUFSIZ, fp)) > 0) {
        EVP_DigestSignUpdate(md_ctx, buf, nread);
    }
    fseek(fp, 0, SEEK_SET);

    EVP_DigestSignFinal(md_ctx, NULL, sig_len);

    sig = (unsigned char*)realloc(sig, *sig_len);
    EVP_DigestSignFinal(md_ctx, sig, sig_len);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(sctx);
    return 0;
}

int ds_verify(EVP_PKEY* pkey, FILE* fp, unsigned char* sig, size_t sig_len)
{
    EVP_MD_CTX* md_ctx_verify = EVP_MD_CTX_new();
    EVP_PKEY_CTX* sctx        = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(sctx, sm2_id, sm2_id_len);
    EVP_MD_CTX_set_pkey_ctx(md_ctx_verify, sctx);

    EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey);

    size_t nread              = 0;
    unsigned char buf[BUFSIZ] = {0};
    while ((nread = fread(buf, 1, BUFSIZ, fp)) > 0) {
        EVP_DigestVerifyUpdate(md_ctx_verify, buf, nread);
    }
    fseek(fp, 0, SEEK_SET);

    if ((EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len)) != 1) {
        printf("Verify SM2 signature failed!\n");
    } else {
        printf("Verify SM2 signature succeeded!\n");
    }

    EVP_PKEY_CTX_free(sctx);
    EVP_MD_CTX_free(md_ctx_verify);
    return 0;
}
