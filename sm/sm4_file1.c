// sm4_file1.c
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#define BUFSIZE 20

/**
 * @brief 对文件内容进行加密
 *
 * @param fp 要对里面的内容进行加密的文件指针
 * @param out 加密后的数据输出
 * @param outlen 加密后的数据长度
 * @param key 秘钥,可以为NULL
 * @return int 函数错误码
 */
int do_encrypt(FILE* fp, unsigned char* out, int* outlen,
               const unsigned char* key)
{
    int tmplen          = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, NULL);

    unsigned char buf[BUFSIZE] = {0};
    size_t nread               = 0;
    while ((nread = fread(buf, 1, BUFSIZE, fp)) > 0) {
        EVP_EncryptUpdate(ctx, out + tmplen, outlen, buf, nread);
        tmplen += (*outlen);
    }
    EVP_EncryptFinal_ex(ctx, out + tmplen, outlen);
    *outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/**
 * @brief 对文件的加密内容进行解密
 *
 * @param fp 文件指针
 * @param out 解密后数据
 * @param outlen 解密后的数据长度
 * @param key 秘钥，可以为NULL
 * @return int
 */
int do_decrypt(FILE* fp, unsigned char* out, int* outlen,
               const unsigned char* key)
{
    int tmplen          = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, NULL);

    unsigned char buf[BUFSIZE] = {0};
    size_t nread               = 0;
    while ((nread = fread(buf, 1, BUFSIZE, fp)) > 0) {
        EVP_DecryptUpdate(ctx, out + tmplen, outlen, buf, nread);
        tmplen += (*outlen);
    }
    EVP_DecryptFinal_ex(ctx, out + tmplen, outlen);
    *outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int main(int argc, char const* argv[])
{
    unsigned char key[] = {0, 1, 2,  3,  4,  5,  6,  7,
                           8, 9, 10, 11, 12, 13, 14, 15};
    int ret             = 0;
    int outlen          = 0;
    if (argc < 2) {
        printf("usage: %s <file name>\n", argv[0]);
        return 1;
    }
    FILE* fp = fopen(argv[1], "r");
    // encrypt
    unsigned char out[BUFSIZ];
    ret = do_encrypt(fp, out, &outlen, key);
    fclose(fp);
    const char* enc_file = "/tmp/sm4_enc_file.txt";
    const char* dec_file = "/tmp/sm4_dec_file.txt";
    FILE* enc_fp         = fopen(enc_file, "w");
    fwrite(out, 1, outlen, enc_fp);
    fclose(enc_fp);
    printf("encrypt data write in %s\n", enc_file);

    // decrypt
    enc_fp = fopen(enc_file, "r");
    ret    = do_decrypt(fp, out, &outlen, key);
    fclose(enc_fp);

    FILE* dec_fp = fopen(dec_file, "w");
    fwrite(out, 1, outlen, dec_fp);
    fclose(dec_fp);
    printf("decrypt data write in %s\n", dec_file);
    return ret;
}
