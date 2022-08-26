// sm3_file.c
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

// 哈希值长度（字节）
static const unsigned int HASH_RESULT_LEN = 32;
static const size_t BUFSIZE = 8;
/**
 * @brief 计算文件中的数据哈希值
 * 
 * @param fp 文件结构体
 * @param hash_result 文件哈希值
 */
void hash_file(FILE* fp, unsigned char* hash_result)
{
    const EVP_MD* md = EVP_sm3();
    EVP_MD_CTX* ctx  = EVP_MD_CTX_new();

    char buf[BUFSIZE];
    size_t nread = 0;

    EVP_DigestInit_ex(ctx, md, NULL);
    while ((nread = fread(buf, 1, BUFSIZE, fp)) > 0) {
        EVP_DigestUpdate(ctx, buf, nread);
    }
    EVP_DigestFinal_ex(ctx, hash_result, NULL);

    EVP_MD_CTX_free(ctx);
    return;
}

int main(int argc, char const* argv[])
{
    if (argc != 2) {
        printf("usage: %s <file name>\n", argv[0]);
        return 1;
    }
    FILE* fp = fopen(argv[1], "r");
    if (!fp) {
        printf("%s open failed.\n", argv[1]);
        return 1;
    }

    unsigned char hash_result[HASH_RESULT_LEN];
    hash_file(fp, hash_result);
    printf("SM3(%s)= ", argv[1]);
    for (int i = 0; i < HASH_RESULT_LEN; i++) {
        printf("%02x", hash_result[i]);
    }
    printf("\n");

    fclose(fp);
    return 0;
}
