// sm3_str.c
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static unsigned int HASH_RESULT_LEN = 32;

/**
 * @brief 计算一段数据的哈希值
 * 
 * @param str 数据
 * @param len 数据长度
 * @param hash_result 哈希值
 * @return unsigned int 哈希值长度
 */
unsigned int hash_str(const char* str, const size_t len,
                      unsigned char* hash_result)
{
    unsigned int ret;
    const EVP_MD* alg = EVP_sm3();
    EVP_Digest(str, len, hash_result, &ret, alg, NULL);
    return ret;
}

int main(int argc, char const* argv[])
{
    char* str = "hello world";
    // HASH_RESULT_LEN = EVP_MD_size(EVP_sm3());
    unsigned char hash_result[HASH_RESULT_LEN];
    unsigned int retlen = hash_str(str, strlen(str), hash_result);

    printf("hash '%s', return len=%d\nhash=", str, retlen);
    for (int i = 0; i < HASH_RESULT_LEN; i++) {
        printf("%02X", hash_result[i]);
    }
    printf("\n");

    return 0;
}
