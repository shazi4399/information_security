#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>


const static int md5buflen = 1024;
const static int md5len = 16;
const static int sha256buflen = 1024;
const static int sha256len = 32;

int filetosha256(const char* file, unsigned char* result)
{
    if(file == NULL || result == NULL)
    {
        fprintf(stderr, " file or result string is NULL.\n");
        return 1;
    }
    FILE* pfile = fopen(file, "r");
    if(pfile == NULL)
    {
        fprintf(stderr, "open %s failed\n", file);
        return 1;
    }

    SHA256_CTX sha256_ctx;
    char databuf[sha256buflen];
    unsigned char sha256[sha256len];
    int readlen;

    SHA256_Init(&sha256_ctx);
    while( 0 < (readlen = fread(databuf, 1, sha256buflen, pfile)))
    {
        SHA256_Update(&sha256_ctx, databuf, readlen);
    }
    SHA256_Final(sha256, &sha256_ctx);
    
    memcpy(result, sha256, sha256len);
    return 0;
}

// 生成一个128位散列值
int filetomd5(const char* file, unsigned char* result)
{
    if(file == NULL || result == NULL)
    {
        fprintf(stderr, " file or result string is NULL.\n");
        return 1;
    }
    FILE* pfile = fopen(file, "r");
    if(pfile == NULL)
    {
        fprintf(stderr, "open %s failed\n", file);
        return 1;
    }

    MD5_CTX md5_ctr;
    char databuf[md5buflen];
    MD5_Init(&md5_ctr);

    int readlen;
    while ( 0 < (readlen = fread(databuf, 1, md5buflen, pfile)))
    {
        MD5_Update(&md5_ctr, databuf, readlen);
    }

    unsigned char md5[md5len];
    MD5_Final(md5, &md5_ctr);
    memcpy(result, md5, md5len);
    return 0;   
}

void test_filetomd5(char const*argv[])
{
    unsigned char result[md5len];
    if(filetomd5(argv[1], result))
    {
        fprintf(stderr, "md5 sum failed\n");
        return;
    }
    printf("MD5: ");
    for (int i = 0; i < md5len; i++)
    {
        printf("%02x", result[i]);
    }
    
    printf("  %s\n", argv[1]);
    return;
}

void test_filetosha256(char const*argv[])
{
    unsigned char result[sha256len];
    if(filetosha256(argv[1], result))
    {
        fprintf(stderr, "sha256 sum failed\n");
        return;
    }
    printf("SHA256: ");
    for (int i = 0; i < sha256len; i++)
    {
        printf("%02x", result[i]);
    }
    
    printf("  %s\n", argv[1]);
    return;
}

int main(int argc, char const *argv[])
{
    if(argc != 2){
        fprintf(stderr, "parameter invalid.\n ./a.out filename\n");
        return 1;
    }

    test_filetomd5(argv);
    test_filetosha256(argv);
}

// gcc main.c -lcrypto -std=c11
// https://blog.csdn.net/dgyanyong/article/details/21415961
// https://www.cnblogs.com/binchen-china/p/5653337.html

