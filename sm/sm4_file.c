// sm4_file.c
#include <openssl/evp.h>
#include <stdio.h>

static unsigned char key[] = {0, 1, 2,  3,  4,  5,  6,  7,
                              8, 9, 10, 11, 12, 13, 14, 15};

/**
 * @brief 加密或解密文件中的数据
 * 
 * @param in 输入文件
 * @param out 输出文件
 * @param do_encrypt 1-加密，0-解密
 * @return int 成功返回0，否则返回-1
 */
int do_crypt(FILE* in, FILE* out, int do_encrypt)
{
    unsigned char inbuf[BUFSIZ], outbuf[BUFSIZ + EVP_MAX_BLOCK_LENGTH];
    int outlen;
    size_t inlen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    // 指定SM4初始化ctx
    EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, key, NULL, do_encrypt);

    while ((inlen = fread(inbuf, 1, BUFSIZ, in)) > 0) {
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            EVP_CIPHER_CTX_free(ctx); return 1;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        EVP_CIPHER_CTX_free(ctx); return 1;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int main(int argc, char const* argv[])
{
    if (argc != 2) {
        printf("usage: %s <filename>\n", argv[0]);
        return 1;
    }

    char* encry_file_neme = "/tmp/encry_file";
    char* decry_file_name = "/tmp/decry_file";
    FILE* orig_file  = fopen(argv[1], "r");
    FILE* encry_file = fopen(encry_file_neme, "w");
    
    // encrypt
    do_crypt(orig_file, encry_file, 1);

    fclose(orig_file);
    fclose(encry_file);
    encry_file       = fopen(encry_file_neme, "r");
    FILE* decry_file = fopen(decry_file_name, "w");

    // decrypt
    do_crypt(encry_file, decry_file, 0);
    fclose(encry_file);
    fclose(decry_file);

    printf("sm4 do_encry finish. see encrypt file:%s and decrypt file:%s.\n",
           encry_file_neme, decry_file_name);
    return 0;
}
