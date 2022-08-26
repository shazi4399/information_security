#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static const char* finput = "/home/ngx/NoteBook/stuff/symmetric_encrypt_evp.c";
static const char* foutput = "/tmp/out.c";
static const char* fresume = "/tmp/resume.c";

unsigned char key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

int do_crypt(FILE *in, FILE *out, int do_encrypt);

int main(int argc, char const *argv[])
{
    FILE* fin = fopen(finput, "r");
    FILE* fout = fopen(foutput, "w+");
    if(fin == NULL || fout == NULL)
    {
        printf("file open failed.\n");
        return 1;
    }
    do_crypt(fin, fout, 1); // encrypt
    fclose(fin);
    fclose(fout);
    

    FILE* ffin = fopen(foutput, "r");
    FILE* ffout = fopen(fresume, "w+"); 
    if(ffin == NULL || ffout == NULL)
    if(fin == NULL || fout == NULL)
    {
        printf("file open failed.\n");
        return 1;
    }    
    do_crypt(ffin, ffout, 0); // decrypt
    fclose(ffin);
    fclose(ffout);
    return 0;
}

/**
 * @brief 对称密钥加密解密
 * 
 * @param in 输入文件句柄
 * @param out 输出文件句柄
 * @param do_encrypt 1：加密，0：解密
 * @return int 0
 */
int do_crypt(FILE *in, FILE *out, int do_encrypt)
{
    int buflen = 1024;
    unsigned char inbuf[buflen], outbuf[buflen + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, NULL,
                      do_encrypt);

    for (;;) {
        if((inlen = fread(inbuf, 1, buflen, in)) <= 0)
            break;
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}