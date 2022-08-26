// https://www.jianshu.com/p/9da812e0b8d0

// https://blog.csdn.net/zzj806683450/article/details/17426193
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

static const char* pubkey_file = "/tmp/test/pubkey.pem";
static const char* prikey_file = "/tmp/test/prikey.pem";
const char* passwd = "123";
static const int  passwd_len = 3;
#define len 1024

int generate_key_file()
{
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, bn, NULL);
    if(rsa == NULL)
    {
        fprintf(stderr, "RSA_generate_key error!\n");
        return 1;
    }
    FILE* fpubkey = fopen(pubkey_file, "w");
    if(fpubkey == NULL)
    {
        printf("open %s failed .\n", pubkey_file);
        exit(1);
    }
    PEM_write_RSAPublicKey(fpubkey, rsa);
    fclose(fpubkey);

    FILE* fprikey = fopen(prikey_file, "w");
    if(fprikey == NULL)
    {
        printf("open %s failed .\n", prikey_file);
        exit(1);
    }
    PEM_write_RSAPrivateKey(fprikey, rsa, EVP_des_ede3_ofb(),
                            (unsigned char*)passwd, passwd_len, NULL, NULL);
    fclose(fprikey);

    RSA_free(rsa);
    BN_free(bn);
    return 0;
}

RSA* read_pubkey()
{
    FILE* fpubkey = fopen(pubkey_file, "r");
    if(fpubkey == NULL)
    {
        printf("open %s failed .\n", pubkey_file);
        exit(1);
    }
    RSA* rsa = PEM_read_RSAPublicKey(fpubkey, NULL, NULL, NULL);
    if(rsa == NULL)
    {
        printf("read %s failed . \n", pubkey_file);
        exit(1);
    }
    printf("read public pem file\n");

    fclose(fpubkey);
    return rsa;
}

RSA* read_prikey()
{
    FILE* fprikey = fopen(prikey_file, "r");
    if(fprikey == NULL)
    {
        printf("open %s failed .\n", pubkey_file);
        exit(1);
    }
    RSA* rsa = PEM_read_RSAPrivateKey(fprikey, NULL, NULL, NULL);
    if(rsa == NULL)
    {
        printf("read %s failed . \n", prikey_file);
        exit(1);
    }
    // printf("read private pem file\n");
    fclose(fprikey);
    return rsa;  
}

int encrypt(const unsigned char* from, unsigned char* to)
{
    RSA *rsa = RSA_new();
    rsa = read_pubkey();
    int ret = RSA_public_encrypt(RSA_size(rsa),
                        from, to, rsa, RSA_NO_PADDING);
    RSA_free(rsa);
    if(ret < 0)
    {
        printf("RSA_public_encrypt faild .\n");
        return 1;
    }
    return 0;
}

int decrypt(const unsigned char* from, unsigned char* to)
{
    RSA *rsa = RSA_new();
    rsa = read_prikey();
    int ret = RSA_private_decrypt(RSA_size(rsa),
            from, to, rsa, RSA_NO_PADDING);   
    RSA_free(rsa);
    if(ret < 0)
    {
        printf("RSA_private_decrypt failed \n");
        return 1;
    }
    return 0;
}

int main(int argc, char const *argv[])
{
    generate_key_file();

    unsigned char plain[len]="hello world";
    unsigned char tmp[len]={0};
    printf("befor encrypt:%s\n", plain);

    encrypt(plain, tmp);
    printf("after encrypt:%s\n", tmp);

    unsigned char decrypt_ret[len]={0};
    decrypt(tmp, decrypt_ret);
    printf("after decrypt:%s\n", decrypt_ret);
    return 0;
}
