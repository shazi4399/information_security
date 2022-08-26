#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

// 计算hash值
int hash_file(const char *file_name, unsigned char *hash, const EVP_MD* md);

void print_result(const unsigned char* hash_value, const unsigned int hash_value_len, const char* filename);

void print_info();

int main(int argc, char *argv[])
{
    unsigned int hash_value_len = 0;
    EVP_MD* md = NULL;
    const char* filename = NULL;

    while (1) {
        int c;
        int option_index = 0;
        static struct option long_options[] = {
            {"sm3",     no_argument,       0,  'a' },
            {"sha256",  no_argument,       0,  'b' },
            {"sha512",  no_argument,       0,  'c' },
            {"md5",     no_argument,       0,  'd' },
            {"help",    no_argument,       0,  'h' },  
            {"file",    required_argument, 0,  'f' }   
        };

        c = getopt_long(argc, argv, "",
                long_options, &option_index);
        if (-1 == c)
            break;

        switch (c) {
        case 'a':
            md = (EVP_MD*)EVP_sm3();
            hash_value_len = 32;
            break;
        case 'b':
            md = (EVP_MD*)EVP_sha256();
            hash_value_len = 32;
            break;
        case 'c':
            md = (EVP_MD*)EVP_sha512();
            hash_value_len = 64;
            break;
        case 'd':
            md = (EVP_MD*)EVP_md5();
            hash_value_len = 16;
        case 'f':
            filename = optarg;
            break;
        case 'h':
            print_info();
            return 0;
        default:
            printf("?? getopt returned character code 0%o ??\n", c);
            print_info();
            return 1;
        }
    }

    if(md == NULL || filename == NULL){
        print_info();
        return 1;
    }

    unsigned char* hash_value = calloc(hash_value_len, 1);
    if(hash_value == NULL){
        printf("calloc failed .");
        return 1;
    }

    hash_file(filename, hash_value, md);
    print_result(hash_value, hash_value_len, filename);
    free(hash_value);
    return 0;
}


int hash_file(const char *file_name, unsigned char *hash, const EVP_MD* md)
{
    int fd;
    ssize_t len;
    unsigned char buf[BUFSIZ];

    if ((fd = open(file_name, O_RDONLY)) < 0)
	{
		printf("open file error\n");
                return -1;
	}

    EVP_MD_CTX * md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, md, NULL);
    while ((len = read(fd, buf, (size_t)BUFSIZ)) > 0)
	{
    	EVP_DigestUpdate(md_ctx, buf, (size_t)len);
    }

    close(fd);
    EVP_DigestFinal_ex(md_ctx, hash, NULL);
    EVP_MD_CTX_free(md_ctx);
    return 0;
}

void print_result(const unsigned char* hash_value, const unsigned int hash_value_len, const char* filename){
    for (int i = 0; i < hash_value_len; i++)
    {
        printf("%02x", hash_value[i]);
    }
    printf("  %s\n", filename);
    return;
}

void print_info()
{
    printf("usage: %s --<opt> --file <filename>\n", __FILE__);
    printf("opt:\n\t--sm3\n\t--sha256\n\t--sha512\n\t--md5\n\t\n");
    printf("\n--help\n");
}
