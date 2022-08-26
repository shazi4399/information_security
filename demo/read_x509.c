#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test(const char* file)
{
    FILE* fpub = fopen(file, "r");
    if (fpub == NULL) {
        printf("fopen %s failed.\n", file);
        goto clean;
    }

    X509* x = X509_new();
    PEM_read_X509(fpub, &x, NULL, NULL);

    printf("version= %ld\n", X509_get_version(x));
    printf("seriaNumber= ");
    for (int i = 0; i < (X509_get0_serialNumber(x)->length); i++) {
        printf("%2X", (X509_get0_serialNumber(x)->data)[i]);
    }
    printf("\nemail=%s\n", (char*)X509_get1_email(x));
    printf("issuer_name= %s\n",
           X509_NAME_oneline(X509_get_issuer_name(x), 0, 0));
    printf("subject_name= %s\n",
           X509_NAME_oneline(X509_get_subject_name(x), 0, 0));
    printf("notBefore= %s\n", X509_getm_notBefore(x)->data);
    printf("notAfter= %s\n", X509_get0_notAfter(x)->data);
    printf("signature_type= %d\n", X509_get_signature_type(x));

    int j;
    unsigned int n;
    unsigned char md[EVP_MAX_MD_SIZE];
    const EVP_MD* fdig = EVP_sha1();
    X509_digest(x, fdig, md, &n);
    printf("Fingerprint= ");
    for (j = 0; j < (int)n; j++) {
        printf("%02X", md[j]);
    }
    printf("\n");

    printf("\n");
    X509_free(x);
clean:
    fclose(fpub);
}

void test1(const char* file)
{
    FILE* fpub = fopen(file, "r");
    if (fpub == NULL) {
        printf("fopen %s failed.\n", file);
        goto clean;
    }

    X509_REQ* x = X509_REQ_new();
    PEM_read_X509_REQ(fpub, &x, NULL, NULL);
    printf("version= %ld\n", X509_REQ_get_version(x));
    printf("subject_name= %s\n",
           X509_NAME_oneline(X509_REQ_get_subject_name(x), 0, 0));

clean:
    X509_REQ_free(x);
    fclose(fpub);
}

int main(int argc, char const* argv[])
{
    const char* pubkey_file = "../keys/pubcert_user.pem";
    test(pubkey_file);
    // test1(pubkey_file);
    return 0;
}
