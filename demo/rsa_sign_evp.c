#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "comm.h"

static const char* PRIVATE_KEY_FILE = "/tmp/test/pri.tmp1";
static const char* PUBLIC_KEY_FILE =  "/tmp/test/pub.tmp2";

static char* msg = "hello world !";

const char* RSA_PRIKEY_PSW = "123";
size_t slen;

// 私钥签名
unsigned char* signing(EVP_PKEY* key)
{
	EVP_MD_CTX* mdctx = EVP_MD_CTX_create();

	EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key);

	EVP_DigestSignUpdate(mdctx, msg, strlen(msg));

	EVP_DigestSignFinal(mdctx, NULL, &slen);

	unsigned char* sig = calloc(slen, 1);	
	EVP_DigestSignFinal(mdctx, sig, &slen);

	EVP_MD_CTX_free(mdctx);
	return sig;
}

// 公钥验证
int verifying(EVP_PKEY* key, const unsigned char* sig)
{
	EVP_MD_CTX* mdctx = EVP_MD_CTX_create();

	EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, key);

	EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg));

	if (1 == EVP_DigestVerifyFinal(mdctx, sig, slen))
	{
		printf("true\n");
	}else
	{
		printf("failed\n");
	}
	EVP_MD_CTX_free(mdctx);
	return 0;
}


int main(int argc, char **argv)
{
	// 生成公钥和私钥文件
	generate_key_files(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE,
		(unsigned char*)RSA_PRIKEY_PSW);

	EVP_PKEY *pri_key = open_private_key(PRIVATE_KEY_FILE);
	
	unsigned char* sig;
	sig = signing(pri_key);

	EVP_PKEY *pub_key = open_public_key(PUBLIC_KEY_FILE);
	verifying(pub_key, sig);

	free(sig);
	EVP_PKEY_free(pub_key);
	EVP_PKEY_free(pri_key);
	return 0;
}
