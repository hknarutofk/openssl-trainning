#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

void printhexDump(const char *buffer, size_t len)
{
    if (buffer == NULL || len <= 0)
    {
        return;
    }
    printf("0x%x: [", buffer);
    for (size_t i = 0; i < len; i++)
    {
        printf("%.2X ", (unsigned char)buffer[i]);
    }
    printf("]\n");
}

void main()
{
    RSA *rsa_publickey = NULL;
    BIO *bio = NULL;
    char buffer[1024];
    int len = 0;

    bio = BIO_new_file("/home/yeqiang/code/training/pubkey.pem", "r");
    // PEM_read_RSA_PUBKEY() reads the PEM format. PEM_read_RSAPublicKey() reads the PKCS#1
    rsa_publickey = PEM_read_bio_RSA_PUBKEY(bio, &rsa_publickey, NULL, NULL);
    printf("%X\n", rsa_publickey);

    RSA_print_fp(stdout, rsa_publickey, 0);

    BIO_free(bio);
}