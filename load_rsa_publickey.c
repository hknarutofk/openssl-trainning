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

    //加载方式2，字符串输入
    char *pubString = "-----BEGIN PUBLIC KEY-----\n"
                      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3/mncP8WG/w9X9X2L0qs\n"
                      "Pni0o1D8DGGPrDprwJXiYvm/wp+UpIQo9IMP2TxO4CRRC86Bsu8gjfZeViqz8qio\n"
                      "FXMB6ujnvqWDgJNAqwKzh+Q6SdxWkYZZfTUCEOh2OkjGSSsgdOF+ZVV9XiZrUcTb\n"
                      "XpTxE4eW5AG2Ii9bDK4AkKrDwOwb6IozuA4EGZPQg8EN0FzgycfYX4n40REzt68P\n"
                      "w/hZS9BbX2dPUYgJGLqghoiuQk5IRdvZx3oysvm41qZgZkrbar0gccyMXIoX61FA\n"
                      "78yzlyhcSwUsbkB1CO54iywiY2SoCkA3/e9ZoQdoHDjpIlLwAUz8eH71hB1QWjDG\n"
                      "dQIDAQAB\n"
                      "-----END PUBLIC KEY-----";
    int pubStringLen = strlen(pubString);
    bio = BIO_new_mem_buf(pubString, pubStringLen);
    rsa_publickey = PEM_read_bio_RSA_PUBKEY(bio, &rsa_publickey, NULL, NULL);
    printf("%X\n", rsa_publickey);
    RSA_print_fp(stdout, rsa_publickey, 0);
    BIO_free(bio);
    printf("zzzzzzzzzzzzzz\n");
}