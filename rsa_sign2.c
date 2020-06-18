#include <string.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

void printhexDump(const char *buffer, size_t len)
{
    if (buffer == NULL || len <= 0)
    {
        return;
    }
    printf("0x%x: (len=%d)[", buffer, len);
    for (size_t i = 0; i < len; i++)
    {
        printf("%.2X ", (unsigned char)buffer[i]);
    }
    printf("]\n");
}

/**
 * 从磁盘加载openssl生成的公私密钥对签名，验证签名
 */
int main()
{
    int ret;
    RSA *privateKey = NULL, *publicKey = NULL;
    int i, bits = 1024, signlen, datalen, alg, nid;
    unsigned long e = RSA_3;
    unsigned char data[64], signret[1024];
    BIO *bio, *bio2;

    datalen = sizeof(data);
    nid = NID_md5;
    for (int i = 0; i < sizeof(data); i++)
    {
        data[i] = (unsigned char)i;
    }

    bio = BIO_new_file("/home/yeqiang/code/training/key.pem", "r");
    privateKey = PEM_read_bio_RSAPrivateKey(bio, &privateKey, NULL, NULL);
    printf("%X\n", privateKey);
    RSA_print_fp(stdout, privateKey, 0);
    BIO_free(bio);

    bio2 = BIO_new_file("/home/yeqiang/code/training/pubkey.pem", "r");
    publicKey = PEM_read_bio_RSA_PUBKEY(bio2, &publicKey, NULL, NULL);
    printf("%X\n", publicKey);
    RSA_print_fp(stdout, publicKey, 0);
    BIO_free(bio2);

    ret = RSA_sign(nid, data, datalen, signret, &signlen, privateKey);
    if (ret != 1)
    {
        printf("RSA_sign err!\n");
        RSA_free(privateKey);
        return -1;
    }
    printhexDump(signret, signlen);
    ret = RSA_verify(nid, data, datalen, signret, signlen, publicKey);
    if (ret != 1)
    {
        printf("RSA_verify err!\n");
        RSA_free(publicKey);
        return -1;
    }
    RSA_free(privateKey);
    RSA_free(publicKey);
    printf("test ok!\n");
    return 0;
}