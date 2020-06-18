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
 * 生成签名文件，丢给java验证签名
 */
int sign()
{
    int ret;
    RSA *privateKey = NULL;
    int i, bits = 1024, signlen, datalen, alg, nid;
    unsigned long e = RSA_3;
    unsigned char *data = "1cfdde231dbc13b3bfdbc0c6430da839", signret[1024];
    BIO *bio;

    datalen = sizeof(data);
    nid = NID_md5;

    bio = BIO_new_file("/home/yeqiang/code/training/key.pem", "r");
    privateKey = PEM_read_bio_RSAPrivateKey(bio, &privateKey, NULL, NULL);
    printf("%X\n", privateKey);
    RSA_print_fp(stdout, privateKey, 0);
    BIO_free(bio);

    ret = RSA_sign(nid, data, datalen, signret, &signlen, privateKey);
    if (ret != 1)
    {
        printf("RSA_sign err!\n");
        RSA_free(privateKey);
        return -1;
    }
    printhexDump(signret, signlen);
    // 签名值输出到文件
    bio = BIO_new_file("/tmp/c_sign.bin", "w");
    BIO_write(bio, signret, signlen);
    BIO_free(bio);

    RSA_free(privateKey);
    printf("RSA_verify ok!\n");
    return 0;
}

/**
 * 读取java生成的签名文件， c验证签名
 */
int verify()
{
    int ret;
    RSA *publicKey = NULL;
    int i, bits = 1024, signlen, datalen, alg, nid;
    unsigned long e = RSA_3;
    unsigned char *data = "1cfdde231dbc13b3bfdbc0c6430da839", signret[1024];
    BIO *bio;

    datalen = sizeof(data);
    nid = NID_md5;

    bio = BIO_new_file("/home/yeqiang/code/training/pubkey.pem", "r");
    publicKey = PEM_read_bio_RSA_PUBKEY(bio, &publicKey, NULL, NULL);
    printf("%X\n", publicKey);
    RSA_print_fp(stdout, publicKey, 0);
    BIO_free(bio);

    //读取Java生成的签名文件
    bio = BIO_new_file("/tmp/java_sign.bin", "r");
    signlen = BIO_read(bio, signret, 1024);
    printhexDump(signret, signlen);
    ret = RSA_verify(nid, data, datalen, signret, signlen, publicKey);
    if (ret != 1)
    {
        printf("RSA_verify err!\n");
        RSA_free(publicKey);
        return -1;
    }
    RSA_free(publicKey);
    printf("RSA_verify ok!\n");
    return 0;
}

/**
 * 与Java程序交叉签名验证签名测试，采用openssl生成的RSA密钥对
 */
int main()
{
    sign();
}