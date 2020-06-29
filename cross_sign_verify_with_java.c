/**
 * 配合Java代码，交叉签名认证
 * https://github.com/hknarutofk/training/blob/master/src/test/java/com/example/demo/util/CipherUtilTest.java
 * testCrossSignVerify() * 
 */

#include <string.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/md5.h>

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
    unsigned char md5Buffer[16] = {0};
    int md5BufferLen = sizeof(md5Buffer);

    datalen = strlen(data);
    /**
     * 对应Java代码： Signature.getInstance("MD5withRSA")
     * 注意，此处nid不能副值为NID_md5WithRSA
     */
    nid = NID_md5;

    printhexDump(data, datalen);
    MD5(data, datalen, md5Buffer);
    printhexDump(md5Buffer, md5BufferLen);

    bio = BIO_new_file("/home/yeqiang/code/training/key.pk8.pem", "r");
    privateKey = PEM_read_bio_RSAPrivateKey(bio, &privateKey, NULL, NULL);
    printf("%X\n", privateKey);
    RSA_print_fp(stdout, privateKey, 0);
    BIO_free(bio);

    /**
     * 注意！
     * RSA_sign 接口并不会根据nid计算摘要值，需要自己现算好
     * 而Java 对应的Signature类会根据算法计算摘要！
     */
    ret = RSA_sign(nid, md5Buffer, md5BufferLen, signret, &signlen, privateKey);
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
    printf("RSA_sign ok!\n");
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
    unsigned char md5Buffer[16] = {0};
    int md5BufferLen = sizeof(md5Buffer);

    datalen = strlen(data);
    nid = NID_md5;

    printhexDump(data, datalen);
    MD5(data, datalen, md5Buffer);
    printhexDump(md5Buffer, md5BufferLen);

    bio = BIO_new_file("/home/yeqiang/code/training/pubkey.x509.pem", "r");
    publicKey = PEM_read_bio_RSA_PUBKEY(bio, &publicKey, NULL, NULL);
    printf("%X\n", publicKey);
    RSA_print_fp(stdout, publicKey, 0);
    BIO_free(bio);

    //读取Java生成的签名文件
    bio = BIO_new_file("/tmp/java_sign.bin", "r");
    signlen = BIO_read(bio, signret, 1024);
    printhexDump(signret, signlen);
    ret = RSA_verify(nid, md5Buffer, md5BufferLen, signret, signlen, publicKey);
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
    verify();
}