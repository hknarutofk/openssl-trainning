#include <string.h>
#include <openssl/bio.h>
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

int md5_small_data()
{

    unsigned char *data = "1cfdde231dbc13b3bfdbc0c6430da839";
    unsigned char md5Buffer[16] = {0};
    int md5BufferLen = sizeof(md5Buffer), datalen = strlen(data);

    printhexDump(data, datalen);
    MD5(data, datalen, md5Buffer);
    printhexDump(md5Buffer, md5BufferLen);

    return 0;
}

int md5_big_data()
{
    BIO *bio;
    unsigned char data[1024];
    unsigned char md5Buffer[16] = {0};
    int md5BufferLen = sizeof(md5Buffer), datalen = sizeof(data);
    MD5_CTX md5ctx;
    /*
     * 自行用脚本生成一个大文件
     * dd if=/dev/urandom of=/tmp/big.data bs=1M count=1024
     */
    bio = BIO_new_file("/tmp/big.data", "r");

    if (!MD5_Init(&md5ctx))
    {
        printf("error init!\n");
        return 1;
    }

    int r = 0;
    while ((r = BIO_read(bio, data, datalen)) > 0)
    {
        // printhexDump(data, r);
        MD5_Update(&md5ctx, data, r);
    }
    MD5_Final(md5Buffer, &md5ctx);

    printhexDump(md5Buffer, md5BufferLen);

    BIO_free(bio);

    return 0;
}

int main()
{
    md5_small_data();
    md5_big_data();
}