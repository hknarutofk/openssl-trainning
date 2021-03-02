#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

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

int main()
{
    unsigned char key[32] = "12345678901234567890123456789012";
    unsigned char *rawData = "12345678901234561234567890123456";
    int rawDataLen = strlen(rawData);
    int encLen = 0;
    int outLen = 0;

    //明文密文长度关系 https://www.cnblogs.com/lori/archive/2020/12/30/14210066.html
    //预计的密文长度
    int encDataLen = (rawDataLen / 16 + 1) * 16;
    unsigned char *encData = (unsigned char *)malloc(encDataLen);
    printf("%s\n", rawData);
    printf("%d\n", encDataLen);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL, AES_ENCRYPT);
    EVP_CipherUpdate(ctx, encData, &outLen, rawData, rawDataLen);
    encLen = outLen;
    printf("%d\n", encLen);
    EVP_CipherFinal(ctx, encData + outLen, &outLen);
    encLen += outLen;
    //实际密文长度
    printf("%d\n", encLen);
    EVP_CIPHER_CTX_free(ctx);
    printhexDump(encData, encLen);

    //
    int decLen = 0;
    int outlen = 0;
    // 明文长度<=密文长度，解密缓冲区可以直接取密文长度
    unsigned char *decData = (unsigned char *)malloc(encLen);
    EVP_CIPHER_CTX *ctx2;
    ctx2 = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx2, EVP_aes_256_ecb(), NULL, key, NULL, AES_DECRYPT);
    EVP_CipherUpdate(ctx2, decData, &outlen, encData, encLen);
    decLen = outlen;
    EVP_CipherFinal(ctx2, decData + outlen, &outlen);
    decLen += outlen;
    EVP_CIPHER_CTX_free(ctx2);

    decData[decLen] = '\0';
    printf("decrypt: %s\n", decData);

    free(encData);
    free(decData);
    return 0;
}

/**
 Crypto.js

 <script type="text/javascript" src="crypto-js.js"></script>
 <script type="text/javascript">
  // Encrypt
        var ciphertext = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse('123456'), CryptoJS.enc.Utf8.parse('12345678901234567890123456789012'), { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString();
        console.log(ciphertext);
        // Decrypt        
        var bytes = CryptoJS.AES.decrypt(ciphertext, CryptoJS.enc.Utf8.parse('12345678901234567890123456789012'), { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
        var originalText = bytes.toString(CryptoJS.enc.Utf8);
        console.log(originalText); 
  </script>
 */

/**
 * Java
    public static byte[] AES_256_ecb_encrypt(byte[] input, byte[] byteKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKey key = new SecretKeySpec(byteKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(input);
        return encrypted;
    }

    public static byte[] AES_256_ecb_decrypt(byte[] input, byte[] byteKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKey key = new SecretKeySpec(byteKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(input);
        return decrypted;
    }
 */