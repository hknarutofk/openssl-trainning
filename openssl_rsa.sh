#生成明文私钥文件:
openssl genrsa -out key.pem
openssl asn1parse -inform PEM -in key.pem 
# 转换为 DER 编码:
openssl rsa -in key.pem -outform der -out key.der
# 将明文私钥文件转换为密码保护:
openssl rsa -inform der -in key.der -des3 -out enckey.pem
# 将公钥写入文件:
openssl rsa -in key.pem -pubout -out pubkey.pem
# 打印公钥信息:
openssl rsa -pubin -in pubkey.pem -text -modulus
#显示私钥信息
openssl rsa -in enckey.pem 

echo "data" > data.txt

# 签名
openssl rsautl -sign -inkey key.pem -in data.txt -out sig.dat

openssl rsautl -verify -inkey key.pem -in sig.dat


# 导出Java可识别的PKCS#8 der 格式私钥
openssl pkcs8 -topk8 -in key.pem -out key.pk8.der -nocrypt -outform der
# 导出Java可识别的X509 der格式公钥
openssl rsa -in key.pem -pubout -out pubkey.x509.der -outform der