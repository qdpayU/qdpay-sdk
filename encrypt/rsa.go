package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
)

func RSAEncrypt(publicKey string, plainText string) (string, error) {
	publicKeyPEM := fmt.Sprintf(`-----BEGIN PUBLIC KEY-----  
%s  
-----END PUBLIC KEY-----`, publicKey)

	// 解码PEM格式的公钥
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", errors.New("failed to decode PEM block containing the public key")
	}

	// 解析公钥
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", errors.New(fmt.Sprintf("failed to parse DER encoded public key: %v", err))
	}

	// 断言公钥类型为*rsa.PublicKey
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("not a valid RSA public key")
	}

	// 对明文进行PKCS#1 v1.5填充后进行加密
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte(plainText))
	if err != nil {
		log.Fatalf("failed to encrypt message: %v", err)
	}

	// 将加密后的字节转换为Base64字符串，方便打印和传输
	encryptedBase64 := base64.StdEncoding.EncodeToString(encrypted)
	return encryptedBase64, nil
}
