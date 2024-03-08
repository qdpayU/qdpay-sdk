package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// pkcs5Unpadding
func pkcs5Unpadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("invalid padding")
	}
	return src[:(length - unpadding)], nil
}

func DecryptAESCBC(keyBase64 string, cipherstring string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", err
	}

	// 确保密钥长度是16字节（对于AES-128）
	if len(key) != 16 {
		panic("invalid key size for AES-128")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Base64解码密文
	ciphertext, err := base64.StdEncoding.DecodeString(cipherstring)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// 去除PKCS#5填充
	plaintext, err := pkcs5Unpadding(ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// pkcs7Padding appends the PKCS#7 padding to a slice of bytes.
func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// pkcs7Unpadding removes the PKCS#7 padding from a slice of bytes.
func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])

	if unpadding > length {
		return nil, fmt.Errorf("crypto/cipher: input is not padded correctly")
	}

	return data[:(length - unpadding)], nil
}

func EncryptAESCBC(keyBase64, plaintext string) (string, error) {
	// Decode Base64 key
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", err
	}

	// Check the key size
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("invalid AES key size: %d bytes", len(key))
	}

	// Create the cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a random Initialization Vector (IV)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// PKCS#7 Padding
	paddedPlaintext := pkcs7Padding([]byte(plaintext), block.BlockSize())

	// Create the CBC encrypter
	mode := cipher.NewCBCEncrypter(block, iv)

	// Create the ciphertext buffer with space for the IV
	ciphertext := make([]byte, aes.BlockSize+len(paddedPlaintext))

	// Copy the IV into the buffer
	copy(ciphertext[:aes.BlockSize], iv)

	// Encrypt the padded plaintext
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedPlaintext)

	// Encode the ciphertext to Base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
