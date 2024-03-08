package encrypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func HmacSha256(key string, content string) string {
	// 密钥和消息
	secretKey := []byte(key)
	message := []byte(content)

	// 创建一个新的HMAC，使用SHA256作为哈希函数
	h := hmac.New(sha256.New, secretKey)
	h.Write(message)
	hmacSum := h.Sum(nil)

	hmacHex := hex.EncodeToString(hmacSum)

	return hmacHex
}
