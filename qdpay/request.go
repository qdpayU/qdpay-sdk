package qdpay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/qdpayU/qdpay-sdk/encrypt"
	"io/ioutil"
	"log"
	mathRand "math/rand"
	"net/http"
	"time"
)

type Client struct {
	BaseUrl      string
	MerchantCode string
	AesKey       string
	AppKey       string
	PrivateKey   string
}

// 构建请求头中的Authentication字段
func (c Client) buildAuthentication(timestamp int64, nonce string) (string, error) {
	signature := encrypt.HmacSha256(c.AppKey, fmt.Sprintf("%d.%s", timestamp, nonce))
	authData := map[string]interface{}{
		"timestamp": timestamp,
		"nonce":     nonce,
		"signature": signature,
	}
	authJSON, err := json.Marshal(authData)
	if err != nil {
		return "", err
	}

	log.Println("header body: " + string(authJSON))

	return encrypt.EncryptAESCBC(c.AesKey, string(authJSON))
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(length int) string {
	b := make([]byte, length)
	// 为rand.NewSource提供种子值，通常是当前时间
	mathRand.Seed(time.Now().UnixNano())
	// 生成指定长度的随机字节切片
	for i := range b {
		b[i] = charset[mathRand.Intn(len(charset))]
	}
	return string(b)
}

// 发送POST请求
func (c Client) SendPostRequest(url string, payload interface{}) (string, error) {
	timestamp := time.Now().UnixMilli()
	nonce := randomString(32)
	auth, err := c.buildAuthentication(timestamp, nonce)
	if err != nil {
		return "", err
	}

	// 加密请求体
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encryptedPayloadBase64, err := encrypt.EncryptAESCBC(c.AesKey, string(payloadBytes))
	if err != nil {
		return "", err
	}

	payloadRequest := map[string]string{
		"payload": encryptedPayloadBase64,
	}
	payloadRequestBytes, err := json.Marshal(payloadRequest)
	if err != nil {
		return "", err
	}

	log.Println("Request Header: " + c.MerchantCode + ", Authentication: " + auth)
	log.Println("Request Body: " + string(payloadRequestBytes))
	// 创建请求体
	body := bytes.NewBufferString(string(payloadRequestBytes))

	// 创建请求
	req, err := http.NewRequest("POST", c.BaseUrl+url, body)
	if err != nil {
		return "", err
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MerchantCode", c.MerchantCode)
	req.Header.Set("Authentication", auth)
	// 其他必要的请求头设置...

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 读取响应体
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var payloadResponse map[string]string
	err = json.Unmarshal(respBody, &payloadResponse)
	if err != nil {
		return "", err
	}

	if payloadResponse["errorCode"] != "" {
		return "", errors.New(payloadResponse["errorMessage"])
	}
	//return "", err
	result, err := encrypt.DecryptAESCBC(c.AesKey, payloadResponse["payload"])
	if err != nil {
		return "", err
	}
	return result, nil
}
