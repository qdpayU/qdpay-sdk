package main

import (
	"github.com/qdpayU/qdpay-sdk/qdpay"
)

func main() {
	client := qdpay.Client{
		BaseUrl:      "",
		MerchantCode: "",
		AppKey:       "",
		AesKey:       "",
		PrivateKey:   "",
	}

	client.SendPostRequest("/test/aop", map[string]string{})

	//log.Println()encrypt.DecryptAESCBC("VwiZM1jGt6S5zDnYP9hsbQ==", "jXRoCCIiYMA+FX6hxLI2uJo6axywgRl5BcxTI/Ljgqilel944wuSbnsrj4zAFgl6")
}
