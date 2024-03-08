package main

import (
	"github.com/qdpayU/qdpay-sdk/qdpay"
	"log"
)

func main() {
	client := qdpay.Client{
		BaseUrl:      "",
		MerchantCode: "",
		AppKey:       "",
		AesKey:       "",
		PrivateKey:   "",
	}

	log.Println(client.SendPostRequest("/test/aop", map[string]string{
		"username": "zhouhuajian",
	}))

	//log.Println()encrypt.DecryptAESCBC("VwiZM1jGt6S5zDnYP9hsbQ==", "jXRoCCIiYMA+FX6hxLI2uJo6axywgRl5BcxTI/Ljgqilel944wuSbnsrj4zAFgl6")
}
