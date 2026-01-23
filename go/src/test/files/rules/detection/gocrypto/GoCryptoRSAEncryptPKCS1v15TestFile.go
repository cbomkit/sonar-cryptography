package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	// Generate a 2048-bit RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // Noncompliant {{(PublicKeyEncryption) RSA-2048}}
	if err != nil {
		panic(err)
	}

	var pub = &privateKey.PublicKey

	// Encrypt with RSA PKCS#1 v1.5
	ciphertext, err2 := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte("hello")) // Noncompliant {{(PublicKeyEncryption) RSA-2048}}
	if err2 != nil {
		panic(err2)
	}
	_ = ciphertext
}
