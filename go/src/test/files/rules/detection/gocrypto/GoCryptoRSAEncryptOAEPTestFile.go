package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func main() {
	// Generate a 2048-bit RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // Noncompliant {{(PublicKeyEncryption) RSA-2048}}
	if err != nil {
		panic(err)
	}

	var pub = &privateKey.PublicKey

	// Encrypt with RSA-OAEP using SHA-256
	ciphertext, err2 := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte("hello"), nil) // Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}
	if err2 != nil {
		panic(err2)
	}
	_ = ciphertext
}
