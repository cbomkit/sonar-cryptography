package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	// Generate a 2048-bit RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // Noncompliant {{(PublicKeyEncryption) RSA}}
	if err != nil {
		panic(err)
	}
	_ = privateKey
}
