package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	// Generate a 2048-bit RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // Noncompliant {{(PublicKeyEncryption) RSA-2048}}
	if err != nil {
		panic(err)
	}

	var priv = privateKey

	hashed := []byte("hash of message that is 32 bytes")

	// Sign with RSA PKCS#1 v1.5 using SHA-256
	sig, err2 := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed) // Noncompliant {{(Signature) RSA}}
	if err2 != nil {
		panic(err2)
	}
	_ = sig
}
