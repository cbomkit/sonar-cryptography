package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func main() {
	// Verify the signature using VerifyASN1
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // Noncompliant {{(Signature) ECDSA}}
	if err != nil {
		panic(err)
	}

	var publicKey = &privateKey.PublicKey

	var hash []byte
	var sig []byte
	valid := ecdsa.VerifyASN1(publicKey, hash, sig) // Noncompliant {{(Signature) ECDSA}}
	_ = valid
}
