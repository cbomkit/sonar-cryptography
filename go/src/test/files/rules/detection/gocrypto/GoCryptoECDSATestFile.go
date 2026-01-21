package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func main() {
	// Generate an ECDSA key pair using P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // Noncompliant {{(Signature) ECDSA}}
	if err != nil {
		panic(err)
	}
	_ = privateKey
}
