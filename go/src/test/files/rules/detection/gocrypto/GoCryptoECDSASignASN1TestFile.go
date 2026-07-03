package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func main() {
	// Sign the hash using SignASN1
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // Noncompliant {{(Signature) ECDSA-secp256r1}}

	var hash []byte
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash) // Noncompliant {{(Signature) ECDSA-secp256r1}}
	if err != nil {
		panic(err)
	}
	_ = sig
}
