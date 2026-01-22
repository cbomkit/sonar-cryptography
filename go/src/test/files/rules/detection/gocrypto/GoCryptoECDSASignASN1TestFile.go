package main

import (
	"crypto/ecdsa"
	"crypto/rand"
)

func main() {
	// Sign the hash using SignASN1
	var privateKey *ecdsa.PrivateKey
	var hash []byte
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash) // Noncompliant {{(Signature) ECDSA}}
	if err != nil {
		panic(err)
	}
	_ = sig
}
