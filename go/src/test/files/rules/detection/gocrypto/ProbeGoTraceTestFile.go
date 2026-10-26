package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func main() {
	decoyKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)   // Noncompliant {{(Signature) ECDSA-secp521r1}}
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // Noncompliant {{(Signature) ECDSA-secp256r1}}

	var hash []byte
	sig, _ := ecdsa.SignASN1(rand.Reader, privateKey, hash)          // Noncompliant {{(Signature) ECDSA-secp256r1}}
	_ = sig
	_ = decoyKey
}
