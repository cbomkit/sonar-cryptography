package main

import (
	"crypto/ecdsa"
)

func main() {
	// Verify the signature using VerifyASN1
	var publicKey *ecdsa.PublicKey
	var hash []byte
	var sig []byte
	valid := ecdsa.VerifyASN1(publicKey, hash, sig) // Noncompliant {{(Signature) ECDSA}}
	_ = valid
}
