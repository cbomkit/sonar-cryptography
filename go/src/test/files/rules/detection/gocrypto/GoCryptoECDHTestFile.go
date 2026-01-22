package main

import (
	"crypto/ecdh"
	"crypto/rand"
)

func main() {
	// Get the P256 curve
	curve := ecdh.P256() // Noncompliant {{(KeyAgreement) ECDH}}

	// Generate a key pair
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	_ = privateKey
}
