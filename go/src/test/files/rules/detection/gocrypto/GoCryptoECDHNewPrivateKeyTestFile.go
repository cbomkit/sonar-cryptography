package main

import (
	"crypto/ecdh"
)

func main() {
	// Test NewPrivateKey with P256 curve
	curve := ecdh.P256() // Noncompliant {{(KeyAgreement) ECDH}}

	// Create a private key from raw bytes (32 bytes for P256)
	privateKeyBytes := make([]byte, 32)
	privateKey, err := curve.NewPrivateKey(privateKeyBytes)
	if err != nil {
		panic(err)
	}

	_ = privateKey
}
