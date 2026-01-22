package main

import (
	"crypto/ecdh"
)

func main() {
	// Test NewPublicKey with X25519 curve
	curve := ecdh.X25519() // Noncompliant {{(KeyAgreement) ECDH}}

	// Create a public key from raw bytes (32 bytes for X25519)
	publicKeyBytes := make([]byte, 32)
	publicKey, err := curve.NewPublicKey(publicKeyBytes) // Noncompliant {{(KeyAgreement) ECDH}}
	if err != nil {
		panic(err)
	}

	_ = publicKey
}
