package main

import (
	"crypto/ed25519"
	"crypto/rand"
)

func main() {
	// GenerateKey - generates a public/private key pair
	_, _, err := ed25519.GenerateKey(rand.Reader) // Noncompliant {{(Signature) Ed25519}}
	if err != nil {
		panic(err)
	}

	// NewKeyFromSeed - creates a private key from seed
	seed := make([]byte, ed25519.SeedSize)
	_ = ed25519.NewKeyFromSeed(seed) // Noncompliant {{(Signature) Ed25519}}
}
