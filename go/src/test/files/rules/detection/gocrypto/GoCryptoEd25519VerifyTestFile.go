package main

import (
	"crypto/ed25519"
	"crypto/rand"
)

func main() {
	// Generate an Ed25519 key pair
	pub, _, err := ed25519.GenerateKey(rand.Reader) // Noncompliant {{(Signature) Ed25519}}
	if err != nil {
		panic(err)
	}

	// Verify a signature
	var message []byte
	var sig []byte
	valid := ed25519.Verify(pub, message, sig) // Noncompliant {{(Signature) Ed25519}}
	_ = valid
}
