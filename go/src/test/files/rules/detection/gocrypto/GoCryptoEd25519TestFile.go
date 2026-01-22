package main

import (
	"crypto/ed25519"
	"crypto/rand"
)

func main() {
	// GenerateKey - generates a public/private key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader) // Noncompliant {{(Signature) Ed25519}}
	if err != nil {
		panic(err)
	}

	// Sign - signs a message
	message := []byte("test message")
	sig := ed25519.Sign(priv, message) // Noncompliant {{(Signature) Ed25519}}

	// Verify - verifies a signature
	valid := ed25519.Verify(pub, message, sig) // Noncompliant {{(Signature) Ed25519}}
	_ = valid
}
