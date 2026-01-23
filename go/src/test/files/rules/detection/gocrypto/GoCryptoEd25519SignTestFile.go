package main

import (
	"crypto/ed25519"
	"crypto/rand"
)

func main() {
	// Generate an Ed25519 key pair
	_, priv, err := ed25519.GenerateKey(rand.Reader) // Noncompliant {{(Signature) Ed25519}}
	if err != nil {
		panic(err)
	}

	// Sign a message
	message := []byte("test message")
	sig := ed25519.Sign(priv, message) // Noncompliant {{(Signature) Ed25519}}
	_ = sig
}
