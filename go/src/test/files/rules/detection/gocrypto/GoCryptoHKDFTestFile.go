package main

import (
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
)

func main() {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")

	// HKDF Key derivation
	reader := hkdf.New(sha256.New, secret, salt, info) // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-256}}
	_ = reader
}
