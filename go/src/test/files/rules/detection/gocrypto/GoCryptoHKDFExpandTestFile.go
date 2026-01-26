package main

import (
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
)

func main() {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")

	// HKDF Extract step
	prk := hkdf.Extract(sha256.New, secret, salt)

	// HKDF Expand step
	reader := hkdf.Expand(sha256.New, prk, info, 32) // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-256}}
	_ = reader
}
