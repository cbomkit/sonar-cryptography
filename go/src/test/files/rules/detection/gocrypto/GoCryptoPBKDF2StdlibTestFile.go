package main

import (
	"crypto/pbkdf2"
	"crypto/sha256"
)

func main() {
	salt := make([]byte, 16)

	// PBKDF2 Key derivation using stdlib API (Go 1.24+)
	key, err := pbkdf2.Key(sha256.New, "password", salt, 600000, 32) // Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2-SHA256}}
	if err != nil {
		panic(err)
	}

	_ = key
}
