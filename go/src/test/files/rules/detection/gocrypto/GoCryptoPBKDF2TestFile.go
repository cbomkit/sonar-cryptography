package main

import (
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

func main() {
	password := []byte("password")
	salt := []byte("salt")
	iterations := 10000
	keyLen := 32

	// PBKDF2 Key derivation
	key := pbkdf2.Key(password, salt, iterations, keyLen, sha256.New) // Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2}}
	_ = key
}
