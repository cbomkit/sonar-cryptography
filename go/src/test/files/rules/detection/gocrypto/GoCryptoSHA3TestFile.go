package main

import (
	"golang.org/x/crypto/sha3"
)

func main() {
	// SHA3-256 hash
	h256 := sha3.New256() // Noncompliant {{(MessageDigest) SHA-3-256}}
	h256.Write([]byte("test"))
	_ = h256.Sum(nil)

	// SHA3-512 hash
	h512 := sha3.New512() // Noncompliant {{(MessageDigest) SHA-3-512}}
	_ = h512

	// Sum256 - direct hash computation
	hash := sha3.Sum256([]byte("test")) // Noncompliant {{(MessageDigest) SHA-3-256}}
	_ = hash
}
