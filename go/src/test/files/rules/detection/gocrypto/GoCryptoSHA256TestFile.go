package main

import (
	"crypto/sha256"
	"fmt"
)

func main() {
	// Test sha256.New() - SHA-256
	h := sha256.New() // Noncompliant {{(MessageDigest) SHA256}}
	h.Write([]byte("hello"))
	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Test sha256.New224() - SHA-224
	h224 := sha256.New224() // Noncompliant {{(MessageDigest) SHA224}}
	h224.Write([]byte("hello"))
	sum224 := h224.Sum(nil)
	fmt.Printf("%x\n", sum224)

	// Test sha256.Sum256() - SHA-256
	sum256 := sha256.Sum256([]byte("data")) // Noncompliant {{(MessageDigest) SHA256}}
	_ = sum256

	// Test sha256.Sum224() - SHA-224
	sum224Direct := sha256.Sum224([]byte("data")) // Noncompliant {{(MessageDigest) SHA224}}
	_ = sum224Direct
}
