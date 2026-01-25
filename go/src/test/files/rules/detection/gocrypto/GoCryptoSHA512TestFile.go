package main

import (
	"crypto/sha512"
	"fmt"
)

func main() {
	// Test sha512.New() - SHA-512
	h := sha512.New() // Noncompliant {{(MessageDigest) SHA-512}}
	h.Write([]byte("hello"))
	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Test sha512.New384() - SHA-384
	h384 := sha512.New384() // Noncompliant {{(MessageDigest) SHA-384}}
	h384.Write([]byte("hello"))
	sum384 := h384.Sum(nil)
	fmt.Printf("%x\n", sum384)

	// Test sha512.Sum512() - SHA-512
	sum512 := sha512.Sum512([]byte("data")) // Noncompliant {{(MessageDigest) SHA-512}}
	_ = sum512

	// Test sha512.Sum384() - SHA-384
	sum384Direct := sha512.Sum384([]byte("data")) // Noncompliant {{(MessageDigest) SHA-384}}
	_ = sum384Direct
}
