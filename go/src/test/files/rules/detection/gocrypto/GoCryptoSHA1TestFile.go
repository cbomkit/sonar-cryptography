package main

import (
	"crypto/sha1"
	"fmt"
)

func main() {
	h := sha1.New() // Noncompliant {{(MessageDigest) SHA1}}
	h.Write([]byte("hello"))
	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Also test sha1.Sum directly
	checksum := sha1.Sum([]byte("data")) // Noncompliant {{(MessageDigest) SHA1}}
	fmt.Printf("%x\n", checksum)
}
