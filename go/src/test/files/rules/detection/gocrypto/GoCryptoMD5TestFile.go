package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	h := md5.New() // Noncompliant {{(MessageDigest) MD5}}
	h.Write([]byte("hello"))
	sum := h.Sum(nil)
	fmt.Printf("%x\n", sum)

	// Also test md5.Sum directly
	checksum := md5.Sum([]byte("data")) // Noncompliant {{(MessageDigest) MD5}}
	fmt.Printf("%x\n", checksum)
}
