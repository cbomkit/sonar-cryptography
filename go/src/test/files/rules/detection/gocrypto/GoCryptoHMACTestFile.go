package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func main() {
	key := []byte("secret-key")
	h := hmac.New(sha256.New, key) // Noncompliant {{(Mac) HMAC-SHA256}}
	h.Write([]byte("hello"))
	fmt.Printf("%x\n", h.Sum(nil))
}
