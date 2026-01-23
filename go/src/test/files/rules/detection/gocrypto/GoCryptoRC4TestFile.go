package main

import (
	"crypto/rc4"
)

func main() {
	key := make([]byte, 16)

	// Create a new RC4 cipher with a 128-bit key
	cipher, err := rc4.NewCipher(key) // Noncompliant {{(StreamCipher) RC4}}
	if err != nil {
		panic(err)
	}

	// Encrypt data using XOR key stream
	src := []byte("plaintext")
	dst := make([]byte, len(src))
	cipher.XORKeyStream(dst, src)
}
