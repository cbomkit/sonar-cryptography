package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func main() {
	// Generate a random 32-byte key (AES-256)
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	// Create a new AES cipher block - this should be detected
	block, err := aes.NewCipher(key) // Noncompliant {{(BlockCipher) AES}}
	if err != nil {
		panic(err)
	}

	// Create a GCM mode cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// Example plaintext
	plaintext := []byte("Hello, World!")

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	_ = ciphertext
}
