package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// AES-GCM Decryption with custom nonce size
func AesGcmDecrypt(cipherText, cek, nonce, authTag, aad []byte) ([]byte, error) {
	cipherTextWithAuthTag := append(cipherText, authTag...)

	block, err := aes.NewCipher(cek) // Noncompliant {{(AuthenticatedEncryption) AES-GCM}}
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, err
	}
	plainText, err := aesgcm.Open(nil, nonce, cipherTextWithAuthTag, aad)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

// AES-GCM Encryption with custom nonce size
func AesGcmEncrypt(plainText, cek, nonce, aad []byte) ([]byte, []byte, error) {
	_len := len(plainText)
	block, err := aes.NewCipher(cek) // Noncompliant {{(AuthenticatedEncryption) AES-GCM}}
	if err != nil {
		return nil, nil, err
	}

	aesGcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, nil, err
	}

	cipherText := aesGcm.Seal(nil, nonce, plainText, aad)
	return cipherText[:_len], cipherText[_len:], nil
}
