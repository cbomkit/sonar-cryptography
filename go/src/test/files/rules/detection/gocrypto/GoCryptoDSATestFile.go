package main

import (
	"crypto/dsa"
	"crypto/rand"
)

func main() {
	// Generate DSA parameters with L2048N256 size
	params := new(dsa.Parameters)
	err := dsa.GenerateParameters(params, rand.Reader, dsa.L2048N256) // Noncompliant {{(Signature) DSA}}
	if err != nil {
		panic(err)
	}

	// Generate a DSA key pair
	privateKey := new(dsa.PrivateKey)
	privateKey.Parameters = *params
	err = dsa.GenerateKey(privateKey, rand.Reader) // Noncompliant {{(Signature) DSA}}
	if err != nil {
		panic(err)
	}

	// Sign a hash
	hash := []byte("test message hash")
	r, s, err := dsa.Sign(rand.Reader, privateKey, hash) // Noncompliant {{(Signature) DSA}}
	if err != nil {
		panic(err)
	}

	// Verify the signature
	valid := dsa.Verify(&privateKey.PublicKey, hash, r, s) // Noncompliant {{(Signature) DSA}}
	_ = valid
}
