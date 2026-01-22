package main

import (
	"crypto/elliptic"
	"fmt"
)

func main() {
	// Test P-224 curve
	p224 := elliptic.P224() // Noncompliant {{(PublicKeyEncryption) EC-secp224r1}}
	fmt.Println("P-224:", p224.Params().Name)

	// Test P-256 curve
	p256 := elliptic.P256() // Noncompliant {{(PublicKeyEncryption) EC-secp256r1}}
	fmt.Println("P-256:", p256.Params().Name)

	// Test P-384 curve
	p384 := elliptic.P384() // Noncompliant {{(PublicKeyEncryption) EC-secp384r1}}
	fmt.Println("P-384:", p384.Params().Name)

	// Test P-521 curve
	p521 := elliptic.P521() // Noncompliant {{(PublicKeyEncryption) EC-secp521r1}}
	fmt.Println("P-521:", p521.Params().Name)
}
