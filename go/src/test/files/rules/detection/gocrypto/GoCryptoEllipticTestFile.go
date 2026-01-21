package main

import (
	"crypto/elliptic"
	"fmt"
)

func main() {
	// Test P-224 curve
	p224 := elliptic.P224() // Noncompliant {{(EllipticCurve) P-224}}
	fmt.Println("P-224:", p224.Params().Name)

	// Test P-256 curve
	p256 := elliptic.P256() // Noncompliant {{(EllipticCurve) P-256}}
	fmt.Println("P-256:", p256.Params().Name)

	// Test P-384 curve
	p384 := elliptic.P384() // Noncompliant {{(EllipticCurve) P-384}}
	fmt.Println("P-384:", p384.Params().Name)

	// Test P-521 curve
	p521 := elliptic.P521() // Noncompliant {{(EllipticCurve) P-521}}
	fmt.Println("P-521:", p521.Params().Name)
}
