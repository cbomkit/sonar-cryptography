package main

import (
	"crypto/mlkem"
)

func main() {
	// Generate an ML-KEM-1024 decapsulation key
	dk, err := mlkem.GenerateKey1024() // Noncompliant {{(KeyEncapsulationMechanism) ML-KEM-1024}}
	if err != nil {
		panic(err)
	}

	_ = dk
}
