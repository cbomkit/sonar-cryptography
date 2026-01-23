package main

import (
	"crypto/mlkem"
)

func main() {
	// Generate an ML-KEM-768 decapsulation key
	dk, err := mlkem.GenerateKey768() // Noncompliant {{(KeyEncapsulationMechanism) ML-KEM-768}}
	if err != nil {
		panic(err)
	}

	_ = dk
}
