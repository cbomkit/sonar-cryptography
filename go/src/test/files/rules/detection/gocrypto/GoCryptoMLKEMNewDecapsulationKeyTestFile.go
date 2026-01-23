package main

import (
	"crypto/mlkem"
)

func main() {
	// Create an ML-KEM-768 decapsulation key from a seed (SeedSize = 64)
	seed := make([]byte, 64)
	dk, err := mlkem.NewDecapsulationKey768(seed) // Noncompliant {{(KeyEncapsulationMechanism) ML-KEM-768}}
	if err != nil {
		panic(err)
	}

	_ = dk
}
