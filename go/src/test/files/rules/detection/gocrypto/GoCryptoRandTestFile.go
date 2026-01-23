package main

import (
	"crypto/rand"
	"fmt"
)

func main() {
	key := make([]byte, 32)
	_, err := rand.Read(key) // Noncompliant {{(PseudorandomNumberGenerator) NATIVEPRNG}}
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", key)
}
