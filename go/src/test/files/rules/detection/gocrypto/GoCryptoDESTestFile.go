package main

import (
	"crypto/des"
)

func main() {
	key := make([]byte, 8)
	block, err := des.NewCipher(key) // Noncompliant {{(BlockCipher) DES64}}
	if err != nil {
		panic(err)
	}
	_ = block
}
