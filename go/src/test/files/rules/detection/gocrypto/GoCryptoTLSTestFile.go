package main

import (
	"crypto/tls"
)

func main() {
	// Dial a TLS connection
	conf := tls.Config{ // Noncompliant {{(TLS) TLS}}
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	conn, err := tls.Dial("tcp", "example.com:443", &conf)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
}
