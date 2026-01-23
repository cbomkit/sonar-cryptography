package main

import (
	"crypto/tls"
	"fmt"
)

func main() {
	// Dial a TLS connection
	conf := tls.Config{
		MinVersion: tls.VersionTLS12, // Noncompliant {{(TLS) TLSv1.2}} {{(TLS) TLSv1.2}}
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	conn, err := tls.Dial("tcp", "example.com:443", &conf)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Listen for TLS connections
	ln, err := tls.Listen("tcp", ":443", &tls.Config{
		MinVersion: tls.VersionTLS13, // Noncompliant {{(TLS) TLSv1.3}}
	})
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("Done")
}
