package main

import (
	"crypto/tls"
)

func main() {
	// Dial a TLS connection
	conf := tls.Config{ // Noncompliant {{(TLS) TLSv1.2}}
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

// VersionSSL30: the family (SSL, not TLS) must be preserved in the translated node's name.
func dialSsl30() {
	confSsl30 := tls.Config{ // Noncompliant {{(TLS) SSLv3.0}}
		MinVersion: tls.VersionSSL30,
	}
	connSsl30, errSsl30 := tls.Dial("tcp", "example.com:443", &confSsl30)
	if errSsl30 != nil {
		panic(errSsl30)
	}
	defer connSsl30.Close()
}
