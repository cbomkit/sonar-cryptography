package main

import (
	"crypto/x509"
	"io"
)

func justCheckingThings(b []byte, r io.Reader, c *x509.Certificate, cr *x509.CertificateRequest, pub any, priv any) {
	// whatever, let's just parse some crap
	x509.ParseCertificate(b) // Noncompliant
	x509.ParseCertificates(b) // Noncompliant
	
	// creating certs
	x509.CreateCertificate(r, c, c, pub, priv) // Noncompliant
	

	// public keys
	x509.ParsePKIXPublicKey(b) // Noncompliant
	x509.MarshalPKIXPublicKey(pub) // Noncompliant
	
	// private keys pkcs1, man this is tedious
	// why so many formats
	x509.ParsePKCS1PrivateKey(b) // Noncompliant
	x509.MarshalPKCS1PrivateKey(nil) // Noncompliant
	
	x509.ParsePKCS8PrivateKey(b) // Noncompliant
	x509.MarshalPKCS8PrivateKey(priv) // Noncompliant
	
	x509.ParseECPrivateKey(b) // Noncompliant
	x509.MarshalECPrivateKey(nil) // Noncompliant
}
