package identity

// Простые утилиты для экстракта username из SAN

import (
	"crypto/x509"
	"fmt"
	"net/url"
)

func usernameFromURIs(uris []*url.URL) (string, error) {
	for _, uri := range uris {
		if uri.Scheme == "user" {
			return uri.Host, nil
		}
	}
	return "", fmt.Errorf("no user URI in SAN")
}

// UsernameFromCSR достаёт из SAN CSR username
func UsernameFromCSR(csr *x509.CertificateRequest) (string, error) {
	return usernameFromURIs(csr.URIs)
}

// UsernameFromCert достаёт из SAN cert username
func UsernameFromCert(cert *x509.Certificate) (string, error) {
	return usernameFromURIs(cert.URIs)
}
