package loading

// Утилиты для считывания данных с диска

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func LoadTLSConfig(caPath string) (*tls.Config, error) {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("parse CA cert")
	}

	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}, nil
}

// LoadMTLSConfig загружает клиентский TLS конфиг с клиентским сертификатом для mTLS.
// Используется клиентом при подключении к control plane после enrollment.
func LoadMTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	// CA для проверки сервера
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("parse CA cert")
	}

	// Клиентский сертификат для предъявления серверу
	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}
