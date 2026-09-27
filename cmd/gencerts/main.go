package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"

	"rdp_zero_trust/internal/logging"
	"rdp_zero_trust/internal/saving"
)

func main() {
	logLevel := flag.String("log-level", "info", "log level")
	flag.Parse()

	if err := logging.Configure(*logLevel); err != nil {
		logging.Fatalf("failed to configure logger", "err", err)
	}

	// Создаём папку для сертификатов
	os.MkdirAll("certs", 0755)

	// 1. Генерируем корневой CA
	caKey, caCert := generateCA()

	if err := saving.SaveKey("certs/ca.key", caKey); err != nil {
		logging.Fatalf("save CA key", "err", err)
	}
	saveCert("certs/ca.crt", caCert)
	slog.Info("CA сгенерирован")

	// 2. Генерируем сертификат сервера подписанный CA
	serverKey, serverCert := generateServerCert(caKey, caCert)
	if err := saving.SaveKey("certs/server.key", serverKey); err != nil {
		logging.Fatalf("save server key", "err", err)
	}
	saveCert("certs/server.crt", serverCert)
	slog.Info("Сертификат сервера сгенерирован")

	slog.Info("Готово. Файлы в папке certs/")
}

func generateCA() (*ecdsa.PrivateKey, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logging.Fatalf("CA key", "err", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "RDP Zero Trust CA",
			Organization: []string{"My Diploma Project"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 лет
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		logging.Fatalf("CA cert", "err", err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	return key, cert
}

func generateServerCert(caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logging.Fatalf("server key", "err", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "rdp-server",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // 1 год
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		// Прописываем IP и DNS по которым будет доступен сервер
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("192.168.56.102"), // IP твоего сервера
		},
		DNSNames: []string{
			"localhost",
			// сюда потом добавим домен
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		logging.Fatalf("server cert", "err", err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	return key, cert
}

func saveCert(path string, cert *x509.Certificate) {
	f, err := os.Create(path)
	if err != nil {
		logging.Fatalf("create cert file", "err", err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
