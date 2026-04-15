package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	// Создаём папку для сертификатов
	os.MkdirAll("certs", 0755)

	// 1. Генерируем корневой CA
	caKey, caCert := generateCA()
	saveKey("certs/ca.key", caKey)
	saveCert("certs/ca.crt", caCert)
	log.Println("CA сгенерирован")

	// 2. Генерируем сертификат сервера подписанный CA
	serverKey, serverCert := generateServerCert(caKey, caCert)
	saveKey("certs/server.key", serverKey)
	saveCert("certs/server.crt", serverCert)
	log.Println("Сертификат сервера сгенерирован")

	log.Println("Готово. Файлы в папке certs/")
}

func generateCA() (*ecdsa.PrivateKey, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("CA key: %v", err)
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
		log.Fatalf("CA cert: %v", err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	return key, cert
}

func generateServerCert(caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("server key: %v", err)
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
			net.ParseIP("192.168.0.21"), // IP твоего сервера
		},
		DNSNames: []string{
			"localhost",
			// сюда потом добавим домен
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		log.Fatalf("server cert: %v", err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	return key, cert
}

func saveKey(path string, key *ecdsa.PrivateKey) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("create key file: %v", err)
	}
	defer f.Close()

	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}
	pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
}

func saveCert(path string, cert *x509.Certificate) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("create cert file: %v", err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
