package enrollServer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"rdp_zero_trust/internal/enrollment/api"
	"rdp_zero_trust/internal/identity"
)

// AuthHandler — серверная сторона интерфейса Auth.
// Каждый способ аутентификации регистрирует свой обработчик.
type AuthHandler interface {
	// Type должен совпадать с Auth.Type() на клиенте
	Type() string
	// Verify проверяет credentials и возвращает username
	Verify(credentials map[string]string) (username string, err error)
}

// Server — enrollment HTTP сервер
type Server struct {
	handlers map[string]AuthHandler
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
}

func NewServer(caKeyPath, caCertPath string) (*Server, error) {
	// Загружаем CA (ключ и сертификат) для подписи клиентских сертификатов
	caKey, caCert, err := loadCA(caKeyPath, caCertPath)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}

	return &Server{
		handlers: make(map[string]AuthHandler),
		caKey:    caKey,
		caCert:   caCert,
	}, nil
}

// RegisterAuth регистрирует обработчик первичной аутентификации.
// Чтобы добавить новый способ — просто регистрируем новый обработчик.
func (s *Server) RegisterAuth(handler AuthHandler) {
	s.handlers[handler.Type()] = handler
}

// Start запускает enrollment сервер с TLS
func (s *Server) Start(srvAddr, srvCertPath, srvKeyPath string) error {
	srvCert, err := tls.LoadX509KeyPair(srvCertPath, srvKeyPath)
	if err != nil {
		return fmt.Errorf("load server cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		MinVersion:   tls.VersionTLS13,
		// Клиентский сертификат не требуем — его у клиента ещё нет
		ClientAuth: tls.NoClientCert,
	}

	// Создаём HTTP мультиплексор
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll", s.handleEnroll)

	srv := &http.Server{
		Addr:      srvAddr,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	log.Printf("enrollment сервер слушает %s", srvAddr)
	// Используем высокоуровневый ListenAndServeTLS для автоматического обработки HTTP запросов
	return srv.ListenAndServeTLS("", "")
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req api.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Выбираем обработчик по типу аутентификации
	handler, ok := s.handlers[req.AuthType]
	if !ok {
		writeError(w, "unknown auth type: "+req.AuthType, http.StatusBadRequest)
		return
	}

	// Проверяем credentials — получаем username
	username, err := handler.Verify(req.Credentials)
	if err != nil {
		log.Printf("enrollment auth failed: %v", err)
		writeError(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Парсим CSR
	csrBlock, _ := pem.Decode([]byte(req.CSR))
	if csrBlock == nil {
		writeError(w, "invalid CSR", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		writeError(w, "parse CSR failed", http.StatusBadRequest)
		return
	}

	// Проверяем что CSR подписан приватным ключом, соответсвующим публичному
	if err := csr.CheckSignature(); err != nil {
		writeError(w, "invalid CSR signature", http.StatusBadRequest)
		return
	}

	// Проверяем соответсвие username в request на аутентификацию и в SAN CSR
	usernameCSR, err := identity.UsernameFromCSR(csr)
	if err != nil {
		writeError(w, "CSR SAN username empty", http.StatusBadRequest)
		return
	}
	if username != usernameCSR {
		writeError(w, "CSR username mismatch", http.StatusBadRequest)
		return
	}

	// Подписываем сертификат нашим CA
	certPEM, err := s.signCSR(csr)
	if err != nil {
		log.Printf("sign CSR failed for %s: %v", username, err)
		writeError(w, "signing failed", http.StatusInternalServerError)
		return
	}

	log.Printf("enrollment: выдан сертификат для %s", username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.Response{Certificate: certPEM})

}

func (s *Server) signCSR(csr *x509.CertificateRequest) (string, error) {
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      csr.Subject,
		URIs:         csr.URIs,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader, template, s.caCert, csr.PublicKey, s.caKey,
	)
	if err != nil {
		return "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM), nil
}

// writeError консистентно записывает ошибки в response
func writeError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(api.Response{Error: msg})
}

// loadCA загружает ключ и сертификат CA из соответсвующих файлов
func loadCA(keyPath, certPath string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	// Загружаем ключ CA
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("parse CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}

	// Загружаем сертификат CA
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("parse CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	return key, cert, nil
}

func randomSerial() *big.Int {
	b := make([]byte, 16)
	rand.Read(b)
	return new(big.Int).SetBytes(b)
}
