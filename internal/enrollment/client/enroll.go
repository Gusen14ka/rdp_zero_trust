package enrollClient

// CSR логика для клиента

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"rdp_zero_trust/internal/enrollment/api"
	"rdp_zero_trust/internal/loading"
	"rdp_zero_trust/internal/saving"
)

// GenerateKeyAndCSR генерирует приватный ключ на клиенте и CSR.
// Приватный ключ сохраняется локально и никуда не отправляется.
func GenerateKeyAndCSR(username, keyPath string) (csrPEM string, err error) {
	// Генерируем ключевую пару
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}

	// Сохраняем приватный ключ - он никуда не уходит
	// В будущем возможно сделать безопасное хранилище
	if err := saving.SaveKey(keyPath, key); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}

	// Создаём шаблон CSR
	// Сохраняем username в SAN URIs первым url со схемой "user"
	template := &x509.CertificateRequest{
		URIs: []*url.URL{
			{
				Scheme: "user",
				Host:   username,
			},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return "", fmt.Errorf("create CSR: %w", err)
	}

	csrPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEMBytes), nil
}

// Enroll выполняет enrollment: отправляет CSR на сервер,
// получает подписанный сертификат и сохраняет его.
func Enroll(serverAddr, caPath, certPath string, auth Auth, csrPEM string) error {
	// TLS конфиг — проверяем сервер через наш CA
	tlsCfg, err := loading.LoadTLSConfig(caPath)
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}

	// Формируем запрос
	req := api.Request{
		AuthType:    auth.Type(),
		Credentials: auth.Credentials(),
		CSR:         csrPEM,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	// Отправляем на сервер
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	resp, err := client.Post(
		"https://"+serverAddr+"/enroll",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("enroll request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enroll failed: status %s", resp.Status)
	}

	var enrollResp api.Response
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if enrollResp.Error != "" {
		return fmt.Errorf("server error: %s", enrollResp.Error)
	}

	// Сохраняем сертификат - пока что просто файлом
	if err := os.WriteFile(certPath, []byte(enrollResp.Certificate), 0644); err != nil {
		return fmt.Errorf("save cert: %w", err)
	}

	return nil
}
