package main

import (
	"flag"
	"log/slog"

	enrollClient "rdp_zero_trust/internal/enrollment/client"
	"rdp_zero_trust/internal/logging"
)

func main() {
	serverAddr := flag.String("server", "192.168.56.102:9003", "адрес enrollment endpoint")
	username := flag.String("user", "user1", "имя пользователя")
	password := flag.String("pass", "secret", "пароль")
	caPath := flag.String("ca", "certs/ca.crt", "корневой сертификат CA")
	certPath := flag.String("cert", "certs/client_cert.crt", "куда сохранить сертификат")
	keyPath := flag.String("key", "certs/client_key.key", "куда сохранить приватный ключ")
	logLevel := flag.String("log-level", "info", "log level")
	flag.Parse()

	if err := logging.Configure(*logLevel); err != nil {
		logging.Fatalf("failed to configure logger", "err", err)
	}

	slog.Info("генерируем ключевую пару", "username", *username)

	// Ключ генерируется локально и сохраняется в keyPath
	// На сервер уходит только CSR (публичная часть)
	csrPEM, err := enrollClient.GenerateKeyAndCSR(*username, *keyPath)
	if err != nil {
		logging.Fatalf("generate key/CSR", "err", err)
	}
	slog.Info("ключ сохранён, CSR сформирован", "key_path", *keyPath)

	// Первичная аутентификация через пароль
	auth := enrollClient.NewPasswordAuth(*username, *password)

	slog.Info("отправляем CSR на сервер", "server", *serverAddr)
	if err := enrollClient.Enroll(*serverAddr, *caPath, *certPath, auth, csrPEM); err != nil {
		logging.Fatalf("enrollment", "err", err)
	}

	slog.Info("готово! сертификат сохранён", "cert_path", *certPath)
	slog.Info("теперь запускай клиент с флагами", "cert", *certPath, "key", *keyPath)
}
