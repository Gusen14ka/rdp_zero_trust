package main

import (
	"flag"
	"log"

	enrollClient "rdp_zero_trust/internal/enrollment/client"
)

func main() {
	serverAddr := flag.String("server", "192.168.0.21:9003", "адрес enrollment endpoint")
	username := flag.String("user", "user1", "имя пользователя")
	password := flag.String("pass", "secret", "пароль")
	caPath := flag.String("ca", "certs/ca.crt", "корневой сертификат CA")
	certPath := flag.String("cert", "certs/client_cert.crt", "куда сохранить сертификат")
	keyPath := flag.String("key", "certs/client_key.key", "куда сохранить приватный ключ")
	flag.Parse()

	log.Printf("генерируем ключевую пару для %s...", *username)

	// Ключ генерируется локально и сохраняется в keyPath
	// На сервер уходит только CSR (публичная часть)
	csrPEM, err := enrollClient.GenerateKeyAndCSR(*username, *keyPath)
	if err != nil {
		log.Fatalf("generate key/CSR: %v", err)
	}
	log.Printf("ключ сохранён в %s, CSR сформирован", *keyPath)

	// Первичная аутентификация через пароль
	auth := enrollClient.NewPasswordAuth(*username, *password)

	log.Printf("отправляем CSR на сервер %s...", *serverAddr)
	if err := enrollClient.Enroll(*serverAddr, *caPath, *certPath, auth, csrPEM); err != nil {
		log.Fatalf("enrollment: %v", err)
	}

	log.Printf("готово! сертификат сохранён в %s", *certPath)
	log.Printf("теперь запускай клиент с флагами:")
	log.Printf("  -cert %s -key %s", *certPath, *keyPath)
}
