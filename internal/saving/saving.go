package saving

// Утилиты для сохранения данных на диск

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func SaveKey(path string, key *ecdsa.PrivateKey) (err error) {
	// Tолько владелец может читать и писать файл - только Unix
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer f.Close()

	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %v", err)
	}
	pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	return nil
}
