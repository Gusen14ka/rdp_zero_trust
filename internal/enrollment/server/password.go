package enrollServer

import (
	"fmt"

	"rdp_zero_trust/internal/config"
)

// PasswordAuthHandler — серверная проверка пароля при enrollment.
// Использует тот же config что и основной сервер.
type PasswordAuthHandler struct {
	cfg *config.Config
}

func NewPasswordAuthHandler(cfg *config.Config) AuthHandler {
	return &PasswordAuthHandler{cfg: cfg}
}

func (h *PasswordAuthHandler) Type() string {
	return "password"
}

func (h *PasswordAuthHandler) Verify(credentials map[string]string) (string, error) {
	username, ok := credentials["username"]
	if !ok {
		return "", fmt.Errorf("missing username")
	}
	password, ok := credentials["password"]
	if !ok {
		return "", fmt.Errorf("missing password")
	}

	if !h.cfg.Authenticate(username, password) {
		return "", fmt.Errorf("invalid credentials for %s", username)
	}

	return username, nil
}
