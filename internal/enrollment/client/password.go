package enrollClient

// PasswordAuth - простейшая реализация интерфейса Auth
// Простая аутентификация через логин/пароль
type PasswordAuth struct {
	username string
	password string
}

func NewPasswordAuth(username, password string) Auth {
	return &PasswordAuth{username: username, password: password}
}

func (p *PasswordAuth) Type() string {
	return "password"
}

func (p *PasswordAuth) Credentials() map[string]string {
	return map[string]string{
		"username": p.username,
		"password": p.password,
	}
}
