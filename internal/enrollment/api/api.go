package api

// Request — то что клиент отправляет на сервер при enrollment
type Request struct {
	// AuthType определяет какой обработчик использовать на сервере
	AuthType string `json:"auth_type"`
	// Credentials — данные первичной аутентификации
	Credentials map[string]string `json:"credentials"`
	// CSR — запрос на подпись сертификата в PEM формате
	CSR string `json:"csr"`
}

// Response — то что сервер возвращает клиенту
type Response struct {
	// Certificate — подписанный сертификат в PEM формате
	Certificate string `json:"certificate"`
	Error       string `json:"error,omitempty"`
}
