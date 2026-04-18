package enrollClient

// Auth — способ первичной аутентификации при enrollment.
// Реализации: Password, TOTP, OneTimeToken и т.д.
// Сервер получает Credentials и сам решает как их проверять.
type Auth interface {
	// Type возвращает строковый идентификатор способа аутентификации.
	// Сервер использует его чтобы выбрать нужный обработчик.
	Type() string

	// Credentials возвращает данные для передачи серверу.
	Credentials() map[string]string
}
