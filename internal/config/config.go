package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type UserConfig struct {
	Password string   `json:"password"`
	Machines []string `json:"machines"`
}

type Config struct {
	Machines map[string]string      `json:"machines"`
	Users    map[string]*UserConfig `json:"users"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return &cfg, nil
}

// CanAccess проверяет есть ли у пользователя доступ к машине
func (c *Config) CanAccess(username, machineID string) bool {
	user, ok := c.Users[username]
	if !ok {
		return false
	}
	for _, m := range user.Machines {
		if m == machineID {
			return true
		}
	}
	return false
}

// Authenticate проверяет пароль
func (c *Config) Authenticate(username, password string) bool {
	user, ok := c.Users[username]
	if !ok {
		return false
	}
	return user.Password == password
}
