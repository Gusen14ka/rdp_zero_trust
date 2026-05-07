package benchmark

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"rdp_zero_trust/internal/metrics"
)

// Result — полный результат одного прогона эксперимента.
// Содержит параметры эксперимента и метрики обоих направлений.
type Result struct {
	// Параметры эксперимента
	Pattern   string    `json:"pattern"`
	Transport string    `json:"transport"` // "tcp" или "quic"
	Scenario  string    `json:"scenario"`  // "baseline", "loss_2" и т.д.
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration"`

	// Метрики отправителя (клиентская сторона)
	Sent SenderResult `json:"sent"`

	// Метрики получателя (серверная сторона через admin API)
	// Снимается в конце прогона через GET /sessions/{id}/metrics
	Received metrics.Snapshot `json:"received"`
}

// Save сохраняет результат в JSON файл.
func (r *Result) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create result file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
