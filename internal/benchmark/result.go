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

	// ClientMetrics — RTT и jitter измеренные на клиенте.
	// Latency здесь = RTT (round-trip time).
	// Это основная метрика для сравнения TCP vs QUIC.
	ClientMetrics metrics.Snapshot `json:"client_metrics"`

	// ServerMetrics — throughput и jitter на сервере.
	// Latency в серверных метриках теперь не используется.
	ServerMetrics metrics.Snapshot `json:"server_metrics"`
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
