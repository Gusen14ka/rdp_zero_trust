package benchproto

import (
	"fmt"
	"strconv"
	"strings"
)

// Константы формата benchmark пакета.
// Вынесены в отдельный пакет чтобы избежать циклического импорта
// между benchmark и metrics.
//
// Формат пакета:
// [4B magic "RDP0"][8B timestamp ns][4B payload size][payload]
// Обоснование формата:
// - magic позволяет отличить benchmark трафик от реального RDP
// - timestamp позволяет измерить one-way latency
// - случайный payload имитирует сжатые данные (несжимаемые)

const (
	Magic            uint32 = 0x52445030 // "RDP0" в ASCII
	PacketHeaderSize int    = 16
)

// BenchParams — параметры сетевой деградации для эксперимента.
// Передаются клиентом серверу в рамках BENCH handshake.
// Нулевые значения означают отсутствие ограничения.
type BenchParams struct {
	LossPct          float64 // потери пакетов в процентах, например 2.0
	DelayMs          int     // базовая задержка в миллисекундах
	JitterMs         int     // джиттер ±ms (нормальное распределение)
	RateMbit         float64 // ограничение bandwidth в Mbit/s, 0 = без ограничения
	ClientIntervalMs int     // ожидаемый интервал между пакетами клиента
}

// Encode сериализует параметры в строку для передачи через proto.Send
// Формат: "loss=2.0,delay=50,jitter=20,rate=0"
func (p BenchParams) Encode() string {
	return fmt.Sprintf("loss=%.2f,delay=%d,jitter=%d,rate=%.2f,interval=%d",
		p.LossPct, p.DelayMs, p.JitterMs, p.RateMbit, p.ClientIntervalMs)
}

// DecodeBenchParams парсит строку обратно в BenchParams
func DecodeBenchParams(s string) (BenchParams, error) {
	var p BenchParams
	parts := strings.Split(s, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return p, fmt.Errorf("неверный формат: %s", part)
		}
		k, v := kv[0], kv[1]
		switch k {
		case "loss":
			val, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return p, fmt.Errorf("loss: %w", err)
			}
			p.LossPct = val
		case "delay":
			val, err := strconv.Atoi(v)
			if err != nil {
				return p, fmt.Errorf("delay: %w", err)
			}
			p.DelayMs = val
		case "jitter":
			val, err := strconv.Atoi(v)
			if err != nil {
				return p, fmt.Errorf("jitter: %w", err)
			}
			p.JitterMs = val
		case "rate":
			val, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return p, fmt.Errorf("rate: %w", err)
			}
			p.RateMbit = val
		case "interval":
			val, err := strconv.Atoi(v)
			if err != nil {
				return p, fmt.Errorf("interval: %w", err)
			}
			p.ClientIntervalMs = val
		default:
			return p, fmt.Errorf("неизвестный параметр: %s", k)
		}
	}
	return p, nil
}
