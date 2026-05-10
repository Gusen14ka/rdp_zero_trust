package benchmark

import (
	"context"
	"io"
	"log"
	"time"

	"rdp_zero_trust/internal/benchproto"
	"rdp_zero_trust/internal/metrics"
)

// RunReceiver читает echo пакеты от сервера и считает RTT.
// RTT = время от отправки пакета до получения echo.
// Это корректное измерение latency без синхронизации часов —
// timestamp записывается и читается на одной машине (клиент).
func RunReceiver(ctx context.Context, r io.Reader, m *metrics.StreamMetrics) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Читаем echo пакет — формат тот же что отправляли
		sentAt, _, payloadSize, err := ReadPacket(r)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("benchmark receiver: read error: %v", err)
			return
		}

		// RTT = now() - sentAt
		// Оба момента времени на клиенте — синхронизация не нужна
		rtt := time.Since(sentAt)
		m.RecordBenchmark(rtt, benchproto.PacketHeaderSize+payloadSize)
	}
}
