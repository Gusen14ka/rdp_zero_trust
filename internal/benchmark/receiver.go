package benchmark

import (
	"context"
	"io"
	"log"

	"rdp_zero_trust/internal/benchproto"
	"rdp_zero_trust/internal/metrics"
)

// RunReceiver читает benchmark пакеты из r и пишет метрики в m.
// Используется на стороне сервера — MeteredConn уже детектирует
// benchmark пакеты и вызывает RecordBenchmark.
//
// RunReceiver используется на стороне клиента когда клиент
// принимает ответные пакеты от сервера (направление server → client).
func RunReceiver(ctx context.Context, r io.Reader, m *metrics.StreamMetrics) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sentAt, receivedAt, payloadSize, err := ReadPacket(r)
		if err != nil {
			if ctx.Err() != nil {
				// Контекст отменён — нормальное завершение
				return
			}
			log.Printf("benchmark receiver: read error: %v", err)
			return
		}

		latency := receivedAt.Sub(sentAt)
		m.RecordBenchmark(latency, benchproto.PacketHeaderSize+payloadSize)
	}
}
