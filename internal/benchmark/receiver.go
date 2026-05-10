package benchmark

import (
	"context"
	"io"
	"log"
	"strings"
	"time"

	"rdp_zero_trust/internal/benchproto"
	"rdp_zero_trust/internal/metrics"
)

// RunReceiver читает echo пакеты от сервера и считает RTT.
// RTT = время от отправки пакета до получения echo.
// Это корректное измерение latency без синхронизации часов —
// timestamp записывается и читается на одной машине (клиент).
// В RunReceiver добавляем обработку закрытия соединения
func RunReceiver(ctx context.Context, r io.Reader, m *metrics.StreamMetrics) {
	for {
		// Проверяем ctx перед каждым чтением
		select {
		case <-ctx.Done():
			return
		default:
		}

		sentAt, _, payloadSize, err := ReadPacket(r)
		if err != nil {
			// EOF или closed connection — нормальное завершение
			if err == io.EOF {
				return
			}
			if ctx.Err() != nil {
				return
			}
			// Проверяем что это не просто закрытие соединения
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Printf("benchmark receiver: read error: %v", err)
			return
		}

		rtt := time.Since(sentAt)
		m.RecordBenchmark(rtt, benchproto.PacketHeaderSize+payloadSize)
	}
}
