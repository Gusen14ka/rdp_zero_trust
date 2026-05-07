package benchmark

import (
	"context"
	"io"
	"log"
	"rdp_zero_trust/internal/benchproto"
	"time"
)

type SenderResult struct {
	PacketsSent int64
	BytesSent   int64
	// Errors — количество ошибок записи.
	// Ненулевое значение означает потери на стороне отправителя.
	Errors int64
}

// RunSender отправляет пакеты заданного размера с заданным интервалом.
// Запускается отдельно для каждого направления:
//   - клиент запускает для имитации input events (client → server)
//   - клиент запускает для имитации bitmap updates (server → client)
//     через отдельное соединение в режиме echo
//
// Останавливается когда ctx отменяется.
func RunSender(ctx context.Context, w io.Writer, packetSize int, interval time.Duration) SenderResult {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var result SenderResult
	for {
		select {
		case <-ctx.Done():
			return result
		case <-ticker.C:
			_, err := WritePacket(w, packetSize)
			if err != nil {
				log.Printf("benchmark sender: write error: %v", err)
				result.Errors++
				// Не выходим сразу — считаем ошибки как потери
				if result.Errors > 10 {
					log.Printf("benchmark sender: слишком много ошибок, выходим")
					return result
				}
				continue
			}
			result.PacketsSent++
			result.BytesSent += int64(benchproto.PacketHeaderSize + packetSize)
		}
	}
}
