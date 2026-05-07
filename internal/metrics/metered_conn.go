package metrics

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"

	"rdp_zero_trust/internal/benchproto"
)

// MeteredConn оборачивает net.Conn и прозрачно собирает метрики.
// Детектирует benchmark пакеты по magic числу и пишет их в отдельный буфер.
// Реальный RDP трафик пишется в rawSamples без latency.
// Поток байт наружу не изменяется — pipe.PipeWithDone работает как обычно.
type MeteredConn struct {
	net.Conn
	metrics *StreamMetrics

	// Внутренний буфер для детекции magic числа.
	// Нужен потому что Read может вернуть произвольное количество байт —
	// magic может прийти разбитым на несколько вызовов.
	buf     bytes.Buffer
	pending []byte // байты которые уже детектированы и ждут возврата
}

func NewMeteredConn(c net.Conn, m *StreamMetrics) *MeteredConn {
	return &MeteredConn{Conn: c, metrics: m}
}

func (mc *MeteredConn) Read(p []byte) (int, error) {
	// Если есть pending байты от предыдущего Read — сначала отдаём их
	if len(mc.pending) > 0 {
		n := copy(p, mc.pending)
		mc.pending = mc.pending[n:]
		return n, nil
	}

	// Читаем из реального соединения
	tmp := make([]byte, len(p))
	n, err := mc.Conn.Read(tmp)
	if n == 0 {
		return 0, err
	}
	raw := tmp[:n]

	// Добавляем в буфер детекции
	mc.buf.Write(raw)

	// Пытаемся обработать всё что накопилось в буфере
	processed := mc.processBuf()

	// Возвращаем обработанные байты
	if len(processed) == 0 {
		// Буфер накапливает header — ещё не можем вернуть данные.
		// Рекурсивно читаем дальше.
		return mc.Read(p)
	}

	n2 := copy(p, processed)
	if n2 < len(processed) {
		// Не всё влезло в p — сохраняем остаток в pending
		mc.pending = append(mc.pending, processed[n2:]...)
	}
	return n2, err
}

// processBuf пытается распознать пакеты в буфере.
// Возвращает байты готовые к передаче наружу.
func (mc *MeteredConn) processBuf() []byte {
	var result []byte

	for mc.buf.Len() > 0 {
		data := mc.buf.Bytes()

		// Ищем magic число в начале буфера
		if len(data) >= 4 {
			m := binary.BigEndian.Uint32(data[0:4])

			if m == benchproto.Magic {
				// Это benchmark пакет — ждём полный header
				if len(data) < benchproto.PacketHeaderSize {
					// Header ещё не пришёл полностью — ждём
					break
				}

				// Читаем размер payload
				payloadSize := int(binary.BigEndian.Uint32(data[12:16]))
				totalSize := benchproto.PacketHeaderSize + payloadSize

				if len(data) < totalSize {
					// Payload ещё не пришёл полностью — ждём
					break
				}

				// Полный benchmark пакет получен — записываем метрики
				ns := binary.BigEndian.Uint64(data[4:12])
				sentAt := time.Unix(0, int64(ns))
				latency := time.Since(sentAt)

				mc.metrics.RecordBenchmark(latency, totalSize)

				// Забираем пакет из буфера и передаём наружу как есть
				pkt := make([]byte, totalSize)
				mc.buf.Read(pkt)
				result = append(result, pkt...)
				continue
			}
		}

		// Не benchmark пакет — читаем побайтово пока не найдём magic
		// или не кончатся данные.
		// Оптимизация: если в буфере нет magic — отдаём всё сразу.
		magicIdx := findMagic(data)
		if magicIdx < 0 {
			// Magic не найден — весь буфер это реальный RDP трафик
			mc.metrics.RecordRaw(mc.buf.Len())
			out := make([]byte, mc.buf.Len())
			mc.buf.Read(out)
			result = append(result, out...)
			break
		}

		if magicIdx > 0 {
			// До magic идёт реальный RDP трафик
			mc.metrics.RecordRaw(magicIdx)
			out := make([]byte, magicIdx)
			mc.buf.Read(out)
			result = append(result, out...)
			// Продолжаем — теперь в начале буфера magic
			continue
		}

		// magicIdx == 0 но данных меньше 4 байт — ждём ещё
		break
	}

	return result
}

// findMagic ищет magic число benchmark пакета в срезе байт.
// Возвращает индекс начала или -1 если не найдено.
func findMagic(data []byte) int {
	target := []byte{0x52, 0x44, 0x50, 0x30} // "RDP0"
	for i := 0; i <= len(data)-4; i++ {
		if data[i] == target[0] &&
			data[i+1] == target[1] &&
			data[i+2] == target[2] &&
			data[i+3] == target[3] {
			return i
		}
	}
	if len(data) < 4 {
		return 0 // возможно начало magic — ждём
	}
	return -1
}

// Проверяем что MeteredConn реализует net.Conn
var _ io.Reader = (*MeteredConn)(nil) // compile-time проверка
