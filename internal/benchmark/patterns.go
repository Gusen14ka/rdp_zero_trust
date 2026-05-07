package benchmark

import "time"

// TrafficPattern описывает паттерн RDP-like трафика.
// Основан на характеристиках реального RDP трафика из MS-RDPBCGR спецификации
// и исследований трафика удалённых рабочих столов.
type TrafficPattern struct {
	Name string `json:"name"`

	// Client → Server: события ввода (мышь, клавиатура)
	// Источник: MS-RDPBCGR 2.2.8.1.1.3 — Mouse Event PDU
	// Типичный размер: 20-30 байт, интервал: 50ms при активной работе
	ClientPacketSize     int           `json:"client_packet_size_bytes"`
	ClientPacketInterval time.Duration `json:"client_packet_interval_ms"`

	// Server → Client: графические обновления (bitmap updates)
	// Источник: MS-RDPBCGR 2.2.9.1.1.3 — Bitmap Update
	// Типичный размер: 4-12KB в зависимости от активности экрана
	ServerPacketSize     int           `json:"server_packet_size_bytes"`
	ServerPacketInterval time.Duration `json:"server_packet_interval_ms"`

	Duration time.Duration `json:"duration_ms"`
}

var (
	// PatternIdle — пользователь не активен, смотрит на экран.
	// Bandwidth: ~5-10 Kbit/s
	// Источник: типичный измеренный RDP idle трафик
	PatternIdle = TrafficPattern{
		Name:                 "idle",
		ClientPacketSize:     20,
		ClientPacketInterval: 5 * time.Second,
		ServerPacketSize:     500,
		ServerPacketInterval: 3 * time.Second,
		Duration:             60 * time.Second,
	}

	// PatternInput — активная работа: печать текста, движение мыши.
	// Mouse Event PDU каждые 50ms, bitmap update каждые 33ms (30fps).
	// Bandwidth: ~100-500 Kbit/s
	PatternInput = TrafficPattern{
		Name:                 "input",
		ClientPacketSize:     30,
		ClientPacketInterval: 50 * time.Millisecond,
		ServerPacketSize:     4 * 1024,
		ServerPacketInterval: 33 * time.Millisecond,
		Duration:             60 * time.Second,
	}

	// PatternScroll — интенсивная графика: скроллинг, анимации.
	// Полное обновление экрана каждые 16ms (60fps).
	// 1080p сжатый RDP ~10-12KB на кадр.
	// Bandwidth: ~1-5 Mbit/s
	PatternScroll = TrafficPattern{
		Name:                 "scroll",
		ClientPacketSize:     20,
		ClientPacketInterval: 16 * time.Millisecond,
		ServerPacketSize:     12 * 1024,
		ServerPacketInterval: 16 * time.Millisecond,
		Duration:             60 * time.Second,
	}

	AllPatterns = []TrafficPattern{PatternIdle, PatternInput, PatternScroll}
)
