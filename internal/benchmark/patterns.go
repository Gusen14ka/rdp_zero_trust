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
	// PatternIdle — пользователь не активен
	PatternIdle = TrafficPattern{
		Name:                 "idle",
		ClientPacketSize:     20,
		ClientPacketInterval: 5 * time.Second,
		ServerPacketSize:     500,
		ServerPacketInterval: 3 * time.Second,
		Duration:             30 * time.Second,
	}

	// PatternInput — активная работа: мышь + клавиатура + 30fps
	PatternInput = TrafficPattern{
		Name:                 "input",
		ClientPacketSize:     30,
		ClientPacketInterval: 50 * time.Millisecond,
		ServerPacketSize:     4 * 1024,
		ServerPacketInterval: 33 * time.Millisecond,
		Duration:             60 * time.Second,
	}

	// PatternScroll — интенсивный скроллинг, 60fps
	PatternScroll = TrafficPattern{
		Name:                 "scroll",
		ClientPacketSize:     20,
		ClientPacketInterval: 16 * time.Millisecond,
		ServerPacketSize:     12 * 1024,
		ServerPacketInterval: 16 * time.Millisecond,
		Duration:             60 * time.Second,
	}

	// PatternVideo — RemoteFX / видео поток, максимальная нагрузка
	// Источник: RDP с включённым RemoteFX ~8-15 Mbit/s
	PatternVideo = TrafficPattern{
		Name:                 "video",
		ClientPacketSize:     30,
		ClientPacketInterval: 16 * time.Millisecond,
		ServerPacketSize:     32 * 1024, // 32KB — сжатый видеокадр
		ServerPacketInterval: 16 * time.Millisecond,
		Duration:             60 * time.Second,
	}

	// PatternBurst — пакетная нагрузка: чередование активности и тишины
	// Имитирует открытие приложений, переключение окон
	PatternBurst = TrafficPattern{
		Name:                 "burst",
		ClientPacketSize:     50,
		ClientPacketInterval: 100 * time.Millisecond,
		ServerPacketSize:     64 * 1024, // 64KB — максимальный burst
		ServerPacketInterval: 100 * time.Millisecond,
		Duration:             60 * time.Second,
	}

	AllPatterns = []TrafficPattern{
		PatternIdle,
		PatternInput,
		PatternScroll,
		PatternVideo,
		PatternBurst,
	}
)
