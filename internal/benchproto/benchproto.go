package benchproto

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
