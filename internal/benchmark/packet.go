package benchmark

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"rdp_zero_trust/internal/benchproto"
)

// WritePacket записывает один benchmark пакет в w.
// Payload заполняется криптографически случайными байтами —
// осознанное решение: тестируем транспортный уровень, не компрессию.
// Размеры пакетов взяты из спецификации MS-RDPBCGR, поэтому
// сжимаемость payload не влияет на репрезентативность эксперимента.
func WritePacket(w io.Writer, payloadSize int) (sentAt time.Time, err error) {
	header := make([]byte, benchproto.PacketHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], benchproto.Magic)
	sentAt = time.Now()
	binary.BigEndian.PutUint64(header[4:12], uint64(sentAt.UnixNano()))
	binary.BigEndian.PutUint32(header[12:16], uint32(payloadSize))

	payload := make([]byte, payloadSize)
	rand.Read(payload)

	if _, err = w.Write(header); err != nil {
		return
	}
	_, err = w.Write(payload)
	return
}

// ReadPacket читает один benchmark пакет из r.
// Возвращает время отправки, время получения и размер payload.
func ReadPacket(r io.Reader) (sentAt, receivedAt time.Time, payloadSize int, err error) {
	header := make([]byte, benchproto.PacketHeaderSize)
	if _, err = io.ReadFull(r, header); err != nil {
		return
	}

	m := binary.BigEndian.Uint32(header[0:4])
	if m != benchproto.Magic {
		err = fmt.Errorf("неверный magic: %x ожидался %x", m, benchproto.Magic)
		return
	}

	ns := binary.BigEndian.Uint64(header[4:12])
	sentAt = time.Unix(0, int64(ns))
	payloadSize = int(binary.BigEndian.Uint32(header[12:16]))
	receivedAt = time.Now()

	// Дропаем payload — нам нужен только timestamp для latency
	payload := make([]byte, payloadSize)
	_, err = io.ReadFull(r, payload)
	return
}
