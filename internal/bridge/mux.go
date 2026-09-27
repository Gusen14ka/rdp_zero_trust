package bridge

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// Кадр общего стрима в режиме single: [1B канал][4B длина LE][данные]
const muxHeaderSize = 5

type muxWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// writeFrame пишет кадр одним вызовом под мьютексом: кадры разных каналов
// не должны перемежаться внутри общего стрима
func (m *muxWriter) writeFrame(ch int, data []byte) error {
	buf := make([]byte, muxHeaderSize+len(data))
	buf[0] = byte(ch)
	binary.LittleEndian.PutUint32(buf[1:5], uint32(len(data)))
	copy(buf[muxHeaderSize:], data)

	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := writeAll(m.w, buf)
	return err
}

func readFrame(r io.Reader) (int, []byte, error) {
	var hdr [muxHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	ch := int(hdr[0])
	size := binary.LittleEndian.Uint32(hdr[1:5])
	if ch >= ChannelCount {
		return 0, nil, fmt.Errorf("неверный канал в кадре: %d", ch)
	}
	if size == 0 || size > 64*1024 {
		return 0, nil, fmt.Errorf("неверный размер кадра: %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return 0, nil, err
	}
	return ch, data, nil
}

func logBridgeErr(name, dir string, err error) {
	if isClosedErr(err) {
		slog.Debug("канал закрыт", "channel", name, "dir", dir, "err", err)
	} else {
		slog.Error("ошибка канала", "channel", name, "dir", dir, "err", err)
	}
}

// BridgeMux связывает поканальные соединения (кадры [4B len][data]) с одним
// общим стримом (кадры [1B канал][4B len][data]). На клиенте chans —
// unix-сокеты, на сервере — стримы агента. Возвращается, когда общий
// стрим закрылся или сломался.
func BridgeMux(chans []io.ReadWriter, mux io.ReadWriter) {
	mw := &muxWriter{w: mux}

	for i := 0; i < ChannelCount; i++ {
		go func(ch int) {
			name := ChannelNames[ch]
			for {
				pdu, err := ReadPDU(chans[ch])
				if err != nil {
					logBridgeErr(name, "unix→quic", err)
					return
				}
				if err := mw.writeFrame(ch, pdu); err != nil {
					logBridgeErr(name, "unix→quic", err)
					return
				}
				if Rec != nil {
					Rec.Record(name, "unix→quic", len(pdu))
				}
			}
		}(i)
	}

	for {
		ch, data, err := readFrame(mux)
		if err != nil {
			logBridgeErr("mux", "quic→unix", err)
			return
		}
		if err := WritePDU(chans[ch], data); err != nil {
			logBridgeErr(ChannelNames[ch], "quic→unix", err)
			return
		}
		if Rec != nil {
			Rec.Record(ChannelNames[ch], "quic→unix", len(data))
		}
	}
}
