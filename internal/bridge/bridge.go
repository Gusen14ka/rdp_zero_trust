package bridge

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/quic-go/quic-go"
)

const SocketDir = "/tmp/rdp_quic_bridge"

// Каналы — порядок должен совпадать с C кодом
const (
	ChannelGraphics = 0
	ChannelInput    = 1
	ChannelVChannel = 2
	ChannelControl  = 3
	ChannelCount    = 4
)

var ChannelNames = [ChannelCount]string{
	"graphics",
	"input",
	"vchannel",
	"control",
}

// ReadPDU читает один PDU из соединения
// Wire format: [4 байта uint32 LE = длина][данные]
func ReadPDU(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(lenBuf)
	if size == 0 || size > 64*1024 {
		return nil, fmt.Errorf("неверный размер PDU: %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

// WritePDU пишет один PDU с wire format заголовком
func WritePDU(w io.Writer, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := writeAll(w, lenBuf); err != nil {
		return err
	}
	_, err := writeAll(w, data)
	return err
}

// writeAll гарантирует что все байты записаны
func writeAll(w io.Writer, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := w.Write(data[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ListenAll создаёт 4 Unix listener'а и принимает по одному подключению
// Возвращает массив соединений [graphics, input, vchannel, control]
func ListenAll() ([]net.Conn, error) {
	os.MkdirAll(SocketDir, 0700)

	listeners := make([]net.Listener, ChannelCount)
	conns := make([]net.Conn, ChannelCount)

	// Создаём все listener'ы
	for i := 0; i < ChannelCount; i++ {
		path := SocketDir + "/" + ChannelNames[i] + ".sock"
		os.Remove(path) // убираем старый если был

		ln, err := net.Listen("unix", path)
		if err != nil {
			return conns, fmt.Errorf("listen %s: %w", path, err)
		}
		listeners[i] = ln
		log.Printf("bridge: слушаем канал %s", ChannelNames[i])
	}

	// Принимаем подключения
	for i := 0; i < ChannelCount; i++ {
		conn, err := listeners[i].Accept()
		if err != nil {
			return conns, fmt.Errorf("accept %s: %w", ChannelNames[i], err)
		}
		conns[i] = conn
		listeners[i].Close()
		log.Printf("bridge: канал %s подключён", ChannelNames[i])
	}

	return conns, nil
}

func forwardPDUs(wg *sync.WaitGroup, src io.Reader, dst io.Writer,
	name string, direction string) {
	defer wg.Done()

	for {
		pdu, err := ReadPDU(src)
		if err != nil {
			log.Printf("[%s] read: %v", name, err)
			return
		}

		if err := WritePDU(dst, pdu); err != nil {
			log.Printf("[%s] write: %v", name, err)
			return
		}

		log.Printf("[%s] %s %d bytes",
			name,
			direction,
			len(pdu),
		)
	}
}

func BridgeChannels(
	unixConns []net.Conn,
	quicStreams []*quic.Stream,
) {
	var wg sync.WaitGroup

	for i := 0; i < ChannelCount; i++ {
		wg.Add(2)

		unixConn := unixConns[i]
		quicStream := quicStreams[i]
		name := ChannelNames[i]

		go forwardPDUs(
			&wg,
			unixConn,
			quicStream,
			name,
			"unix→quic",
		)

		go forwardPDUs(
			&wg,
			quicStream,
			unixConn,
			name,
			"quic→unix",
		)
	}

	log.Printf("все каналы запущены")
	wg.Wait()
}
