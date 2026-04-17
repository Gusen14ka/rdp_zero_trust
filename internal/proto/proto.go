package proto

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Типы сообщений
const (
	MsgHello   = "HELLO"
	MsgConnect = "CONNECT"
	MsgSession = "SESSION"
	MsgPing    = "PING"
	MsgPong    = "PONG"
	MsgOK      = "OK"
	MsgError   = "ERROR"
)

// Таймауты
const (
	TimeoutRecv = 30
	TimeoutSend = 30
)

// Conn — обёртка над net.Conn с буферизованным чтением
type Conn struct {
	conn   net.Conn
	reader *bufio.Reader
}

func NewConn(c net.Conn) *Conn {
	return &Conn{
		conn:   c,
		reader: bufio.NewReader(c),
	}
}

// Send отправляет сообщение вида "TYPE arg1 arg2\n"
func (c *Conn) Send(msgType string, args ...string) error {
	parts := append([]string{msgType}, args...)
	line := strings.Join(parts, " ") + "\n"
	c.conn.SetWriteDeadline(time.Now().Add(TimeoutSend * time.Second))
	_, err := fmt.Fprint(c.conn, line)
	return err
}

// Recv читает одну строку и разбивает на тип + аргументы
func (c *Conn) Recv() (msgType string, args []string, err error) {
	//c.conn.SetReadDeadline(time.Now().Add(TimeoutRecv * time.Second))
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	line = strings.TrimSpace(line)
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("empty message")
	}
	return parts[0], parts[1:], nil
}

// Close закрывает соединение
func (c *Conn) Close() error {
	return c.conn.Close()
}

// RawConn возвращает исходный net.Conn (нужен для data plane)
func (c *Conn) RawConn() net.Conn {
	return c.conn
}

// BufferedReader возвращает bufio.Reader (чтобы передать буферизованные данные в pipe)
func (c *Conn) BufferedReader() *bufio.Reader {
	return c.reader
}

// DataPlaneConn создаёт специальный reader который сначала читает из буфера proto.Conn, потом из соединения
// Это необходимо чтобы не потерять данные которые буфер мог прочитать при handshake
type dataPlaneConn struct {
	buffered *bufio.Reader // bufio.Reader с буферизованными данными
	conn     net.Conn      // сырое соединение
	bufUsed  bool          // флаг что мы уже использовали буфер
}

func (dpc *dataPlaneConn) Read(b []byte) (int, error) {
	if !dpc.bufUsed {
		// Сначала читаем из буфера
		n, err := dpc.buffered.Read(b)
		if err == io.EOF || n == len(b) {
			dpc.bufUsed = true
		}
		if n > 0 {
			return n, nil
		}
		dpc.bufUsed = true
		if err != nil && err != io.EOF {
			return 0, err
		}
	}
	// Потом читаем из соединения
	return dpc.conn.Read(b)
}

func (dpc *dataPlaneConn) Write(b []byte) (int, error) {
	return dpc.conn.Write(b)
}

func (dpc *dataPlaneConn) Close() error {
	return dpc.conn.Close()
}

func (dpc *dataPlaneConn) LocalAddr() net.Addr {
	return dpc.conn.LocalAddr()
}

func (dpc *dataPlaneConn) RemoteAddr() net.Addr {
	return dpc.conn.RemoteAddr()
}

func (dpc *dataPlaneConn) SetDeadline(t time.Time) error {
	return dpc.conn.SetDeadline(t)
}

func (dpc *dataPlaneConn) SetReadDeadline(t time.Time) error {
	return dpc.conn.SetReadDeadline(t)
}

func (dpc *dataPlaneConn) SetWriteDeadline(t time.Time) error {
	return dpc.conn.SetWriteDeadline(t)
}

func (dpc *dataPlaneConn) CloseWrite() error {
	if hc, ok := dpc.conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return dpc.conn.Close()
}

// DataPlaneConnForPipe создаёт net.Conn для pipe.Pipe который сохраняет буферизованные данные
func (c *Conn) DataPlaneConnForPipe() net.Conn {
	return &dataPlaneConn{
		buffered: c.reader,
		conn:     c.conn,
		bufUsed:  false,
	}
}
