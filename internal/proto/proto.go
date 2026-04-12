package proto

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

// Типы сообщений
const (
	MsgHello   = "HELLO"
	MsgConnect = "CONNECT"
	MsgSession = "SESSION"
	MsgOK      = "OK"
	MsgError   = "ERROR"
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
	_, err := fmt.Fprint(c.conn, line)
	return err
}

// Recv читает одну строку и разбивает на тип + аргументы
func (c *Conn) Recv() (msgType string, args []string, err error) {
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
