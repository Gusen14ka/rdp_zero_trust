package quicconn

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICConn оборачивает quic.Stream и quic.Connection в интерфейс net.Conn.
// quic.Stream содержит данные, quic.Connection содержит адреса —
// net.Conn требует и то и другое, поэтому нужна обёртка.

// Read/Write/SetDeadline — делегируем стриму
// LocalAddr/RemoteAddr   — делегируем connection
type QUICConn struct {
	stream *quic.Stream
	conn   *quic.Conn
}

func New(conn *quic.Conn, stream *quic.Stream) net.Conn {
	return &QUICConn{
		stream: stream,
		conn:   conn,
	}
}

func (c *QUICConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *QUICConn) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

// Close закрывает исходящее направление стрима (FIN).
// В QUIC stream.Close() = half-close = аналог TCP CloseWrite.
// Полная отмена стрима — через CancelRead/CancelWrite, но нам это не нужно.
func (c *QUICConn) Close() error {
	return c.stream.Close()
}

// CloseWrite нужен для совместимости с pipe.halfCloser —
// pipe.Pipe вызывает CloseWrite когда одна сторона закончила писать.
func (c *QUICConn) CloseWrite() error {
	return c.stream.Close()
}

func (c *QUICConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *QUICConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *QUICConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *QUICConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *QUICConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}
