package proto

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Типы сообщений
const (
	MsgHello   = "HELLO"
	MsgConnect = "CONNECT"
	MsgBench   = "BENCH"
	MsgSession = "SESSION"
	MsgOK      = "OK"
	MsgError   = "ERROR"
)

// Таймауты
const (
	TimeoutRecv = 30
	TimeoutSend = 10
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
	defer c.conn.SetWriteDeadline(time.Time{})
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

// BenchParams — параметры сетевой деградации для эксперимента.
// Передаются клиентом серверу в рамках BENCH handshake.
// Нулевые значения означают отсутствие ограничения.
type BenchParams struct {
	LossPct  float64 // потери пакетов в процентах, например 2.0
	DelayMs  int     // базовая задержка в миллисекундах
	JitterMs int     // джиттер ±ms (нормальное распределение)
	RateMbit float64 // ограничение bandwidth в Mbit/s, 0 = без ограничения
}

// Encode сериализует параметры в строку для передачи через proto.Send
// Формат: "loss=2.0,delay=50,jitter=20,rate=0"
func (p BenchParams) Encode() string {
	return fmt.Sprintf("loss=%.2f,delay=%d,jitter=%d,rate=%.2f",
		p.LossPct, p.DelayMs, p.JitterMs, p.RateMbit)
}

// DecodeBenchParams парсит строку обратно в BenchParams
func DecodeBenchParams(s string) (BenchParams, error) {
	var p BenchParams
	parts := strings.Split(s, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return p, fmt.Errorf("неверный формат: %s", part)
		}
		k, v := kv[0], kv[1]
		switch k {
		case "loss":
			val, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return p, fmt.Errorf("loss: %w", err)
			}
			p.LossPct = val
		case "delay":
			val, err := strconv.Atoi(v)
			if err != nil {
				return p, fmt.Errorf("delay: %w", err)
			}
			p.DelayMs = val
		case "jitter":
			val, err := strconv.Atoi(v)
			if err != nil {
				return p, fmt.Errorf("jitter: %w", err)
			}
			p.JitterMs = val
		case "rate":
			val, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return p, fmt.Errorf("rate: %w", err)
			}
			p.RateMbit = val
		default:
			return p, fmt.Errorf("неизвестный параметр: %s", k)
		}
	}
	return p, nil
}
