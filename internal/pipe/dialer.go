package pipe

import (
	"net"
	"time"
)

// NoDelayDialer создаёт dialer с отключённым алгоритмом Нейгла и настроенным keepalive.
// Используется для всех исходящих TLS соединений где TuneConn недоступен.
// Использует ControlContext вместо Control для поддержки отмены через context.
func NoDelayDialer(keepAliveTime time.Duration) *net.Dialer {
	return &net.Dialer{
		KeepAlive:      keepAliveTime,
		ControlContext: noDelayControlContext,
	}
}
