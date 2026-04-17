//go:build windows

package pipe

import (
	"context"
	"syscall"

	"golang.org/x/sys/windows"
)

// noDelayControlContext применяется к сокету до установки соединения.
// Отключает алгоритм Нейгла (TCP_NODELAY) на уровне syscall —
// единственный способ применить это к TLS соединениям,
// где net.TCPConn недоступен напрямую.
// Принимает context — позволяет отменить установку соединения извне.
func noDelayControlContext(_ context.Context, network, address string, c syscall.RawConn) error {
	var setSockOptErr error

	err := c.Control(func(fd uintptr) {
		setSockOptErr = windows.SetsockoptInt(
			windows.Handle(fd),
			windows.IPPROTO_TCP,
			windows.TCP_NODELAY,
			1,
		)
	})

	if err != nil {
		return err
	}
	return setSockOptErr
}
