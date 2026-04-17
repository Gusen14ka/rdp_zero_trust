//go:build !windows

package pipe

import (
	"context"
	"syscall"

	"golang.org/x/sys/unix"
)

// noDelayControlContext применяется к сокету до установки соединения.
// Отключает алгоритм Нейгла (TCP_NODELAY) на уровне syscall —
// единственный способ применить это к TLS соединениям,
// где net.TCPConn недоступен напрямую.
// Принимает context — позволяет отменить установку соединения извне.
func noDelayControlContext(_ context.Context, network, address string, c syscall.RawConn) error {
	var setSockOptErr error

	err := c.Control(func(fd uintptr) {
		setSockOptErr = unix.SetsockoptInt(
			int(fd),
			unix.IPPROTO_TCP,
			unix.TCP_NODELAY,
			1,
		)
	})

	if err != nil {
		return err
	}

	return setSockOptErr
}
