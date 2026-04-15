package pipe

import (
	"io"
	"net"
)

// Создаём интерфейс для корретной работы с type assertion

type halfCloser interface {
	CloseWrite() error
}

func closeWrite(c net.Conn) {
	if hc, ok := c.(halfCloser); ok {
		hc.CloseWrite()
	} else {
		c.Close()
	}
}

// Ждём завершения обоих направлений
// io.Copy в цикле копирует данные (байты) до EOF соединения
// когда копирование закончилось мы закрываем соединение (в которое копирутеся)
// таким образом data_plane и rdp поймут, где конец
// Мы не закрываем сразу соединение, тк это убъёт сразу оба направления, а наш приёмник мог ещё не успеть всё прочитать

func Pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(b, a)
		closeWrite(b)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(a, b)
		closeWrite(a)
		done <- struct{}{}
	}()

	<-done
	<-done
}
