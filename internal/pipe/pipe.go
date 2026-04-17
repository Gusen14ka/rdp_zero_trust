package pipe

import (
	"io"
	"log"
	"net"
	"time"
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

func TuenConn(c net.Conn) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	tcp.SetKeepAlive(true)
	tcp.SetKeepAlivePeriod(10 * time.Second)
	tcp.SetNoDelay(true)
}

// Ждём завершения обоих направлений
// io.Copy в цикле копирует данные (байты) до EOF соединения
// когда копирование закончилось мы закрываем соединение (в которое копирутеся)
// таким образом data_plane и rdp поймут, где конец
// Мы не закрываем сразу соединение, тк это убъёт сразу оба направления, а наш приёмник мог ещё не успеть всё прочитать

func Pipe(a, b net.Conn) (errAB, errBA error) {
	done := make(chan struct{}, 2)

	go func() {
		_, err := io.Copy(b, a)
		if err != nil {
			log.Printf("pipe: %s -> %s copy error: %v", a.RemoteAddr(), b.RemoteAddr(), err)
		} else {
			log.Printf("pipe: %s -> %s copy finished", a.RemoteAddr(), b.RemoteAddr())
		}
		closeWrite(b)
		errAB = err
		done <- struct{}{}
	}()

	go func() {
		_, err := io.Copy(a, b)
		if err != nil {
			log.Printf("pipe: %s <- %s copy error: %v", a.RemoteAddr(), b.RemoteAddr(), err)
		} else {
			log.Printf("pipe: %s <- %s copy finished", a.RemoteAddr(), b.RemoteAddr())
		}
		closeWrite(a)
		errBA = err
		done <- struct{}{}
	}()

	<-done
	<-done
	return errAB, errBA
}
