package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"rdp_zero_trust/internal/bridge"
	"rdp_zero_trust/internal/loading"
	"rdp_zero_trust/internal/pipe"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/quicconn"

	"github.com/quic-go/quic-go"
)

func main() {
	serverAddr := flag.String("server", "192.168.0.21:9000", "адрес control plane")
	dataAddr := flag.String("data", "192.168.0.21:9001", "адрес data plane")
	//dataQUICAddr := flag.String("quic", "192.168.0.21:9002", "адрес data plane (QUIC)")
	localAddr := flag.String("local", "localhost:13389", "локальный адрес для mstsc/freerdp")
	username := flag.String("user", "user1", "имя пользователя")
	password := flag.String("pass", "secret", "пароль")
	machineId := flag.String("machine", "machine1", "Id машины")
	caPath := flag.String("ca", "certs/ca.crt", "корневой сертификат CA")
	clientCertPath := flag.String("cert", "certs/client_cert.crt", "клиентский сертификат")
	clientKeyPath := flag.String("key", "certs/client_key.key", "приватный ключ клиента")
	transport := flag.String("transport", "tcp", "транспорт data plane: tcp или quic")
	mode := flag.String("mode", "freerdp", "режим работы: mstsc или freerdp")
	flag.Parse()

	// Шаг 1: control plane — аутентификация и запрос машины
	sessionId, err := authenticate(*serverAddr, *username, *password, *machineId,
		*caPath, *clientCertPath, *clientKeyPath, *mode)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	log.Printf("сессия получена: %s", sessionId)

	switch *mode {
	case "mstsc":
		runMstscMode(*localAddr, *dataAddr, *transport, sessionId, *caPath)
	case "freerdp":
		runFreerdpMode(*dataAddr, sessionId, *caPath)
	}

}

// Реализация пайплайна с подключением в freerdp
func runFreerdpMode(dataAddr, sessionID, caPath string) {
	log.Printf("режим freerdp: ждём подключения xfreerdp-quic...")

	// Шаг 1: принимаем Unix сокеты от xfreerdp-quic
	unixConns, err := bridge.ListenAll()
	if err != nil {
		log.Fatalf("bridge listen: %v", err)
	}
	defer func() {
		for _, c := range unixConns {
			c.Close()
		}
	}()
	log.Printf("все каналы подключены, устанавливаем QUIC...")

	// TODO: 2 и 3 шаги вынести в отдельную функцию и объединить с tunnelQUIC
	// Шаг 2: устанавливаем QUIC соединение с сервером
	tlsCfg, err := loading.LoadTLSConfig(caPath)
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}
	tlsCfg.NextProtos = []string{"rdp-zero-trust"}

	conn, err := quic.DialAddr(context.Background(), dataAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  5 * time.Minute,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		log.Fatalf("quic dial: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	// Шаг 3: SESSION handshake на контрольном стриме (стрим 0)
	ctrlStream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatalf("open ctrl stream: %v", err)
	}
	qctrl := quicconn.New(conn, ctrlStream)
	c := proto.NewConn(qctrl)
	c.Send(proto.MsgSession, sessionID)
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		if len(args) > 0 {
			log.Fatalf("сервер отклонил: %s", args[0])
		}
		log.Fatalf("handshake failed: %v", err)
	}
	log.Printf("сессия подтверждена, открываем каналы...")

	// Шаг 4: открываем отдельный QUIC стрим для каждого канала
	quicStreams := make([]*quic.Stream, bridge.ChannelCount)
	for i := 0; i < bridge.ChannelCount; i++ {
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			log.Fatalf("open stream %s: %v", bridge.ChannelNames[i], err)
		}
		quicStreams[i] = stream
		log.Printf("стрим %s открыт (id=%d)",
			bridge.ChannelNames[i], stream.StreamID())
	}

	// Шаг 5: для каждого канала запускаем пересылку в обе стороны
	bridge.BridgeChannels(unixConns, quicStreams)
	log.Printf("runFreerdpMode завершён")
}

// Релизация пайплайна с подключением в mstsc
func runMstscMode(localAddr, dataAddr, transport, sessionId, caPath string) {
	// Шаг 2: поднимаем локальный listener для mstsc
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("local listen: %v", err)
	}
	log.Printf("слушаем на %s — открывай mstsc на этот адрес", localAddr)

	for {
		local, err := ln.Accept()
		if err != nil {
			log.Printf("local accept: %v", err)
			continue
		}

		switch transport {
		case "tcp":
			go tunnelTCP(local, dataAddr, sessionId, caPath)
		case "quic":
			go tunnelQUIC(local, dataAddr, sessionId, caPath)
		}
	}
}

// authenticate подключается к control plane и получает адрес целевой машины
func authenticate(serverAddr, username, password, machineId, caPath, clientCertPath, clientKeyPath, mode string) (string, error) {
	tlsCfg, err := loading.LoadMTLSConfig(caPath, clientCertPath, clientKeyPath)
	if err != nil {
		return "", err
	}

	dialer := pipe.NoDelayDialer(30 * time.Second)
	raw, err := tls.DialWithDialer(dialer, "tcp", serverAddr, tlsCfg)
	if err != nil {
		return "", fmt.Errorf("tls dial: %w", err)
	}
	// Намеренно не закрываем — держим сессию живой
	// В продакшне это горутина с keepalive

	c := proto.NewConn(raw)

	// HELLO
	c.Send(proto.MsgHello, username, password)
	msgType, _, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		raw.Close()
		return "", fmt.Errorf("hello rejected")
	}

	// CONNECT
	c.Send(proto.MsgConnect, machineId, mode)
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK || len(args) == 0 {
		raw.Close()
		return "", fmt.Errorf("connect rejected")
	}

	sessionId := args[0]

	// Держим proto.Conn открытым до закрытия контрольного соединения
	go func() {
		defer raw.Close()
		// Ждём сообщения от сервера — это либо истечение TTL либо отзыв
		msgType, args, err := c.Recv()
		if err != nil {
			log.Printf("control: соединение закрыто")
		} else if msgType == proto.MsgError && len(args) > 0 {
			// Сервер прислал причину завершения
			log.Printf("control: сессия завершена сервером: %s", args[0])
		}
		// В продакшне здесь был бы graceful shutdown всех активных туннелей
		// Пока просто логируем — mstsc сам увидит что соединение пропало
	}()

	return sessionId, nil
}

// tunnelQUIC — QUIC версия туннеля
func tunnelQUIC(local net.Conn, quicAddr, sessionId, caPath string) {
	defer local.Close()
	log.Printf("tunnel quic: [%s] новое соединение от %s", sessionId[:8], local.RemoteAddr())

	tlsCfg, err := loading.LoadTLSConfig(caPath)
	if err != nil {
		log.Printf("tunnel quic: tls config: %v", err)
		return
	}
	// ALPN должен совпадать с сервером
	tlsCfg.NextProtos = []string{"rdp-zero-trust"}

	// Устанавливаем QUIC соединение
	conn, err := quic.DialAddr(context.Background(), quicAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  5 * time.Minute,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		log.Printf("tunnel quic: dial: %v", err)
		return
	}
	defer conn.CloseWithError(0, "done")

	// Открываем стрим внутри QUIC соединения
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("tunnel quic: open stream: %v", err)
		return
	}

	// Оборачиваем в net.Conn и делаем handshake — всё то же самое что в TCP
	qconn := quicconn.New(conn, stream)
	c := proto.NewConn(qconn)
	c.Send(proto.MsgSession, sessionId)

	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		if len(args) > 0 {
			log.Printf("tunnel quic: сервер отклонил: %s", args[0])
		} else {
			log.Printf("tunnel quic: ошибка handshake: %v", err)
		}
		return
	}
	log.Printf("tunnel quic: [%s] старт", sessionId[:8])

	tlsCfg.KeyLogWriter = keyLogWriter("quic_keylog.txt")

	err1, err2 := pipe.Pipe(qconn, local)
	log.Printf("tunnel quic: [%s] завершено err1=%v err2=%v", sessionId[:8], err1, err2)
}

// tunnel: принимает соединение от mstsc, пробрасывает через data plane
func tunnelTCP(local net.Conn, dataAddr, sessionId, caPath string) {
	defer local.Close()
	log.Printf("tunnel: [%s] НАЧАЛО - новое соединение от %s", sessionId[:8], local.RemoteAddr())

	tlsCfg, err := loading.LoadTLSConfig(caPath)
	if err != nil {
		log.Printf("tunnel: tls config: %v", err)
	}

	dialer := pipe.NoDelayDialer(10 * time.Second)
	raw, err := tls.DialWithDialer(dialer, "tcp", dataAddr, tlsCfg)
	if err != nil {
		log.Printf("tunnel: dial data plane: %v", err)
		return
	}
	defer raw.Close()

	// Фаза 1: Handshake через текстовый протокол
	c := proto.NewConn(raw)
	// Отправляем запрос сессии
	c.Send(proto.MsgSession, sessionId)
	log.Printf("tunnel: отправлен SESSION %s", sessionId)

	// ЖДЁМ ПОДТВЕРЖДЕНИЯ ОТ СЕРВЕРА перед началом передачи RDP данных
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		if msgType == proto.MsgError && len(args) > 0 {
			log.Printf("tunnel: сервер отклонил: %s", args[0])
		} else {
			log.Printf("tunnel: ошибка handshake: %v", err)
		}
		return
	}
	log.Printf("tunnel: [%s] старт", sessionId[:8])

	// Фаза 2: Binary transfer
	// После handshake буфер reader пуст — передаём raw напрямую
	log.Printf("tunnel: [%s] старт data transfering", sessionId[:8])
	err1, err2 := pipe.Pipe(raw, local)
	log.Printf("tunnel: [%s] завершено err1=%v err2=%v", sessionId[:8], err1, err2)
}

// Утилита для эксперимента (временно)
func keyLogWriter(path string) io.Writer {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("keylog: %v", err)
		return nil
	}
	return f
}
