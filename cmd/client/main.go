package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"rdp_zero_trust/internal/pipe"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/quicconn"

	"github.com/quic-go/quic-go"
)

func main() {
	serverAddr := flag.String("server", "192.168.0.21:9000", "адрес control plane")
	dataAddr := flag.String("data", "192.168.0.21:9001", "адрес data plane")
	dataQUICAddr := flag.String("quic", "192.168.0.21:9002", "адрес data plane (QUIC)")
	localAddr := flag.String("local", "localhost:13389", "локальный адрес для mstsc")
	username := flag.String("user", "user1", "имя пользователя")
	password := flag.String("pass", "secret", "пароль")
	machineID := flag.String("machine", "machine1", "ID машины")
	caPath := flag.String("ca", "certs/ca.crt", "корневой сертификат CA")
	transport := flag.String("transport", "tcp", "транспорт data plane: tcp или quic")
	flag.Parse()

	// Шаг 1: control plane — аутентификация и запрос машины
	sessionID, err := authenticate(*serverAddr, *username, *password, *machineID, *caPath)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	log.Printf("сессия получена: %s", sessionID)

	// Шаг 2: поднимаем локальный listener для mstsc
	ln, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatalf("local listen: %v", err)
	}
	log.Printf("слушаем на %s — открывай mstsc на этот адрес", *localAddr)

	for {
		local, err := ln.Accept()
		if err != nil {
			log.Printf("local accept: %v", err)
			continue
		}

		switch *transport {
		case "tcp":
			go tunnelTCP(local, *dataAddr, sessionID, *caPath)
		case "quic":
			go tunnelQUIC(local, *dataQUICAddr, sessionID, *caPath)
		}
	}
}

func loadTLSConfig(caPath string) (*tls.Config, error) {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("parse CA cert")
	}

	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}, nil
}

// authenticate подключается к control plane и получает адрес целевой машины
func authenticate(serverAddr, username, password, machineID, caPath string) (string, error) {
	tlsCfg, err := loadTLSConfig(caPath)
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
	c.Send(proto.MsgConnect, machineID)
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK || len(args) == 0 {
		raw.Close()
		return "", fmt.Errorf("connect rejected")
	}

	sessionID := args[0]

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

	return sessionID, nil
}

// tunnelQUIC — QUIC версия туннеля
func tunnelQUIC(local net.Conn, quicAddr, sessionID, caPath string) {
	defer local.Close()
	log.Printf("tunnel quic: [%s] новое соединение от %s", sessionID[:8], local.RemoteAddr())

	tlsCfg, err := loadTLSConfig(caPath)
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
	c.Send(proto.MsgSession, sessionID)

	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		if len(args) > 0 {
			log.Printf("tunnel quic: сервер отклонил: %s", args[0])
		} else {
			log.Printf("tunnel quic: ошибка handshake: %v", err)
		}
		return
	}
	log.Printf("tunnel quic: [%s] старт", sessionID[:8])

	err1, err2 := pipe.Pipe(qconn, local)
	log.Printf("tunnel quic: [%s] завершено err1=%v err2=%v", sessionID[:8], err1, err2)
}

// tunnel: принимает соединение от mstsc, пробрасывает через data plane
func tunnelTCP(local net.Conn, dataAddr, sessionID, caPath string) {
	defer local.Close()
	log.Printf("tunnel: [%s] НАЧАЛО - новое соединение от %s", sessionID[:8], local.RemoteAddr())

	tlsCfg, err := loadTLSConfig(caPath)
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
	c.Send(proto.MsgSession, sessionID)
	log.Printf("tunnel: отправлен SESSION %s", sessionID)

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
	log.Printf("tunnel: [%s] старт", sessionID[:8])

	// Фаза 2: Binary transfer
	// После handshake буфер reader пуст — передаём raw напрямую
	log.Printf("tunnel: [%s] старт data transfering", sessionID[:8])
	err1, err2 := pipe.Pipe(raw, local)
	log.Printf("tunnel: [%s] завершено err1=%v err2=%v", sessionID[:8], err1, err2)
}
