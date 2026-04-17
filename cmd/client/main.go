package main

import (
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
)

func main() {
	serverAddr := flag.String("server", "192.168.0.21:9000", "адрес control plane")
	dataAddr := flag.String("data", "192.168.0.21:9001", "адрес data plane")
	localAddr := flag.String("local", "localhost:13389", "локальный адрес для mstsc")
	username := flag.String("user", "user1", "имя пользователя")
	password := flag.String("pass", "secret", "пароль")
	machineID := flag.String("machine", "machine1", "ID машины")
	caPath := flag.String("ca", "certs/ca.crt", "корневой сертификат CA")
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
		go tunnel(local, *dataAddr, sessionID)
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
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
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
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			if err := c.Send(proto.MsgPing); err != nil {
				log.Printf("control keepalive send failed: %v", err)
				return
			}

			msgType, _, err := c.Recv()
			if err != nil {
				log.Printf("control keepalive recv failed: %v", err)
				return
			}
			if msgType != proto.MsgPong {
				log.Printf("control keepalive: unexpected msgType=%s", msgType)
				return
			}

			select {
			case <-ticker.C:
				continue
			}
		}
	}()

	return sessionID, nil
}

// tunnel: принимает соединение от mstsc, пробрасывает через data plane
func tunnel(local net.Conn, dataAddr, sessionID string) {
	defer local.Close()
	log.Printf("tunnel: [%s] НАЧАЛО - новое соединение от %s", sessionID[:8], local.RemoteAddr())

	raw, err := net.Dial("tcp", dataAddr)
	if err != nil {
		log.Printf("tunnel: dial data plane: %v", err)
		return
	}
	if tcpConn, ok := raw.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
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
	log.Printf("tunnel: [%s] сессия подтверждена, начинаем передачу данных", sessionID[:8])

	// Фаза 2: Binary transfer — используем DataPlaneConnForPipe() чтобы сохранить буферизованные данные
	log.Printf("tunnel: [%s] старт data transfering", sessionID[:8])
	err1, err2 := pipe.Pipe(c.DataPlaneConnForPipe(), local)
	log.Printf("tunnel: [%s] ЗАВЕРШЕНО data transfering, err data->local=%v err local->data=%v", sessionID[:8], err1, err2)
}
