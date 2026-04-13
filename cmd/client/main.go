package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"rdp_zero_trust/internal/proto"
)

func main() {
	serverAddr := flag.String("server", "localhost:9000", "адрес control plane")
	dataAddr := flag.String("data", "localhost:9001", "адрес data plane")
	localAddr := flag.String("local", "localhost:13389", "локальный адрес для mstsc")
	username := flag.String("user", "user1", "имя пользователя")
	password := flag.String("pass", "secret", "пароль")
	machineID := flag.String("machine", "machine1", "ID машины")
	flag.Parse()

	// Шаг 1: control plane — аутентификация и запрос машины
	sessionID, err := authenticate(*serverAddr, *username, *password, *machineID)
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

// authenticate подключается к control plane и получает адрес целевой машины
func authenticate(serverAddr, username, password, machineID string) (string, error) {
	raw, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return "", err
	}
	// Намеренно не закрываем — держим сессию живой
	// В продакшне это горутина с keepalive

	c := proto.NewConn(raw)

	// HELLO
	c.Send(proto.MsgHello, username, password)
	msgType, _, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		return "", fmt.Errorf("hello rejected")
	}

	// CONNECT
	c.Send(proto.MsgConnect, machineID)
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK || len(args) == 0 {
		return "", fmt.Errorf("connect rejected: %v", args)
	}

	return args[0], nil // адрес целевой машины
}

// tunnel: принимает соединение от mstsc, пробрасывает через data plane
func tunnel(local net.Conn, dataAddr, sessionID string) {
	defer local.Close()

	raw, err := net.Dial("tcp", dataAddr)
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
	log.Printf("tunnel: сессия подтверждена, начинаем передачу данных")

	// Фаза 2: Binary transfer — используем raw соединение (буфер Proto уже прочитан)
	// Ждём завершения обоих направлений
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(raw, local)
		raw.(*net.TCPConn).CloseWrite()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(local, raw)
		local.(*net.TCPConn).CloseWrite()
		done <- struct{}{}
	}()

	<-done
	<-done
	log.Printf("tunnel: сессия завершена")
}
