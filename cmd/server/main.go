package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"

	"rdp_zero_trust/internal/config"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/session"
)

var (
	cfg      *config.Config
	sessions *session.Store
)

func main() {
	controlAddr := flag.String("control", ":9000", "адрес control plane")
	dataAddr := flag.String("data", ":9001", "адрес data plane")
	configPath := flag.String("config", "configs/config.json", "путь к конфигу")
	certPath := flag.String("cert", "certs/server.crt", "сертификат сервера")
	keyPath := flag.String("key", "certs/server.key", "ключ сервера")
	flag.Parse()

	// Запускаем оба листенера параллельно
	var err error
	cfg, err = config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("загружено машин: %d, пользователей: %d", len(cfg.Machines), len(cfg.Users))

	sessions = session.NewStore()

	go listenControl(*controlAddr, *certPath, *keyPath)
	listenData(*dataAddr)
}

// listenControl — принимает управляющие соединения
func listenControl(addr string, certPath, keyPath string) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("tls cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // только TLS 1.3
	}

	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		log.Fatalf("control listen: %v", err)
	}
	log.Printf("control plane (TLS) слушает %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("control accept: %v", err)
			continue
		}
		go handleControl(conn)
	}
}

// handleControl — обрабатывает одного клиента на control plane
func handleControl(raw net.Conn) {
	c := proto.NewConn(raw)
	defer c.Close()

	log.Printf("новое control-соединение от %s", raw.RemoteAddr())

	// Шаг 1: HELLO <username> <password>
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgHello || len(args) < 2 {
		c.Send(proto.MsgError, "expected HELLO <username> <password>")
		return
	}
	username, password := args[0], args[1]

	if !cfg.Authenticate(username, password) {
		c.Send(proto.MsgError, "invalid credentials")
		log.Printf("[%s] неверный пароль", username)
		return
	}
	log.Printf("[%s] аутентифицирован", username)
	c.Send(proto.MsgOK)

	// Шаг 2: CONNECT <machine_id>
	msgType, args, err = c.Recv()
	if err != nil || msgType != proto.MsgConnect || len(args) == 0 {
		c.Send(proto.MsgError, "expected CONNECT <machine_id>")
		return
	}
	machineID := args[0]

	if !cfg.CanAccess(username, machineID) {
		c.Send(proto.MsgError, "access denied")
		log.Printf("[%s] нет доступа к %s", username, machineID)
		return
	}

	targetAddr, ok := cfg.Machines[machineID]
	if !ok {
		c.Send(proto.MsgError, "unknown machine")
		return
	}

	// Создаём сессию
	sess, err := sessions.Create(username, machineID, targetAddr)
	if err != nil {
		c.Send(proto.MsgError, "internal error")
		log.Printf("create session: %v", err)
		return
	}

	log.Printf("[%s] сессия %s -> %s (%s)", username, sess.ID, machineID, targetAddr)
	c.Send(proto.MsgOK, sess.ID)

	// Держим control-соединение открытым — в будущем здесь будет TTL и сигналы
	// Пока просто ждём закрытия
	c.Recv()
	sessions.Delete(sess.ID)
	log.Printf("сессия %s завершена", sess.ID)
}

// listenData — принимает data-соединения и проксирует на целевую машину
func listenData(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("data listen: %v", err)
	}
	log.Printf("data plane слушает %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("data accept: %v", err)
			continue
		}
		go handleData(conn)
	}
}

// handleData — первая строка от клиента: SESSION <id>
func handleData(raw net.Conn) {
	c := proto.NewConn(raw)
	defer raw.Close()

	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgSession || len(args) == 0 {
		log.Printf("data: ожидал SESSION <id>")
		c.Send(proto.MsgError, "invalid session request")
		return
	}
	sessionID := args[0]

	sess, ok := sessions.Get(sessionID)
	if !ok {
		log.Printf("data: неизвестная сессия %s", sessionID)
		c.Send(proto.MsgError, "session not found")
		return
	}

	log.Printf("data: сессия %s -> %s", sessionID, sess.TargetAddr)

	target, err := net.Dial("tcp", sess.TargetAddr)
	if err != nil {
		log.Printf("data: не могу подключиться к %s: %v", sess.TargetAddr, err)
		c.Send(proto.MsgError, "target connection failed")
		return
	}
	defer target.Close()

	// Отправляем подтверждение: сервер готов к передаче RDP данных
	c.Send(proto.MsgOK)

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(target, raw)
		if tcp, ok := target.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		io.Copy(raw, target)
		if tcp, ok := raw.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}
