package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"rdp_zero_trust/internal/admin"
	"rdp_zero_trust/internal/config"
	enrollServer "rdp_zero_trust/internal/enrollment/server"
	"rdp_zero_trust/internal/identity"
	"rdp_zero_trust/internal/metrics"
	"rdp_zero_trust/internal/pipe"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/quicconn"
	"rdp_zero_trust/internal/session"
)

var (
	cfg        *config.Config
	sessions   *session.Store
	sessionTTL time.Duration

	// sessionMetrics хранит метрики активных сессий
	sessionMetrics sync.Map // map[sessionID]*metrics.StreamMetrics
)

func main() {
	controlAddr := flag.String("control", ":9000", "адрес control plane")
	dataTCPAddr := flag.String("data", ":9001", "адрес data plane (TCP)")
	dataQUICAddr := flag.String("quic", ":9002", "адрес data plane (QUIC)")
	adminAddr := flag.String("admin", "0.0.0.0:9999", "адрес admin HTTP (только localhost)")
	enrollAddr := flag.String("enroll", ":9003", "адрес enrollment сервера")
	configPath := flag.String("config", "configs/config.json", "путь к конфигу")
	caCertPath := flag.String("ca-cert", "certs/ca.crt", "сертификат CA")
	caKeyPath := flag.String("ca-key", "certs/ca.key", "приватный ключ CA")
	certPath := flag.String("cert", "certs/server.crt", "сертификат сервера")
	keyPath := flag.String("key", "certs/server.key", "ключ сервера")
	ttl := flag.Duration("ttl", session.DefaultTTL, "TTL сессии")
	flag.Parse()

	sessionTTL = *ttl

	// Запускаем оба листенера параллельно
	var err error
	cfg, err = config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("загружено машин: %d, пользователей: %d", len(cfg.Machines), len(cfg.Users))

	sessions = session.NewStore()

	// Enrollment сервер
	enrollSrv, err := enrollServer.NewServer(*caKeyPath, "certs/ca.crt")
	if err != nil {
		log.Fatalf("enrollment server: %v", err)
	}
	// Регистрируем способ аутентификации — пароль
	// Чтобы добавить TOTP: enrollSrv.RegisterAuth(enrollment.NewTOTPAuthHandler(...))
	enrollSrv.RegisterAuth(enrollServer.NewPasswordAuthHandler(cfg))
	go func() {
		if err := enrollSrv.Start(*enrollAddr, *certPath, *keyPath); err != nil {
			log.Fatalf("enrollment: %v", err)
		}
	}()

	// Запускаем admin HTTP сервер
	adminSrv := admin.NewServer(sessions, &sessionMetrics)
	go adminSrv.Start(*adminAddr)

	go listenControl(*controlAddr, *certPath, *keyPath, *caCertPath)
	go listenTcpData(*dataTCPAddr, *certPath, *keyPath)
	listenQuicData(*dataQUICAddr, *certPath, *keyPath)
}

// listenControl — принимает управляющие tcp соединения на data plane
func listenControl(addr, certPath, keyPath, caCertPath string) {
	// Загружаем сертификат сервера
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("tls cert: %v", err)
	}

	// Загружаем сертификат CA и создаем пул
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("read ca: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("parse ca cert")
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,               // только TLS 1.3
		ClientAuth:   tls.RequireAndVerifyClientCert, // Для соединения требовать и проверять клиентский сертификат
		ClientCAs:    caPool,                         // Предоставляем CA который подпиал клиентский сертификат
	}

	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		log.Fatalf("control listen: %v", err)
	}
	log.Printf("control plane (mTLS) слушает %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("control accept error: %v", err)
			continue
		}
		// У нас tls поверх соединения - берём его
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			conn.Close()
			log.Printf("client-control plane is not tls")
			continue
		}
		go handleControl(tlsConn)
	}
}

// handleControl — обрабатывает одного клиента на control plane
func handleControl(tlsConn *tls.Conn) {
	c := proto.NewConn(tlsConn)
	defer c.Close()

	log.Printf("новое control-соединение от %s", tlsConn.RemoteAddr())

	// Из-за ленивой оптимизации go может провести handshake после Accept
	// Говорим ему сделать его прямо сейчас, тк нам нужно взять сертификат client
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("handshake failed: %v", err)
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("no client certificate")
		return
	}

	cert := state.PeerCertificates[0]

	certUsername, err := identity.UsernameFromCert(cert)
	if err != nil {
		log.Printf("invalid certificate: %v", err)
		return
	}

	log.Printf("control: подключился %s (из SAN)", certUsername)

	// Шаг 1: HELLO <username> <password>
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgHello || len(args) < 2 {
		c.Send(proto.MsgError, "expected HELLO <username> <password>")
		return
	}
	username, password := args[0], args[1]

	// Проверка 1: SAN vs сообщение
	if username != certUsername {
		c.Send(proto.MsgError, "certificate username mismatch")
		log.Printf("mTLS mismatch: cert=%s msg=%s", certUsername, username)
		return
	}

	// Проверка 2: пароль (второй фактор)
	if !cfg.Authenticate(username, password) {
		c.Send(proto.MsgError, "invalid credentials")
		log.Printf("[%s] неверный пароль", username)
		return
	}

	log.Printf("[%s] аутентифицирован (mTLS + пароль)", username)
	c.Send(proto.MsgOK)

	// Шаг 2: CONNECT <machine_id> или BENCH
	msgType, args, err = c.Recv()
	if err != nil {
		c.Send(proto.MsgError, "read error")
		return
	}

	switch msgType {
	case proto.MsgConnect:
		handleConnectRequest(c, args, username, sessionTTL)
	case proto.MsgBench:
		handleBenchRequest(c, username)
	default:
		c.Send(proto.MsgError, "expected CONNECT or BENCH")
	}
}

func handleConnectRequest(c *proto.Conn, args []string, username string, ttl time.Duration) {
	if len(args) == 0 {
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
	sess, err := sessions.Create(username, machineID, targetAddr, ttl)
	if err != nil {
		c.Send(proto.MsgError, "internal error")
		return
	}

	log.Printf("[%s] сессия %s -> %s (TTL: %v, истекает: %s)",
		username, sess.ID, machineID, ttl, sess.ExpiresAt.Format("15:04:05"))
	c.Send(proto.MsgOK, sess.ID)

	// Ждём одно из 3 событий:
	// 1. TTL истёк
	// 2. Сессия отозвана admin API
	// 3. Клиент сам отключился
	ttlTimer := time.NewTimer(time.Until(sess.ExpiresAt))
	defer ttlTimer.Stop()

	// Канал для отслеживания закрытия соединения клиентов
	clientGone := make(chan struct{})
	go func() {
		// Блокируемся на чтении — когда клиент закроет соединение получим ошибку
		c.Recv()
		close(clientGone)
	}()

	select {
	case <-ttlTimer.C:
		log.Printf("сессия %s истекла по TTL", sess.ID)
		c.Send(proto.MsgError, "session expired")
	case <-sess.Done():
		log.Printf("сессия %s отозвана", sess.ID)
		c.Send(proto.MsgError, "session revoked")
	case <-clientGone:
		log.Printf("сессия %s: клиент отключился", sess.ID)
	}

	sessions.Delete(sess.ID)
	log.Printf("сессия %s завершена (удалена)", sess.ID)
}

func handleBenchRequest(c *proto.Conn, username string) {
	// Создаём benchmark сессию — без привязки к машине
	sess, err := sessions.Create(username, "benchmark", "benchmark", sessionTTL)
	if err != nil {
		c.Send(proto.MsgError, "internal error")
		return
	}

	log.Printf("[%s] benchmark сессия %s", username, sess.ID)
	c.Send(proto.MsgOK, sess.ID)

	// Держим открытым пока клиент не отключится
	clientGone := make(chan struct{})
	go func() {
		c.Recv()
		close(clientGone)
	}()

	select {
	case <-sess.Done():
		c.Send(proto.MsgError, "session revoked")
	case <-clientGone:
		log.Printf("benchmark сессия %s завершена", sess.ID)
	}

	sessions.Delete(sess.ID)
}

// listenTCPData — принимает tcp data-соединения и проксирует на целевую машину
func listenTcpData(addr, certPath, keyPath string) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("data tls cert: %v", err)
	}
	tlsCfg := tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", addr, &tlsCfg)
	if err != nil {
		log.Fatalf("data listen: %v", err)
	}
	log.Printf("data plane (TLS) слушает %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("data accept: %v", err)
			continue
		}
		go handleTcpData(conn)
	}
}

// listenQUICData — принимает QUIC соединения на data plane
func listenQuicData(addr, certPath, keyPath string) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("quic tls cert: %v", err)
	}

	// TLS конфиг для QUIC — указываем NextProtos (ALPN)
	// это обязательно для QUIC, идентифицирует наш протокол
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"rdp-zero-trust"},
	}

	ln, err := quic.ListenAddr(addr, tlsCfg, &quic.Config{
		// Максимальное время простоя соединения
		MaxIdleTimeout: 5 * time.Minute,
		// Разрешаем keepalive — QUIC будет слать PING фреймы
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		log.Fatalf("quic listen: %v", err)
	}
	log.Printf("data plane (QUIC) слушает %s", addr)

	for {
		// Принимаем новое QUIC соединение
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Printf("quic accept: %v", err)
			continue
		}
		go handleQuicData(conn)
	}
}

// handleTcpData — обработка обычного TLS/TCP соединения
func handleTcpData(raw net.Conn) {
	// raw уже реализует net.Conn (внутри это tls.Conn)
	// дополнительной обёртки не требуется
	handleDataConn(raw, "data")
}

// handleQUIC — обрабатывает одно QUIC соединение
// Одно соединение = один стрим = одна RDP сессия
func handleQuicData(conn *quic.Conn) {
	// Закрываем QUIC соединение при выходе
	defer conn.CloseWithError(0, "done")

	// Принимаем стрим от клиента (в QUIC данные идут через стримы)
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("quic accept stream: %v", err)
		return
	}
	defer stream.Close()

	// Оборачиваем (conn + stream) в net.Conn-подобный интерфейс
	// чтобы дальше использовать ту же логику, что и для TCP
	qconn := quicconn.New(conn, stream)

	// Передаём в общий обработчик
	handleDataConn(qconn, "quic")
}

func handleDataConn(conn net.Conn, protoName string) {
	defer conn.Close()

	// Убираем задержки и Нейгла
	pipe.TuneConn(conn)
	// Оборачиваем соединение в наш протокол (чтение/запись сообщений)
	c := proto.NewConn(conn)

	// Ожидаем первое сообщение от клиента: SESSION <id>
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgSession || len(args) == 0 {
		log.Printf("%s: ожидал SESSION, получил: %v %v err=%v", protoName, msgType, args, err)
		c.Send(proto.MsgError, "invalid session request")
		return
	}
	sessionID := args[0]

	// Ищем сессию, которую ранее создали на control-plane
	sess, ok := sessions.Get(sessionID)
	if !ok {
		log.Printf("%s: неизвестная сессия %s", protoName, sessionID)
		c.Send(proto.MsgError, "session not found")
		return
	}

	// Benchmark сессия — отдельный обработчик без подключения к машине
	if sess.MachineID == "benchmark" {
		handleBenchmarkData(conn, c, sess, sessionID)
		return
	}

	log.Printf("%s: [%s] старт -> %s", protoName, sessionID[:8], sess.TargetAddr)

	// Подключаемся к целевой машине (RDP сервер или любой TCP target)
	target, err := net.Dial("tcp", sess.TargetAddr)
	if err != nil {
		log.Printf("%s: не могу подключиться к %s: %v", protoName, sess.TargetAddr, err)
		c.Send(proto.MsgError, "target connection failed")
		return
	}
	defer target.Close()

	// Оптимизируем TCP-соединение (nodelay, буферы и т.п.)
	pipe.TuneConn(target)

	// Создаём коллектор метрик для этой сессии
	// Измеряем входящий трафик (клиент → сервер)
	// Обоснование: участок сервер → машина симметричен и находится
	// в локальной сети без деградации (см. методологию)
	m := metrics.NewStreamMetrics()
	sessionMetrics.Store(sessionID, m)
	defer sessionMetrics.Delete(sessionID)

	// Сообщаем клиенту, что всё готово и можно начинать проксирование данных
	c.Send(proto.MsgOK)

	// MeteredReader прозрачно считает метрики входящего потока
	meteredRaw := metrics.NewMeteredConn(conn, m)

	// Дальше просто проксируем трафик в обе стороны до завершения сессии
	// conn — клиент (TLS или QUIC)
	// target — целевой сервер
	err1, err2 := pipe.PipeWithDone(meteredRaw, target, sess.Done())

	log.Printf("%s: [%s] завершено err1=%v err2=%v", protoName, sessionID[:8], err1, err2)
}

// handleBenchmarkData - обработка бенчмарка (только client-server)
// принимает уже созданный proto.Conn
func handleBenchmarkData(raw net.Conn, c *proto.Conn, sess *session.Session, sessionID string) {
	m := metrics.NewStreamMetrics()
	sessionMetrics.Store(sessionID, m)
	defer sessionMetrics.Delete(sessionID)

	c.Send(proto.MsgOK)
	log.Printf("bench: [%s] старт", sessionID[:8])

	meteredRaw := metrics.NewMeteredConn(raw, m)
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-sess.Done():
			log.Printf("bench: [%s] сессия отозвана", sessionID[:8])
			return
		default:
		}
		raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := meteredRaw.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("bench: [%s] завершено: %v", sessionID[:8], err)
			return
		}
	}
}
