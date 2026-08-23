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
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"rdp_zero_trust/internal/admin"
	"rdp_zero_trust/internal/benchproto"
	"rdp_zero_trust/internal/bridge"
	"rdp_zero_trust/internal/config"
	enrollServer "rdp_zero_trust/internal/enrollment/server"
	"rdp_zero_trust/internal/identity"
	"rdp_zero_trust/internal/metrics"
	"rdp_zero_trust/internal/netem"
	"rdp_zero_trust/internal/pipe"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/quicconn"
	"rdp_zero_trust/internal/session"
)

var (
	cfg        *config.Config
	sessions   *session.Store
	sessionTtl time.Duration

	// sessionMetrics хранит метрики активных сессий
	sessionMetrics sync.Map // map[sessionId]*metrics.StreamMetrics

	netCtrl *netem.Controller
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
	netIface := flag.String("iface", "enp0s3", "сетевой интерфейс для tc netem")
	flag.Parse()

	sessionTtl = *ttl

	// Загружаем конфиг
	var err error
	cfg, err = config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("загружено машин: %d, пользователей: %d", len(cfg.Machines), len(cfg.Users))

	sessions = session.NewStore()

	netCtrl = netem.New(*netIface)

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

	// Запускаем оба листенера параллельно
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

	// Шаг 2: CONNECT <machine_id> или BENCH <net params>
	msgType, args, err = c.Recv()
	if err != nil {
		c.Send(proto.MsgError, "read error")
		return
	}

	switch msgType {
	case proto.MsgConnect:
		handleConnectRequest(c, args, username)
	case proto.MsgBench:
		handleBenchRequest(c, args, username)
	default:
		c.Send(proto.MsgError, fmt.Sprintf("expected CONNECT or BENCH, got %s", msgType))
	}
}

func handleConnectRequest(c *proto.Conn, args []string, username string) {
	if len(args) == 0 {
		c.Send(proto.MsgError, "expected CONNECT <machine_id>")
		return
	}
	machineId := args[0]
	mode := args[1]

	if !cfg.CanAccess(username, machineId) {
		c.Send(proto.MsgError, "access denied")
		log.Printf("[%s] нет доступа к %s", username, machineId)
		return
	}

	targetAddr, ok := cfg.Machines[machineId]
	if !ok {
		c.Send(proto.MsgError, "unknown machine")
		return
	}

	// Создаём сессию
	sess, err := sessions.Create(username, machineId, targetAddr, mode, sessionTtl)
	if err != nil {
		c.Send(proto.MsgError, "internal error")
		return
	}

	log.Printf("[%s] сессия %s -> %s (TTL: %v, истекает: %s)",
		username, sess.ID, machineId, sessionTtl, sess.ExpiresAt.Format("15:04:05"))
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

func handleBenchRequest(c *proto.Conn, args []string, username string) {
	// Парсим сетевые параметры
	// Формат: BENCH loss=2.00,delay=50,jitter=20,rate=0.00
	benchParams, err := benchproto.DecodeBenchParams(args[0])
	if err != nil {
		c.Send(proto.MsgError, fmt.Sprintf("invalid bench params: %v", err))
		return
	}

	// Применяем сетевые условия
	netParams := netem.NetParams{
		LossPct:  benchParams.LossPct,
		DelayMs:  benchParams.DelayMs,
		JitterMs: benchParams.JitterMs,
		RateMbit: benchParams.RateMbit,
	}

	if err := netCtrl.Apply(netParams); err != nil {
		c.Send(proto.MsgError, fmt.Sprintf("netem apply: %v", err))
		return
	}

	// Создаём benchmark сессию — без привязки к машине
	sess, err := sessions.CreateBench(username, sessionTtl, benchParams.ClientIntervalMs)
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

	// Сбрасываем сетевые условия после завершения
	netCtrl.Reset()

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
func handleTcpData(conn net.Conn) {
	defer conn.Close()

	// Подготавливаем соединение
	sess, err := prepareDataConn(conn, "tcp")
	if err != nil {
		log.Printf("err in preparing DataConn: %v", err)
		return
	}

	defer sessionMetrics.Delete(sess.ID)

	switch sess.Mode {
	case session.Mstsc:
		target, err := connectToTarget(conn, sess, "tcp")
		if err != nil {
			log.Printf("error in connecting to target: %v", err)
			return
		}
		handleDataDefault(conn, target, sess, "tcp")

	default:
		log.Printf("unknown session mode: %v", sess.Mode)
		return
	}
}

// handleQUIC — обрабатывает одно QUIC соединение
// Одно соединение = один стрим = одна RDP сессия
func handleQuicData(qconn *quic.Conn) {
	// Закрываем QUIC соединение при выходе
	defer qconn.CloseWithError(0, "done")

	// Принимаем стрим от клиента (в QUIC данные идут через стримы)
	stream, err := qconn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("quic accept stream: %v", err)
		return
	}
	defer stream.Close()

	// Оборачиваем (conn + stream) в net.Conn-подобный интерфейс
	// чтобы дальше использовать ту же логику, что и для TCP
	conn := quicconn.New(qconn, stream)

	// Передаём в общий обработчик
	sess, err := prepareDataConn(conn, "quic")
	if err != nil {
		log.Printf("error in preparing DataConn: %v", err)
		return
	}

	defer sessionMetrics.Delete(sess.ID)

	switch sess.Mode {
	case session.Mstsc:
		target, err := connectToTarget(conn, sess, "quic")
		if err != nil {
			log.Printf("error in connecting to target: %v", err)
			return
		}
		defer target.Close()
		handleDataDefault(conn, target, sess, "quic")

	case session.Freerdp:
		handleDataFreerdp(qconn, sess)
	}
}

/*
Подготавливаем соединение на DataPlane:
Получаем сессию от клиента TODO: проверить нельзя ли на этом этапе клиенту дать нам любой id сессии
Возвращаем объект сессии (там классификация соединения)
*/
func prepareDataConn(conn net.Conn, protoName string) (*session.Session, error) {
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
		return nil, fmt.Errorf("invalid session request")
	}
	sessionId := args[0]

	// Ищем сессию, которую ранее создали на control-plane
	sess, ok := sessions.Get(sessionId)
	if !ok {
		log.Printf("%s: неизвестная сессия %s", protoName, sessionId)
		c.Send(proto.MsgError, "session not found")
		return nil, fmt.Errorf("session not found")
	}

	// Benchmark сессия — отдельный обработчик без подключения к машине
	// if sess.MachineID == "benchmark" {
	// 	handleBenchmarkData(conn, c, sess, sessionId)
	// 	return
	// }

	log.Printf("%s: [%s] старт -> %s", protoName, sessionId[:8], sess.TargetAddr)

	return sess, nil

	// MeteredReader прозрачно считает метрики входящего потока
	// meteredRaw := metrics.NewMeteredConn(conn, m)

	// // Дальше просто проксируем трафик в обе стороны до завершения сессии
	// // conn — клиент (TLS или QUIC)
	// // target — целевой сервер
	// err1, err2 := pipe.PipeWithDone(meteredRaw, target, sess.Done())

	// log.Printf("%s: [%s] завершено err1=%v err2=%v", protoName, sessionId[:8], err1, err2)
}

/*
Соединяемся с таргет-машиной
Создаём коллектор метрик
*/
func connectToTarget(conn net.Conn, sess *session.Session, protoName string) (net.Conn, error) {
	// Оборачиваем соединение в наш протокол (чтение/запись сообщений)
	c := proto.NewConn(conn)

	// Подключаемся к целевой машине (RDP сервер или любой TCP target)
	target, err := net.Dial("tcp", sess.TargetAddr)
	if err != nil {
		log.Printf("%s: не могу подключиться к %s: %v", protoName, sess.TargetAddr, err)
		c.Send(proto.MsgError, "target connection failed")
		return nil, fmt.Errorf("target connection failed: %v", err)
	}

	// Оптимизируем TCP-соединение (nodelay, буферы и т.п.)
	pipe.TuneConn(target)

	// Создаём коллектор метрик для этой сессии
	// Измеряем входящий трафик (клиент → сервер)
	// Обоснование: участок сервер → машина симметричен и находится
	// в локальной сети без деградации (см. методологию)
	m := metrics.NewStreamMetrics()
	sessionMetrics.Store(sess.ID, m)
	//defer sessionMetrics.Delete(sessionId)

	// Сообщаем клиенту, что всё готово и можно начинать проксирование данных
	if err := c.Send(proto.MsgOK); err != nil {
		target.Close()
		sessionMetrics.Delete(sess.ID)
		return nil, err
	}

	return target, nil
}

// Проксирование данных одним потоком
func handleDataDefault(conn net.Conn, target net.Conn, sess *session.Session, protoName string) {
	// MeteredReader прозрачно считает метрики входящего потока
	value, ok := sessionMetrics.Load(sess.ID)
	if !ok || value == nil {
		log.Printf("error in getting metrics by session id: %v", sess.ID)
		return
	}
	m := value.(*metrics.StreamMetrics)
	meteredRaw := metrics.NewMeteredConn(conn, m)

	// Дальше просто проксируем трафик в обе стороны до завершения сессии
	// conn — клиент (TLS или QUIC)
	// target — целевой сервер
	err1, err2 := pipe.PipeWithDone(meteredRaw, target, sess.Done())

	log.Printf("%s: [%s] завершено err1=%v err2=%v", protoName, sess.ID[:8], err1, err2)
}

// Мультиплексированное проксирвоание N quic стримами
func handleDataFreerdp(qconn *quic.Conn, sess *session.Session) {
	unixConns, err := bridge.ListenAll()
	if err != nil {
		log.Printf("bridge listen: %v", err)
		return
	}
	defer func() {
		for _, c := range unixConns {
			c.Close()
		}
	}()

	quicStreams := make([]*quic.Stream, bridge.ChannelCount)

	for i := 0; i < bridge.ChannelCount; i++ {
		stream, err := qconn.OpenStreamSync(context.Background())
		if err != nil {
			log.Fatalf("open stream %s: %v", bridge.ChannelNames[i], err)
		}
		quicStreams[i] = stream
		log.Printf("стрим %s открыт (id=%d)",
			bridge.ChannelNames[i], stream.StreamID())
	}

	bridge.BridgeChannels(unixConns, quicStreams)
	log.Printf("handleDataFreerdp завершён")
}

// handleBenchmarkData - обработка бенчмарка (только client-server)
// принимает уже созданный proto.Conn
func handleBenchmarkData(raw net.Conn, c *proto.Conn, sess *session.Session, sessionId string) {
	m := metrics.NewStreamMetrics()
	if sess.BenchClientIntervalMs > 0 {
		m.SetExpectedInterval(
			time.Duration(sess.BenchClientIntervalMs) * time.Millisecond,
		)
	}
	sessionMetrics.Store(sessionId, m)
	defer sessionMetrics.Delete(sessionId)

	c.Send(proto.MsgOK)
	log.Printf("bench: [%s] старт", sessionId[:8])

	// Буфер для чтения пакетов
	// Используем MeteredConn для подсчёта байт и jitter
	meteredRaw := metrics.NewMeteredConn(raw, m)
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-sess.Done():
			log.Printf("bench: [%s] сессия отозвана", sessionId[:8])
			return
		default:
		}
		raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := meteredRaw.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("bench: [%s] завершено: %v", sessionId[:8], err)
			return
		}

		// Echo — отправляем пакет обратно клиенту без изменений.
		// Клиент по timestamp внутри пакета посчитает RTT.
		// Используем raw (не meteredRaw) чтобы не считать echo как входящий трафик.
		if n > 0 {
			raw.SetWriteDeadline(time.Now().Add(5 * time.Second))
			raw.Write(buf[:n])
			raw.SetWriteDeadline(time.Time{})
		}
	}
}
