package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"rdp_zero_trust/internal/admin"
	"rdp_zero_trust/internal/agentpool"
	"rdp_zero_trust/internal/benchproto"
	"rdp_zero_trust/internal/bridge"
	"rdp_zero_trust/internal/config"
	enrollServer "rdp_zero_trust/internal/enrollment/server"
	"rdp_zero_trust/internal/identity"
	"rdp_zero_trust/internal/logging"
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
	agentAddr := flag.String("agent", ":9004", "адрес agent plane (QUIC)")
	logLevel := flag.String("log-level", "info", "log level")
	flag.Parse()

	if err := logging.Configure(*logLevel); err != nil {
		logging.Fatalf("failed to configure logger", "err", err)
	}

	sessionTtl = *ttl

	// Загружаем конфиг
	var err error
	cfg, err = config.Load(*configPath)
	if err != nil {
		logging.Fatalf("config", "err", err)
	}
	slog.Info("config loaded", "machines", len(cfg.Machines), "users", len(cfg.Users))

	sessions = session.NewStore()

	netCtrl = netem.New(*netIface)

	// Enrollment сервер
	enrollSrv, err := enrollServer.NewServer(*caKeyPath, "certs/ca.crt")
	if err != nil {
		logging.Fatalf("enrollment server", "err", err)
	}
	// Регистрируем способ аутентификации — пароль
	// Чтобы добавить TOTP: enrollSrv.RegisterAuth(enrollment.NewTOTPAuthHandler(...))
	enrollSrv.RegisterAuth(enrollServer.NewPasswordAuthHandler(cfg))
	go func() {
		if err := enrollSrv.Start(*enrollAddr, *certPath, *keyPath); err != nil {
			logging.Fatalf("enrollment", "err", err)
		}
	}()

	// Запускаем admin HTTP сервер
	adminSrv := admin.NewServer(sessions, &sessionMetrics)
	go adminSrv.Start(*adminAddr)

	// Запускаем сервер для агентов
	go listenAgentData(*agentAddr, *certPath, *keyPath, *caCertPath)

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
		logging.Fatalf("tls cert", "err", err)
	}

	// Загружаем сертификат CA и создаем пул
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		logging.Fatalf("read ca", "err", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		logging.Fatalf("parse ca cert", "err", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,               // только TLS 1.3
		ClientAuth:   tls.RequireAndVerifyClientCert, // Для соединения требовать и проверять клиентский сертификат
		ClientCAs:    caPool,                         // Предоставляем CA который подпиал клиентский сертификат
	}

	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		logging.Fatalf("control listen", "err", err)
	}
	slog.Info("control plane (mTLS) слушает", "addr", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("control accept error", "err", err)
			continue
		}
		// У нас tls поверх соединения - берём его
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			conn.Close()
			slog.Warn("client-control plane is not tls")
			continue
		}
		go handleControl(tlsConn)
	}
}

// handleControl — обрабатывает одного клиента на control plane
func handleControl(tlsConn *tls.Conn) {
	c := proto.NewConn(tlsConn)
	defer c.Close()

	slog.Info("новое control-соединение", "remote_addr", tlsConn.RemoteAddr())

	// Из-за ленивой оптимизации go может провести handshake после Accept
	// Говорим ему сделать его прямо сейчас, тк нам нужно взять сертификат client
	if err := tlsConn.Handshake(); err != nil {
		slog.Warn("handshake failed", "err", err)
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		slog.Warn("no client certificate")
		return
	}

	cert := state.PeerCertificates[0]

	certUsername, err := identity.UsernameFromCert(cert)
	if err != nil {
		slog.Warn("invalid certificate", "err", err)
		return
	}

	slog.Info("control: подключился", "cert_username", certUsername)

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
		slog.Warn("mTLS mismatch", "cert_username", certUsername, "msg_username", username)
		return
	}

	// Проверка 2: пароль (второй фактор)
	if !cfg.Authenticate(username, password) {
		c.Send(proto.MsgError, "invalid credentials")
		slog.Warn("неверный пароль", "username", username)
		return
	}

	slog.Info("аутентифицирован (mTLS + пароль)", "username", username)
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
		slog.Error("нет доступа к машине", "username", username, "machine_id", machineId)
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

	slog.Info("сессия создана",
		"username", username,
		"session_id", sess.ID,
		"machine_id", machineId,
		"ttl", sessionTtl,
		"expires_at", sess.ExpiresAt.Format("15:04:05"),
	)
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
		slog.Info("сессия истекла по TTL", "session_id", sess.ID)
		c.Send(proto.MsgError, "session expired")
	case <-sess.Done():
		slog.Info("сессия отозвана", "session_id", sess.ID)
		c.Send(proto.MsgError, "session revoked")
	case <-clientGone:
		slog.Info("сессия: клиент отключился", "session_id", sess.ID)
	}

	sessions.Delete(sess.ID)
	slog.Info("сессия завершена (удалена)", "session_id", sess.ID)
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

	slog.Info("benchmark сессия создана", "username", username, "session_id", sess.ID)
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
		slog.Info("benchmark сессия завершена", "session_id", sess.ID)
	}

	// Сбрасываем сетевые условия после завершения
	netCtrl.Reset()

	sessions.Delete(sess.ID)
}

// listenTCPData — принимает tcp data-соединения и проксирует на целевую машину
func listenTcpData(addr, certPath, keyPath string) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		logging.Fatalf("data tls cert", "err", err)
	}
	tlsCfg := tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", addr, &tlsCfg)
	if err != nil {
		logging.Fatalf("data listen", "err", err)
	}
	slog.Info("data plane (TLS) слушает", "addr", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("data accept", "err", err)
			continue
		}
		go handleTcpData(conn)
	}
}

// listenQUICData — принимает QUIC соединения на data plane
func listenQuicData(addr, certPath, keyPath string) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		logging.Fatalf("quic tls cert", "err", err)
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
		logging.Fatalf("quic listen", "err", err)
	}
	slog.Info("data plane (QUIC) слушает", "addr", addr)

	for {
		// Принимаем новое QUIC соединение
		conn, err := ln.Accept(context.Background())
		if err != nil {
			slog.Error("quic accept", "err", err)
			continue
		}
		go handleQuicData(conn)
	}
}

// handleTcpData — обработка обычного TLS/TCP соединения
func handleTcpData(conn net.Conn) {
	defer conn.Close()

	protoConn := proto.NewConn(conn)

	// Подготавливаем соединение
	sess, err := prepareDataConn(protoConn, "tcp")
	if err != nil {
		slog.Error("err in preparing DataConn", "proto", "tcp", "err", err)
		return
	}

	defer sessionMetrics.Delete(sess.ID)

	switch sess.Mode {
	case session.Mstsc:
		target, err := connectToTarget(protoConn, sess, "tcp")
		if err != nil {
			slog.Error("error in connecting to target", "proto", "tcp", "session_id", sess.ID, "err", err)
			return
		}
		handleDataDefault(conn, target, sess, "tcp")

	default:
		slog.Error("unknown session mode", "proto", "tcp", "mode", sess.Mode)
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
		slog.Error("quic accept stream", "err", err)
		return
	}
	defer stream.Close()

	// Оборачиваем (conn + stream) в net.Conn-подобный интерфейс
	// чтобы дальше использовать ту же логику, что и для TCP
	conn := quicconn.New(qconn, stream)

	protoConn := proto.NewConn(conn)

	// Передаём в общий обработчик
	sess, err := prepareDataConn(protoConn, "quic")
	if err != nil {
		slog.Error("error in preparing DataConn", "proto", "quic", "err", err)
		return
	}

	defer sessionMetrics.Delete(sess.ID)

	switch sess.Mode {
	case session.Mstsc:
		target, err := connectToTarget(protoConn, sess, "quic")
		if err != nil {
			slog.Error("error in connecting to target", "proto", "quic", "session_id", sess.ID, "err", err)
			return
		}
		defer target.Close()
		handleDataDefault(conn, target, sess, "quic")

	case session.Freerdp:
		// Сообщаем клиенту, что всё готово и можно начинать проксирование данных
		if err := protoConn.Send(proto.MsgOK); err != nil {
			return
		}
		handleDataFreerdp(qconn, protoConn, sess)
	}
}

/*
Подготавливаем соединение на DataPlane:
Получаем сессию от клиента TODO: проверить нельзя ли на этом этапе клиенту дать нам любой id сессии
Возвращаем объект сессии (там классификация соединения)
*/
func prepareDataConn(conn *proto.Conn, protoName string) (*session.Session, error) {

	// Убираем задержки и Нейгла
	pipe.TuneConn(conn.RawConn())

	// Ожидаем первое сообщение от клиента: SESSION <id>
	msgType, args, err := conn.Recv()
	if err != nil || msgType != proto.MsgSession || len(args) == 0 {
		slog.Error("ожидал SESSION", "proto", protoName, "msg_type", msgType, "args", args, "err", err)
		conn.Send(proto.MsgError, "invalid session request")
		return nil, fmt.Errorf("invalid session request")
	}
	sessionId := args[0]

	// Ищем сессию, которую ранее создали на control-plane
	sess, ok := sessions.Get(sessionId)
	if !ok {
		slog.Error("неизвестная сессия", "proto", protoName, "session_id", sessionId)
		conn.Send(proto.MsgError, "session not found")
		return nil, fmt.Errorf("session not found")
	}

	// Benchmark сессия — отдельный обработчик без подключения к машине
	// if sess.MachineID == "benchmark" {
	// 	handleBenchmarkData(conn, c, sess, sessionId)
	// 	return
	// }

	slog.Info("data session start", "proto", protoName, "session_id", sessionId[:8], "target", sess.TargetAddr)

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
func connectToTarget(conn *proto.Conn, sess *session.Session, protoName string) (net.Conn, error) {

	// Подключаемся к целевой машине (RDP сервер или любой TCP target)
	target, err := net.Dial("tcp", sess.TargetAddr)
	if err != nil {
		slog.Error("не могу подключиться к target", "proto", protoName, "target", sess.TargetAddr, "err", err)
		conn.Send(proto.MsgError, "target connection failed")
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
	if err := conn.Send(proto.MsgOK); err != nil {
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
		slog.Error("error in getting metrics by session id", "session_id", sess.ID)
		return
	}
	m := value.(*metrics.StreamMetrics)
	meteredRaw := metrics.NewMeteredConn(conn, m)

	// Дальше просто проксируем трафик в обе стороны до завершения сессии
	// conn — клиент (TLS или QUIC)
	// target — целевой сервер
	err1, err2 := pipe.PipeWithDone(meteredRaw, target, sess.Done())

	slog.Info("session завершена", "proto", protoName, "session_id", sess.ID[:8], "err1", err1, "err2", err2)
}

// handleDataFreerdp — фаза 1: сырой relay негоциации между xfreerdp-quic (через
// клиента) и pf_server; фаза 2 (после SWITCH_CHANNELS): 4 QUIC-стрима напрямую
// в unix-сокеты, которые уже льёт наш C-модуль quicmux внутри pf_server.
func handleDataFreerdp(qconn *quic.Conn, ctrl *proto.Conn, sess *session.Session) {
	agent, ok := agentpool.Get(sess.MachineID)
	if !ok {
		slog.Error("freerdp: нет подключённого агента", "session_id", sess.ID[:8], "machine_id", sess.MachineID)
		ctrl.Send(proto.MsgError, "agent not connected")
		return
	}

	// Поднимаем relay до pf_server ЗАРАНЕЕ — до того как клиент вообще
	// откроет локальный порт для xfreerdp-quic
	agentRelayStream, err := agent.RequestRelay(sess.ID, 10*time.Second)
	if err != nil {
		slog.Error("freerdp: не удалось получить relay от агента", "session_id", sess.ID[:8], "err", err)
		ctrl.Send(proto.MsgError, "agent relay failed")
		return
	}

	if err := ctrl.Send(proto.MsgRelayReady); err != nil {
		slog.Error("freerdp: не удалось отправить RELAY_READY", "err", err)
		agentRelayStream.Close()
		return
	}

	relayStream, err := qconn.AcceptStream(context.Background())
	if err != nil {
		slog.Error("freerdp: accept relay stream", "err", err)
		return
	}

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		bridgeQuicStreams("Фиктивное соединение", relayStream, agentRelayStream)
		slog.Info("freerdp: фаза 1 relay завершена", "session_id", sess.ID[:8])
	}()

	msgType, args, err := ctrl.Recv() // ждём SWITCH_CHANNELS <muxMode>
	if err != nil || msgType != proto.MsgSwitchChannels {
		slog.Error("freerdp: не дождались SWITCH_CHANNELS", "msg_type", msgType, "err", err)
		relayStream.Close()
		agentRelayStream.Close()
		<-relayDone
		return
	}

	muxMode := "multi"
	if len(args) > 0 {
		muxMode = args[0]
	}

	agentStreams, err := agent.RequestBridge(sess.ID, 10*time.Second)
	if err != nil {
		slog.Error("freerdp: не удалось получить мост от агента", "session_id", sess.ID[:8], "err", err)
		ctrl.Send(proto.MsgError, "agent bridge failed")
		return
	}

	if err := ctrl.Send(proto.MsgOK); err != nil {
		slog.Error("freerdp: не удалось подтвердить переключение клиенту", "err", err)
		return
	}

	if muxMode == "single" {
		stream, err := qconn.AcceptStream(context.Background())
		if err != nil {
			slog.Error("freerdp: accept mux stream:", "err", err)
			return
		}
		pc := proto.NewConn(quicconn.New(qconn, stream))
		msgType, args, err := pc.Recv()
		if err != nil || msgType != proto.MsgSession || len(args) < 2 || args[1] != "mux" {
			slog.Error("freerdp: некорректный хендшейк mux-стрима:", "msg_type", msgType, "args", args, "err", err)
			return
		}
		if err := pc.Send(proto.MsgOK); err != nil {
			slog.Error("freerdp: не удалось подтвердить mux-стрим:", "err", err)
			return
		}

		chans := make([]io.ReadWriter, bridge.ChannelCount)
		for i := range chans {
			chans[i] = agentStreams[i]
		}
		rw := struct {
			io.Reader
			io.Writer
		}{pc.Reader(), stream}

		slog.Info("freerdp: режим single", "sess id", sess.ID[:8])
		bridge.BridgeMux(chans, rw)

		// Агентское соединение постоянное — явно закрываем его стримы,
		// иначе мост на агенте останется висеть после конца сессии
		for _, s := range agentStreams {
			s.CancelRead(0)
			s.Close()
		}
		stream.Close()
		slog.Info("handleDataFreerdp: завершён (single)", "sess id", sess.ID[:8])
		return
	}

	clientStreams := make([]*quic.Stream, bridge.ChannelCount)
	for i := 0; i < bridge.ChannelCount; i++ {
		stream, err := qconn.AcceptStream(context.Background())
		if err != nil {
			slog.Error("freerdp: accept client stream", "err", err)
			return
		}

		pc := proto.NewConn(quicconn.New(qconn, stream))
		msgType, args, err := pc.Recv()
		if err != nil || msgType != proto.MsgSession || len(args) < 3 {
			slog.Error("freerdp: некорректный хендшейк клиентского стрима", "msg_type", msgType, "args", args, "err", err)
			return
		}

		idx, err := strconv.Atoi(args[2])
		if err != nil || idx < 0 || idx >= bridge.ChannelCount || clientStreams[idx] != nil {
			slog.Error("freerdp: некорректный индекс канала", "channel_index", args[2])
			return
		}

		if err := pc.Send(proto.MsgOK); err != nil {
			slog.Error("freerdp: не удалось подтвердить стрим", "err", err)
			return
		}

		clientStreams[idx] = stream
		slog.Info("freerdp: принят клиентский стрим", "session_id", sess.ID[:8], "channel", bridge.ChannelNames[idx])
	}

	var wg sync.WaitGroup
	for i := 0; i < bridge.ChannelCount; i++ {
		wg.Add(1)
		go func(name string, a, b *quic.Stream) {
			defer wg.Done()
			bridgeQuicStreams(name, a, b)
		}(bridge.ChannelNames[i], clientStreams[i], agentStreams[i])
	}
	wg.Wait()

	slog.Info("handleDataFreerdp завершён", "session_id", sess.ID[:8])
}

// bridgeQuicStreams гоняет байты между двумя QUIC-стримами в обе стороны —
// клиентским (к xfreerdp-quic) и агентским (к quicmux на таргет-машине).
func bridgeQuicStreams(name string, a, b *quic.Stream) {
	done := make(chan struct{}, 2)
	go func() {
		n, err := io.Copy(a, b)
		slog.Debug("agent→client copy", "name", name, "bytes", n, "err", err)
		a.Close()
		done <- struct{}{}
	}()
	go func() {
		n, err := io.Copy(b, a)
		slog.Debug("client→agent copy", "name", name, "bytes", n, "err", err)
		b.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
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
	slog.Info("bench start", "session_id", sessionId[:8])

	// Буфер для чтения пакетов
	// Используем MeteredConn для подсчёта байт и jitter
	meteredRaw := metrics.NewMeteredConn(raw, m)
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-sess.Done():
			slog.Info("bench: session revoked", "session_id", sessionId[:8])
			return
		default:
		}
		raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := meteredRaw.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			slog.Info("bench завершено", "session_id", sessionId[:8], "err", err)
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

func listenAgentData(addr, certPath, keyPath, caCertPath string) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		logging.Fatalf("agent tls cert", "err", err)
	}
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		logging.Fatalf("agent read ca", "err", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		logging.Fatalf("agent parse ca cert", "err", "pem parse failed")
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		NextProtos:   []string{"rdp-zero-trust-agent"},
	}

	ln, err := quic.ListenAddr(addr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  5 * time.Minute,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		logging.Fatalf("agent listen", "err", err)
	}
	slog.Info("agent plane (QUIC mTLS) слушает", "addr", addr)

	for {
		qconn, err := ln.Accept(context.Background())
		if err != nil {
			slog.Error("agent accept", "err", err)
			continue
		}
		go handleAgentConn(qconn)
	}
}

func handleAgentConn(qconn *quic.Conn) {
	ctrlStream, err := qconn.AcceptStream(context.Background())
	if err != nil {
		slog.Error("agent: accept ctrl stream", "err", err)
		qconn.CloseWithError(0, "no ctrl stream")
		return
	}
	ctrl := proto.NewConn(quicconn.New(qconn, ctrlStream))

	msgType, args, err := ctrl.Recv()
	if err != nil || msgType != proto.MsgRegister || len(args) == 0 {
		ctrl.Send(proto.MsgError, "expected REGISTER <machine_id>")
		return
	}
	machineID := args[0]

	// TODO: сверить machineID с CN из клиентского сертификата агента —
	// сейчас доверяем значению из REGISTER как есть, это временное упрощение
	if err := ctrl.Send(proto.MsgOK); err != nil {
		return
	}

	agent := agentpool.Register(machineID, qconn, ctrl)
	slog.Info("agent: зарегистрирован", "machine_id", machineID)

	<-qconn.Context().Done()
	agentpool.Unregister(machineID, agent)
	slog.Info("agent: отключился", "machine_id", machineID)
}
