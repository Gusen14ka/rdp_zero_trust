package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"rdp_zero_trust/internal/bridge"
	"rdp_zero_trust/internal/loading"
	"rdp_zero_trust/internal/logging"
	"rdp_zero_trust/internal/pipe"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/quicconn"
)

var (
	sessionsMu   sync.Mutex
	sessionConns = map[string]chan []net.Conn{}
)

func main() {
	serverAddr := flag.String("server", "192.168.0.21:9004", "адрес agent-plane на Go-сервере")
	machineID := flag.String("machine", "machine1", "Id этой машины, как в config.json сервера")
	pfServerAddr := flag.String("pfserver", "127.0.0.1:3390", "локальный адрес freerdp-proxy (pf_server) НА ЭТОЙ машине")
	caPath := flag.String("ca", "certs/ca.crt", "корневой сертификат CA")
	certPath := flag.String("cert", "certs/agent_cert.crt", "сертификат агента")
	keyPath := flag.String("key", "certs/agent_key.key", "приватный ключ агента")
	logLevel := flag.String("log-level", "info", "log level")
	flag.Parse()

	if err := logging.Configure(*logLevel); err != nil {
		logging.Fatalf("failed to configure logger", "err", err)
	}

	for {
		if err := run(*serverAddr, *machineID, *pfServerAddr, *caPath, *certPath, *keyPath); err != nil {
			slog.Warn("agent: соединение оборвалось, переподключение через 5с", "err", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func run(serverAddr, machineID, pfServerAddr, caPath, certPath, keyPath string) error {
	tlsCfg, err := loading.LoadMTLSConfig(caPath, certPath, keyPath)
	if err != nil {
		return err
	}
	tlsCfg.NextProtos = []string{"rdp-zero-trust-agent"}

	qconn, err := quic.DialAddr(context.Background(), serverAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  5 * time.Minute,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	defer qconn.CloseWithError(0, "done")

	ctrlStream, err := qconn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	ctrl := proto.NewConn(quicconn.New(qconn, ctrlStream))

	if err := ctrl.Send(proto.MsgRegister, machineID); err != nil {
		return err
	}
	msgType, args, err := ctrl.Recv()
	if err != nil || msgType != proto.MsgOK {
		if len(args) > 0 {
			slog.Error("agent: сервер отклонил регистрацию", "machine_id", machineID, "arg", args[0])
		}
		return err
	}
	slog.Info("agent: зарегистрирован, жду запросов от сервера...", "machine_id", machineID)

	for {
		msgType, args, err := ctrl.Recv()
		if err != nil {
			return err
		}
		if len(args) == 0 {
			slog.Error("agent: сообщение без sessionID", "msg_type", msgType)
			continue
		}
		sessionID := args[0]

		switch msgType {
		case proto.MsgOpenRelay:
			go handleRelay(qconn, pfServerAddr, sessionID)
		case proto.MsgOpenBridge:
			go handleBridge(qconn, sessionID)
		default:
			slog.Error("agent: неожиданное сообщение", "msg_type", msgType, "args", args)
		}
	}
}

// handleRelay — фаза 1: локально дозванивается до pf_server (127.0.0.1, ЭТА
// машина) и открывает ОДИН QUIC-стрим до сервера, помеченный этой сессией
// и purpose="relay", дальше просто гоняет байты в обе стороны.
func handleRelay(qconn *quic.Conn, pfServerAddr, sessionID string) {
	// Сокеты должны существовать ДО того как pf_server примет соединение:
	// quicmux коннектится к ним в ServerSessionStarted, то есть сразу,
	// иначе хук падает и pf_server рвёт сессию.
	listeners, err := bridge.BindAll()
	if err != nil {
		slog.Error("agent: bind unix", "session_id", sessionID[:8], "err", err)
		return
	}

	connsCh := make(chan []net.Conn, 1)
	sessionsMu.Lock()
	sessionConns[sessionID] = connsCh
	sessionsMu.Unlock()

	go func() {
		conns, err := bridge.AcceptAll(listeners)
		if err != nil {
			slog.Error("agent: accept unix", "session_id", sessionID[:8], "err", err)
			return
		}
		slog.Info("agent: quicmux подключился ко всем каналам", "session_id", sessionID[:8])
		connsCh <- conns
	}()

	slog.Info("agent: фаза 1 — дозваниваюсь до pf_server", "session_id", sessionID[:8], "pf_server", pfServerAddr)
	target, err := net.Dial("tcp", pfServerAddr)
	if err != nil {
		slog.Error("agent: не могу подключиться к pf_server", "session_id", sessionID[:8], "pf_server", pfServerAddr, "err", err)
		return
	}
	defer target.Close()
	pipe.TuneConn(target)

	stream, err := qconn.OpenStreamSync(context.Background())
	if err != nil {
		slog.Error("agent: open relay stream", "session_id", sessionID[:8], "err", err)
		return
	}

	sc := quicconn.New(qconn, stream)
	pc := proto.NewConn(sc)
	if err := pc.Send(proto.MsgSession, sessionID, "relay"); err != nil {
		slog.Error("agent: handshake relay-стрима", "session_id", sessionID[:8], "err", err)
		return
	}
	if msgType, _, err := pc.Recv(); err != nil || msgType != proto.MsgOK {
		slog.Error("agent: сервер не подтвердил relay-стрим", "session_id", sessionID[:8], "err", err)
		return
	}

	err1, err2 := pipe.Pipe(sc, target)
	slog.Info("agent: фаза 1 завершена", "session_id", sessionID[:8], "err1", err1, "err2", err2)
}

// handleBridge — фаза 2: поднимает unix-мост (сюда стучится quicmux) и
// мультиплексирует 4 канала в 4 QUIC-стрима, каждый помечен purpose="bridge".
func handleBridge(qconn *quic.Conn, sessionID string) {
	sessionsMu.Lock()
	connsCh, ok := sessionConns[sessionID]
	delete(sessionConns, sessionID)
	sessionsMu.Unlock()

	if !ok {
		slog.Error("agent: нет подготовленных unix-каналов", "session_id", sessionID[:8])
		return
	}

	var unixConns []net.Conn
	select {
	case unixConns = <-connsCh:
	case <-time.After(10 * time.Second):
		slog.Error("agent: таймаут ожидания подключения quicmux", "session_id", sessionID[:8])
		return
	}
	defer func() {
		for _, c := range unixConns {
			c.Close()
		}
	}()

	slog.Info("agent: фаза 2 — открываю QUIC-стримы", "session_id", sessionID[:8])

	quicStreams := make([]*quic.Stream, bridge.ChannelCount)
	for i := 0; i < bridge.ChannelCount; i++ {
		stream, err := qconn.OpenStreamSync(context.Background())
		if err != nil {
			slog.Error("agent: open stream", "session_id", sessionID[:8], "channel", bridge.ChannelNames[i], "err", err)
			return
		}

		pc := proto.NewConn(quicconn.New(qconn, stream))
		if err := pc.Send(proto.MsgSession, sessionID, "bridge", strconv.Itoa(i)); err != nil {
			slog.Error("agent: handshake на стриме", "session_id", sessionID[:8], "channel", bridge.ChannelNames[i], "err", err)
			return
		}
		if msgType, _, err := pc.Recv(); err != nil || msgType != proto.MsgOK {
			slog.Error("agent: сервер не подтвердил стрим", "session_id", sessionID[:8], "channel", bridge.ChannelNames[i], "err", err)
			return
		}
		quicStreams[i] = stream
	}

	bridge.BridgeChannels(unixConns, quicStreams)
	slog.Info("agent: мост завершён", "session_id", sessionID[:8])
}
