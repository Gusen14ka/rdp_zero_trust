package main

import (
	"context"
	"flag"
	"log"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"rdp_zero_trust/internal/bridge"
	"rdp_zero_trust/internal/loading"
	"rdp_zero_trust/internal/pipe"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/quicconn"
)

func main() {
	serverAddr := flag.String("server", "192.168.0.21:9004", "адрес agent-plane на Go-сервере")
	machineID := flag.String("machine", "machine1", "Id этой машины, как в config.json сервера")
	pfServerAddr := flag.String("pfserver", "127.0.0.1:3390", "локальный адрес freerdp-proxy (pf_server) НА ЭТОЙ машине")
	caPath := flag.String("ca", "certs/ca.crt", "корневой сертификат CA")
	certPath := flag.String("cert", "certs/agent_cert.crt", "сертификат агента")
	keyPath := flag.String("key", "certs/agent_key.key", "приватный ключ агента")
	flag.Parse()

	for {
		if err := run(*serverAddr, *machineID, *pfServerAddr, *caPath, *certPath, *keyPath); err != nil {
			log.Printf("agent: соединение оборвалось: %v, переподключение через 5с", err)
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
			log.Printf("agent: сервер отклонил регистрацию: %s", args[0])
		}
		return err
	}
	log.Printf("agent: зарегистрирован как %s, жду запросов от сервера...", machineID)

	for {
		msgType, args, err := ctrl.Recv()
		if err != nil {
			return err
		}
		if len(args) == 0 {
			log.Printf("agent: сообщение без sessionID: %s", msgType)
			continue
		}
		sessionID := args[0]

		switch msgType {
		case proto.MsgOpenRelay:
			go handleRelay(qconn, pfServerAddr, sessionID)
		case proto.MsgOpenBridge:
			go handleBridge(qconn, sessionID)
		default:
			log.Printf("agent: неожиданное сообщение: %s %v", msgType, args)
		}
	}
}

// handleRelay — фаза 1: локально дозванивается до pf_server (127.0.0.1, ЭТА
// машина) и открывает ОДИН QUIC-стрим до сервера, помеченный этой сессией
// и purpose="relay", дальше просто гоняет байты в обе стороны.
func handleRelay(qconn *quic.Conn, pfServerAddr, sessionID string) {
	log.Printf("agent: [%s] фаза 1 — дозваниваюсь до pf_server %s", sessionID[:8], pfServerAddr)

	target, err := net.Dial("tcp", pfServerAddr)
	if err != nil {
		log.Printf("agent: [%s] не могу подключиться к pf_server: %v", sessionID[:8], err)
		return
	}
	defer target.Close()
	pipe.TuneConn(target)

	stream, err := qconn.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("agent: [%s] open relay stream: %v", sessionID[:8], err)
		return
	}

	sc := quicconn.New(qconn, stream)
	pc := proto.NewConn(sc)
	if err := pc.Send(proto.MsgSession, sessionID, "relay"); err != nil {
		log.Printf("agent: [%s] handshake relay-стрима: %v", sessionID[:8], err)
		return
	}
	msgType, _, err := pc.Recv()
	if err != nil || msgType != proto.MsgOK {
		log.Printf("agent: [%s] сервер не подтвердил relay-стрим: %v", sessionID[:8], err)
		return
	}

	err1, err2 := pipe.Pipe(sc, target)
	log.Printf("agent: [%s] фаза 1 завершена err1=%v err2=%v", sessionID[:8], err1, err2)
}

// handleBridge — фаза 2: поднимает unix-мост (сюда стучится quicmux) и
// мультиплексирует 4 канала в 4 QUIC-стрима, каждый помечен purpose="bridge".
func handleBridge(qconn *quic.Conn, sessionID string) {
	log.Printf("agent: [%s] фаза 2 — поднимаю мост, жду quicmux...", sessionID[:8])

	unixConns, err := bridge.ListenAll()
	if err != nil {
		log.Printf("agent: [%s] bridge listen: %v", sessionID[:8], err)
		return
	}
	defer func() {
		for _, c := range unixConns {
			c.Close()
		}
	}()
	log.Printf("agent: [%s] все unix-каналы подключены (quicmux на связи)", sessionID[:8])

	quicStreams := make([]*quic.Stream, bridge.ChannelCount)
	for i := 0; i < bridge.ChannelCount; i++ {
		stream, err := qconn.OpenStreamSync(context.Background())
		if err != nil {
			log.Printf("agent: [%s] open stream %s: %v", sessionID[:8], bridge.ChannelNames[i], err)
			return
		}

		pc := proto.NewConn(quicconn.New(qconn, stream))
		if err := pc.Send(proto.MsgSession, sessionID, "bridge"); err != nil {
			log.Printf("agent: [%s] handshake на стриме %s: %v",
				sessionID[:8], bridge.ChannelNames[i], err)
			return
		}
		msgType, _, err := pc.Recv()
		if err != nil || msgType != proto.MsgOK {
			log.Printf("agent: [%s] сервер не подтвердил стрим %s: %v",
				sessionID[:8], bridge.ChannelNames[i], err)
			return
		}

		quicStreams[i] = stream
	}

	bridge.BridgeChannels(unixConns, quicStreams)
	log.Printf("agent: [%s] мост завершён", sessionID[:8])
}
