// cmd/agent — лёгкий процесс, который запускается на таргет-машине рядом с
// freerdp-proxy/quicmux. Держит одно QUIC-соединение к центральному Go-серверу,
// по запросу сервера поднимает unix-сокеты (bridge.ListenAll — то самое место,
// куда стучится quicmux через quic_bridge_connect) и мультиплексирует их
// в 4 QUIC-стрима до сервера.
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/quic-go/quic-go"

	"rdp_zero_trust/internal/bridge"
	"rdp_zero_trust/internal/loading"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/quicconn"
)

func main() {
	serverAddr := flag.String("server", "192.168.0.21:9004", "адрес agent-plane на Go-сервере")
	machineID := flag.String("machine", "machine1", "Id этой машины, как в config.json сервера")
	caPath := flag.String("ca", "certs/ca.crt", "корневой сертификат CA")
	certPath := flag.String("cert", "certs/agent_cert.crt", "сертификат агента")
	keyPath := flag.String("key", "certs/agent_key.key", "приватный ключ агента")
	flag.Parse()

	for {
		if err := run(*serverAddr, *machineID, *caPath, *certPath, *keyPath); err != nil {
			log.Printf("agent: соединение оборвалось: %v, переподключение через 5с", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func run(serverAddr, machineID, caPath, certPath, keyPath string) error {
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
	log.Printf("agent: зарегистрирован как %s, жду запросов моста...", machineID)

	for {
		msgType, args, err := ctrl.Recv()
		if err != nil {
			return err
		}
		if msgType != proto.MsgOpenBridge || len(args) == 0 {
			log.Printf("agent: неожиданное сообщение: %s %v", msgType, args)
			continue
		}
		sessionID := args[0]
		go handleBridge(qconn, sessionID)
	}
}

// handleBridge поднимает unix-сокеты для одной сессии и мультиплексирует их
// в 4 QUIC-стрима, открытых к серверу с меткой этой сессии.
func handleBridge(qconn *quic.Conn, sessionID string) {
	log.Printf("agent: [%s] поднимаю мост, жду quicmux...", sessionID[:8])

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

		// Помечаем стрим принадлежностью к сессии — сервер сопоставляет
		// пришедшие от разных агентов/сессий стримы именно по этому хендшейку
		pc := proto.NewConn(quicconn.New(qconn, stream))
		if err := pc.Send(proto.MsgSession, sessionID); err != nil {
			log.Printf("agent: [%s] session handshake на стриме %s: %v",
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
