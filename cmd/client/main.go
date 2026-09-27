package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"rdp_zero_trust/internal/bridge"
	"rdp_zero_trust/internal/loading"
	"rdp_zero_trust/internal/logging"
	"rdp_zero_trust/internal/pipe"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/quicconn"

	"github.com/quic-go/quic-go"
)

func main() {
	serverAddr := flag.String("server", "192.168.0.21:9000", "адрес control plane")
	dataAddr := flag.String("data", "192.168.0.21:9001", "адрес data plane")
	//dataQUICAddr := flag.String("quic", "192.168.0.21:9002", "адрес data plane (QUIC)")
	localAddr := flag.String("local", "localhost:13389", "локальный адрес для mstsc/freerdp")
	username := flag.String("user", "user1", "имя пользователя")
	password := flag.String("pass", "secret", "пароль")
	machineId := flag.String("machine", "machine1", "Id машины")
	caPath := flag.String("ca", "certs/ca.crt", "корневой сертификат CA")
	clientCertPath := flag.String("cert", "certs/client_cert.crt", "клиентский сертификат")
	clientKeyPath := flag.String("key", "certs/client_key.key", "приватный ключ клиента")
	transport := flag.String("transport", "tcp", "транспорт data plane: tcp или quic")
	mode := flag.String("mode", "freerdp", "режим работы: mstsc или freerdp")
	logLevel := flag.String("log-level", "info", "log level")
	record := flag.String("record", "", "путь к CSV для записи метрик PDU (пусто = не писать)")
	flag.Parse()

	// Настриваем логгер
	if err := logging.Configure(*logLevel); err != nil {
		logging.Fatalf("failed to configure logger", "err", err)
	}

	// Настраиваем benchmark record
	if *record != "" {
		rec, err := bridge.NewRecorder(*record)
		if err != nil {
			logging.Fatalf("recorder:", "err", err)
		}
		bridge.Rec = rec
		defer rec.Close()
	}

	// Шаг 1: control plane — аутентификация и запрос машины
	sessionId, err := authenticate(*serverAddr, *username, *password, *machineId,
		*caPath, *clientCertPath, *clientKeyPath, *mode)
	if err != nil {
		logging.Fatalf("auth:", "err", err)
	}
	slog.Info("Сессия получена:", "sessionId", sessionId)

	switch *mode {
	case "mstsc":
		runMstscMode(*localAddr, *dataAddr, *transport, sessionId, *caPath)
	case "freerdp":
		runFreerdpMode(*localAddr, *dataAddr, sessionId, *caPath)
	}

}

// Реализация пайплайна с подключением в freerdp
func runFreerdpMode(localAddr, dataAddr, sessionID, caPath string) {
	slog.Info("режим freerdp: ждём подключения xfreerdp-quic...")

	// TODO: 2 и 3 шаги вынести в отдельную функцию и объединить с tunnelQUIC
	// Шаг 2: устанавливаем QUIC соединение с сервером
	tlsCfg, err := loading.LoadTLSConfig(caPath)
	if err != nil {
		logging.Fatalf("tls config:", "err", err)
	}
	tlsCfg.NextProtos = []string{"rdp-zero-trust"}

	conn, err := quic.DialAddr(context.Background(), dataAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  5 * time.Minute,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		logging.Fatalf("quic dial:", "err", err)
	}
	defer conn.CloseWithError(0, "done")

	// Шаг 3: SESSION handshake на контрольном стриме (стрим 0)
	ctrlStream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		logging.Fatalf("open ctrl stream:", "err", err)
	}
	qctrl := quicconn.New(conn, ctrlStream)
	c := proto.NewConn(qctrl)
	c.Send(proto.MsgSession, sessionID)
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		if len(args) > 0 {
			logging.Fatalf("сервер отклонил:", "args", args[0])
		}
		logging.Fatalf("handshake failed:", "err", args[0])
	}
	slog.Info("сессия подтверждена")

	// ВАЖНО: xfreerdp-quic подключается к unix-сокетам в СВОЁМ PreConnect —
	// то есть ДО того как вообще попытается дозвониться по TCP на /v:.
	// Поэтому bridge.ListenAll() должен идти раньше локального TCP listener'а,
	// а не после него.
	unixConns, err := bridge.ListenAll()
	if err != nil {
		logging.Fatalf("bridge listen:", "err", err)
	}
	defer func() {
		for _, uc := range unixConns {
			uc.Close()
		}
	}()
	slog.Info("все 4 unix-канала подключены (xfreerdp-quic прошёл PreConnect)")

	// Ждём, пока сервер прогреет relay до pf_server — только после этого
	// открываем локальный порт, чтобы xfreerdp-quic коннектился уже в
	// готовую трубу, без гонки по первому чтению
	msgType, args, err = c.Recv()
	if err != nil || msgType != proto.MsgRelayReady {
		if len(args) > 0 {
			logging.Fatalf("сервер отклонил relay:", "arg", args[0])
		}
		logging.Fatalf("не дождались RELAY_READY:", "err", err)
	}
	slog.Info("relay-плечо на сервере готово")

	// Фаза 1: теперь начинается по-настоящему — открываем
	// локальный TCP listener, на который xfreerdp-quic будет дозваниваться
	// как на свой /v:-адрес (это следующий шаг FreeRDP после PreConnect).
	relayStream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		logging.Fatalf("open relay stream:", "err", err)
	}

	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		logging.Fatalf("local listen:", "err", err)
	}
	slog.Info("слушаю %s — сюда должен стучаться xfreerdp-quic (/v:%s)", localAddr, localAddr)

	local, err := ln.Accept()
	ln.Close()
	if err != nil {
		logging.Fatalf("accept from xfreerdp-quic:", "err", err)
	}

	relayDone := make(chan struct{})
	relayStreamPConn := quicconn.New(conn, relayStream)
	go func() {
		defer close(relayDone)
		relayCopyLocalOnly(relayStreamPConn, local)
		slog.Info("фаза 1 relay (клиентская сторона) завершена")
	}()

	// Настоящий сигнал переключения — не факт подключения unix-сокетов
	// (это уже случилось раньше), а маркер READY, который PostConnect
	// у xfreerdp-quic шлёт через control-канал, когда хуки транспорта
	// реально встали.
	slog.Info("жду READY маркер от xfreerdp-quic (PostConnect)...")
	marker, err := bridge.ReadPDU(unixConns[bridge.ChannelControl])
	if err != nil {
		logging.Fatalf("не дождались READY маркера:", "err", err)
	}
	if string(marker) != "QUICMUX_READY" {
		logging.Fatalf("неожиданный маркер вместо READY:", "marker", marker)
	}
	slog.Info("получен READY, останавливаю фазу 1")

	//local.Close()
	// local НЕ закрываем: EOF сделал бы TCP-сокет у xfreerdp-quic
	// «вечно читаемым», и его цикл крутился бы вхолостую. Сокет просто
	// молчит до конца сессии — после PostConnect в него никто не пишет.
	// relayStream.Close()
	// <-relayDone

	if bridge.Rec != nil {
		bridge.Rec.Mark("relay_ready")
	}

	c.Send(proto.MsgSwitchChannels)
	msgType, args, err = c.Recv()
	if err != nil || msgType != proto.MsgOK {
		logging.Fatalf("сервер не подтвердил переключение:",
			"msgType", msgType,
			"args", args,
			"err", err)
	}

	if bridge.Rec != nil {
		bridge.Rec.Mark("switch_channels")
	}

	// Шаг 4: открываем отдельный QUIC стрим для каждого канала
	quicStreams := make([]*quic.Stream, bridge.ChannelCount)
	for i := 0; i < bridge.ChannelCount; i++ {
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			logging.Fatalf("open stream:",
				"channel name", bridge.ChannelNames[i],
				"err", err)
		}

		// Обязательно пишем хендшейк СРАЗУ: пока по стриму не ушёл первый байт,
		// сервер вообще не увидит, что стрим открыт (AcceptStream не вернётся),
		// и весь мост встанет намертво.
		pc := proto.NewConn(quicconn.New(conn, stream))
		if err := pc.Send(proto.MsgSession, sessionID, "bridge", strconv.Itoa(i)); err != nil {
			logging.Fatalf("handshake стрима ",
				"channel name", bridge.ChannelNames[i],
				"err", err)
		}
		msgType, _, err := pc.Recv()
		if err != nil || msgType != proto.MsgOK {
			logging.Fatalf("сервер не подтвердил стрим",
				"channel name", bridge.ChannelNames[i],
				"err", err)
		}

		quicStreams[i] = stream
		slog.Info("стрим открыт и подтверждён",
			"channel name", bridge.ChannelNames[i],
			"stream id", stream.StreamID())
	}

	// Шаг 5: для каждого канала запускаем пересылку в обе стороны
	bridge.BridgeChannels(unixConns, quicStreams)
	slog.Info("runFreerdpMode завершён")
}

// Релизация пайплайна с подключением в mstsc
func runMstscMode(localAddr, dataAddr, transport, sessionId, caPath string) {
	// Шаг 2: поднимаем локальный listener для mstsc
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		logging.Fatalf("local listen:", "err", err)
	}
	slog.Info(fmt.Sprintf("слушаем на %s — открывай mstsc на этот адрес", localAddr))

	for {
		local, err := ln.Accept()
		if err != nil {
			slog.Warn("local accept:", "err", err)
			continue
		}

		switch transport {
		case "tcp":
			go tunnelTCP(local, dataAddr, sessionId, caPath)
		case "quic":
			go tunnelQUIC(local, dataAddr, sessionId, caPath)
		}
	}
}

// relayCopyLocalOnly гоняет байты между quicSide и local, но, в отличие от
// pipe.Pipe, НИКОГДА не закрывает и не half-close'ит quicSide — этот QUIC-
// стрим должен остаться живым для pf_server даже после того как local
// закроется (xfreerdp-quic переключился на unix-каналы).
func relayCopyLocalOnly(quicSide io.ReadWriter, local net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(local, quicSide)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(quicSide, local)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// authenticate подключается к control plane и получает адрес целевой машины
func authenticate(serverAddr, username, password, machineId, caPath, clientCertPath, clientKeyPath, mode string) (string, error) {
	tlsCfg, err := loading.LoadMTLSConfig(caPath, clientCertPath, clientKeyPath)
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
	c.Send(proto.MsgConnect, machineId, mode)
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK || len(args) == 0 {
		raw.Close()
		return "", fmt.Errorf("connect rejected")
	}

	sessionId := args[0]

	// Держим proto.Conn открытым до закрытия контрольного соединения
	go func() {
		defer raw.Close()
		// Ждём сообщения от сервера — это либо истечение TTL либо отзыв
		msgType, args, err := c.Recv()
		if err != nil {
			slog.Info("control: соединение закрыто")
		} else if msgType == proto.MsgError && len(args) > 0 {
			// Сервер прислал причину завершения
			slog.Info("control: сессия завершена сервером:", "arg", args[0])
		}
		// В продакшне здесь был бы graceful shutdown всех активных туннелей
		// Пока просто логируем — mstsc сам увидит что соединение пропало
	}()

	return sessionId, nil
}

// tunnelQUIC — QUIC версия туннеля
func tunnelQUIC(local net.Conn, quicAddr, sessionId, caPath string) {
	defer local.Close()
	slog.Info(fmt.Sprintf("tunnel quic: [%s] новое соединение от %s", sessionId[:8], local.RemoteAddr()))

	tlsCfg, err := loading.LoadTLSConfig(caPath)
	if err != nil {
		slog.Error("tunnel quic: tls config:", "err", err)
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
		slog.Error("tunnel quic: dial:", "err", err)
		return
	}
	defer conn.CloseWithError(0, "done")

	// Открываем стрим внутри QUIC соединения
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		slog.Error("tunnel quic: open stream:", "err", err)
		return
	}

	// Оборачиваем в net.Conn и делаем handshake — всё то же самое что в TCP
	qconn := quicconn.New(conn, stream)
	c := proto.NewConn(qconn)
	c.Send(proto.MsgSession, sessionId)

	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		if len(args) > 0 {
			slog.Error("tunnel quic: сервер отклонил:", "arg", args[0])
		} else {
			slog.Error("tunnel quic: ошибка handshake:", "err", err)
		}
		return
	}
	slog.Info("tunnel quic: старт", "sess id", sessionId[:8])

	tlsCfg.KeyLogWriter = keyLogWriter("quic_keylog.txt")

	err1, err2 := pipe.Pipe(qconn, local)
	slog.Info(fmt.Sprintf("tunnel quic: [%s] завершено err1=%v err2=%v", sessionId[:8], err1, err2))
}

// tunnel: принимает соединение от mstsc, пробрасывает через data plane
func tunnelTCP(local net.Conn, dataAddr, sessionId, caPath string) {
	defer local.Close()
	slog.Info(fmt.Sprintf("tunnel: [%s] НАЧАЛО - новое соединение от %s", sessionId[:8], local.RemoteAddr()))

	tlsCfg, err := loading.LoadTLSConfig(caPath)
	if err != nil {
		slog.Error("tunnel: tls config:", "err", err)
	}

	dialer := pipe.NoDelayDialer(10 * time.Second)
	raw, err := tls.DialWithDialer(dialer, "tcp", dataAddr, tlsCfg)
	if err != nil {
		slog.Error("tunnel: dial data plane:", "err", err)
		return
	}
	defer raw.Close()

	// Фаза 1: Handshake через текстовый протокол
	c := proto.NewConn(raw)
	// Отправляем запрос сессии
	c.Send(proto.MsgSession, sessionId)
	slog.Info("tunnel: отправлен sessionId", "id", sessionId)

	// ЖДЁМ ПОДТВЕРЖДЕНИЯ ОТ СЕРВЕРА перед началом передачи RDP данных
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		if msgType == proto.MsgError && len(args) > 0 {
			slog.Error("tunnel: сервер отклонил:", "arg", args[0])
		} else {
			slog.Error("tunnel: ошибка handshake:", "err", err)
		}
		return
	}
	slog.Info("tunnel: старт", "sess id", sessionId[:8])

	// Фаза 2: Binary transfer
	// После handshake буфер reader пуст — передаём raw напрямую
	slog.Info("tunnel: старт data transfering", "sess id", sessionId[:8])
	err1, err2 := pipe.Pipe(raw, local)
	slog.Info(fmt.Sprintf("tunnel: [%s] завершено err1=%v err2=%v", sessionId[:8], err1, err2))
}

// Утилита для эксперимента (временно)
func keyLogWriter(path string) io.Writer {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		slog.Error("keylog:", "error", err)
		return nil
	}
	return f
}
