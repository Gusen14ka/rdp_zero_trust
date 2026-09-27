package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"rdp_zero_trust/internal/benchmark"
	"rdp_zero_trust/internal/benchproto"
	"rdp_zero_trust/internal/loading"
	"rdp_zero_trust/internal/logging"
	"rdp_zero_trust/internal/metrics"
	"rdp_zero_trust/internal/pipe"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/quicconn"

	"github.com/quic-go/quic-go"
)

func main() {
	serverAddr := flag.String("server", "192.168.0.21:9000", "адрес control plane")
	dataAddr := flag.String("data", "192.168.0.21:9001", "адрес data plane TCP")
	quicAddr := flag.String("quic", "192.168.0.21:9002", "адрес data plane QUIC")
	caPath := flag.String("ca", "certs/ca.crt", "CA сертификат")
	certPath := flag.String("cert", "certs/client_cert.crt", "клиентский сертификат")
	keyPath := flag.String("key", "certs/client_key.key", "приватный ключ")
	username := flag.String("user", "user1", "пользователь")
	password := flag.String("pass", "secret", "пароль")
	machineID := flag.String("machine", "machine1", "ID машины")
	patternStr := flag.String("pattern", "input", "паттерн: idle, input, scroll")
	scenario := flag.String("scenario", "baseline", "название сценария для лога")
	transport := flag.String("transport", "tcp", "транспорт: tcp или quic")
	outPath := flag.String("out", "result.json", "путь для сохранения результата")
	logLevel := flag.String("log-level", "info", "log level")
	// Параметры сетевой эмуляции
	lossPct := flag.Float64("loss", 0, "потери пакетов в процентах")
	delayMs := flag.Int("delay", 0, "задержка в миллисекундах")
	jitterMs := flag.Int("jitter", 0, "джиттер в миллисекундах")
	rateMbit := flag.Float64("rate", 0, "ограничение bandwidth в Mbit/s")
	flag.Parse()

	if err := logging.Configure(*logLevel); err != nil {
		logging.Fatalf("failed to configure logger", "err", err)
	}

	// Выбираем паттерн
	pat, err := selectPattern(*patternStr)
	if err != nil {
		logging.Fatalf("паттерн", "err", err)
	}

	slog.Info("=== Benchmark ===")
	slog.Info("bench setup", "pattern", pat.Name, "transport", *transport, "scenario", *scenario, "duration", pat.Duration)

	benchParams := benchproto.BenchParams{
		LossPct:          *lossPct,
		DelayMs:          *delayMs,
		JitterMs:         *jitterMs,
		RateMbit:         *rateMbit,
		ClientIntervalMs: int(pat.ClientPacketInterval.Milliseconds()),
	}

	// Шаг 1: аутентификация через control plane
	sessionID, ctrlConn, err := authenticate(
		*serverAddr, *username, *password, *machineID,
		*caPath, *certPath, *keyPath, benchParams,
	)
	if err != nil {
		logging.Fatalf("auth", "err", err)
	}
	defer ctrlConn.Close()
	slog.Info("сессия создана", "session_id", sessionID)

	// Шаг 2: data plane соединение
	dataConn, err := connectData(*transport, *dataAddr, *quicAddr, *caPath, sessionID)
	if err != nil {
		logging.Fatalf("data plane", "err", err)
	}
	defer dataConn.Close()
	slog.Info("data plane подключён", "transport", *transport)

	// Шаг 3: запускаем benchmark
	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), pat.Duration)
	defer cancel()

	// Локальные метрики клиентской стороны — для направления server→client
	// Сервер сам считает направление client→server через MeteredConn
	clientMetrics := metrics.NewStreamMetrics()
	if pat.ClientPacketInterval > 0 {
		clientMetrics.SetExpectedInterval(pat.ClientPacketInterval)
	}

	var wg sync.WaitGroup
	var sentResult benchmark.SenderResult

	// Направление client → server: имитируем input events
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("sender старт", "packet_size", pat.ClientPacketSize, "interval", pat.ClientPacketInterval)
		sentResult = benchmark.RunSender(ctx, dataConn,
			pat.ClientPacketSize, pat.ClientPacketInterval)
		slog.Info("sender завершён", "packets_sent", sentResult.PacketsSent)
	}()

	// Направление server → client (echo): считаем RTT
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("receiver старт (RTT)")
		benchmark.RunReceiver(ctx, dataConn, clientMetrics)
		slog.Info("receiver завершён", "packets_received", clientMetrics.PacketsReceived)
	}()

	wg.Wait()

	// После завершения контекста закрываем соединение
	// чтобы разблокировать io.ReadFull в RunReceiver
	//dataConn.Close()

	actualDuration := time.Since(startedAt)
	slog.Info("benchmark завершён", "duration", actualDuration)

	// Шаг 4: получаем серверные метрики через admin API
	// log.Printf("получаем метрики с сервера...")
	// serverSnap, err := fetchServerMetrics(*adminAddr, sessionID)
	// if err != nil {
	// 	log.Printf("не удалось получить серверные метрики: %v", err)
	// 	// Не фатально — сохраняем что есть
	// }

	// Шаг 5: сохраняем результат
	result := &benchmark.Result{
		Pattern:       pat.Name,
		Transport:     *transport,
		Scenario:      *scenario,
		StartedAt:     startedAt,
		Duration:      actualDuration.String(),
		Sent:          sentResult,
		ClientMetrics: clientMetrics.Snapshot(), // RTT здесь
	}
	// Создаём папку если не существует
	if err := os.MkdirAll(filepath.Dir(*outPath), 0755); err != nil {
		logging.Fatalf("mkdir", "err", err)
	}

	if err := result.Save(*outPath); err != nil {
		logging.Fatalf("save result", "err", err)
	}

	// Печатаем краткую сводку
	printSummary(result, *outPath)
}

func selectPattern(name string) (benchmark.TrafficPattern, error) {
	for _, p := range benchmark.AllPatterns {
		if p.Name == name {
			return p, nil
		}
	}
	return benchmark.TrafficPattern{},
		fmt.Errorf("неизвестный паттерн %q, доступны: idle, input, scroll", name)
}

// authenticate проходит аутентификацию и возвращает sessionID и control соединение.
// Соединение намеренно не закрываем — держим сессию живой на время benchmark.
func authenticate(serverAddr, username, password, machineID, caPath, certPath, keyPath string, benchParams benchproto.BenchParams) (string, io.Closer, error) {
	tlsCfg, err := loading.LoadMTLSConfig(caPath, certPath, keyPath)
	if err != nil {
		return "", nil, fmt.Errorf("tls config: %w", err)
	}

	dialer := pipe.NoDelayDialer(30 * time.Second)
	raw, err := tls.DialWithDialer(dialer, "tcp", serverAddr, tlsCfg)
	if err != nil {
		return "", nil, fmt.Errorf("dial control: %w", err)
	}

	c := proto.NewConn(raw)

	c.Send(proto.MsgHello, username, password)
	msgType, _, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		raw.Close()
		return "", nil, fmt.Errorf("hello rejected")
	}

	c.Send(proto.MsgBench, benchParams.Encode())
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		raw.Close()
		if len(args) == 0 {
			return "", nil, fmt.Errorf("connect rejected: %w", err)
		} else {
			return "", nil, fmt.Errorf("connect rejected: %s", args[0])
		}
	}

	return args[0], raw, nil
}

// connectData устанавливает data plane соединение и выполняет SESSION handshake.
func connectData(transport, dataAddr, quicAddr, caPath, sessionID string) (net.Conn, error) {
	switch transport {
	case "tcp":
		return connectTCP(dataAddr, caPath, sessionID)
	case "quic":
		return connectQUIC(quicAddr, caPath, sessionID)
	default:
		return nil, fmt.Errorf("неизвестный транспорт: %s", transport)
	}
}

func connectTCP(dataAddr, caPath, sessionID string) (net.Conn, error) {
	tlsCfg, err := loading.LoadTLSConfig(caPath)
	if err != nil {
		return nil, err
	}

	dialer := pipe.NoDelayDialer(10 * time.Second)
	raw, err := tls.DialWithDialer(dialer, "tcp", dataAddr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("dial tcp data: %w", err)
	}

	c := proto.NewConn(raw)
	c.Send(proto.MsgSession, sessionID)
	msgType, _, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		raw.Close()
		return nil, fmt.Errorf("session handshake failed")
	}

	return raw, nil
}

func connectQUIC(quicAddr, caPath, sessionID string) (net.Conn, error) {
	tlsCfg, err := loading.LoadTLSConfig(caPath)
	if err != nil {
		return nil, err
	}
	tlsCfg.NextProtos = []string{"rdp-zero-trust"}

	conn, err := quic.DialAddr(context.Background(), quicAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  5 * time.Minute,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("dial quic: %w", err)
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "stream failed")
		return nil, fmt.Errorf("open quic stream: %w", err)
	}

	qconn := quicconn.New(conn, stream)
	c := proto.NewConn(qconn)
	c.Send(proto.MsgSession, sessionID)
	msgType, _, err := c.Recv()
	if err != nil || msgType != proto.MsgOK {
		conn.CloseWithError(0, "handshake failed")
		return nil, fmt.Errorf("quic session handshake failed")
	}

	return qconn, nil
}

// fetchServerMetrics получает снимок метрик с сервера через admin API.
func fetchServerMetrics(adminAddr, sessionID string) (metrics.Snapshot, error) {
	url := fmt.Sprintf("http://%s/sessions/%s/metrics", adminAddr, sessionID)
	resp, err := http.Get(url)
	if err != nil {
		return metrics.Snapshot{}, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return metrics.Snapshot{}, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var snap metrics.Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return metrics.Snapshot{}, fmt.Errorf("decode: %w", err)
	}
	return snap, nil
}

// printSummary печатает краткую сводку результатов в консоль.
func printSummary(result *benchmark.Result, outPath string) {
	fmt.Println("\n=== Результаты ===")
	fmt.Printf("паттерн:      %s\n", result.Pattern)
	fmt.Printf("транспорт:    %s\n", result.Transport)
	fmt.Printf("сценарий:     %s\n", result.Scenario)
	fmt.Printf("длительность: %s\n\n", result.Duration)

	fmt.Println("--- Отправлено ---")
	fmt.Printf("пакетов: %d  байт: %d  ошибок: %d\n\n",
		result.Sent.PacketsSent,
		result.Sent.BytesSent,
		result.Sent.Errors,
	)

	// RTT — основная метрика
	c := result.ClientMetrics.BenchmarkTraffic
	fmt.Println("--- RTT (round-trip time, ms) ---")
	fmt.Printf("получено echo: %d пакетов\n", c.PacketsReceived)
	fmt.Printf("avg: %.2f  p50: %.2f  p95: %.2f  p99: %.2f  max: %.2f\n\n",
		c.Latency.Avg,
		c.Latency.P50,
		c.Latency.P95,
		c.Latency.P99,
		c.Latency.Max,
	)

	fmt.Println("--- Jitter (ms) ---")
	fmt.Printf("avg: %.2f  max: %.2f\n\n",
		c.Jitter.Avg,
		c.Jitter.Max,
	)

	// Throughput с сервера
	// s := result.ServerMetrics
	// fmt.Println("--- Throughput (сервер) ---")
	// fmt.Printf("%.2f KB/s\n\n", s.ThroughputBps/1024)

	// Loss rate
	lossRate := float64(0)
	if result.Sent.PacketsSent > 0 {
		received := c.PacketsReceived
		lost := result.Sent.PacketsSent - received
		if lost < 0 {
			lost = 0
		}
		lossRate = float64(lost) / float64(result.Sent.PacketsSent) * 100
	}
	fmt.Printf("потери echo: %.2f%%\n", lossRate)
	fmt.Printf("\nРезультат сохранён: %s\n", outPath)
}
