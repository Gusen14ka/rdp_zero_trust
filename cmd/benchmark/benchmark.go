package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"rdp_zero_trust/internal/benchmark"
	"rdp_zero_trust/internal/loading"
	"rdp_zero_trust/internal/metrics"
	"rdp_zero_trust/internal/pipe"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/quicconn"

	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
)

func main() {
	serverAddr := flag.String("server", "192.168.0.21:9000", "адрес control plane")
	dataAddr := flag.String("data", "192.168.0.21:9001", "адрес data plane TCP")
	quicAddr := flag.String("quic", "192.168.0.21:9002", "адрес data plane QUIC")
	adminAddr := flag.String("admin", "192.168.0.21:9999", "адрес admin HTTP")
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
	flag.Parse()

	// Выбираем паттерн
	pat, err := selectPattern(*patternStr)
	if err != nil {
		log.Fatalf("паттерн: %v", err)
	}

	log.Printf("=== Benchmark ===")
	log.Printf("паттерн:   %s", pat.Name)
	log.Printf("транспорт: %s", *transport)
	log.Printf("сценарий:  %s", *scenario)
	log.Printf("длительность: %v", pat.Duration)

	// Шаг 1: аутентификация через control plane
	sessionID, ctrlConn, err := authenticate(
		*serverAddr, *username, *password, *machineID,
		*caPath, *certPath, *keyPath,
	)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	defer ctrlConn.Close()
	log.Printf("сессия: %s", sessionID)

	// Шаг 2: data plane соединение
	dataConn, err := connectData(*transport, *dataAddr, *quicAddr, *caPath, sessionID)
	if err != nil {
		log.Fatalf("data plane: %v", err)
	}
	defer dataConn.Close()
	log.Printf("data plane подключён (%s)", *transport)

	// Шаг 3: запускаем benchmark
	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), pat.Duration)
	defer cancel()

	// Локальные метрики клиентской стороны — для направления server→client
	// Сервер сам считает направление client→server через MeteredConn
	//clientMetrics := metrics.NewStreamMetrics()

	var wg sync.WaitGroup
	var sentResult benchmark.SenderResult

	// Направление client → server: имитируем input events
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("sender старт: %d байт каждые %v",
			pat.ClientPacketSize, pat.ClientPacketInterval)
		sentResult = benchmark.RunSender(ctx, dataConn,
			pat.ClientPacketSize, pat.ClientPacketInterval)
		log.Printf("sender завершён: отправлено %d пакетов", sentResult.PacketsSent)
	}()

	// Направление server → client: читаем что сервер нам шлёт
	// В benchmark режиме сервер проксирует наши пакеты на машину и обратно —
	// мы видим echo. Метрики этого направления считаем локально.
	// wg.Add(1)
	// go func() {
	// 	defer wg.Done()
	// 	log.Printf("receiver старт")
	// 	benchmark.RunReceiver(ctx, dataConn, clientMetrics)
	// 	log.Printf("receiver завершён: получено %d пакетов",
	// 		clientMetrics.PacketsReceived)
	// }()

	wg.Wait()
	actualDuration := time.Since(startedAt)
	log.Printf("benchmark завершён за %v", actualDuration)

	// Шаг 4: получаем серверные метрики через admin API
	log.Printf("получаем метрики с сервера...")
	serverSnap, err := fetchServerMetrics(*adminAddr, sessionID)
	if err != nil {
		log.Printf("не удалось получить серверные метрики: %v", err)
		// Не фатально — сохраняем что есть
	}

	// Шаг 5: сохраняем результат
	result := &benchmark.Result{
		Pattern:   pat.Name,
		Transport: *transport,
		Scenario:  *scenario,
		StartedAt: startedAt,
		Duration:  actualDuration.String(),
		Sent:      sentResult,
		Received:  serverSnap,
	}
	// Создаём папку если не существует
	if err := os.MkdirAll(filepath.Dir(*outPath), 0755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	if err := result.Save(*outPath); err != nil {
		log.Fatalf("save result: %v", err)
	}

	// Печатаем краткую сводку
	//printSummary(result, clientMetrics.Snapshot(), *outPath)
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
func authenticate(serverAddr, username, password, machineID, caPath, certPath, keyPath string) (string, io.Closer, error) {
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

	c.Send(proto.MsgBench, "benchmark")
	msgType, args, err := c.Recv()
	if err != nil || msgType != proto.MsgOK || len(args) == 0 {
		raw.Close()
		return "", nil, fmt.Errorf("connect rejected")
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
func printSummary(result *benchmark.Result, clientSnap metrics.Snapshot, outPath string) {
	fmt.Println("\n=== Результаты ===")
	fmt.Printf("паттерн:   %s\n", result.Pattern)
	fmt.Printf("транспорт: %s\n", result.Transport)
	fmt.Printf("сценарий:  %s\n", result.Scenario)
	fmt.Printf("длительность: %s\n\n", result.Duration)

	fmt.Println("--- Отправлено (client → server) ---")
	fmt.Printf("пакетов: %d\n", result.Sent.PacketsSent)
	fmt.Printf("байт:    %d\n", result.Sent.BytesSent)
	fmt.Printf("ошибок:  %d\n\n", result.Sent.Errors)

	fmt.Println("--- Получено сервером (метрики сервера) ---")
	s := result.Received
	fmt.Printf("пакетов:    %d\n", s.PacketsReceived)
	fmt.Printf("throughput: %.2f KB/s\n", s.ThroughputBps/1024)

	if s.BenchmarkTraffic.PacketsReceived > 0 {
		fmt.Println("\n  Latency (ms):")
		fmt.Printf("  avg: %.2f  p50: %.2f  p95: %.2f  p99: %.2f  max: %.2f\n",
			s.BenchmarkTraffic.Latency.Avg,
			s.BenchmarkTraffic.Latency.P50,
			s.BenchmarkTraffic.Latency.P95,
			s.BenchmarkTraffic.Latency.P99,
			s.BenchmarkTraffic.Latency.Max,
		)
		fmt.Println("\n  Jitter (ms):")
		fmt.Printf("  avg: %.2f  max: %.2f\n",
			s.BenchmarkTraffic.Jitter.Avg,
			s.BenchmarkTraffic.Jitter.Max,
		)
	}

	lossRate := float64(0)
	if result.Sent.PacketsSent > 0 {
		received := s.BenchmarkTraffic.PacketsReceived
		lost := result.Sent.PacketsSent - received
		if lost < 0 {
			lost = 0
		}
		lossRate = float64(lost) / float64(result.Sent.PacketsSent) * 100
	}
	fmt.Printf("\nпотери: %.2f%%\n", lossRate)
	fmt.Printf("\nРезультат сохранён: %s\n", outPath)
}
