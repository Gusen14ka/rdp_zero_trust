package metrics

import (
	"sort"
	"sync"
	"time"
)

const (
	// maxSamples — максимальный размер ring buffer для latency/jitter.
	// При 16ms интервале за 10 минут = 37500 samples.
	// 10000 достаточно для статистически значимых перцентилей.
	maxSamples = 10000
)

type StreamMetrics struct {
	mu sync.Mutex

	startedAt  time.Time
	lastPacket time.Time

	PacketsReceived int64
	BytesReceived   int64

	// rawSamples — реальный RDP трафик, latency неизвестна
	rawBytes    int64
	rawPackets  int64
	rawArrivals []float64
	rawArrIdx   int
	rawArrFull  bool

	// benchmarkSamples — синтетические пакеты с известным timestamp
	benchPackets  int64
	benchBytes    int64
	benchLatency  []float64
	benchLatIdx   int
	benchLatFull  bool
	benchArrivals []float64
	benchArrIdx   int
	benchArrFull  bool
}

func NewStreamMetrics() *StreamMetrics {
	return &StreamMetrics{
		startedAt:     time.Now(),
		rawArrivals:   make([]float64, maxSamples),
		benchLatency:  make([]float64, maxSamples),
		benchArrivals: make([]float64, maxSamples),
	}
}

// RecordRaw записывает реальный RDP трафик — latency неизвестна
func (m *StreamMetrics) RecordRaw(bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if !m.lastPacket.IsZero() {
		interval := float64(now.Sub(m.lastPacket).Milliseconds())
		m.rawArrivals[m.rawArrIdx] = interval
		m.rawArrIdx = (m.rawArrIdx + 1) % maxSamples
		if m.rawArrIdx == 0 {
			m.rawArrFull = true
		}
	}
	m.lastPacket = now
	m.rawPackets++
	m.rawBytes += int64(bytes)
	m.PacketsReceived++
	m.BytesReceived += int64(bytes)
}

// RecordBenchmark записывает benchmark пакет с известной latency
func (m *StreamMetrics) RecordBenchmark(latency time.Duration, bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Jitter между benchmark пакетами
	if !m.lastPacket.IsZero() {
		interval := float64(now.Sub(m.lastPacket).Milliseconds())
		m.benchArrivals[m.benchArrIdx] = interval
		m.benchArrIdx = (m.benchArrIdx + 1) % maxSamples
		if m.benchArrIdx == 0 {
			m.benchArrFull = true
		}
	}
	m.lastPacket = now

	// Latency
	ms := float64(latency.Milliseconds())
	m.benchLatency[m.benchLatIdx] = ms
	m.benchLatIdx = (m.benchLatIdx + 1) % maxSamples
	if m.benchLatIdx == 0 {
		m.benchLatFull = true
	}

	m.benchPackets++
	m.benchBytes += int64(bytes)
	m.PacketsReceived++
	m.BytesReceived += int64(bytes)
}

// Snapshot возвращает текущий снимок метрик
func (m *StreamMetrics) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	elapsed := time.Since(m.startedAt)
	var throughput float64
	if elapsed > 0 {
		throughput = float64(m.BytesReceived) / elapsed.Seconds()
	}

	return Snapshot{
		PacketsReceived: m.PacketsReceived,
		BytesReceived:   m.BytesReceived,
		ThroughputBps:   throughput,
		ElapsedMs:       elapsed.Milliseconds(),
		// Реальный RDP — только jitter (latency недоступна без timestamp)
		RawTraffic: RawStats{
			PacketsReceived: m.rawPackets,
			BytesReceived:   m.rawBytes,
			Jitter:          calcStats(activeSlice(m.rawArrivals, m.rawArrIdx, m.rawArrFull)),
		},

		// Benchmark — полные метрики
		BenchmarkTraffic: BenchStats{
			PacketsReceived: m.benchPackets,
			BytesReceived:   m.benchBytes,
			Latency:         calcStats(activeSlice(m.benchLatency, m.benchLatIdx, m.benchLatFull)),
			Jitter:          calcStats(activeSlice(m.benchArrivals, m.benchArrIdx, m.benchArrFull)),
		},
	}
}

// activeSlice возвращает актуальные данные из ring buffer в правильном порядке
func activeSlice(buf []float64, idx int, full bool) []float64 {
	if !full {
		result := make([]float64, idx)
		copy(result, buf[:idx])
		return result
	}
	result := make([]float64, maxSamples)
	copy(result, buf[idx:])
	copy(result[maxSamples-idx:], buf[:idx])
	return result
}

type Snapshot struct {
	PacketsReceived  int64      `json:"packets_received"`
	BytesReceived    int64      `json:"bytes_received"`
	ThroughputBps    float64    `json:"throughput_bps"`
	ElapsedMs        int64      `json:"elapsed_ms"`
	RawTraffic       RawStats   `json:"raw_traffic"`
	BenchmarkTraffic BenchStats `json:"benchmark_traffic"`
}

type RawStats struct {
	PacketsReceived int64 `json:"packets_received"`
	BytesReceived   int64 `json:"bytes_received"`
	// Latency недоступна — реальный RDP не несёт timestamp.
	// Для измерения latency реального RDP нужна модификация протокола
	// что выходит за рамки данной работы.
	Jitter Stats `json:"jitter_ms"`
}

type BenchStats struct {
	PacketsReceived int64 `json:"packets_received"`
	BytesReceived   int64 `json:"bytes_received"`
	Latency         Stats `json:"latency_ms"`
	Jitter          Stats `json:"jitter_ms"`
}

type Stats struct {
	Avg float64 `json:"avg"`
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
	Max float64 `json:"max"`
}

func calcStats(data []float64) Stats {
	if len(data) == 0 {
		return Stats{}
	}

	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted) // O(n log n)

	var sum float64
	for _, v := range sorted {
		sum += v
	}

	return Stats{
		Avg: sum / float64(len(sorted)),
		P50: interpolatedPercentile(sorted, 50),
		P95: interpolatedPercentile(sorted, 95),
		P99: interpolatedPercentile(sorted, 99),
		Max: sorted[len(sorted)-1],
	}
}

// interpolatedPercentile — линейная интерполяция между соседними элементами.
// Даёт более точный результат чем nearest rank на малых выборках.
func interpolatedPercentile(sorted []float64, p float64) float64 {
	if len(sorted) == 1 {
		return sorted[0]
	}
	// Позиция в [0, n-1]
	pos := p / 100 * float64(len(sorted)-1)
	lower := int(pos)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	// Линейная интерполяция
	frac := pos - float64(lower)
	return sorted[lower] + frac*(sorted[upper]-sorted[lower])
}
