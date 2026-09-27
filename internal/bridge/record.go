package bridge

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"
)

// Recorder пишет по строке на каждый PDU: время от старта (мкс), канал,
// направление, размер. nil = запись выключена.
type Recorder struct {
	mu    sync.Mutex
	f     *os.File
	w     *bufio.Writer
	start time.Time
	stop  chan struct{}
}

var Rec *Recorder

func NewRecorder(path string) (*Recorder, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	r := &Recorder{
		f:     f,
		w:     bufio.NewWriterSize(f, 64*1024),
		start: time.Now(),
		stop:  make(chan struct{}),
	}
	fmt.Fprintln(r.w, "t_us,channel,direction,size")

	// Периодический сброс буфера, чтобы данные не терялись при Ctrl+C
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				r.mu.Lock()
				r.w.Flush()
				r.mu.Unlock()
			case <-r.stop:
				return
			}
		}
	}()
	return r, nil
}

func (r *Recorder) Record(channel, direction string, size int) {
	us := time.Since(r.start).Microseconds()
	r.mu.Lock()
	fmt.Fprintf(r.w, "%d,%s,%s,%d\n", us, channel, direction, size)
	r.mu.Unlock()
}

// Mark — служебное событие (READY, начало сценария и т.п.)
func (r *Recorder) Mark(event string) {
	r.Record(event, "mark", 0)
}

func (r *Recorder) Close() error {
	close(r.stop)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.w.Flush()
	return r.f.Close()
}
