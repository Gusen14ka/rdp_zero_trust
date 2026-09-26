package agentpool

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"rdp_zero_trust/internal/bridge"
	"rdp_zero_trust/internal/proto"
	"rdp_zero_trust/internal/quicconn"
)

const (
	PurposeRelay  = "relay"  // 1 стрим — сырой байтовый relay негоциации
	PurposeBridge = "bridge" // 4 стрима — graphics/input/vchannel/control
)

type waiter struct {
	want int
	got  []*quic.Stream
	ch   chan []*quic.Stream
}

// Agent — одно постоянное соединение от процесса cmd/agent на таргет-машине.
type Agent struct {
	MachineID string
	qconn     *quic.Conn
	ctrl      *proto.Conn

	mu      sync.Mutex
	waiters map[string]*waiter // ключ: sessionID+":"+purpose
}

var (
	mu   sync.Mutex
	byID = map[string]*Agent{}
)

func Register(machineID string, qconn *quic.Conn, ctrl *proto.Conn) *Agent {
	a := &Agent{
		MachineID: machineID,
		qconn:     qconn,
		ctrl:      ctrl,
		waiters:   make(map[string]*waiter),
	}

	mu.Lock()
	if old, ok := byID[machineID]; ok {
		log.Printf("agentpool: заменяю предыдущего агента для %s", machineID)
		old.qconn.CloseWithError(0, "replaced")
	}
	byID[machineID] = a
	mu.Unlock()

	go a.dispatchLoop()
	return a
}

func Unregister(machineID string, a *Agent) {
	mu.Lock()
	defer mu.Unlock()
	if cur, ok := byID[machineID]; ok && cur == a {
		delete(byID, machineID)
	}
}

func Get(machineID string) (*Agent, bool) {
	mu.Lock()
	defer mu.Unlock()
	a, ok := byID[machineID]
	return a, ok
}

func waiterKey(sessionID, purpose string) string {
	return sessionID + ":" + purpose
}

// dispatchLoop постоянно принимает стримы, открытые агентом, читает на каждом
// первое сообщение SESSION <id> <purpose> и складывает их в нужный waiter,
// пока не наберётся ожидаемое количество (1 для relay, 4 для bridge).
func (a *Agent) dispatchLoop() {
	for {
		stream, err := a.qconn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("agentpool[%s]: dispatch loop завершён: %v", a.MachineID, err)
			return
		}
		go a.handleIncomingStream(stream)
	}
}

func (a *Agent) handleIncomingStream(s *quic.Stream) {
	sc := quicconn.New(a.qconn, s)
	pc := proto.NewConn(sc)

	msgType, args, err := pc.Recv()
	if err != nil || msgType != proto.MsgSession || len(args) < 2 {
		log.Printf("agentpool[%s]: некорректный стрим при открытии: %v %v err=%v",
			a.MachineID, msgType, args, err)
		s.CancelRead(0)
		s.CancelWrite(0)
		return
	}
	sessionID, purpose := args[0], args[1]
	if err := pc.Send(proto.MsgOK); err != nil {
		return
	}

	key := waiterKey(sessionID, purpose)

	a.mu.Lock()
	w, ok := a.waiters[key]
	if !ok {
		// стрим пришёл раньше, чем RequestX успел зарегистрировать waiter —
		// не должно происходить при нормальном порядке вызовов, но на
		// всякий случай не теряем стрим молча
		log.Printf("agentpool[%s]: стрим для %s без ожидающего запроса, отбрасываю",
			a.MachineID, key)
		a.mu.Unlock()
		s.CancelRead(0)
		s.CancelWrite(0)
		return
	}
	w.got = append(w.got, s)
	full := len(w.got) == w.want
	var toSend []*quic.Stream
	if full {
		toSend = w.got
		delete(a.waiters, key)
	}
	a.mu.Unlock()

	if full {
		w.ch <- toSend
	}
}

func (a *Agent) request(purpose string, sessionID string, want int, timeout time.Duration) ([]*quic.Stream, error) {
	key := waiterKey(sessionID, purpose)
	ch := make(chan []*quic.Stream, 1)

	a.mu.Lock()
	a.waiters[key] = &waiter{want: want, ch: ch}
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.waiters, key)
		a.mu.Unlock()
	}()

	var msgTypeToSend string
	if purpose == PurposeRelay {
		msgTypeToSend = proto.MsgOpenRelay
	} else {
		msgTypeToSend = proto.MsgOpenBridge
	}

	if err := a.ctrl.Send(msgTypeToSend, sessionID); err != nil {
		return nil, fmt.Errorf("не удалось отправить запрос агенту: %w", err)
	}

	select {
	case streams := <-ch:
		return streams, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("таймаут ожидания %s от агента %s", purpose, a.MachineID)
	}
}

// RequestRelay просит агента открыть 1 стрим для сырого relay фазы 1.
func (a *Agent) RequestRelay(sessionID string, timeout time.Duration) (*quic.Stream, error) {
	streams, err := a.request(PurposeRelay, sessionID, 1, timeout)
	if err != nil {
		return nil, err
	}
	return streams[0], nil
}

// RequestBridge просит агента открыть 4 стрима для фазы 2 (мультиплекс).
func (a *Agent) RequestBridge(sessionID string, timeout time.Duration) ([bridge.ChannelCount]*quic.Stream, error) {
	var zero [bridge.ChannelCount]*quic.Stream
	streams, err := a.request(PurposeBridge, sessionID, bridge.ChannelCount, timeout)
	if err != nil {
		return zero, err
	}
	var result [bridge.ChannelCount]*quic.Stream
	copy(result[:], streams)
	return result, nil
}
