// Package agentpool хранит зарегистрированных агентов (по одному на таргет-машину)
// и сопоставляет входящие от агента QUIC-стримы с сессиями, которые их ждут.
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

// Agent — одно постоянное соединение от процесса cmd/agent на таргет-машине.
type Agent struct {
	MachineID string
	qconn     *quic.Conn
	ctrl      *proto.Conn

	mu      sync.Mutex
	pending map[string]chan [bridge.ChannelCount]*quic.Stream // sessionID -> канал ожидания
}

var (
	mu   sync.Mutex
	byID = map[string]*Agent{}
)

// Register регистрирует нового агента и запускает его диспетчер стримов.
// qconn должен жить, пока агент подключён — вызывающий код отвечает за
// закрытие при обрыве соединения (см. Unregister).
func Register(machineID string, qconn *quic.Conn, ctrl *proto.Conn) *Agent {
	a := &Agent{
		MachineID: machineID,
		qconn:     qconn,
		ctrl:      ctrl,
		pending:   make(map[string]chan [bridge.ChannelCount]*quic.Stream),
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

// Unregister убирает агента из реестра (вызывать при обрыве соединения).
func Unregister(machineID string, a *Agent) {
	mu.Lock()
	defer mu.Unlock()
	if cur, ok := byID[machineID]; ok && cur == a {
		delete(byID, machineID)
	}
}

// Get возвращает агента для машины, если он сейчас подключён.
func Get(machineID string) (*Agent, bool) {
	mu.Lock()
	defer mu.Unlock()
	a, ok := byID[machineID]
	return a, ok
}

// dispatchLoop постоянно принимает стримы, открытые агентом, читает на каждом
// первое сообщение SESSION <id> и складывает 4 набранных стрима в pending-канал
// соответствующей сессии.
func (a *Agent) dispatchLoop() {
	collected := make(map[string][]*quic.Stream)

	for {
		stream, err := a.qconn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("agentpool[%s]: dispatch loop завершён: %v", a.MachineID, err)
			return
		}

		go func(s *quic.Stream) {
			sc := quicconn.New(a.qconn, s)
			pc := proto.NewConn(sc)

			msgType, args, err := pc.Recv()
			if err != nil || msgType != proto.MsgSession || len(args) == 0 {
				log.Printf("agentpool[%s]: некорректный стрим при открытии: %v %v err=%v",
					a.MachineID, msgType, args, err)
				s.CancelRead(0)
				s.CancelWrite(0)
				return
			}
			sessionID := args[0]
			if err := pc.Send(proto.MsgOK); err != nil {
				return
			}

			a.mu.Lock()
			collected[sessionID] = append(collected[sessionID], s)
			full := len(collected[sessionID]) == bridge.ChannelCount
			var toSend [bridge.ChannelCount]*quic.Stream
			if full {
				copy(toSend[:], collected[sessionID])
				delete(collected, sessionID)
			}
			ch := a.pending[sessionID]
			a.mu.Unlock()

			if full && ch != nil {
				ch <- toSend
			}
		}(stream)
	}
}

// RequestBridge просит агента открыть мост для sessionID и дожидается
// 4 собранных стримов (или ошибки/таймаута).
func (a *Agent) RequestBridge(sessionID string, timeout time.Duration) ([bridge.ChannelCount]*quic.Stream, error) {
	var zero [bridge.ChannelCount]*quic.Stream

	ch := make(chan [bridge.ChannelCount]*quic.Stream, 1)
	a.mu.Lock()
	a.pending[sessionID] = ch
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pending, sessionID)
		a.mu.Unlock()
	}()

	if err := a.ctrl.Send(proto.MsgOpenBridge, sessionID); err != nil {
		return zero, fmt.Errorf("не удалось отправить OPEN_BRIDGE агенту: %w", err)
	}

	select {
	case streams := <-ch:
		return streams, nil
	case <-time.After(timeout):
		return zero, fmt.Errorf("таймаут ожидания моста от агента %s", a.MachineID)
	}
}
