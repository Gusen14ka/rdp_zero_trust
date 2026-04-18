package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const DefaultTTL = 60 * time.Minute

type Session struct {
	ID         string
	Username   string
	MachineID  string
	TargetAddr string
	CreatedAt  time.Time
	ExpiresAt  time.Time

	// cancel закрывается когда сессия должна завершиться —
	// control plane горутина читает из него и рвёт соединение
	cancel chan struct{}
}

// Cancel принудительно завершает сессию
func (s *Session) Cancel() {
	select {
	case <-s.cancel:
		// Если уже закрывали сработает этот кейс => ничего не делаем
	default:
		close(s.cancel)
	}
}

// Done возвращает read-only канал, который закроется при завершении сесии
func (s *Session) Done() <-chan struct{} {
	return s.cancel
}

type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

func NewStore() *Store {
	return &Store{
		sessions: make(map[string]*Session),
	}
}

func (s *Store) Create(username, machineID, targetAddr string, ttl time.Duration) (*Session, error) {
	id, err := randomID()
	if err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}

	now := time.Now()
	sess := &Session{
		ID:         id,
		Username:   username,
		MachineID:  machineID,
		TargetAddr: targetAddr,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		cancel:     make(chan struct{}),
	}

	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()

	return sess, nil
}

func (s *Store) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

func (s *Store) Delete(id string) {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	s.mu.Unlock()

	if ok {
		// Сначала отменяет - посылаем сигнал в горутины, далее удаляем
		sess.Cancel()
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
	}
}

// ByUser возвращает все сессии пользователя
func (s *Store) ByUser(username string) []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []*Session
	for _, sess := range s.sessions {
		if sess.Username == username {
			result = append(result, sess)
		}
	}
	return result
}

func (s *Store) All() []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		result = append(result, sess)
	}

	return result
}

func randomID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
