package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type Session struct {
	ID         string
	Username   string
	MachineID  string
	TargetAddr string
	CreatedAt  time.Time
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

func (s *Store) Create(username, machineID, targetAddr string) (*Session, error) {
	id, err := randomID()
	if err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}

	sess := &Session{
		ID:         id,
		Username:   username,
		MachineID:  machineID,
		TargetAddr: targetAddr,
		CreatedAt:  time.Now(),
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
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func randomID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
