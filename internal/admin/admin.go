package admin

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"rdp_zero_trust/internal/session"
)

type Server struct {
	sessions *session.Store
}

func NewServer(sessions *session.Store) *Server {
	return &Server{sessions: sessions}
}

// Start запускает HTTP сервер только на localhost —
// снаружи он недоступен, только администратор с доступом к серверу
func (s *Server) Start(addr string) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /sessions", s.listSessions)
	mux.HandleFunc("DELETE /sessions/{id}", s.deleteSession)
	mux.HandleFunc("DELETE /users/{username}/sessions", s.deleteUserSessions)

	log.Printf("admin HTTP слушает %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("admin: %v", err)
	}
}

// deleteSession - принудительно завершает и удаляет сессию по ID
func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}

	_, ok := s.sessions.Get(id)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	s.sessions.Delete(id)
	log.Printf("admib: сессия %s принудительно завершена", id)
	w.WriteHeader(http.StatusNoContent)
}

// deleteUserSessions - завершает все сессии пользователя
func (s *Server) deleteUserSessions(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		http.Error(w, "missing username", http.StatusBadRequest)
		return
	}

	userSessions := s.sessions.ByUser(username)
	if len(userSessions) == 0 {
		http.Error(w, "no sessions found", http.StatusNotFound)
		return
	}

	for _, sess := range userSessions {
		s.sessions.Delete(sess.ID)
	}

	log.Printf("admin: завершено %d сессий пользователя %s", len(userSessions), username)
	w.WriteHeader(http.StatusNoContent)
}

// listSessions — список всех сессий
func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	sessions := s.sessions.All()

	type sessionView struct {
		ID        string    `json:"id"`
		Username  string    `json:"username"`
		MachineID string    `json:"machine_id"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	result := make([]sessionView, 0, len(sessions))
	for _, sess := range sessions {
		result = append(result, sessionView{
			ID:        sess.ID,
			Username:  sess.Username,
			MachineID: sess.MachineID,
			CreatedAt: sess.CreatedAt,
			ExpiresAt: sess.ExpiresAt,
		})
	}

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(result)
}
