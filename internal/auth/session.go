package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const sessionCookieName = "multipass_session"

// SessionStore manages browser sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, userInfo *UserInfo) (*Session, error)
	GetSession(ctx context.Context, sessionID string) (*Session, bool, error)
	DeleteSession(ctx context.Context, sessionID string) error
	Close() error
}

// MemorySessionStore stores sessions in process.
type MemorySessionStore struct {
	sessions  map[string]*Session // sessionID -> Session
	mu        sync.RWMutex
	ttl       time.Duration
	stopCh    chan struct{}
	closeOnce sync.Once
}

// NewMemorySessionStore creates an in-memory session store.
func NewMemorySessionStore(ttl time.Duration) *MemorySessionStore {
	store := &MemorySessionStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
		stopCh:   make(chan struct{}),
	}

	go store.cleanupLoop()

	return store
}

// CreateSession creates a session for a user.
func (s *MemorySessionStore) CreateSession(ctx context.Context, userInfo *UserInfo) (*Session, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("generating session ID: %w", err)
	}

	session := &Session{
		SessionID: sessionID,
		UserInfo:  cloneUserInfo(userInfo),
		ExpiresAt: time.Now().Add(s.ttl),
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	return session, nil
}

// GetSession returns a session by ID.
func (s *MemorySessionStore) GetSession(ctx context.Context, sessionID string) (*Session, bool, error) {
	s.mu.RLock()
	session, ok := s.sessions[sessionID]
	s.mu.RUnlock()

	if !ok {
		return nil, false, nil
	}

	if time.Now().After(session.ExpiresAt) {
		_ = s.DeleteSession(ctx, sessionID)
		return nil, false, nil
	}

	return cloneSession(session), true, nil
}

// DeleteSession removes a session.
func (s *MemorySessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

// cleanupLoop periodically removes expired sessions.
func (s *MemorySessionStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopCh:
			return
		}
	}
}

// cleanup removes expired sessions.
func (s *MemorySessionStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

// Close stops the cleanup loop.
func (s *MemorySessionStore) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopCh)
	})
	return nil
}

func cloneSession(session *Session) *Session {
	if session == nil {
		return nil
	}

	var userInfo *UserInfo
	if session.UserInfo != nil {
		copied := *session.UserInfo
		userInfo = &copied
	}

	return &Session{
		SessionID: session.SessionID,
		UserInfo:  userInfo,
		ExpiresAt: session.ExpiresAt,
	}
}

func cloneUserInfo(userInfo *UserInfo) *UserInfo {
	if userInfo == nil {
		return &UserInfo{}
	}

	copied := *userInfo
	return &copied
}

// generateSessionID creates a random session ID.
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SetSessionCookie sets the session cookie.
func SetSessionCookie(w http.ResponseWriter, sessionID string, maxAge int, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetSessionCookie returns the session cookie.
func GetSessionCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// ClearSessionCookie removes the session cookie.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// IsSecureRequest reports whether cookies should be secure.
func IsSecureRequest(r *http.Request, trustForwardedProto bool) bool {
	if r != nil && r.TLS != nil {
		return true
	}

	if !trustForwardedProto {
		return false
	}

	forwardedProto := ""
	if r != nil {
		forwardedProto = r.Header.Get("X-Forwarded-Proto")
	}

	return strings.EqualFold(forwardedProto, "https")
}
