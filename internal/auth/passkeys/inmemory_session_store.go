package passkeys

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// InMemorySessionStore implements the SessionStore interface with in-memory storage
type InMemorySessionStore struct {
	sessions     map[string]*Session
	mutex        sync.RWMutex
	logger       logging.Logger
	cleanupTimer *time.Timer
}

// NewInMemorySessionStore creates a new in-memory session store
func NewInMemorySessionStore(logger logging.Logger) SessionStore {
	store := &InMemorySessionStore{
		sessions: make(map[string]*Session),
		logger:   logger,
	}

	// Start session cleanup goroutine
	go store.cleanupExpiredSessions()

	return store
}

// StoreSession stores a session
func (s *InMemorySessionStore) StoreSession(ctx context.Context, session *Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Create a deep copy of the session to avoid reference issues
	sessionCopy := &Session{
		ID:        session.ID,
		UserID:    session.UserID,
		Type:      session.Type,
		ExpiresAt: session.ExpiresAt,
	}

	// Deep copy session data
	if session.Data != nil {
		// Marshal and unmarshal to create a deep copy
		dataBytes, err := json.Marshal(session.Data)
		if err != nil {
			return errors.Wrap(errors.CodeInternalServer, err, "failed to marshal session data")
		}

		var dataCopy webauthn.SessionData
		if err := json.Unmarshal(dataBytes, &dataCopy); err != nil {
			return errors.Wrap(errors.CodeInternalServer, err, "failed to unmarshal session data")
		}

		sessionCopy.Data = &dataCopy
	}

	s.sessions[session.ID] = sessionCopy
	return nil
}

// GetSession retrieves a session by ID
func (s *InMemorySessionStore) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "session not found")
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		// Clean up expired session asynchronously
		go func() {
			s.mutex.Lock()
			defer s.mutex.Unlock()
			delete(s.sessions, sessionID)
		}()
		return nil, errors.New(errors.CodeTokenExpired, "session has expired")
	}

	// Create a deep copy of the session to return
	sessionCopy := &Session{
		ID:        session.ID,
		UserID:    session.UserID,
		Type:      session.Type,
		ExpiresAt: session.ExpiresAt,
	}

	// Deep copy session data
	if session.Data != nil {
		// Marshal and unmarshal to create a deep copy
		dataBytes, err := json.Marshal(session.Data)
		if err != nil {
			return nil, errors.Wrap(errors.CodeInternalServer, err, "failed to marshal session data")
		}

		var dataCopy webauthn.SessionData
		if err := json.Unmarshal(dataBytes, &dataCopy); err != nil {
			return nil, errors.Wrap(errors.CodeInternalServer, err, "failed to unmarshal session data")
		}

		sessionCopy.Data = &dataCopy
	}

	return sessionCopy, nil
}

// DeleteSession deletes a session
func (s *InMemorySessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.sessions[sessionID]; !exists {
		return errors.New(errors.CodeNotFound, "session not found")
	}

	delete(s.sessions, sessionID)
	return nil
}

// cleanupExpiredSessions periodically removes expired sessions
func (s *InMemorySessionStore) cleanupExpiredSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C

		s.mutex.Lock()
		now := time.Now()
		for id, session := range s.sessions {
			if now.After(session.ExpiresAt) {
				delete(s.sessions, id)
				s.logger.Debug("Removed expired session",
					logging.String("session_id", id),
					logging.String("user_id", session.UserID),
				)
			}
		}
		s.mutex.Unlock()
	}
}
