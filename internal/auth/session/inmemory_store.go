package session

import (
	"context"
	"sync"
	"time"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// InMemoryStore implements an in-memory session store
type InMemoryStore struct {
	sessions        map[string]*sessionData
	mutex           sync.RWMutex
	logger          logging.Logger
	cleanupInterval time.Duration
}

// NewInMemoryStore creates a new in-memory session store
func NewInMemoryStore(logger logging.Logger, cleanupInterval time.Duration) *InMemoryStore {
	store := &InMemoryStore{
		sessions:        make(map[string]*sessionData),
		logger:          logger,
		cleanupInterval: cleanupInterval,
	}

	// Start background cleanup
	// go store.startCleanup()

	return store
}

// StoreSession stores a session with an expiration time
func (s *InMemoryStore) StoreSession(ctx context.Context, token string, session *SessionInfo, expiry time.Duration) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Set expiration time
	expiresAt := time.Now().Add(expiry)

	// Store session
	s.sessions[token] = &sessionData{
		session:   session,
		expiresAt: expiresAt,
	}

	return "", nil
}

// GetSession retrieves a session by token
func (s *InMemoryStore) GetSession(ctx context.Context, token string) (*SessionInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Get session data
	data, ok := s.sessions[token]
	if !ok {
		return nil, errors.New(errors.CodeNotFound, "session not found")
	}

	// Check if the session has expired
	if time.Now().After(data.expiresAt) {
		// Session has expired, remove it
		go s.DeleteSession(ctx, token)
		return nil, errors.New(errors.CodeSessionExpired, "session has expired")
	}

	return data.session, nil
}

// UpdateSession updates an existing session
func (s *InMemoryStore) UpdateSession(ctx context.Context, token string, session *SessionInfo) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Get session data
	data, ok := s.sessions[token]
	if !ok {
		return errors.New(errors.CodeNotFound, "session not found")
	}

	// Update session, keeping the same expiration time
	data.session = session

	return nil
}

// DeleteSession deletes a session
func (s *InMemoryStore) DeleteSession(ctx context.Context, token string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Delete session
	delete(s.sessions, token)

	return nil
}

// startCleanup starts the background cleanup process
func (s *InMemoryStore) startCleanup() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanup()
	}
}

// cleanup removes expired sessions
func (s *InMemoryStore) cleanup() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Current time
	now := time.Now()

	// Track expired sessions
	var expired []string

	// Find expired sessions
	for token, data := range s.sessions {
		if now.After(data.expiresAt) {
			expired = append(expired, token)
		}
	}

	// Remove expired sessions
	for _, token := range expired {
		delete(s.sessions, token)
	}

	if len(expired) > 0 {
		s.logger.Debug("Cleaned up expired sessions", logging.Int("count", len(expired)))
	}
}
