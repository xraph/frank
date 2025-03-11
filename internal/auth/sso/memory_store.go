package sso

import (
	"context"
	"sync"
	"time"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// InMemoryStateStore implements StateStore using an in-memory map
// This is useful for development, testing, or low-traffic scenarios
type InMemoryStateStore struct {
	states     map[string]*stateEntry
	mutex      sync.RWMutex
	logger     logging.Logger
	cleanupPtr *time.Timer
}

// stateEntry represents a stored state with its data and expiration
type stateEntry struct {
	Data      *StateData
	ExpiresAt time.Time
}

// NewInMemoryStateStore creates a new in-memory state store
func NewInMemoryStateStore(logger logging.Logger) *InMemoryStateStore {
	store := &InMemoryStateStore{
		states: make(map[string]*stateEntry),
		logger: logger,
	}

	// Start periodic cleanup
	store.startCleanup()

	return store
}

// StoreState stores SSO state data with an expiration time
func (s *InMemoryStateStore) StoreState(ctx context.Context, state string, data *StateData, expiry time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Calculate expiration time
	expiresAt := time.Now().Add(expiry)

	// Store state
	s.states[state] = &stateEntry{
		Data:      data,
		ExpiresAt: expiresAt,
	}

	return nil
}

// GetState retrieves SSO state data
func (s *InMemoryStateStore) GetState(ctx context.Context, state string) (*StateData, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Get state entry
	entry, ok := s.states[state]
	if !ok {
		return nil, errors.New(errors.CodeInvalidOAuthState, "state not found")
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		// Clean up expired state
		go func() {
			s.mutex.Lock()
			defer s.mutex.Unlock()
			delete(s.states, state)
		}()
		return nil, errors.New(errors.CodeInvalidOAuthState, "state has expired")
	}

	return entry.Data, nil
}

// DeleteState deletes SSO state data
func (s *InMemoryStateStore) DeleteState(ctx context.Context, state string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.states, state)
	return nil
}

// CleanupExpiredStates removes all expired states
func (s *InMemoryStateStore) CleanupExpiredStates(ctx context.Context) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	count := 0

	// Find and remove expired states
	for state, entry := range s.states {
		if now.After(entry.ExpiresAt) {
			delete(s.states, state)
			count++
		}
	}

	return count, nil
}

// startCleanup begins periodic cleanup of expired states
func (s *InMemoryStateStore) startCleanup() {
	// Run cleanup every 5 minutes
	cleanupInterval := 5 * time.Minute

	s.cleanupPtr = time.AfterFunc(cleanupInterval, func() {
		// Run cleanup
		count, err := s.CleanupExpiredStates(context.Background())
		if err != nil {
			s.logger.Error("Failed to clean up expired states",
				logging.Error(err),
			)
		} else if count > 0 {
			s.logger.Debug("Cleaned up expired states",
				logging.Int("count", count),
			)
		}

		// Reschedule cleanup
		s.cleanupPtr.Reset(cleanupInterval)
	})
}

// Close stops the cleanup timer
func (s *InMemoryStateStore) Close() {
	if s.cleanupPtr != nil {
		s.cleanupPtr.Stop()
	}
}
