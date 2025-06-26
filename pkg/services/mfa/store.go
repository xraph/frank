package mfa

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/redis/go-redis/v9"
)

// SessionStore MFA session storage interface
type SessionStore interface {
	Store(ctx context.Context, token string, login *model.PendingMFALogin, expiry time.Duration) error
	Get(ctx context.Context, token string) (*model.PendingMFALogin, error)
	Delete(ctx context.Context, token string) error
}

// Redis implementation
type redisMFASessionStore struct {
	client redis.UniversalClient
	prefix string
}

func NewRedisSessionStore(client *data.Clients) SessionStore {
	return &redisMFASessionStore{
		client: client.Redis,
		prefix: "mfa_session:",
	}
}

func (r *redisMFASessionStore) Store(ctx context.Context, token string, login *model.PendingMFALogin, expiry time.Duration) error {
	data, err := json.Marshal(login)
	if err != nil {
		return err
	}

	key := r.prefix + token
	return r.client.Set(ctx, key, data, expiry).Err()
}

func (r *redisMFASessionStore) Get(ctx context.Context, token string) (*model.PendingMFALogin, error) {
	key := r.prefix + token
	data, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New(errors.CodeNotFound, "MFA session not found")
		}
		return nil, err
	}

	var login model.PendingMFALogin
	err = json.Unmarshal([]byte(data), &login)
	if err != nil {
		return nil, err
	}

	return &login, nil
}

func (r *redisMFASessionStore) Delete(ctx context.Context, token string) error {
	key := r.prefix + token
	return r.client.Del(ctx, key).Err()
}

// In-memory fallback implementation (for development/testing)
type inMemoryMFASessionStore struct {
	sessions map[string]*model.PendingMFALogin
	mu       sync.RWMutex
}

func NewInMemorySessionStore() SessionStore {
	store := &inMemoryMFASessionStore{
		sessions: make(map[string]*model.PendingMFALogin),
	}

	// Start cleanup goroutine
	go store.cleanup()

	return store
}

func (m *inMemoryMFASessionStore) Store(ctx context.Context, token string, login *model.PendingMFALogin, expiry time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[token] = login
	return nil
}

func (m *inMemoryMFASessionStore) Get(ctx context.Context, token string) (*model.PendingMFALogin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	login, exists := m.sessions[token]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "MFA session not found")
	}

	if time.Now().After(login.ExpiresAt) {
		go m.Delete(context.Background(), token) // async cleanup
		return nil, errors.New(errors.CodeNotFound, "MFA session expired")
	}

	return login, nil
}

func (m *inMemoryMFASessionStore) Delete(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, token)
	return nil
}

func (m *inMemoryMFASessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for token, login := range m.sessions {
			if now.After(login.ExpiresAt) {
				delete(m.sessions, token)
			}
		}
		m.mu.Unlock()
	}
}
