package passkeys

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// // RedisClient defines the interface for Redis operations
// type RedisClient interface {
// 	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
// 	Get(ctx context.Context, key string) *redis.StringCmd
// 	Del(ctx context.Context, keys ...string) *redis.IntCmd
// }

// RedisSessionStore implements the SessionStore interface with Redis
type RedisSessionStore struct {
	client    redis.UniversalClient
	keyPrefix string
	logger    logging.Logger
}

// NewRedisSessionStore creates a new Redis-backed session store
func NewRedisSessionStore(client redis.UniversalClient, keyPrefix string, logger logging.Logger) SessionStore {
	return &RedisSessionStore{
		client:    client,
		keyPrefix: keyPrefix,
		logger:    logger,
	}
}

// StoreSession stores a session in Redis
func (s *RedisSessionStore) StoreSession(ctx context.Context, session *Session) error {
	// Serialize session to JSON
	data, err := json.Marshal(session)
	if err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to marshal session")
	}

	// Calculate expiration time
	expiration := session.ExpiresAt.Sub(time.Now())
	if expiration <= 0 {
		return errors.New(errors.CodeInvalidInput, "session already expired")
	}

	// Store in Redis
	key := s.formatKey(session.ID)
	if err := s.client.Set(ctx, key, data, expiration).Err(); err != nil {
		return errors.Wrap(errors.CodeStorageError, err, "failed to store session in Redis")
	}

	return nil
}

// GetSession retrieves a session from Redis
func (s *RedisSessionStore) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	key := s.formatKey(sessionID)
	data, err := s.client.Get(ctx, key).Result()

	if err != nil {
		if err == redis.Nil {
			return nil, errors.New(errors.CodeNotFound, "session not found")
		}
		return nil, errors.Wrap(errors.CodeStorageError, err, "failed to retrieve session from Redis")
	}

	// Deserialize session from JSON
	var session Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, errors.Wrap(errors.CodeInternalServer, err, "failed to unmarshal session")
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		// Delete expired session
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.DeleteSession(ctx, sessionID)
		}()
		return nil, errors.New(errors.CodeTokenExpired, "session has expired")
	}

	return &session, nil
}

// DeleteSession deletes a session from Redis
func (s *RedisSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	key := s.formatKey(sessionID)
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return errors.Wrap(errors.CodeStorageError, err, "failed to delete session from Redis")
	}

	return nil
}

// formatKey formats a Redis key with the prefix
func (s *RedisSessionStore) formatKey(sessionID string) string {
	return fmt.Sprintf("%s:%s", s.keyPrefix, sessionID)
}
