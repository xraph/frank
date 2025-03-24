package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// RedisStore implements a Redis-backed session store
type RedisStore struct {
	client    redis.UniversalClient
	keyPrefix string
	logger    logging.Logger
}

// NewRedisStore creates a new Redis-backed session store
func NewRedisStore(client redis.UniversalClient, keyPrefix string, logger logging.Logger) *RedisStore {
	return &RedisStore{
		client:    client,
		keyPrefix: keyPrefix,
		logger:    logger,
	}
}

// StoreSession stores a session with an expiration time
func (s *RedisStore) StoreSession(ctx context.Context, token string, session *SessionInfo, expiry time.Duration) (string, error) {
	// Serialize session to JSON
	data, err := json.Marshal(session)
	if err != nil {
		return "", errors.Wrap(errors.CodeStorageError, err, "failed to serialize session")
	}

	// Store in Redis with expiration
	key := s.formatKey(token)
	_, err = s.client.Set(ctx, key, string(data), expiry).Result()
	return "", err
}

// GetSession retrieves a session by token
func (s *RedisStore) GetSession(ctx context.Context, token string) (*SessionInfo, error) {
	// Get from Redis
	key := s.formatKey(token)
	data, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, errors.New(errors.CodeNotFound, "session not found")
	} else if err != nil {
		return nil, errors.Wrap(errors.CodeStorageError, err, "failed to retrieve session")
	}

	// Deserialize session
	var session SessionInfo
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, errors.Wrap(errors.CodeStorageError, err, "failed to deserialize session")
	}

	return &session, nil
}

// UpdateSession updates an existing session
func (s *RedisStore) UpdateSession(ctx context.Context, token string, session *SessionInfo) error {
	// Serialize session to JSON
	data, err := json.Marshal(session)
	if err != nil {
		return errors.Wrap(errors.CodeStorageError, err, "failed to serialize session")
	}

	// Get the current TTL of the key
	key := s.formatKey(token)
	ttl, err := s.client.TTL(ctx, key).Result()
	if err != nil {
		return errors.Wrap(errors.CodeStorageError, err, "failed to get session TTL")
	}

	// If TTL is negative, the key doesn't exist or has no expiry
	if ttl < 0 {
		return errors.New(errors.CodeNotFound, "session not found or expired")
	}

	// Update in Redis with the same expiration
	_, err = s.client.Set(ctx, key, string(data), ttl).Result()
	return err
}

// DeleteSession deletes a session
func (s *RedisStore) DeleteSession(ctx context.Context, token string) error {
	// Delete from Redis
	key := s.formatKey(token)
	_, err := s.client.Del(ctx, key).Result()
	return err
}

// formatKey formats a Redis key with the prefix
func (s *RedisStore) formatKey(token string) string {
	return fmt.Sprintf("%s:%s", s.keyPrefix, token)
}
