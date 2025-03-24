package mocks

import (
	"context"
	"sync"
	"time"
)

// MockRedisClient is a mock implementation of RedisClient for testing
type MockRedisClient struct {
	data  map[string]string
	ttl   map[string]time.Time
	mutex sync.RWMutex
}

// NewMockRedisClient creates a new mock Redis client
func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		data: make(map[string]string),
		ttl:  make(map[string]time.Time),
	}
}

// Set sets a key with an expiration
func (c *MockRedisClient) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.data[key] = value

	if expiration > 0 {
		c.ttl[key] = time.Now().Add(expiration)
	} else {
		delete(c.ttl, key)
	}

	return nil
}

// Get gets a key
func (c *MockRedisClient) Get(ctx context.Context, key string) (string, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Check if the key exists
	value, ok := c.data[key]
	if !ok {
		return "", nil
	}

	// Check if the key has expired
	if expires, ok := c.ttl[key]; ok && time.Now().After(expires) {
		// Key has expired, remove it
		go func() {
			c.mutex.Lock()
			defer c.mutex.Unlock()
			delete(c.data, key)
			delete(c.ttl, key)
		}()
		return "", nil
	}

	return value, nil
}

// Del deletes a key
func (c *MockRedisClient) Del(ctx context.Context, key string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.data, key)
	delete(c.ttl, key)

	return nil
}

// TTL gets the TTL of a key
func (c *MockRedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Check if the key exists
	if _, ok := c.data[key]; !ok {
		return -2 * time.Second, nil // Redis returns -2 if the key doesn't exist
	}

	// Check if the key has an expiration
	if expires, ok := c.ttl[key]; ok {
		if time.Now().After(expires) {
			// Key has expired
			return -2 * time.Second, nil
		}
		return expires.Sub(time.Now()), nil
	}

	return -1 * time.Second, nil // Redis returns -1 if the key has no expiration
}
