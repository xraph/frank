package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// Store defines the interface for session storage
type Store interface {
	// StoreSession stores a session with an expiration time
	StoreSession(ctx context.Context, token string, session *Session, expiry time.Duration) error

	// GetSession retrieves a session by token
	GetSession(ctx context.Context, token string) (*Session, error)

	// UpdateSession updates an existing session
	UpdateSession(ctx context.Context, token string, session *Session) error

	// DeleteSession deletes a session
	DeleteSession(ctx context.Context, token string) error
}

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

// CookieStore implements a session store that uses HTTP cookies
type CookieStore struct {
	cookieName     string
	cookieDomain   string
	cookieSecure   bool
	cookieHTTPOnly bool
	cookieSameSite string
	secretKey      string
	logger         logging.Logger
}

// NewCookieStore creates a new cookie-based session store
func NewCookieStore(
	cookieName string,
	cookieDomain string,
	cookieSecure bool,
	cookieHTTPOnly bool,
	cookieSameSite string,
	secretKey string,
	logger logging.Logger,
) *CookieStore {
	return &CookieStore{
		cookieName:     cookieName,
		cookieDomain:   cookieDomain,
		cookieSecure:   cookieSecure,
		cookieHTTPOnly: cookieHTTPOnly,
		cookieSameSite: cookieSameSite,
		secretKey:      secretKey,
		logger:         logger,
	}
}

// StoreSession stores a session in a cookie
func (s *CookieStore) StoreSession(ctx context.Context, token string, session *Session, expiry time.Duration) error {
	// This is a no-op for the cookie store
	// The actual storage happens in the HTTP handler when the response is sent
	return nil
}

// GetSession retrieves a session from the cookie
func (s *CookieStore) GetSession(ctx context.Context, token string) (*Session, error) {
	// This should never be called directly
	// The session is extracted from the cookie in the HTTP handler
	return nil, errors.New(errors.CodeUnsupportedOperation, "direct session retrieval not supported by cookie store")
}

// UpdateSession updates a session in the cookie
func (s *CookieStore) UpdateSession(ctx context.Context, token string, session *Session) error {
	// This is a no-op for the cookie store
	// The actual update happens in the HTTP handler when the response is sent
	return nil
}

// DeleteSession deletes a session from the cookie
func (s *CookieStore) DeleteSession(ctx context.Context, token string) error {
	// This is a no-op for the cookie store
	// The actual deletion happens in the HTTP handler when the response is sent
	return nil
}

// SetSessionCookie sets a session cookie in the HTTP response
func (s *CookieStore) SetSessionCookie(w http.ResponseWriter, token string, expiry time.Duration) {
	// Create a cookie with the session token
	cookie := &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/",
		Domain:   s.cookieDomain,
		Expires:  time.Now().Add(expiry),
		MaxAge:   int(expiry.Seconds()),
		Secure:   s.cookieSecure,
		HttpOnly: s.cookieHTTPOnly,
		SameSite: parseSameSite(s.cookieSameSite),
	}

	http.SetCookie(w, cookie)
}

// GetSessionFromCookie gets a session token from an HTTP request cookie
func (s *CookieStore) GetSessionFromCookie(r *http.Request) (string, error) {
	// Get the cookie
	cookie, err := r.Cookie(s.cookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return "", errors.New(errors.CodeSessionExpired, "session cookie not found")
		}
		return "", errors.Wrap(errors.CodeInvalidToken, err, "failed to read session cookie")
	}

	return cookie.Value, nil
}

// DeleteSessionCookie deletes a session cookie
func (s *CookieStore) DeleteSessionCookie(w http.ResponseWriter) {
	// Set a cookie with an expiration in the past to delete it
	cookie := &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   s.cookieSecure,
		HttpOnly: s.cookieHTTPOnly,
		SameSite: parseSameSite(s.cookieSameSite),
	}

	http.SetCookie(w, cookie)
}

// parseSameSite converts a string to http.SameSite
func parseSameSite(sameSite string) http.SameSite {
	switch strings.ToLower(sameSite) {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// Session represents a session stored in the store
type Session struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	Token          string    `json:"-"` // Don't serialize the token
	OrganizationID string    `json:"organization_id,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	LastActiveAt   time.Time `json:"last_active_at"`
	IsActive       bool      `json:"is_active"`
}

// InMemoryStore implements an in-memory session store
type InMemoryStore struct {
	sessions        map[string]*sessionData
	mutex           sync.RWMutex
	logger          logging.Logger
	cleanupInterval time.Duration
}

// sessionData contains session data with expiration time
type sessionData struct {
	session   *Session
	expiresAt time.Time
}

// NewInMemoryStore creates a new in-memory session store
func NewInMemoryStore(logger logging.Logger, cleanupInterval time.Duration) *InMemoryStore {
	store := &InMemoryStore{
		sessions:        make(map[string]*sessionData),
		logger:          logger,
		cleanupInterval: cleanupInterval,
	}

	// Start background cleanup
	go store.startCleanup()

	return store
}

// StoreSession stores a session with an expiration time
func (s *InMemoryStore) StoreSession(ctx context.Context, token string, session *Session, expiry time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Set expiration time
	expiresAt := time.Now().Add(expiry)

	// Store session
	s.sessions[token] = &sessionData{
		session:   session,
		expiresAt: expiresAt,
	}

	return nil
}

// GetSession retrieves a session by token
func (s *InMemoryStore) GetSession(ctx context.Context, token string) (*Session, error) {
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
func (s *InMemoryStore) UpdateSession(ctx context.Context, token string, session *Session) error {
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

// RedisStore implements a Redis-backed session store
type RedisStore struct {
	client    RedisClient
	keyPrefix string
	logger    logging.Logger
}

// RedisClient defines the interface for Redis operations
type RedisClient interface {
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	TTL(ctx context.Context, key string) (time.Duration, error)
	Del(ctx context.Context, key string) error
}

// NewRedisStore creates a new Redis-backed session store
func NewRedisStore(client RedisClient, keyPrefix string, logger logging.Logger) *RedisStore {
	return &RedisStore{
		client:    client,
		keyPrefix: keyPrefix,
		logger:    logger,
	}
}

// StoreSession stores a session with an expiration time
func (s *RedisStore) StoreSession(ctx context.Context, token string, session *Session, expiry time.Duration) error {
	// Serialize session to JSON
	data, err := json.Marshal(session)
	if err != nil {
		return errors.Wrap(errors.CodeStorageError, err, "failed to serialize session")
	}

	// Store in Redis with expiration
	key := s.formatKey(token)
	return s.client.Set(ctx, key, string(data), expiry)
}

// GetSession retrieves a session by token
func (s *RedisStore) GetSession(ctx context.Context, token string) (*Session, error) {
	// Get from Redis
	key := s.formatKey(token)
	data, err := s.client.Get(ctx, key)
	if err != nil {
		return nil, errors.Wrap(errors.CodeStorageError, err, "failed to retrieve session")
	}

	if data == "" {
		return nil, errors.New(errors.CodeNotFound, "session not found")
	}

	// Deserialize session
	var session Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, errors.Wrap(errors.CodeStorageError, err, "failed to deserialize session")
	}

	return &session, nil
}

// UpdateSession updates an existing session
func (s *RedisStore) UpdateSession(ctx context.Context, token string, session *Session) error {
	// Serialize session to JSON
	data, err := json.Marshal(session)
	if err != nil {
		return errors.Wrap(errors.CodeStorageError, err, "failed to serialize session")
	}

	// Get the current TTL of the key
	key := s.formatKey(token)
	ttl, err := s.client.TTL(ctx, key)
	if err != nil {
		return errors.Wrap(errors.CodeStorageError, err, "failed to get session TTL")
	}

	// If TTL is negative, the key doesn't exist or has no expiry
	if ttl < 0 {
		return errors.New(errors.CodeNotFound, "session not found or expired")
	}

	// Update in Redis with the same expiration
	return s.client.Set(ctx, key, string(data), ttl)
}

// DeleteSession deletes a session
func (s *RedisStore) DeleteSession(ctx context.Context, token string) error {
	// Delete from Redis
	key := s.formatKey(token)
	return s.client.Del(ctx, key)
}

// formatKey formats a Redis key with the prefix
func (s *RedisStore) formatKey(token string) string {
	return fmt.Sprintf("%s:%s", s.keyPrefix, token)
}
