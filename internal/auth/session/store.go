package session

import (
	"context"
	"time"
)

// Store defines the interface for session storage
type Store interface {
	// StoreSession stores a session with an expiration time
	StoreSession(ctx context.Context, token string, session *SessionInfo, expiry time.Duration) (string, error)

	// GetSession retrieves a session by token
	GetSession(ctx context.Context, token string) (*SessionInfo, error)

	// UpdateSession updates an existing session
	UpdateSession(ctx context.Context, token string, session *SessionInfo) error

	// DeleteSession deletes a session
	DeleteSession(ctx context.Context, token string) error
}

// sessionData contains session data with expiration time
type sessionData struct {
	session   *SessionInfo
	expiresAt time.Time
}
