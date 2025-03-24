package session

import (
	"context"
)

// contextKey is a type for context keys specific to the session package
type contextKey string

// Context keys
const (
	// SessionKey is the key for the session in the context
	SessionKey = contextKey("session")

	// UserIDKey is the key for the user ID in the context
	UserIDKey = contextKey("user_id")

	// OrganizationIDKey is the key for the organization ID in the context
	OrganizationIDKey = contextKey("organization_id")
)

// FromContext extracts session information from the context
func FromContext(ctx context.Context) (*SessionInfo, bool) {
	session, ok := ctx.Value(SessionKey).(*SessionInfo)
	return session, ok
}

// UserIDFromContext extracts the user ID from the context
func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(UserIDKey).(string)
	return id, ok
}

// OrganizationIDFromContext extracts the organization ID from the context
func OrganizationIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(OrganizationIDKey).(string)
	return id, ok
}
