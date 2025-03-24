package session

import (
	"context"
	"net/http"
	"time"

	"github.com/juicycleff/frank/ent/session"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/utils"
)

// SessionInfo contains information about a session
type SessionInfo struct {
	ID             string                 `json:"id"`
	UserID         string                 `json:"user_id"`
	Token          string                 `json:"token,omitempty"` // Only included when creating a session
	IPAddress      string                 `json:"ip_address,omitempty"`
	UserAgent      string                 `json:"user_agent,omitempty"`
	DeviceID       string                 `json:"device_id,omitempty"`
	Location       string                 `json:"location,omitempty"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	ExpiresAt      time.Time              `json:"expires_at"`
	CreatedAt      time.Time              `json:"created_at"`
	LastActiveAt   time.Time              `json:"last_active_at"`
	IsActive       bool                   `json:"is_active"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// Option is a function that configures a session
type Option func(*SessionInfo)

// WithIPAddress sets the IP address for a session
func WithIPAddress(ipAddress string) Option {
	return func(s *SessionInfo) {
		s.IPAddress = ipAddress
	}
}

// WithUserAgent sets the user agent for a session
func WithUserAgent(userAgent string) Option {
	return func(s *SessionInfo) {
		s.UserAgent = userAgent
	}
}

// WithDeviceID sets the device ID for a session
func WithDeviceID(deviceID string) Option {
	return func(s *SessionInfo) {
		s.DeviceID = deviceID
	}
}

// WithLocation sets the location for a session
func WithLocation(location string) Option {
	return func(s *SessionInfo) {
		s.Location = location
	}
}

// WithOrganizationID sets the organization ID for a session
func WithOrganizationID(organizationID string) Option {
	return func(s *SessionInfo) {
		s.OrganizationID = organizationID
	}
}

// WithExpiration sets the expiration time for a session
func WithExpiration(duration time.Duration) Option {
	return func(s *SessionInfo) {
		s.ExpiresAt = time.Now().Add(duration)
	}
}

// WithMetadata sets metadata for a session
func WithMetadata(metadata map[string]interface{}) Option {
	return func(s *SessionInfo) {
		s.Metadata = metadata
	}
}

// Middleware creates a middleware that validates sessions
func (m *Manager) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract the token from the request
			token, err := utils.GetBearerToken(r)
			if err != nil {
				utils.RespondError(w, errors.New(errors.CodeUnauthorized, "missing or invalid session token"))
				return
			}

			// Validate the session
			sess, err := m.GetSession(r.Context(), token)
			if err != nil {
				utils.RespondError(w, errors.New(errors.CodeUnauthorized, "invalid or expired session"))
				return
			}

			// Add session info to context
			ctx := context.WithValue(r.Context(), SessionKey, sess)
			ctx = context.WithValue(ctx, UserIDKey, session.UserID)

			// Add organization ID to context if present
			if sess.OrganizationID != "" {
				ctx = context.WithValue(ctx, OrganizationIDKey, session.OrganizationID)
			}

			// Call the next handler with the updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
