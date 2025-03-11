package session

import (
	"context"
	"net/http"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/session"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// Manager handles session operations
type Manager struct {
	client *ent.Client
	config *config.Config
	logger logging.Logger
	store  Store
}

// NewManager creates a new session manager
func NewManager(client *ent.Client, cfg *config.Config, logger logging.Logger, store Store) *Manager {
	return &Manager{
		client: client,
		config: cfg,
		logger: logger,
		store:  store,
	}
}

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

// CreateSession creates a new session for a user
func (m *Manager) CreateSession(ctx context.Context, userID string, options ...SessionOption) (*SessionInfo, error) {
	// Create a default session with options
	session := &SessionInfo{
		UserID:    userID,
		IsActive:  true,
		ExpiresAt: time.Now().Add(m.config.Auth.SessionDuration),
	}

	// Apply options
	for _, option := range options {
		option(session)
	}

	// Generate a secure token
	token, err := crypto.GenerateRandomString(64)
	if err != nil {
		return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate session token")
	}

	// Create the session record
	sessionEntity, err := m.client.Session.Create().
		SetUserID(userID).
		SetToken(token).
		SetActive(true).
		SetExpiresAt(session.ExpiresAt).
		SetLastActiveAt(time.Now()).
		SetNillableIPAddress(nilString(session.IPAddress)).
		SetNillableUserAgent(nilString(session.UserAgent)).
		SetNillableDeviceID(nilString(session.DeviceID)).
		SetNillableLocation(nilString(session.Location)).
		SetNillableOrganizationID(nilString(session.OrganizationID)).
		Save(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create session")
	}

	// Store the session in the cache if using a cache store
	if m.store != nil {
		// Create a session object for the store
		storeSession := &Session{
			ID:             sessionEntity.ID,
			UserID:         userID,
			Token:          token,
			ExpiresAt:      session.ExpiresAt,
			OrganizationID: session.OrganizationID,
			IsActive:       true,
		}

		// Store the session with an expiration time
		if err := m.store.StoreSession(ctx, token, storeSession, m.config.Auth.SessionDuration); err != nil {
			m.logger.Error("Failed to store session in cache",
				logging.String("session_id", sessionEntity.ID),
				logging.Error(err),
			)
			// Continue anyway, we'll fall back to database
		}
	}

	// Return session info with the token
	return &SessionInfo{
		ID:             sessionEntity.ID,
		UserID:         userID,
		Token:          token, // Include token in response
		IPAddress:      session.IPAddress,
		UserAgent:      session.UserAgent,
		DeviceID:       session.DeviceID,
		Location:       session.Location,
		OrganizationID: session.OrganizationID,
		ExpiresAt:      session.ExpiresAt,
		CreatedAt:      sessionEntity.CreatedAt,
		LastActiveAt:   sessionEntity.LastActiveAt,
		IsActive:       true,
	}, nil
}

// GetSession retrieves a session by token
func (m *Manager) GetSession(ctx context.Context, token string) (*SessionInfo, error) {
	// Try to get the session from the cache first
	if m.store != nil {
		cachedSession, err := m.store.GetSession(ctx, token)
		if err == nil && cachedSession != nil {
			// Check if the session is expired
			if time.Now().After(cachedSession.ExpiresAt) {
				// Session is expired, remove it from the cache
				_ = m.store.DeleteSession(ctx, token)
				return nil, errors.New(errors.CodeSessionExpired, "session has expired")
			}

			// Update last active time
			cachedSession.LastActiveAt = time.Now()
			_ = m.store.UpdateSession(ctx, token, cachedSession)

			// Return session info
			return &SessionInfo{
				ID:             cachedSession.ID,
				UserID:         cachedSession.UserID,
				OrganizationID: cachedSession.OrganizationID,
				ExpiresAt:      cachedSession.ExpiresAt,
				LastActiveAt:   cachedSession.LastActiveAt,
				IsActive:       cachedSession.IsActive,
			}, nil
		}
	}

	// If not in cache or there was an error, get from database
	sessionEntity, err := m.client.Session.Query().
		Where(
			session.Token(token),
			session.Active(true),
			session.ExpiresAtGT(time.Now()),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeSessionExpired, "session not found or expired")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query session")
	}

	// Update last active time
	_, err = m.client.Session.UpdateOne(sessionEntity).
		SetLastActiveAt(time.Now()).
		Save(ctx)

	if err != nil {
		m.logger.Error("Failed to update session last active time",
			logging.String("session_id", sessionEntity.ID),
			logging.Error(err),
		)
		// Continue anyway
	}

	// If using a cache store, add this session to the cache
	if m.store != nil {
		storeSession := &Session{
			ID:             sessionEntity.ID,
			UserID:         sessionEntity.UserID,
			Token:          token,
			ExpiresAt:      sessionEntity.ExpiresAt,
			OrganizationID: sessionEntity.OrganizationID,
			IsActive:       sessionEntity.Active,
			LastActiveAt:   time.Now(),
		}

		// Calculate remaining expiration time
		expiresIn := sessionEntity.ExpiresAt.Sub(time.Now())
		if expiresIn > 0 {
			_ = m.store.StoreSession(ctx, token, storeSession, expiresIn)
		}
	}

	// Return session info
	return &SessionInfo{
		ID:             sessionEntity.ID,
		UserID:         sessionEntity.UserID,
		IPAddress:      sessionEntity.IPAddress,
		UserAgent:      sessionEntity.UserAgent,
		DeviceID:       sessionEntity.DeviceID,
		Location:       sessionEntity.Location,
		OrganizationID: sessionEntity.OrganizationID,
		ExpiresAt:      sessionEntity.ExpiresAt,
		CreatedAt:      sessionEntity.CreatedAt,
		LastActiveAt:   sessionEntity.LastActiveAt,
		IsActive:       sessionEntity.Active,
	}, nil
}

// RevokeSession revokes a session by token
func (m *Manager) RevokeSession(ctx context.Context, token string) error {
	// Revoke in database
	count, err := m.client.Session.Update().
		Where(
			session.Token(token),
			session.Active(true),
		).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to revoke session")
	}

	if count == 0 {
		return errors.New(errors.CodeNotFound, "session not found or already inactive")
	}

	// Remove from cache if using a cache store
	if m.store != nil {
		if err := m.store.DeleteSession(ctx, token); err != nil {
			m.logger.Error("Failed to delete session from cache",
				logging.Error(err),
			)
			// Continue anyway
		}
	}

	return nil
}

// RevokeUserSessions revokes all active sessions for a user
func (m *Manager) RevokeUserSessions(ctx context.Context, userID string) error {
	// Get all active sessions for the user
	sessions, err := m.client.Session.Query().
		Where(
			session.UserID(userID),
			session.Active(true),
		).
		All(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to query user sessions")
	}

	// Revoke all sessions in database
	_, err = m.client.Session.Update().
		Where(
			session.UserID(userID),
			session.Active(true),
		).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to revoke user sessions")
	}

	// Remove from cache if using a cache store
	if m.store != nil {
		for _, s := range sessions {
			if err := m.store.DeleteSession(ctx, s.Token); err != nil {
				m.logger.Error("Failed to delete session from cache",
					logging.String("session_id", s.ID),
					logging.Error(err),
				)
				// Continue anyway
			}
		}
	}

	return nil
}

// GetUserSessions gets all active sessions for a user
func (m *Manager) GetUserSessions(ctx context.Context, userID string) ([]*SessionInfo, error) {
	// Get all active sessions for the user
	sessions, err := m.client.Session.Query().
		Where(
			session.UserID(userID),
			session.Active(true),
		).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query user sessions")
	}

	// Convert to session info objects
	var sessionInfos []*SessionInfo
	for _, s := range sessions {
		sessionInfos = append(sessionInfos, &SessionInfo{
			ID:             s.ID,
			UserID:         s.UserID,
			IPAddress:      s.IPAddress,
			UserAgent:      s.UserAgent,
			DeviceID:       s.DeviceID,
			Location:       s.Location,
			OrganizationID: s.OrganizationID,
			ExpiresAt:      s.ExpiresAt,
			CreatedAt:      s.CreatedAt,
			LastActiveAt:   s.LastActiveAt,
			IsActive:       s.Active,
		})
	}

	return sessionInfos, nil
}

// ExtendSession extends the expiration time of a session
func (m *Manager) ExtendSession(ctx context.Context, token string, duration time.Duration) error {
	// Get the session
	sessionEntity, err := m.client.Session.Query().
		Where(
			session.Token(token),
			session.Active(true),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "session not found or inactive")
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to query session")
	}

	// Calculate new expiration time
	newExpiresAt := time.Now().Add(duration)

	// Update expiration time in database
	_, err = m.client.Session.UpdateOne(sessionEntity).
		SetExpiresAt(newExpiresAt).
		SetLastActiveAt(time.Now()).
		Save(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to extend session")
	}

	// Update in cache if using a cache store
	if m.store != nil {
		// Get the session from cache
		cachedSession, err := m.store.GetSession(ctx, token)
		if err == nil && cachedSession != nil {
			// Update expiration time
			cachedSession.ExpiresAt = newExpiresAt
			cachedSession.LastActiveAt = time.Now()

			// Store updated session
			if err := m.store.UpdateSession(ctx, token, cachedSession); err != nil {
				m.logger.Error("Failed to update session in cache",
					logging.String("session_id", sessionEntity.ID),
					logging.Error(err),
				)
				// Continue anyway
			}
		}
	}

	return nil
}

// CleanupExpiredSessions cleans up expired sessions
func (m *Manager) CleanupExpiredSessions(ctx context.Context) (int, error) {
	// Delete expired sessions
	count, err := m.client.Session.Delete().
		Where(
			session.ExpiresAtLT(time.Now()),
		).
		Exec(ctx)

	if err != nil {
		return 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to delete expired sessions")
	}

	m.logger.Info("Cleaned up expired sessions", logging.Int("count", count))
	return count, nil
}

// CheckSession checks if a session is valid
func (m *Manager) CheckSession(ctx context.Context, token string) (bool, error) {
	// Try to get the session
	sessionInfo, err := m.GetSession(ctx, token)
	if err != nil {
		return false, err
	}

	// Check if the session is active and not expired
	return sessionInfo.IsActive && time.Now().Before(sessionInfo.ExpiresAt), nil
}

// RefreshSession invalidates the current session and creates a new one
func (m *Manager) RefreshSession(ctx context.Context, token string) (*SessionInfo, error) {
	// Get the current session
	oldSession, err := m.GetSession(ctx, token)
	if err != nil {
		return nil, err
	}

	// Revoke the current session
	if err := m.RevokeSession(ctx, token); err != nil {
		return nil, err
	}

	// Create a new session with the same properties
	return m.CreateSession(ctx, oldSession.UserID,
		WithIPAddress(oldSession.IPAddress),
		WithUserAgent(oldSession.UserAgent),
		WithDeviceID(oldSession.DeviceID),
		WithLocation(oldSession.Location),
		WithOrganizationID(oldSession.OrganizationID),
	)
}

// Helper function to handle nil strings
func nilString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// SessionOption is a function that configures a session
type SessionOption func(*SessionInfo)

// WithIPAddress sets the IP address for a session
func WithIPAddress(ipAddress string) SessionOption {
	return func(s *SessionInfo) {
		s.IPAddress = ipAddress
	}
}

// WithUserAgent sets the user agent for a session
func WithUserAgent(userAgent string) SessionOption {
	return func(s *SessionInfo) {
		s.UserAgent = userAgent
	}
}

// WithDeviceID sets the device ID for a session
func WithDeviceID(deviceID string) SessionOption {
	return func(s *SessionInfo) {
		s.DeviceID = deviceID
	}
}

// WithLocation sets the location for a session
func WithLocation(location string) SessionOption {
	return func(s *SessionInfo) {
		s.Location = location
	}
}

// WithOrganizationID sets the organization ID for a session
func WithOrganizationID(organizationID string) SessionOption {
	return func(s *SessionInfo) {
		s.OrganizationID = organizationID
	}
}

// WithExpiration sets the expiration time for a session
func WithExpiration(duration time.Duration) SessionOption {
	return func(s *SessionInfo) {
		s.ExpiresAt = time.Now().Add(duration)
	}
}

// WithMetadata sets metadata for a session
func WithMetadata(metadata map[string]interface{}) SessionOption {
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
			session, err := m.GetSession(r.Context(), token)
			if err != nil {
				utils.RespondError(w, errors.New(errors.CodeUnauthorized, "invalid or expired session"))
				return
			}

			// Add session info to context
			ctx := context.WithValue(r.Context(), contextKey("session"), session)
			ctx = context.WithValue(ctx, contextKey("user_id"), session.UserID)

			// Add organization ID to context if present
			if session.OrganizationID != "" {
				ctx = context.WithValue(ctx, contextKey("organization_id"), session.OrganizationID)
			}

			// Call the next handler with the updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

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
