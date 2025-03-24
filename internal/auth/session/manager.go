package session

import (
	"context"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/session"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
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

// CreateSession creates a new session for a user
func (m *Manager) CreateSession(ctx context.Context, userID string, options ...Option) (*SessionInfo, error) {
	// Create a default session with options
	sess := &SessionInfo{
		UserID:    userID,
		IsActive:  true,
		ExpiresAt: time.Now().Add(m.config.Auth.SessionDuration),
	}

	// Apply options
	for _, option := range options {
		option(sess)
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
		SetExpiresAt(sess.ExpiresAt).
		SetLastActiveAt(time.Now()).
		SetNillableIPAddress(nilString(sess.IPAddress)).
		SetNillableUserAgent(nilString(sess.UserAgent)).
		SetNillableDeviceID(nilString(sess.DeviceID)).
		SetNillableLocation(nilString(sess.Location)).
		SetNillableOrganizationID(nilString(sess.OrganizationID)).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create session")
	}

	// Store the session in the cache if using a cache store
	if m.store != nil {
		// Create a session object for the store
		storeSession := &SessionInfo{
			ID:             sessionEntity.ID,
			UserID:         userID,
			Token:          token, // Include token in response
			IPAddress:      sess.IPAddress,
			UserAgent:      sess.UserAgent,
			DeviceID:       sess.DeviceID,
			Location:       sess.Location,
			OrganizationID: sess.OrganizationID,
			ExpiresAt:      sess.ExpiresAt,
			CreatedAt:      sessionEntity.CreatedAt,
			LastActiveAt:   sessionEntity.LastActiveAt,
			IsActive:       true,
		}

		// Store the session with an expiration time
		if _, err := m.store.StoreSession(ctx, token, storeSession, m.config.Auth.SessionDuration); err != nil {
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
		IPAddress:      sess.IPAddress,
		UserAgent:      sess.UserAgent,
		DeviceID:       sess.DeviceID,
		Location:       sess.Location,
		OrganizationID: sess.OrganizationID,
		ExpiresAt:      sess.ExpiresAt,
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
				Metadata:       cachedSession.Metadata,
				IPAddress:      cachedSession.IPAddress,
				UserAgent:      cachedSession.UserAgent,
				DeviceID:       cachedSession.DeviceID,
				Location:       cachedSession.Location,
				CreatedAt:      cachedSession.CreatedAt,
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
		storeSession := &SessionInfo{
			ID:             sessionEntity.ID,
			UserID:         sessionEntity.UserID,
			Token:          token,
			IPAddress:      sessionEntity.IPAddress,
			UserAgent:      sessionEntity.UserAgent,
			DeviceID:       sessionEntity.DeviceID,
			Location:       sessionEntity.Location,
			OrganizationID: sessionEntity.OrganizationID,
			ExpiresAt:      sessionEntity.ExpiresAt,
			CreatedAt:      sessionEntity.CreatedAt,
			LastActiveAt:   time.Now(),
			IsActive:       sessionEntity.Active,
			Metadata:       sessionEntity.Metadata,
		}

		// Calculate remaining expiration time
		expiresIn := sessionEntity.ExpiresAt.Sub(time.Now())
		if expiresIn > 0 {
			_, _ = m.store.StoreSession(ctx, token, storeSession, expiresIn)
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
		Metadata:       sessionEntity.Metadata,
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
func (m *Manager) GetUserSessions(
	ctx context.Context,
	userID string,
) ([]*SessionInfo, error) {
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
			Metadata:       s.Metadata,
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
