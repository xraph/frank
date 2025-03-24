package session

import (
	"context"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/session"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// EntStore implements a Redis-backed session store
type EntStore struct {
	client *ent.Client
	logger logging.Logger
}

// NewEntStore creates a new entgo-backed session store
func NewEntStore(
	client *ent.Client,
	logger logging.Logger,
) *EntStore {
	return &EntStore{
		client: client,
		logger: logger,
	}
}

// StoreSession stores a session with an expiration time
func (s *EntStore) StoreSession(ctx context.Context, token string, session *SessionInfo, expiry time.Duration) (string, error) {
	// Generate a secure token
	token, err := crypto.GenerateRandomString(64)
	if err != nil {
		return "", errors.Wrap(errors.CodeCryptoError, err, "failed to generate session token")
	}

	// Create the session record
	sessionEntity, err := s.client.Session.Create().
		SetUserID(session.UserID).
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
		return "", errors.Wrap(errors.CodeDatabaseError, err, "failed to create session")
	}

	return sessionEntity.ID, nil
}

// GetSession retrieves a session by token
func (s *EntStore) GetSession(ctx context.Context, token string) (*SessionInfo, error) {
	// If not in cache or there was an error, get from database
	sessionEntity, err := s.client.Session.Query().
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
	_, err = s.client.Session.UpdateOne(sessionEntity).
		SetLastActiveAt(time.Now()).
		Save(ctx)

	if err != nil {
		s.logger.Error("Failed to update session last active time",
			logging.String("session_id", sessionEntity.ID),
			logging.Error(err),
		)
		// Continue anyway
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

// UpdateSession updates an existing session
func (s *EntStore) UpdateSession(ctx context.Context, token string, sess *SessionInfo) error {
	sessionEntity, err := s.client.Session.Query().
		Where(
			session.Token(token),
			session.Active(true),
			session.ExpiresAtGT(time.Now()),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeSessionExpired, "session not found or expired")
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to query session")
	}

	// Update last active time
	_, err = s.client.Session.UpdateOne(sessionEntity).
		SetNillableIPAddress(nilString(sess.IPAddress)).
		SetNillableUserAgent(nilString(sess.UserAgent)).
		SetNillableDeviceID(nilString(sess.DeviceID)).
		SetNillableLocation(nilString(sess.Location)).
		SetNillableOrganizationID(nilString(sess.OrganizationID)).
		SetExpiresAt(sess.ExpiresAt).
		SetMetadata(sess.Metadata).
		SetLastActiveAt(sess.LastActiveAt).
		SetActive(sess.IsActive).
		SetUserID(sess.UserID).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeSessionExpired, "session not found or expired")
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to update session")
	}

	return nil
}

// DeleteSession deletes a session
func (s *EntStore) DeleteSession(ctx context.Context, token string) error {
	_, err := s.client.Session.Delete().Where(session.Token(token)).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeSessionExpired, "session not found or expired")
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete session")
	}

	return nil
}
