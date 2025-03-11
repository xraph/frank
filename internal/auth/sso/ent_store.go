package sso

import (
	"context"
	"encoding/json"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/ssostate"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// EntStateStore is an implementation of StateStore using Ent
type EntStateStore struct {
	client *ent.Client
	logger logging.Logger
}

// NewEntStateStore creates a new Ent-based state store
func NewEntStateStore(client *ent.Client, logger logging.Logger) *EntStateStore {
	return &EntStateStore{
		client: client,
		logger: logger,
	}
}

// StoreState stores SSO state data with an expiration time
func (s *EntStateStore) StoreState(ctx context.Context, state string, data *StateData, expiry time.Duration) error {
	// Marshal data to JSON for storage
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to marshal state data")
	}

	// Calculate expiration time
	expiresAt := time.Now().Add(expiry)

	// Check if state already exists (unlikely but possible)
	exists, err := s.client.SSOState.Query().
		Where(ssostate.State(state)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check for existing state")
	}

	if exists {
		// Update existing state
		_, err = s.client.SSOState.Update().
			Where(ssostate.State(state)).
			SetData(string(dataJSON)).
			SetExpiresAt(expiresAt).
			Save(ctx)
	} else {
		// Create new state
		_, err = s.client.SSOState.Create().
			SetState(state).
			SetData(string(dataJSON)).
			SetExpiresAt(expiresAt).
			Save(ctx)
	}

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to store state")
	}

	return nil
}

// GetState retrieves SSO state data
func (s *EntStateStore) GetState(ctx context.Context, state string) (*StateData, error) {
	// Get state from database
	stateEntity, err := s.client.SSOState.Query().
		Where(ssostate.State(state)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeInvalidOAuthState, "state not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query state")
	}

	// Check if state has expired
	if time.Now().After(stateEntity.ExpiresAt) {
		// Clean up expired state
		go func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.DeleteState(cleanupCtx, state)
		}()
		return nil, errors.New(errors.CodeInvalidOAuthState, "state has expired")
	}

	// Unmarshal the stored data
	var stateData StateData
	if err := json.Unmarshal([]byte(stateEntity.Data), &stateData); err != nil {
		return nil, errors.Wrap(errors.CodeInternalServer, err, "failed to unmarshal state data")
	}

	return &stateData, nil
}

// DeleteState deletes SSO state data
func (s *EntStateStore) DeleteState(ctx context.Context, state string) error {
	// Delete state from database
	_, err := s.client.SSOState.Delete().
		Where(ssostate.State(state)).
		Exec(ctx)

	if err != nil {
		// If not found, consider it already deleted
		if ent.IsNotFound(err) {
			return nil
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete state")
	}

	return nil
}

// CleanupExpiredStates removes all expired states from the database
func (s *EntStateStore) CleanupExpiredStates(ctx context.Context) (int, error) {
	// Delete expired states
	count, err := s.client.SSOState.Delete().
		Where(ssostate.ExpiresAtLT(time.Now())).
		Exec(ctx)

	if err != nil {
		return 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to delete expired states")
	}

	return count, nil
}
