package passkeys

import (
	"context"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/passkey"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// EntRepository implements the Repository interface using EntGO
type EntRepository struct {
	client *ent.Client
	logger logging.Logger
}

// NewEntRepository creates a new EntGO repository
func NewEntRepository(client *ent.Client, logger logging.Logger) Repository {
	return &EntRepository{
		client: client,
		logger: logger,
	}
}

// GetUserByID retrieves a user by ID
func (r *EntRepository) GetUserByID(ctx context.Context, userID string) (*ent.User, error) {
	user, err := r.client.User.Query().
		Where(user.ID(userID)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeUserNotFound, "user not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get user")
	}

	return user, nil
}

// GetPasskeysByUserID retrieves all passkeys for a user
func (r *EntRepository) GetPasskeysByUserID(ctx context.Context, userID string) ([]*ent.Passkey, error) {
	passkeys, err := r.client.Passkey.Query().
		Where(passkey.UserID(userID)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get user passkeys")
	}

	return passkeys, nil
}

// GetPasskeyByCredentialID retrieves a passkey by credential ID
func (r *EntRepository) GetPasskeyByCredentialID(ctx context.Context, credentialID string) (*ent.Passkey, error) {
	passkey, err := r.client.Passkey.Query().
		Where(passkey.CredentialID(credentialID)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "passkey not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get passkey")
	}

	return passkey, nil
}

// CreatePasskey creates a new passkey
func (r *EntRepository) CreatePasskey(ctx context.Context, create *ent.PasskeyCreate) (*ent.Passkey, error) {
	passkey, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "passkey already exists")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create passkey")
	}

	return passkey, nil
}

// UpdatePasskey updates a passkey
func (r *EntRepository) UpdatePasskey(ctx context.Context, passkeyID string, updates *ent.PasskeyUpdateOne) (*ent.Passkey, error) {
	passkey, err := updates.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "passkey not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to update passkey")
	}

	return passkey, nil
}

// DeletePasskey deletes a passkey
func (r *EntRepository) DeletePasskey(ctx context.Context, passkeyID string) error {
	err := r.client.Passkey.DeleteOneID(passkeyID).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "passkey not found")
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete passkey")
	}

	return nil
}
