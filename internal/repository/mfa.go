package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/mfa"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

// MFARepository defines the interface for MFA data operations
type MFARepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateMFAInput) (*ent.MFA, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.MFA, error)
	GetByUserIDAndMethod(ctx context.Context, userID xid.ID, method string) (*ent.MFA, error)
	Update(ctx context.Context, id xid.ID, input UpdateMFAInput) (*ent.MFA, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.MFA], error)
	ListActiveByUserID(ctx context.Context, userID xid.ID) ([]*ent.MFA, error)
	ListByMethod(ctx context.Context, method string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.MFA], error)

	// Verification operations
	MarkAsVerified(ctx context.Context, id xid.ID) error
	UpdateLastUsed(ctx context.Context, id xid.ID) error

	// Utility operations
	DeactivateByUserID(ctx context.Context, userID xid.ID) error
	DeactivateMethodByUserID(ctx context.Context, userID xid.ID, method string) error
	CountByUserID(ctx context.Context, userID xid.ID) (int, error)
	CountVerifiedByUserID(ctx context.Context, userID xid.ID) (int, error)

	// Advanced queries
	GetVerifiedByUserIDAndMethod(ctx context.Context, userID xid.ID, method string) (*ent.MFA, error)
	HasVerifiedMFA(ctx context.Context, userID xid.ID) (bool, error)
	ListMethodsByUserID(ctx context.Context, userID xid.ID) ([]string, error)
}

// mfaRepository implements MFARepository interface
type mfaRepository struct {
	client *ent.Client
}

// NewMFARepository creates a new MFA repository
func NewMFARepository(client *ent.Client) MFARepository {
	return &mfaRepository{
		client: client,
	}
}

// CreateMFAInput defines the input for creating an MFA method
type CreateMFAInput struct {
	UserID      xid.ID         `json:"user_id"`
	Method      string         `json:"method"`
	Secret      string         `json:"secret"`
	Verified    bool           `json:"verified"`
	Active      bool           `json:"active"`
	BackupCodes []string       `json:"backup_codes,omitempty"`
	PhoneNumber *string        `json:"phone_number,omitempty"`
	Email       *string        `json:"email,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// UpdateMFAInput defines the input for updating an MFA method
type UpdateMFAInput struct {
	Secret      *string        `json:"secret,omitempty"`
	Verified    *bool          `json:"verified,omitempty"`
	Active      *bool          `json:"active,omitempty"`
	BackupCodes []string       `json:"backup_codes,omitempty"`
	PhoneNumber *string        `json:"phone_number,omitempty"`
	Email       *string        `json:"email,omitempty"`
	LastUsed    *time.Time     `json:"last_used,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Create creates a new MFA method
func (r *mfaRepository) Create(ctx context.Context, input CreateMFAInput) (*ent.MFA, error) {
	builder := r.client.MFA.Create().
		SetUserID(input.UserID).
		SetMethod(input.Method).
		SetSecret(input.Secret).
		SetVerified(input.Verified).
		SetActive(input.Active)

	if input.BackupCodes != nil {
		builder.SetBackupCodes(input.BackupCodes)
	}

	if input.PhoneNumber != nil {
		builder.SetPhoneNumber(*input.PhoneNumber)
	}

	if input.Email != nil {
		builder.SetEmail(*input.Email)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	mfaMethod, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, fmt.Sprintf("MFA method '%s' already exists for this user", input.Method))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to create MFA method")
	}

	return mfaMethod, nil
}

// GetByID retrieves an MFA method by its ID
func (r *mfaRepository) GetByID(ctx context.Context, id xid.ID) (*ent.MFA, error) {
	mfaMethod, err := r.client.MFA.
		Query().
		Where(mfa.ID(id)).
		WithUser().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "MFA method not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get MFA method")
	}

	return mfaMethod, nil
}

// GetByUserIDAndMethod retrieves an MFA method by user ID and method type
func (r *mfaRepository) GetByUserIDAndMethod(ctx context.Context, userID xid.ID, method string) (*ent.MFA, error) {
	mfaMethod, err := r.client.MFA.
		Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(method),
		).
		WithUser().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("MFA method '%s' not found for user", method))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get MFA method by user and method")
	}

	return mfaMethod, nil
}

// Update updates an MFA method
func (r *mfaRepository) Update(ctx context.Context, id xid.ID, input UpdateMFAInput) (*ent.MFA, error) {
	builder := r.client.MFA.UpdateOneID(id)

	if input.Secret != nil {
		builder.SetSecret(*input.Secret)
	}

	if input.Verified != nil {
		builder.SetVerified(*input.Verified)
	}

	if input.Active != nil {
		builder.SetActive(*input.Active)
	}

	if input.BackupCodes != nil {
		builder.SetBackupCodes(input.BackupCodes)
	}

	if input.PhoneNumber != nil {
		builder.SetPhoneNumber(*input.PhoneNumber)
	}

	if input.Email != nil {
		builder.SetEmail(*input.Email)
	}

	if input.LastUsed != nil {
		builder.SetLastUsed(*input.LastUsed)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	mfaMethod, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "MFA method not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to update MFA method")
	}

	return mfaMethod, nil
}

// Delete deletes an MFA method
func (r *mfaRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.MFA.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "MFA method not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete MFA method")
	}

	return nil
}

// ListByUserID retrieves paginated MFA methods for a user
func (r *mfaRepository) ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.MFA], error) {
	query := r.client.MFA.
		Query().
		Where(mfa.UserID(userID)).
		WithUser()

	// Apply ordering
	query.Order(ent.Desc(mfa.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.MFA, *ent.MFAQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list MFA methods by user ID")
	}

	return result, nil
}

// ListActiveByUserID retrieves all active MFA methods for a user
func (r *mfaRepository) ListActiveByUserID(ctx context.Context, userID xid.ID) ([]*ent.MFA, error) {
	mfaMethods, err := r.client.MFA.
		Query().
		Where(
			mfa.UserID(userID),
			mfa.Active(true),
		).
		WithUser().
		Order(ent.Desc(mfa.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list active MFA methods")
	}

	return mfaMethods, nil
}

// ListByMethod retrieves paginated MFA methods by method type
func (r *mfaRepository) ListByMethod(ctx context.Context, method string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.MFA], error) {
	query := r.client.MFA.
		Query().
		Where(mfa.Method(method)).
		WithUser()

	// Apply ordering
	query.Order(ent.Desc(mfa.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.MFA, *ent.MFAQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list MFA methods by method %s", method))
	}

	return result, nil
}

// MarkAsVerified marks an MFA method as verified
func (r *mfaRepository) MarkAsVerified(ctx context.Context, id xid.ID) error {
	err := r.client.MFA.
		UpdateOneID(id).
		SetVerified(true).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "MFA method not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to mark MFA method as verified")
	}

	return nil
}

// UpdateLastUsed updates the last used timestamp for an MFA method
func (r *mfaRepository) UpdateLastUsed(ctx context.Context, id xid.ID) error {
	err := r.client.MFA.
		UpdateOneID(id).
		SetLastUsed(time.Now()).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "MFA method not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to update last used timestamp")
	}

	return nil
}

// DeactivateByUserID deactivates all MFA methods for a user
func (r *mfaRepository) DeactivateByUserID(ctx context.Context, userID xid.ID) error {
	_, err := r.client.MFA.
		Update().
		Where(mfa.UserID(userID)).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to deactivate MFA methods")
	}

	return nil
}

// DeactivateMethodByUserID deactivates a specific MFA method for a user
func (r *mfaRepository) DeactivateMethodByUserID(ctx context.Context, userID xid.ID, method string) error {
	_, err := r.client.MFA.
		Update().
		Where(
			mfa.UserID(userID),
			mfa.Method(method),
		).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to deactivate MFA method %s", method))
	}

	return nil
}

// CountByUserID counts the number of MFA methods for a user
func (r *mfaRepository) CountByUserID(ctx context.Context, userID xid.ID) (int, error) {
	count, err := r.client.MFA.
		Query().
		Where(mfa.UserID(userID)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count MFA methods")
	}

	return count, nil
}

// CountVerifiedByUserID counts the number of verified MFA methods for a user
func (r *mfaRepository) CountVerifiedByUserID(ctx context.Context, userID xid.ID) (int, error) {
	count, err := r.client.MFA.
		Query().
		Where(
			mfa.UserID(userID),
			mfa.Verified(true),
			mfa.Active(true),
		).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count verified MFA methods")
	}

	return count, nil
}

// GetVerifiedByUserIDAndMethod retrieves a verified MFA method by user ID and method type
func (r *mfaRepository) GetVerifiedByUserIDAndMethod(ctx context.Context, userID xid.ID, method string) (*ent.MFA, error) {
	mfaMethod, err := r.client.MFA.
		Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(method),
			mfa.Verified(true),
			mfa.Active(true),
		).
		WithUser().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("Verified MFA method '%s' not found for user", method))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get verified MFA method")
	}

	return mfaMethod, nil
}

// HasVerifiedMFA checks if a user has any verified MFA methods
func (r *mfaRepository) HasVerifiedMFA(ctx context.Context, userID xid.ID) (bool, error) {
	count, err := r.CountVerifiedByUserID(ctx, userID)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// ListMethodsByUserID retrieves a list of MFA method types for a user
func (r *mfaRepository) ListMethodsByUserID(ctx context.Context, userID xid.ID) ([]string, error) {
	var methods []string

	err := r.client.MFA.
		Query().
		Where(
			mfa.UserID(userID),
			mfa.Active(true),
		).
		Select(mfa.FieldMethod).
		Scan(ctx, &methods)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list MFA methods by user ID")
	}

	return methods, nil
}
