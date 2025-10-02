package repository

import (
	"context"
	"database/sql"
	errors2 "errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/uptrace/bun"
	"github.com/xraph/frank/internal/models"
	"github.com/xraph/frank/pkg/errors"
)

// MFARepository defines the interface for MFA data operations
type MFARepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateMFAInput) (*models.MFA, error)
	GetByID(ctx context.Context, id string) (*models.MFA, error)
	GetByUserIDAndMethod(ctx context.Context, userID string, method string) (*models.MFA, error)
	Update(ctx context.Context, id string, input UpdateMFAInput) (*models.MFA, error)
	Delete(ctx context.Context, id string) error

	// Query operations
	ListByUserID(ctx context.Context, userID string, opts models.PaginationParams) (*models.PaginatedOutput[*models.MFA], error)
	ListActiveByUserID(ctx context.Context, userID string) ([]*models.MFA, error)
	ListByMethod(ctx context.Context, method string, opts models.PaginationParams) (*models.PaginatedOutput[*models.MFA], error)

	// Verification operations
	MarkAsVerified(ctx context.Context, id string) error
	UpdateLastUsed(ctx context.Context, id string) error

	// Utility operations
	DeactivateByUserID(ctx context.Context, userID string) error
	DeactivateMethodByUserID(ctx context.Context, userID string, method string) error
	CountByUserID(ctx context.Context, userID string) (int, error)
	CountVerifiedByUserID(ctx context.Context, userID string) (int, error)

	// Advanced queries
	GetVerifiedByUserIDAndMethod(ctx context.Context, userID string, method string) (*models.MFA, error)
	HasVerifiedMFA(ctx context.Context, userID string) (bool, error)
	ListMethodsByUserID(ctx context.Context, userID string) ([]string, error)
}

// mfaRepository implements MFARepository interface
type mfaRepository struct {
	db *bun.DB
}

// NewMFARepository creates a new MFA repository
func NewMFARepository(db *bun.DB) MFARepository {
	return &mfaRepository{
		db: db,
	}
}

// CreateMFAInput defines the input for creating an MFA method
type CreateMFAInput struct {
	UserID      string         `json:"user_id"`
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
func (r *mfaRepository) Create(ctx context.Context, input CreateMFAInput) (*models.MFA, error) {
	mfaMethod := &models.MFA{
		UserID:   input.UserID,
		Method:   input.Method,
		Secret:   input.Secret,
		Verified: input.Verified,
		Active:   input.Active,
	}

	if input.BackupCodes != nil {
		mfaMethod.BackupCodes = input.BackupCodes
	}

	if input.PhoneNumber != nil {
		mfaMethod.PhoneNumber = input.PhoneNumber
	}

	if input.Email != nil {
		mfaMethod.Email = input.Email
	}

	if input.Metadata != nil {
		mfaMethod.Metadata = input.Metadata
	}

	_, err := r.db.NewInsert().
		Model(mfaMethod).
		Exec(ctx)

	if err != nil {
		if errors2.Is(err, &pq.Error{Code: "23505"}) {
			return nil, errors.New(errors.CodeConflict, fmt.Sprintf("MFA method '%s' already exists for this user", input.Method))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to create MFA method")
	}

	return mfaMethod, nil
}

// GetByID retrieves an MFA method by its ID
func (r *mfaRepository) GetByID(ctx context.Context, id string) (*models.MFA, error) {
	mfaMethod := &models.MFA{}

	err := r.db.NewSelect().
		Model(mfaMethod).
		Relation("User").
		Where("mfa.id = ?", id).
		Where("mfa.deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "MFA method not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get MFA method")
	}

	return mfaMethod, nil
}

// GetByUserIDAndMethod retrieves an MFA method by user ID and method type
func (r *mfaRepository) GetByUserIDAndMethod(ctx context.Context, userID string, method string) (*models.MFA, error) {
	mfaMethod := &models.MFA{}

	err := r.db.NewSelect().
		Model(mfaMethod).
		Relation("User").
		Where("mfa.user_id = ?", userID).
		Where("mfa.method = ?", method).
		Where("mfa.deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("MFA method '%s' not found for user", method))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get MFA method by user and method")
	}

	return mfaMethod, nil
}

// Update updates an MFA method
func (r *mfaRepository) Update(ctx context.Context, id string, input UpdateMFAInput) (*models.MFA, error) {
	query := r.db.NewUpdate().
		Model(&models.MFA{}).
		Where("id = ?", id)

	if input.Secret != nil {
		query = query.Set("secret = ?", *input.Secret)
	}

	if input.Verified != nil {
		query = query.Set("verified = ?", *input.Verified)
	}

	if input.Active != nil {
		query = query.Set("active = ?", *input.Active)
	}

	if input.BackupCodes != nil {
		query = query.Set("backup_codes = ?", input.BackupCodes)
	}

	if input.PhoneNumber != nil {
		query = query.Set("phone_number = ?", *input.PhoneNumber)
	}

	if input.Email != nil {
		query = query.Set("email = ?", *input.Email)
	}

	if input.LastUsed != nil {
		query = query.Set("last_used = ?", *input.LastUsed)
	}

	if input.Metadata != nil {
		query = query.Set("metadata = ?", input.Metadata)
	}

	_, err := query.Exec(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to update MFA method")
	}

	return r.GetByID(ctx, id)
}

// Delete deletes an MFA method (soft delete)
func (r *mfaRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model(&models.MFA{}).
		Set("deleted_at = ?", time.Now()).
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete MFA method")
	}

	return nil
}

// ListByUserID retrieves paginated MFA methods for a user
func (r *mfaRepository) ListByUserID(ctx context.Context, userID string, opts models.PaginationParams) (*models.PaginatedOutput[*models.MFA], error) {
	query := r.db.NewSelect().
		Model((*models.MFA)(nil)).
		Relation("User").
		Where("mfa.user_id = ?", userID).
		Where("mfa.deleted_at IS NULL").
		Order("mfa.created_at DESC")

	result, err := models.WithPaginationAndOptions[*models.MFA](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list MFA methods by user ID")
	}

	return result, nil
}

// ListActiveByUserID retrieves all active MFA methods for a user
func (r *mfaRepository) ListActiveByUserID(ctx context.Context, userID string) ([]*models.MFA, error) {
	var mfaMethods []*models.MFA

	err := r.db.NewSelect().
		Model(&mfaMethods).
		Relation("User").
		Where("mfa.user_id = ?", userID).
		Where("mfa.active = ?", true).
		Where("mfa.deleted_at IS NULL").
		Order("mfa.created_at DESC").
		Scan(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list active MFA methods")
	}

	return mfaMethods, nil
}

// ListByMethod retrieves paginated MFA methods by method type
func (r *mfaRepository) ListByMethod(ctx context.Context, method string, opts models.PaginationParams) (*models.PaginatedOutput[*models.MFA], error) {
	query := r.db.NewSelect().
		Model((*models.MFA)(nil)).
		Relation("User").
		Where("mfa.method = ?", method).
		Where("mfa.deleted_at IS NULL").
		Order("mfa.created_at DESC")

	result, err := models.WithPaginationAndOptions[*models.MFA](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list MFA methods by method %s", method))
	}

	return result, nil
}

// MarkAsVerified marks an MFA method as verified
func (r *mfaRepository) MarkAsVerified(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model(&models.MFA{}).
		Set("verified = ?", true).
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to mark MFA method as verified")
	}

	return nil
}

// UpdateLastUsed updates the last used timestamp for an MFA method
func (r *mfaRepository) UpdateLastUsed(ctx context.Context, id string) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model(&models.MFA{}).
		Set("last_used = ?", now).
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to update last used timestamp")
	}

	return nil
}

// DeactivateByUserID deactivates all MFA methods for a user
func (r *mfaRepository) DeactivateByUserID(ctx context.Context, userID string) error {
	_, err := r.db.NewUpdate().
		Model(&models.MFA{}).
		Set("active = ?", false).
		Where("user_id = ?", userID).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to deactivate MFA methods")
	}

	return nil
}

// DeactivateMethodByUserID deactivates a specific MFA method for a user
func (r *mfaRepository) DeactivateMethodByUserID(ctx context.Context, userID string, method string) error {
	_, err := r.db.NewUpdate().
		Model(&models.MFA{}).
		Set("active = ?", false).
		Where("user_id = ?", userID).
		Where("method = ?", method).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to deactivate MFA method %s", method))
	}

	return nil
}

// CountByUserID counts the number of MFA methods for a user
func (r *mfaRepository) CountByUserID(ctx context.Context, userID string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.MFA)(nil)).
		Where("user_id = ?", userID).
		Where("deleted_at IS NULL").
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count MFA methods")
	}

	return count, nil
}

// CountVerifiedByUserID counts the number of verified MFA methods for a user
func (r *mfaRepository) CountVerifiedByUserID(ctx context.Context, userID string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.MFA)(nil)).
		Where("user_id = ?", userID).
		Where("verified = ?", true).
		Where("active = ?", true).
		Where("deleted_at IS NULL").
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count verified MFA methods")
	}

	return count, nil
}

// GetVerifiedByUserIDAndMethod retrieves a verified MFA method by user ID and method type
func (r *mfaRepository) GetVerifiedByUserIDAndMethod(ctx context.Context, userID string, method string) (*models.MFA, error) {
	mfaMethod := &models.MFA{}

	err := r.db.NewSelect().
		Model(mfaMethod).
		Relation("User").
		Where("mfa.user_id = ?", userID).
		Where("mfa.method = ?", method).
		Where("mfa.verified = ?", true).
		Where("mfa.active = ?", true).
		Where("mfa.deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("Verified MFA method '%s' not found for user", method))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get verified MFA method")
	}

	return mfaMethod, nil
}

// HasVerifiedMFA checks if a user has any verified MFA methods
func (r *mfaRepository) HasVerifiedMFA(ctx context.Context, userID string) (bool, error) {
	count, err := r.CountVerifiedByUserID(ctx, userID)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// ListMethodsByUserID retrieves a list of MFA method types for a user
func (r *mfaRepository) ListMethodsByUserID(ctx context.Context, userID string) ([]string, error) {
	var methods []string

	err := r.db.NewSelect().
		Model((*models.MFA)(nil)).
		Column("method").
		Where("user_id = ?", userID).
		Where("active = ?", true).
		Where("deleted_at IS NULL").
		Scan(ctx, &methods)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list MFA methods by user ID")
	}

	return methods, nil
}
