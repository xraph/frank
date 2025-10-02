package repository

import (
	"context"
	"time"

	"github.com/uptrace/bun"
	"github.com/xraph/frank/internal/models"
)

// ===== VERIFICATION REPOSITORY =====

// VerificationRepository defines the interface for verification operations
type VerificationRepository interface {
	Create(ctx context.Context, input CreateVerificationInput) (*models.Verification, error)
	GetByID(ctx context.Context, id string) (*models.Verification, error)
	GetByToken(ctx context.Context, token string) (*models.Verification, error)
	Update(ctx context.Context, id string, input UpdateVerificationInput) (*models.Verification, error)
	Delete(ctx context.Context, id string) error
	DeleteByToken(ctx context.Context, token string) error

	ListByUserID(ctx context.Context, userID string, opts ListVerificationFilter) (*PaginatedOutput[*models.Verification], error)
	ListByType(ctx context.Context, verificationType string, opts PaginationParams) (*PaginatedOutput[*models.Verification], error)
	ListByEmail(ctx context.Context, email string, opts PaginationParams) (*PaginatedOutput[*models.Verification], error)
	ListByPhoneNumber(ctx context.Context, phoneNumber string, opts PaginationParams) (*PaginatedOutput[*models.Verification], error)

	MarkAsUsed(ctx context.Context, id string) error
	MarkTokenAsUsed(ctx context.Context, token string) error
	IncrementAttempts(ctx context.Context, id string) error
	IncrementTokenAttempts(ctx context.Context, token string) error

	IsTokenValid(ctx context.Context, token string) (bool, error)
	GetValidToken(ctx context.Context, token string) (*models.Verification, error)
	GetValidTokenByTypeAndUser(ctx context.Context, verificationType string, userID string) (*models.Verification, error)
	GetRecentVerifications(ctx context.Context, userID string, verificationType string, since time.Time) ([]*models.Verification, error)

	CleanupExpired(ctx context.Context, before time.Time) (int, error)
	CleanupUsed(ctx context.Context, olderThan time.Time) (int, error)
	CountByUserAndType(ctx context.Context, userID string, verificationType string) (int, error)
	InvalidateUserVerifications(ctx context.Context, userID string, verificationType string) (int, error)
	CountAttemptsByIP(ctx context.Context, ipAddress string, since time.Time) (int, error)

	ListExpired(ctx context.Context) ([]*models.Verification, error)
	ListExpiringBefore(ctx context.Context, before time.Time, limit int) ([]*models.Verification, error)
	ListRecentByUser(ctx context.Context, userID string, limit int) ([]*models.Verification, error)
	ListSuspiciousAttempts(ctx context.Context, maxAttempts int, since time.Time) ([]*models.Verification, error)
}

type CreateVerificationInput struct {
	UserID       string
	Type         string
	Token        string
	Email        string
	PhoneNumber  *string
	RedirectURL  *string
	ExpiresAt    time.Time
	IPAddress    *string
	UserAgent    *string
	Attestation  map[string]interface{}
	AttemptCount *int
	Used         bool
	Metadata     map[string]interface{}
}

type UpdateVerificationInput struct {
	Used        *bool
	UsedAt      *time.Time
	Attempts    *int
	ExpiresAt   *time.Time
	RedirectURL *string
	Attestation map[string]interface{}
	Metadata    map[string]interface{}
}

type ListVerificationFilter struct {
	PaginationParams
	Before *time.Time
	Type   *string
}

type verificationRepository struct {
	db *bun.DB
}

func NewVerificationRepository(db *bun.DB) VerificationRepository {
	return &verificationRepository{db: db}
}

func (r *verificationRepository) Create(ctx context.Context, input CreateVerificationInput) (*models.Verification, error) {
	verification := &models.Verification{
		UserID:      input.UserID,
		Type:        input.Type,
		Token:       input.Token,
		Email:       &input.Email,
		PhoneNumber: input.PhoneNumber,
		RedirectURL: input.RedirectURL,
		Used:        input.Used,
		ExpiresAt:   input.ExpiresAt,
		IPAddress:   input.IPAddress,
		UserAgent:   input.UserAgent,
		Attestation: input.Attestation,
		Metadata:    input.Metadata,
	}

	if input.AttemptCount != nil {
		verification.Attempts = *input.AttemptCount
	}

	_, err := r.db.NewInsert().Model(verification).Exec(ctx)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return nil, NewError(CodeConflict, "Verification token already exists")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to create verification")
	}
	return verification, nil
}

func (r *verificationRepository) GetByID(ctx context.Context, id string) (*models.Verification, error) {
	verification := new(models.Verification)
	err := r.db.NewSelect().
		Model(verification).
		Relation("User").
		Where("v.id = ?", id).
		Where("v.deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Verification not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get verification")
	}
	return verification, nil
}

func (r *verificationRepository) GetByToken(ctx context.Context, token string) (*models.Verification, error) {
	verification := new(models.Verification)
	err := r.db.NewSelect().
		Model(verification).
		Relation("User").
		Where("v.token = ?", token).
		Where("v.deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Verification token not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get verification by token")
	}
	return verification, nil
}

func (r *verificationRepository) Update(ctx context.Context, id string, input UpdateVerificationInput) (*models.Verification, error) {
	verification, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	query := r.db.NewUpdate().
		Model(verification).
		Where("id = ?", id).
		Where("deleted_at IS NULL")

	if input.Used != nil {
		query = query.Set("used = ?", *input.Used)
		verification.Used = *input.Used
	}
	if input.UsedAt != nil {
		query = query.Set("used_at = ?", *input.UsedAt)
		verification.UsedAt = input.UsedAt
	}
	if input.Attempts != nil {
		query = query.Set("attempts = ?", *input.Attempts)
		verification.Attempts = *input.Attempts
	}
	if input.ExpiresAt != nil {
		query = query.Set("expires_at = ?", *input.ExpiresAt)
		verification.ExpiresAt = *input.ExpiresAt
	}
	if input.RedirectURL != nil {
		query = query.Set("redirect_url = ?", *input.RedirectURL)
		verification.RedirectURL = input.RedirectURL
	}
	if input.Attestation != nil {
		query = query.Set("attestation = ?", input.Attestation)
		verification.Attestation = input.Attestation
	}
	if input.Metadata != nil {
		query = query.Set("metadata = ?", input.Metadata)
		verification.Metadata = input.Metadata
	}

	_, err = query.Exec(ctx)
	if err != nil {
		return nil, WrapError(err, CodeDatabaseError, "failed to update verification")
	}
	return verification, nil
}

func (r *verificationRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.NewDelete().
		Model((*models.Verification)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

func (r *verificationRepository) DeleteByToken(ctx context.Context, token string) error {
	_, err := r.db.NewDelete().
		Model((*models.Verification)(nil)).
		Where("token = ?", token).
		Exec(ctx)
	return err
}

func (r *verificationRepository) ListByUserID(ctx context.Context, userID string, opts ListVerificationFilter) (*PaginatedOutput[*models.Verification], error) {
	query := r.db.NewSelect().
		Model((*models.Verification)(nil)).
		Relation("User").
		Where("v.user_id = ?", userID).
		Where("v.deleted_at IS NULL")

	if opts.Before != nil {
		query = query.Where("v.created_at < ?", *opts.Before)
	}
	if opts.Type != nil {
		query = query.Where("v.type = ?", *opts.Type)
	}

	return Paginate[*models.Verification](ctx, query, opts.PaginationParams)
}

func (r *verificationRepository) ListByType(ctx context.Context, verificationType string, opts PaginationParams) (*PaginatedOutput[*models.Verification], error) {
	query := r.db.NewSelect().
		Model((*models.Verification)(nil)).
		Relation("User").
		Where("type = ?", verificationType).
		Where("deleted_at IS NULL")

	return Paginate[*models.Verification](ctx, query, opts)
}

func (r *verificationRepository) ListByEmail(ctx context.Context, email string, opts PaginationParams) (*PaginatedOutput[*models.Verification], error) {
	query := r.db.NewSelect().
		Model((*models.Verification)(nil)).
		Relation("User").
		Where("email = ?", email).
		Where("deleted_at IS NULL")

	return Paginate[*models.Verification](ctx, query, opts)
}

func (r *verificationRepository) ListByPhoneNumber(ctx context.Context, phoneNumber string, opts PaginationParams) (*PaginatedOutput[*models.Verification], error) {
	query := r.db.NewSelect().
		Model((*models.Verification)(nil)).
		Relation("User").
		Where("phone_number = ?", phoneNumber).
		Where("deleted_at IS NULL")

	return Paginate[*models.Verification](ctx, query, opts)
}

func (r *verificationRepository) MarkAsUsed(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.Verification)(nil)).
		Set("used = ?", true).
		Set("used_at = ?", time.Now()).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

func (r *verificationRepository) MarkTokenAsUsed(ctx context.Context, token string) error {
	_, err := r.db.NewUpdate().
		Model((*models.Verification)(nil)).
		Set("used = ?", true).
		Set("used_at = ?", time.Now()).
		Where("token = ?", token).
		Exec(ctx)
	return err
}

func (r *verificationRepository) IncrementAttempts(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.Verification)(nil)).
		Set("attempts = attempts + 1").
		Where("id = ?", id).
		Exec(ctx)
	return err
}

func (r *verificationRepository) IncrementTokenAttempts(ctx context.Context, token string) error {
	_, err := r.db.NewUpdate().
		Model((*models.Verification)(nil)).
		Set("attempts = attempts + 1").
		Where("token = ?", token).
		Exec(ctx)
	return err
}

func (r *verificationRepository) IsTokenValid(ctx context.Context, token string) (bool, error) {
	count, err := r.db.NewSelect().
		Model((*models.Verification)(nil)).
		Where("token = ?", token).
		Where("used = ?", false).
		Where("expires_at > ?", time.Now()).
		Where("deleted_at IS NULL").
		Count(ctx)
	return count > 0, err
}

func (r *verificationRepository) GetValidToken(ctx context.Context, token string) (*models.Verification, error) {
	verification := new(models.Verification)
	err := r.db.NewSelect().
		Model(verification).
		Relation("User").
		Where("v.token = ?", token).
		Where("v.used = ?", false).
		Where("v.expires_at > ?", time.Now()).
		Where("v.deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Valid verification token not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get valid verification token")
	}
	return verification, nil
}

func (r *verificationRepository) GetValidTokenByTypeAndUser(ctx context.Context, verificationType string, userID string) (*models.Verification, error) {
	verification := new(models.Verification)
	err := r.db.NewSelect().
		Model(verification).
		Relation("User").
		Where("v.type = ?", verificationType).
		Where("v.user_id = ?", userID).
		Where("v.used = ?", false).
		Where("v.expires_at > ?", time.Now()).
		Where("v.deleted_at IS NULL").
		Order("v.created_at DESC").
		Limit(1).
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Valid verification token not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get valid verification token")
	}
	return verification, nil
}

func (r *verificationRepository) GetRecentVerifications(ctx context.Context, userID string, verificationType string, since time.Time) ([]*models.Verification, error) {
	var verifications []*models.Verification
	err := r.db.NewSelect().
		Model(&verifications).
		Where("user_id = ?", userID).
		Where("type = ?", verificationType).
		Where("created_at >= ?", since).
		Order("created_at DESC").
		Scan(ctx)
	return verifications, err
}

func (r *verificationRepository) CleanupExpired(ctx context.Context, before time.Time) (int, error) {
	res, err := r.db.NewDelete().
		Model((*models.Verification)(nil)).
		Where("expires_at < ?", before).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	rows, _ := res.RowsAffected()
	return int(rows), nil
}

func (r *verificationRepository) CleanupUsed(ctx context.Context, olderThan time.Time) (int, error) {
	res, err := r.db.NewDelete().
		Model((*models.Verification)(nil)).
		Where("used = ?", true).
		Where("created_at < ?", olderThan).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	rows, _ := res.RowsAffected()
	return int(rows), nil
}

func (r *verificationRepository) CountByUserAndType(ctx context.Context, userID string, verificationType string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.Verification)(nil)).
		Where("user_id = ?", userID).
		Where("type = ?", verificationType).
		Count(ctx)
	return count, err
}

func (r *verificationRepository) InvalidateUserVerifications(ctx context.Context, userID string, verificationType string) (int, error) {
	res, err := r.db.NewUpdate().
		Model((*models.Verification)(nil)).
		Set("used = ?", true).
		Set("used_at = ?", time.Now()).
		Where("user_id = ?", userID).
		Where("type = ?", verificationType).
		Where("used = ?", false).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	rows, _ := res.RowsAffected()
	return int(rows), nil
}

func (r *verificationRepository) CountAttemptsByIP(ctx context.Context, ipAddress string, since time.Time) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.Verification)(nil)).
		Where("ip_address = ?", ipAddress).
		Where("created_at >= ?", since).
		Count(ctx)
	return count, err
}

func (r *verificationRepository) ListExpired(ctx context.Context) ([]*models.Verification, error) {
	var verifications []*models.Verification
	err := r.db.NewSelect().
		Model(&verifications).
		Relation("User").
		Where("expires_at < ?", time.Now()).
		Order("expires_at ASC").
		Scan(ctx)
	return verifications, err
}

func (r *verificationRepository) ListExpiringBefore(ctx context.Context, before time.Time, limit int) ([]*models.Verification, error) {
	var verifications []*models.Verification
	err := r.db.NewSelect().
		Model(&verifications).
		Relation("User").
		Where("expires_at < ?", before).
		Where("expires_at > ?", time.Now()).
		Where("used = ?", false).
		Order("expires_at ASC").
		Limit(limit).
		Scan(ctx)
	return verifications, err
}

func (r *verificationRepository) ListRecentByUser(ctx context.Context, userID string, limit int) ([]*models.Verification, error) {
	var verifications []*models.Verification
	err := r.db.NewSelect().
		Model(&verifications).
		Relation("User").
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Scan(ctx)
	return verifications, err
}

func (r *verificationRepository) ListSuspiciousAttempts(ctx context.Context, maxAttempts int, since time.Time) ([]*models.Verification, error) {
	var verifications []*models.Verification
	err := r.db.NewSelect().
		Model(&verifications).
		Relation("User").
		Where("attempts >= ?", maxAttempts).
		Where("created_at >= ?", since).
		Order("attempts DESC").
		Scan(ctx)
	return verifications, err
}

// // ===== MFA REPOSITORY =====
//
// type MFARepository interface {
// 	Create(ctx context.Context, input CreateMFAInput) (*models.MFA, error)
// 	GetByID(ctx context.Context, id string) (*models.MFA, error)
// 	GetByUserIDAndMethod(ctx context.Context, userID string, method string) (*models.MFA, error)
// 	Update(ctx context.Context, id string, input UpdateMFAInput) (*models.MFA, error)
// 	Delete(ctx context.Context, id string) error
//
// 	ListByUserID(ctx context.Context, userID string, opts PaginationParams) (*PaginatedOutput[*models.MFA], error)
// 	ListActiveByUserID(ctx context.Context, userID string) ([]*models.MFA, error)
// 	ListByMethod(ctx context.Context, method string, opts PaginationParams) (*PaginatedOutput[*models.MFA], error)
//
// 	MarkAsVerified(ctx context.Context, id string) error
// 	UpdateLastUsed(ctx context.Context, id string) error
// 	DeactivateByUserID(ctx context.Context, userID string) error
// 	DeactivateMethodByUserID(ctx context.Context, userID string, method string) error
//
// 	CountByUserID(ctx context.Context, userID string) (int, error)
// 	CountVerifiedByUserID(ctx context.Context, userID string) (int, error)
// 	GetVerifiedByUserIDAndMethod(ctx context.Context, userID string, method string) (*models.MFA, error)
// 	HasVerifiedMFA(ctx context.Context, userID string) (bool, error)
// 	ListMethodsByUserID(ctx context.Context, userID string) ([]string, error)
// }
//
// type CreateMFAInput struct {
// 	UserID      string
// 	Method      string
// 	Secret      string
// 	Verified    bool
// 	Active      bool
// 	BackupCodes []string
// 	PhoneNumber *string
// 	Email       *string
// 	Metadata    map[string]interface{}
// }
//
// type UpdateMFAInput struct {
// 	Secret      *string
// 	Verified    *bool
// 	Active      *bool
// 	BackupCodes []string
// 	PhoneNumber *string
// 	Email       *string
// 	LastUsed    *time.Time
// 	Metadata    map[string]interface{}
// }
//
// type mfaRepository struct {
// 	db *bun.DB
// }
//
// func NewMFARepository(db *bun.DB) MFARepository {
// 	return &mfaRepository{db: db}
// }
//
// func (r *mfaRepository) Create(ctx context.Context, input CreateMFAInput) (*models.MFA, error) {
// 	mfa := &models.MFA{
// 		UserID:      input.UserID,
// 		Method:      input.Method,
// 		Secret:      input.Secret,
// 		Verified:    input.Verified,
// 		Active:      input.Active,
// 		BackupCodes: input.BackupCodes,
// 		PhoneNumber: input.PhoneNumber,
// 		Email:       input.Email,
// 		Metadata:    input.Metadata,
// 	}
//
// 	_, err := r.db.NewInsert().Model(mfa).Exec(ctx)
// 	if err != nil {
// 		if IsDuplicateKeyError(err) {
// 			return nil, NewError(CodeConflict, "MFA method already exists for this user")
// 		}
// 		return nil, WrapError(err, CodeDatabaseError, "failed to create MFA method")
// 	}
// 	return mfa, nil
// }
//
// func (r *mfaRepository) GetByID(ctx context.Context, id string) (*models.MFA, error) {
// 	mfa := new(models.MFA)
// 	err := r.db.NewSelect().
// 		Model(mfa).
// 		Relation("User").
// 		Where("mfa.id = ?", id).
// 		Where("mfa.deleted_at IS NULL").
// 		Scan(ctx)
// 	if err != nil {
// 		if IsNotFoundError(err) {
// 			return nil, NewError(CodeNotFound, "MFA method not found")
// 		}
// 		return nil, WrapError(err, CodeDatabaseError, "failed to get MFA method")
// 	}
// 	return mfa, nil
// }
//
// func (r *mfaRepository) GetByUserIDAndMethod(ctx context.Context, userID string, method string) (*models.MFA, error) {
// 	mfa := new(models.MFA)
// 	err := r.db.NewSelect().
// 		Model(mfa).
// 		Relation("User").
// 		Where("mfa.user_id = ?", userID).
// 		Where("mfa.method = ?", method).
// 		Where("mfa.deleted_at IS NULL").
// 		Scan(ctx)
// 	if err != nil {
// 		if IsNotFoundError(err) {
// 			return nil, NewError(CodeNotFound, "MFA method not found")
// 		}
// 		return nil, WrapError(err, CodeDatabaseError, "failed to get MFA method")
// 	}
// 	return mfa, nil
// }
//
// func (r *mfaRepository) Update(ctx context.Context, id string, input UpdateMFAInput) (*models.MFA, error) {
// 	mfa, err := r.GetByID(ctx, id)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	query := r.db.NewUpdate().
// 		Model(mfa).
// 		Where("id = ?", id).
// 		Where("deleted_at IS NULL")
//
// 	if input.Secret != nil {
// 		query = query.Set("secret = ?", *input.Secret)
// 		mfa.Secret = *input.Secret
// 	}
// 	if input.Verified != nil {
// 		query = query.Set("verified = ?", *input.Verified)
// 		mfa.Verified = *input.Verified
// 	}
// 	if input.Active != nil {
// 		query = query.Set("active = ?", *input.Active)
// 		mfa.Active = *input.Active
// 	}
// 	if input.BackupCodes != nil {
// 		query = query.Set("backup_codes = ?", input.BackupCodes)
// 		mfa.BackupCodes = input.BackupCodes
// 	}
// 	if input.PhoneNumber != nil {
// 		query = query.Set("phone_number = ?", *input.PhoneNumber)
// 		mfa.PhoneNumber = input.PhoneNumber
// 	}
// 	if input.Email != nil {
// 		query = query.Set("email = ?", *input.Email)
// 		mfa.Email = input.Email
// 	}
// 	if input.LastUsed != nil {
// 		query = query.Set("last_used = ?", *input.LastUsed)
// 		mfa.LastUsed = input.LastUsed
// 	}
// 	if input.Metadata != nil {
// 		query = query.Set("metadata = ?", input.Metadata)
// 		mfa.Metadata = input.Metadata
// 	}
//
// 	_, err = query.Exec(ctx)
// 	if err != nil {
// 		return nil, WrapError(err, CodeDatabaseError, "failed to update MFA method")
// 	}
// 	return mfa, nil
// }
//
// func (r *mfaRepository) Delete(ctx context.Context, id string) error {
// 	_, err := r.db.NewDelete().
// 		Model((*models.MFA)(nil)).
// 		Where("id = ?", id).
// 		Exec(ctx)
// 	return err
// }
//
// func (r *mfaRepository) ListByUserID(ctx context.Context, userID string, opts PaginationParams) (*PaginatedOutput[*models.MFA], error) {
// 	query := r.db.NewSelect().
// 		Model((*models.MFA)(nil)).
// 		Relation("User").
// 		Where("mfa.user_id = ?", userID).
// 		Where("mfa.deleted_at IS NULL")
//
// 	return Paginate[*models.MFA](ctx, query, opts)
// }
//
// func (r *mfaRepository) ListActiveByUserID(ctx context.Context, userID string) ([]*models.MFA, error) {
// 	var mfaMethods []*models.MFA
// 	err := r.db.NewSelect().
// 		Model(&mfaMethods).
// 		Relation("User").
// 		Where("mfa.user_id = ?", userID).
// 		Where("mfa.active = ?", true).
// 		Where("mfa.deleted_at IS NULL").
// 		Order("mfa.created_at DESC").
// 		Scan(ctx)
// 	return mfaMethods, err
// }
//
// func (r *mfaRepository) ListByMethod(ctx context.Context, method string, opts PaginationParams) (*PaginatedOutput[*models.MFA], error) {
// 	query := r.db.NewSelect().
// 		Model((*models.MFA)(nil)).
// 		Relation("User").
// 		Where("method = ?", method).
// 		Where("deleted_at IS NULL")
//
// 	return Paginate[*models.MFA](ctx, query, opts)
// }
//
// func (r *mfaRepository) MarkAsVerified(ctx context.Context, id string) error {
// 	_, err := r.db.NewUpdate().
// 		Model((*models.MFA)(nil)).
// 		Set("verified = ?", true).
// 		Where("id = ?", id).
// 		Exec(ctx)
// 	return err
// }
//
// func (r *mfaRepository) UpdateLastUsed(ctx context.Context, id string) error {
// 	_, err := r.db.NewUpdate().
// 		Model((*models.MFA)(nil)).
// 		Set("last_used = ?", time.Now()).
// 		Where("id = ?", id).
// 		Exec(ctx)
// 	return err
// }
//
// func (r *mfaRepository) DeactivateByUserID(ctx context.Context, userID string) error {
// 	_, err := r.db.NewUpdate().
// 		Model((*models.MFA)(nil)).
// 		Set("active = ?", false).
// 		Where("user_id = ?", userID).
// 		Exec(ctx)
// 	return err
// }
//
// func (r *mfaRepository) DeactivateMethodByUserID(ctx context.Context, userID string, method string) error {
// 	_, err := r.db.NewUpdate().
// 		Model((*models.MFA)(nil)).
// 		Set("active = ?", false).
// 		Where("user_id = ?", userID).
// 		Where("method = ?", method).
// 		Exec(ctx)
// 	return err
// }
//
// func (r *mfaRepository) CountByUserID(ctx context.Context, userID string) (int, error) {
// 	count, err := r.db.NewSelect().
// 		Model((*models.MFA)(nil)).
// 		Where("user_id = ?", userID).
// 		Where("deleted_at IS NULL").
// 		Count(ctx)
// 	return count, err
// }
//
// func (r *mfaRepository) CountVerifiedByUserID(ctx context.Context, userID string) (int, error) {
// 	count, err := r.db.NewSelect().
// 		Model((*models.MFA)(nil)).
// 		Where("user_id = ?", userID).
// 		Where("verified = ?", true).
// 		Where("active = ?", true).
// 		Where("deleted_at IS NULL").
// 		Count(ctx)
// 	return count, err
// }
//
// func (r *mfaRepository) GetVerifiedByUserIDAndMethod(ctx context.Context, userID string, method string) (*models.MFA, error) {
// 	mfa := new(models.MFA)
// 	err := r.db.NewSelect().
// 		Model(mfa).
// 		Relation("User").
// 		Where("mfa.user_id = ?", userID).
// 		Where("mfa.method = ?", method).
// 		Where("mfa.verified = ?", true).
// 		Where("mfa.active = ?", true).
// 		Where("mfa.deleted_at IS NULL").
// 		Scan(ctx)
// 	if err != nil {
// 		if IsNotFoundError(err) {
// 			return nil, NewError(CodeNotFound, "Verified MFA method not found")
// 		}
// 		return nil, WrapError(err, CodeDatabaseError, "failed to get verified MFA method")
// 	}
// 	return mfa, nil
// }
//
// func (r *mfaRepository) HasVerifiedMFA(ctx context.Context, userID string) (bool, error) {
// 	count, err := r.CountVerifiedByUserID(ctx, userID)
// 	return count > 0, err
// }
//
// func (r *mfaRepository) ListMethodsByUserID(ctx context.Context, userID string) ([]string, error) {
// 	var methods []string
// 	err := r.db.NewSelect().
// 		Model((*models.MFA)(nil)).
// 		Column("method").
// 		Where("user_id = ?", userID).
// 		Where("active = ?", true).
// 		Where("deleted_at IS NULL").
// 		Scan(ctx, &methods)
// 	return methods, err
// }
