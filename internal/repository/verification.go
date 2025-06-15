package repository

import (
	"context"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/verification"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// VerificationRepository defines the interface for verification data operations
type VerificationRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateVerificationInput) (*ent.Verification, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Verification, error)
	GetByToken(ctx context.Context, token string) (*ent.Verification, error)
	Update(ctx context.Context, id xid.ID, input UpdateVerificationInput) (*ent.Verification, error)
	Delete(ctx context.Context, id xid.ID) error
	DeleteByToken(ctx context.Context, token string) error

	// Query operations
	ListByUserID(ctx context.Context, userID xid.ID, opts ListVerificationFilter) (*model.PaginatedOutput[*ent.Verification], error)
	ListByType(ctx context.Context, verificationType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Verification], error)
	ListByEmail(ctx context.Context, email string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Verification], error)
	ListByPhoneNumber(ctx context.Context, phoneNumber string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Verification], error)

	// Verification operations
	MarkAsUsed(ctx context.Context, id xid.ID) error
	MarkTokenAsUsed(ctx context.Context, token string) error
	IncrementAttempts(ctx context.Context, id xid.ID) error
	IncrementTokenAttempts(ctx context.Context, token string) error

	// Validation operations
	IsTokenValid(ctx context.Context, token string) (bool, error)
	GetValidToken(ctx context.Context, token string) (*ent.Verification, error)
	GetValidTokenByCode(ctx context.Context, token string, verificationType string) (*ent.Verification, error)
	GetValidTokenByTypeAndUser(ctx context.Context, verificationType string, userID xid.ID) (*ent.Verification, error)
	GetRecentVerifications(ctx context.Context, userID xid.ID, verificationType string, since time.Time) ([]*ent.Verification, error)
	MarkTokenAsUsedByCode(ctx context.Context, code string, verificationType string) error

	// Utility operations
	CleanupExpired(ctx context.Context, before time.Time) (int, error)
	CleanupUsed(ctx context.Context, olderThan time.Time) (int, error)
	CountByUserAndType(ctx context.Context, userID xid.ID, verificationType string) (int, error)
	InvalidateUserVerifications(ctx context.Context, userID xid.ID, verificationType string) (int, error)
	CountAttemptsByIP(ctx context.Context, ipAddress string, since time.Time) (int, error)

	// Advanced queries
	ListExpired(ctx context.Context) ([]*ent.Verification, error)
	ListExpiringBefore(ctx context.Context, before time.Time, limit int) ([]*ent.Verification, error)
	ListRecentByUser(ctx context.Context, userID xid.ID, limit int) ([]*ent.Verification, error)
	ListSuspiciousAttempts(ctx context.Context, maxAttempts int, since time.Time) ([]*ent.Verification, error)

	// Security operations
	GetVerificationStats(ctx context.Context, since time.Time) (*VerificationStats, error)
	ListHighVolumeIPs(ctx context.Context, minCount int, since time.Time) ([]IPVerificationActivity, error)
}

// verificationRepository implements VerificationRepository interface
type verificationRepository struct {
	client *ent.Client
}

// NewVerificationRepository creates a new verification repository
func NewVerificationRepository(client *ent.Client) VerificationRepository {
	return &verificationRepository{
		client: client,
	}
}

// CreateVerificationInput defines the input for creating a verification
type CreateVerificationInput struct {
	UserID       xid.ID                 `json:"user_id"`
	Type         string                 `json:"type"`
	Token        string                 `json:"token"`
	Email        string                 `json:"email,omitempty"`
	PhoneNumber  *string                `json:"phone_number,omitempty"`
	RedirectURL  *string                `json:"redirect_url,omitempty"`
	ExpiresAt    time.Time              `json:"expires_at"`
	IPAddress    *string                `json:"ip_address,omitempty"`
	UserAgent    *string                `json:"user_agent,omitempty"`
	Attestation  map[string]any         `json:"attestation,omitempty"`
	AttemptCount *int                   `json:"attempt_count,omitempty"`
	Used         bool                   `json:"used,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateVerificationInput defines the input for updating a verification
type UpdateVerificationInput struct {
	Used        *bool          `json:"used,omitempty"`
	UsedAt      *time.Time     `json:"used_at,omitempty"`
	Attempts    *int           `json:"attempts,omitempty"`
	ExpiresAt   *time.Time     `json:"expires_at,omitempty"`
	RedirectURL *string        `json:"redirect_url,omitempty"`
	Attestation map[string]any `json:"attestation,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// VerificationStats represents verification statistics
type VerificationStats struct {
	TotalVerifications      int                      `json:"total_verifications"`
	SuccessfulVerifications int                      `json:"successful_verifications"`
	ExpiredVerifications    int                      `json:"expired_verifications"`
	TypeBreakdown           map[string]int           `json:"type_breakdown"`
	SuccessRate             float64                  `json:"success_rate"`
	AverageAttempts         float64                  `json:"average_attempts"`
	TopIPAddresses          []IPVerificationActivity `json:"top_ip_addresses"`
}

// IPVerificationActivity represents IP verification activity
type IPVerificationActivity struct {
	IPAddress    string  `json:"ip_address"`
	Count        int     `json:"count"`
	SuccessCount int     `json:"success_count"`
	FailureCount int     `json:"failure_count"`
	SuccessRate  float64 `json:"success_rate"`
}

type ListVerificationFilter struct {
	model.PaginationParams
	Before *time.Time `json:"before"`
	Type   *string    `json:"type"`
}

// Create creates a new verification
func (r *verificationRepository) Create(ctx context.Context, input CreateVerificationInput) (*ent.Verification, error) {
	builder := r.client.Verification.Create().
		SetUserID(input.UserID).
		SetType(input.Type).
		SetToken(input.Token).
		SetUsed(input.Used).
		SetExpiresAt(input.ExpiresAt)

	if input.Email != "" {
		builder.SetEmail(input.Email)
	}

	if input.PhoneNumber != nil {
		builder.SetPhoneNumber(*input.PhoneNumber)
	}

	if input.RedirectURL != nil {
		builder.SetRedirectURL(*input.RedirectURL)
	}

	if input.IPAddress != nil {
		builder.SetIPAddress(*input.IPAddress)
	}

	if input.UserAgent != nil {
		builder.SetUserAgent(*input.UserAgent)
	}

	if input.Attestation != nil {
		builder.SetAttestation(input.Attestation)
	}

	if input.AttemptCount != nil {
		builder.SetAttempts(*input.AttemptCount)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	verification, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "Verification token already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to create verification")
	}

	return verification, nil
}

// GetByID retrieves a verification by its ID
func (r *verificationRepository) GetByID(ctx context.Context, id xid.ID) (*ent.Verification, error) {
	verification, err := r.client.Verification.
		Query().
		Where(verification.ID(id)).
		WithUser().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Verification not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get verification")
	}

	return verification, nil
}

// GetByToken retrieves a verification by its token
func (r *verificationRepository) GetByToken(ctx context.Context, token string) (*ent.Verification, error) {
	verification, err := r.client.Verification.
		Query().
		Where(verification.Token(token)).
		WithUser().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Verification token not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get verification by token")
	}

	return verification, nil
}

// Update updates a verification
func (r *verificationRepository) Update(ctx context.Context, id xid.ID, input UpdateVerificationInput) (*ent.Verification, error) {
	builder := r.client.Verification.UpdateOneID(id)

	if input.Used != nil {
		builder.SetUsed(*input.Used)
	}

	if input.UsedAt != nil {
		builder.SetUsedAt(*input.UsedAt)
	}

	if input.Attempts != nil {
		builder.SetAttempts(*input.Attempts)
	}

	if input.ExpiresAt != nil {
		builder.SetExpiresAt(*input.ExpiresAt)
	}

	if input.RedirectURL != nil {
		builder.SetRedirectURL(*input.RedirectURL)
	}

	if input.Attestation != nil {
		builder.SetAttestation(input.Attestation)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	verification, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Verification not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to update verification")
	}

	return verification, nil
}

// Delete deletes a verification
func (r *verificationRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.Verification.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Verification not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete verification")
	}

	return nil
}

// DeleteByToken deletes a verification by its token
func (r *verificationRepository) DeleteByToken(ctx context.Context, token string) error {
	_, err := r.client.Verification.
		Delete().
		Where(verification.Token(token)).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete verification by token")
	}

	return nil
}

// ListByUserID retrieves paginated verifications for a user
func (r *verificationRepository) ListByUserID(ctx context.Context, userID xid.ID, opts ListVerificationFilter) (*model.PaginatedOutput[*ent.Verification], error) {
	query := r.client.Verification.
		Query().
		Where(verification.UserID(userID)).
		WithUser()

	if opts.Before != nil {
		query = query.Where(verification.CreatedAtLT(*opts.Before))
	}

	if opts.Type != nil {
		query = query.Where(verification.Type(*opts.Type))
	}

	// Apply ordering
	query = query.Order(ent.Desc(verification.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.Verification, *ent.VerificationQuery](ctx, query, opts.PaginationParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list verifications by user ID")
	}

	return result, nil
}

// ListByType retrieves paginated verifications by type
func (r *verificationRepository) ListByType(ctx context.Context, verificationType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Verification], error) {
	query := r.client.Verification.
		Query().
		Where(verification.Type(verificationType)).
		WithUser()

	// Apply ordering
	query.Order(ent.Desc(verification.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.Verification, *ent.VerificationQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list verifications by type %s", verificationType))
	}

	return result, nil
}

// ListByEmail retrieves paginated verifications by email
func (r *verificationRepository) ListByEmail(ctx context.Context, email string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Verification], error) {
	query := r.client.Verification.
		Query().
		Where(verification.Email(email)).
		WithUser()

	// Apply ordering
	query.Order(ent.Desc(verification.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.Verification, *ent.VerificationQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list verifications by email")
	}

	return result, nil
}

// ListByPhoneNumber retrieves paginated verifications by phone number
func (r *verificationRepository) ListByPhoneNumber(ctx context.Context, phoneNumber string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Verification], error) {
	query := r.client.Verification.
		Query().
		Where(verification.PhoneNumber(phoneNumber)).
		WithUser()

	// Apply ordering
	query.Order(ent.Desc(verification.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.Verification, *ent.VerificationQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list verifications by phone number")
	}

	return result, nil
}

// MarkAsUsed marks a verification as used
func (r *verificationRepository) MarkAsUsed(ctx context.Context, id xid.ID) error {
	err := r.client.Verification.
		UpdateOneID(id).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Verification not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to mark verification as used")
	}

	return nil
}

// MarkTokenAsUsed marks a verification token as used
func (r *verificationRepository) MarkTokenAsUsed(ctx context.Context, token string) error {
	_, err := r.client.Verification.
		Update().
		Where(verification.Token(token)).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to mark verification token as used")
	}

	return nil
}

// IncrementAttempts increments the attempt count for a verification
func (r *verificationRepository) IncrementAttempts(ctx context.Context, id xid.ID) error {
	// Get current attempts count
	verification, err := r.client.Verification.
		Query().
		Where(verification.ID(id)).
		Select(verification.FieldAttempts).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Verification not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to get verification for attempt increment")
	}

	err = r.client.Verification.
		UpdateOneID(id).
		SetAttempts(verification.Attempts + 1).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to increment verification attempts")
	}

	return nil
}

// IncrementTokenAttempts increments the attempt count for a verification token
func (r *verificationRepository) IncrementTokenAttempts(ctx context.Context, token string) error {
	// Get current attempts count
	verif, err := r.client.Verification.
		Query().
		Where(verification.Token(token)).
		Select(verification.FieldAttempts).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Verification token not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to get verification token for attempt increment")
	}

	_, err = r.client.Verification.
		Update().
		Where(verification.Token(token)).
		SetAttempts(verif.Attempts + 1).
		Save(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to increment verification token attempts")
	}

	return nil
}

// IsTokenValid checks if a verification token is valid (exists, not used, not expired)
func (r *verificationRepository) IsTokenValid(ctx context.Context, token string) (bool, error) {
	count, err := r.client.Verification.
		Query().
		Where(
			verification.Token(token),
			verification.Used(false),
			verification.ExpiresAtGT(time.Now()),
		).
		Count(ctx)

	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "Failed to check token validity")
	}

	return count > 0, nil
}

// GetValidToken retrieves a valid verification token
func (r *verificationRepository) GetValidToken(ctx context.Context, token string) (*ent.Verification, error) {
	verification, err := r.client.Verification.
		Query().
		Where(
			verification.Token(token),
			verification.Used(false),
			verification.ExpiresAtGT(time.Now()),
		).
		WithUser().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Valid verification token not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get valid verification token")
	}

	return verification, nil
}

// GetValidTokenByCode retrieves a valid verification token
func (r *verificationRepository) GetValidTokenByCode(ctx context.Context, token string, verificationType string) (*ent.Verification, error) {
	ver, err := r.client.Verification.
		Query().
		Where(
			verification.Type(verificationType),
			verification.Used(false),
			verification.ExpiresAtGT(time.Now()),
		).
		Where(func(s *sql.Selector) {
			s.Where(sqljson.ValueContains(verification.FieldMetadata, token, sqljson.Path("code")))
		}).
		WithUser().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Valid verification token not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get valid verification token")
	}

	return ver, nil
}

// GetValidTokenByTypeAndUser retrieves a valid verification token by type and user
func (r *verificationRepository) GetValidTokenByTypeAndUser(ctx context.Context, verificationType string, userID xid.ID) (*ent.Verification, error) {
	verification, err := r.client.Verification.
		Query().
		Where(
			verification.Type(verificationType),
			verification.UserID(userID),
			verification.Used(false),
			verification.ExpiresAtGT(time.Now()),
		).
		WithUser().
		Order(ent.Desc(verification.FieldCreatedAt)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Valid verification token not found for user and type")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get valid verification token by type and user")
	}

	return verification, nil
}

// CleanupExpired deletes expired verifications
func (r *verificationRepository) CleanupExpired(ctx context.Context, before time.Time) (int, error) {
	count, err := r.client.Verification.
		Delete().
		Where(verification.ExpiresAtLT(before)).
		Exec(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to cleanup expired verifications")
	}

	return count, nil
}

// CleanupUsed deletes used verifications older than specified time
func (r *verificationRepository) CleanupUsed(ctx context.Context, olderThan time.Time) (int, error) {
	count, err := r.client.Verification.
		Delete().
		Where(
			verification.Used(true),
			verification.CreatedAtLT(olderThan),
		).
		Exec(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to cleanup used verifications")
	}

	return count, nil
}

// CountByUserAndType counts verifications by user and type
func (r *verificationRepository) CountByUserAndType(ctx context.Context, userID xid.ID, verificationType string) (int, error) {
	count, err := r.client.Verification.
		Query().
		Where(
			verification.UserID(userID),
			verification.Type(verificationType),
		).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count verifications by user and type")
	}

	return count, nil
}

// InvalidateUserVerifications counts verifications by user and type
func (r *verificationRepository) InvalidateUserVerifications(ctx context.Context, userID xid.ID, verificationType string) (int, error) {
	count, err := r.client.Verification.
		Update().
		Where(
			verification.UserIDEQ(userID),
			verification.TypeEQ(verificationType),
			verification.Used(false),
		).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count verifications by user and type")
	}

	return count, nil
}

// CountAttemptsByIP counts verification attempts by IP address within a time frame
func (r *verificationRepository) CountAttemptsByIP(ctx context.Context, ipAddress string, since time.Time) (int, error) {
	count, err := r.client.Verification.
		Query().
		Where(
			verification.IPAddress(ipAddress),
			verification.CreatedAtGTE(since),
		).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count verification attempts by IP")
	}

	return count, nil
}

// ListExpired retrieves expired verifications
func (r *verificationRepository) ListExpired(ctx context.Context) ([]*ent.Verification, error) {
	verifications, err := r.client.Verification.
		Query().
		Where(verification.ExpiresAtLT(time.Now())).
		WithUser().
		Order(ent.Asc(verification.FieldExpiresAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list expired verifications")
	}

	return verifications, nil
}

// ListExpiringBefore retrieves verifications expiring before a given time
func (r *verificationRepository) ListExpiringBefore(ctx context.Context, before time.Time, limit int) ([]*ent.Verification, error) {
	verifications, err := r.client.Verification.
		Query().
		Where(
			verification.ExpiresAtLT(before),
			verification.ExpiresAtGT(time.Now()), // Not already expired
			verification.Used(false),             // Not used
		).
		WithUser().
		Order(ent.Asc(verification.FieldExpiresAt)).
		Limit(limit).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list expiring verifications")
	}

	return verifications, nil
}

// ListRecentByUser retrieves recent verifications for a user
func (r *verificationRepository) ListRecentByUser(ctx context.Context, userID xid.ID, limit int) ([]*ent.Verification, error) {
	verifications, err := r.client.Verification.
		Query().
		Where(verification.UserID(userID)).
		WithUser().
		Order(ent.Desc(verification.FieldCreatedAt)).
		Limit(limit).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list recent verifications by user")
	}

	return verifications, nil
}

// ListSuspiciousAttempts retrieves verifications with suspicious attempt patterns
func (r *verificationRepository) ListSuspiciousAttempts(ctx context.Context, maxAttempts int, since time.Time) ([]*ent.Verification, error) {
	verifications, err := r.client.Verification.
		Query().
		Where(
			verification.AttemptsGTE(maxAttempts),
			verification.CreatedAtGTE(since),
		).
		WithUser().
		Order(ent.Desc(verification.FieldAttempts)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list suspicious verification attempts")
	}

	return verifications, nil
}

// GetVerificationStats retrieves verification statistics
func (r *verificationRepository) GetVerificationStats(ctx context.Context, since time.Time) (*VerificationStats, error) {
	stats := &VerificationStats{}

	// Count total verifications
	totalVerifications, err := r.client.Verification.
		Query().
		Where(verification.CreatedAtGTE(since)).
		Count(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count total verifications for stats")
	}

	// Count successful verifications
	successfulVerifications, err := r.client.Verification.
		Query().
		Where(
			verification.CreatedAtGTE(since),
			verification.Used(true),
		).
		Count(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count successful verifications for stats")
	}

	// Count expired verifications
	expiredVerifications, err := r.client.Verification.
		Query().
		Where(
			verification.CreatedAtGTE(since),
			verification.ExpiresAtLT(time.Now()),
			verification.Used(false),
		).
		Count(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count expired verifications for stats")
	}

	stats.TotalVerifications = totalVerifications
	stats.SuccessfulVerifications = successfulVerifications
	stats.ExpiredVerifications = expiredVerifications

	if totalVerifications > 0 {
		stats.SuccessRate = float64(successfulVerifications) / float64(totalVerifications) * 100
	}

	// TODO: Implement additional statistics
	// - TypeBreakdown
	// - AverageAttempts
	// - TopIPAddresses

	return stats, nil
}

// ListHighVolumeIPs retrieves IP addresses with high verification volume
func (r *verificationRepository) ListHighVolumeIPs(ctx context.Context, minCount int, since time.Time) ([]IPVerificationActivity, error) {
	// This would require a more complex aggregation query
	// Implementation depends on your database capabilities

	// For now, return empty slice - implement based on your needs
	return []IPVerificationActivity{}, nil
}

// // GetValidTokenByCode retrieves a valid verification record by code stored in metadata
// func (r *verificationRepository) GetValidTokenByCode(ctx context.Context, code string, verificationType string) (*ent.Verification, error) {
// 	return r.client.Verification.
// 		Query().
// 		Where(
// 			verification.TypeEQ(verificationType),
// 			verification.Used(false),
// 			verification.ExpiresAtGT(time.Now()),
// 		).
// 		Where(func(s *sql.Selector) {
// 			// Query JSON metadata for the code
// 			s.Where(sql.Contains(s.C(verification.FieldMetadata), fmt.Sprintf(`"code":"%s"`, code)))
// 		}).
// 		First(ctx)
// }

// GetRecentVerifications gets recent verification attempts for rate limiting
func (r *verificationRepository) GetRecentVerifications(ctx context.Context, userID xid.ID, verificationType string, since time.Time) ([]*ent.Verification, error) {
	return r.client.Verification.
		Query().
		Where(
			verification.UserIDEQ(userID),
			verification.TypeEQ(verificationType),
			verification.CreatedAtGTE(since),
		).
		Order(ent.Desc(verification.FieldCreatedAt)).
		All(ctx)
}

// MarkTokenAsUsedByCode marks a verification as used by code
func (r *verificationRepository) MarkTokenAsUsedByCode(ctx context.Context, code string, verificationType string) error {
	verification, err := r.GetValidTokenByCode(ctx, code, verificationType)
	if err != nil {
		return err
	}

	return r.MarkTokenAsUsed(ctx, verification.Token)
}
