package repository

import (
	"context"
	"database/sql"
	errors2 "errors"
	"time"

	"github.com/lib/pq"
	"github.com/rs/xid"
	"github.com/uptrace/bun"
	"github.com/xraph/frank/internal/models"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/model"
)

type ApiKeyRepository interface {
	Create(ctx context.Context, input CreateApiKeyInput) (*models.APIKey, error)
	GetByID(ctx context.Context, id xid.ID) (*models.APIKey, error)
	GetByPublicKey(ctx context.Context, publicKey string) (*models.APIKey, error)
	GetByHashedSecretKey(ctx context.Context, hashedSecretKey string) (*models.APIKey, error)
	GetActiveByHashedSecretKey(ctx context.Context, hashedSecretKey string) (*models.APIKey, error)
	Update(ctx context.Context, id xid.ID, input UpdateApiKeyInput) (*models.APIKey, error)
	Delete(ctx context.Context, id xid.ID) error

	List(ctx context.Context, opts ListAPIKeyParams) (*model.PaginatedOutput[*models.APIKey], error)
	ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*models.APIKey], error)
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*models.APIKey], error)
	ListActiveByUserID(ctx context.Context, userID xid.ID) ([]*models.APIKey, error)

	UpdateLastUsed(ctx context.Context, id xid.ID) error
	DeactivateByUserID(ctx context.Context, userID xid.ID) error
	CountByUserID(ctx context.Context, userID xid.ID) (int, error)
}

type apiKeyRepository struct {
	db *bun.DB
}

func NewApiKeyRepository(db *bun.DB) ApiKeyRepository {
	return &apiKeyRepository{db: db}
}

type CreateApiKeyInput struct {
	Name            string
	PublicKey       string
	SecretKey       string
	HashedSecretKey string
	UserID          xid.ID
	OrganizationID  xid.ID
	Type            model.APIKeyType
	Environment     model.Environment
	Active          bool
	Permissions     []string
	Scopes          []string
	Metadata        map[string]any
	ExpiresAt       *time.Time
	IPWhitelist     []string
	RateLimits      *model.APIKeyRateLimits
}

type UpdateApiKeyInput struct {
	Name        *string
	Active      *bool
	Permissions []string
	Scopes      []string
	Metadata    map[string]any
	LastUsed    *time.Time
	ExpiresAt   *time.Time
	IPWhitelist *[]string
	RateLimits  *model.APIKeyRateLimits
}

type ListAPIKeyParams struct {
	model.PaginationParams
	UserID         *xid.ID
	OrganizationID *xid.ID
	Type           model.APIKeyType
	Environment    model.Environment
	Active         *bool
	Search         string
}

func (r *apiKeyRepository) Create(ctx context.Context, input CreateApiKeyInput) (*models.APIKey, error) {
	apiKey := &models.APIKey{
		CommonModel: models.CommonModel{
			ID: xid.New().String(),
		},
		Name:            input.Name,
		PublicKey:       input.PublicKey,
		SecretKey:       input.SecretKey,
		HashedSecretKey: input.HashedSecretKey,
		Type:            input.Type,
		Environment:     input.Environment,
		Active:          input.Active,
		IPWhitelist:     input.IPWhitelist,
	}

	if !input.UserID.IsNil() {
		userID := input.UserID.String()
		apiKey.UserID = &userID
	}

	if !input.OrganizationID.IsNil() {
		orgID := input.OrganizationID.String()
		apiKey.OrganizationID = &orgID
	}

	if input.Permissions != nil {
		apiKey.Permissions = input.Permissions
	}
	if input.Scopes != nil {
		apiKey.Scopes = input.Scopes
	}
	if input.Metadata != nil {
		apiKey.Metadata = input.Metadata
	}
	if input.ExpiresAt != nil {
		apiKey.ExpiresAt = input.ExpiresAt
	}
	if input.RateLimits != nil {
		// Convert RateLimits to map
		apiKey.RateLimits = map[string]interface{}{
			"requests_per_second": input.RateLimits,
		}
	}

	_, err := r.db.NewInsert().
		Model(apiKey).
		Exec(ctx)

	if err != nil {
		// Check for unique constraint violation
		if errors2.Is(err, &pq.Error{Code: "23505"}) {
			return nil, errors.New(errors.CodeConflict, "API key with this public key or secret key already exists")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create API key")
	}

	return apiKey, nil
}

func (r *apiKeyRepository) GetByID(ctx context.Context, id xid.ID) (*models.APIKey, error) {
	var apiKey models.APIKey

	err := r.db.NewSelect().
		Model(&apiKey).
		Where("id = ?", id.String()).
		Relation("User").
		Relation("Organization").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "API key not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get API key")
	}

	return &apiKey, nil
}

func (r *apiKeyRepository) GetByPublicKey(ctx context.Context, publicKey string) (*models.APIKey, error) {
	var apiKey models.APIKey

	err := r.db.NewSelect().
		Model(&apiKey).
		Where("public_key = ?", publicKey).
		Relation("User").
		Relation("Organization").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "API key not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get API key by public key")
	}

	return &apiKey, nil
}

func (r *apiKeyRepository) GetByHashedSecretKey(ctx context.Context, hashedSecretKey string) (*models.APIKey, error) {
	var apiKey models.APIKey

	err := r.db.NewSelect().
		Model(&apiKey).
		Where("hashed_secret_key = ?", hashedSecretKey).
		Relation("User").
		Relation("Organization").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "API key not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get API key by hashed secret key")
	}

	return &apiKey, nil
}

func (r *apiKeyRepository) GetActiveByHashedSecretKey(ctx context.Context, hashedSecretKey string) (*models.APIKey, error) {
	var apiKey models.APIKey

	err := r.db.NewSelect().
		Model(&apiKey).
		Where("hashed_secret_key = ?", hashedSecretKey).
		Where("active = ?", true).
		Where("deleted_at IS NULL").
		Where("(expires_at IS NULL OR expires_at > ?)", time.Now()).
		Relation("User").
		Relation("Organization").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "Active API key not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get active API key")
	}

	return &apiKey, nil
}

func (r *apiKeyRepository) Update(ctx context.Context, id xid.ID, input UpdateApiKeyInput) (*models.APIKey, error) {
	update := r.db.NewUpdate().
		Model((*models.APIKey)(nil)).
		Where("id = ?", id.String())

	if input.Name != nil {
		update = update.Set("name = ?", *input.Name)
	}
	if input.Active != nil {
		update = update.Set("active = ?", *input.Active)
	}
	if input.Permissions != nil {
		update = update.Set("permissions = ?", input.Permissions)
	}
	if input.Scopes != nil {
		update = update.Set("scopes = ?", input.Scopes)
	}
	if input.Metadata != nil {
		update = update.Set("metadata = ?", input.Metadata)
	}
	if input.LastUsed != nil {
		update = update.Set("last_used = ?", *input.LastUsed)
	}
	if input.ExpiresAt != nil {
		update = update.Set("expires_at = ?", *input.ExpiresAt)
	}
	if input.IPWhitelist != nil {
		update = update.Set("ip_whitelist = ?", *input.IPWhitelist)
	}

	result, err := update.Exec(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update API key")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, errors.New(errors.CodeNotFound, "API key not found")
	}

	return r.GetByID(ctx, id)
}

func (r *apiKeyRepository) Delete(ctx context.Context, id xid.ID) error {
	result, err := r.db.NewDelete().
		Model((*models.APIKey)(nil)).
		Where("id = ?", id.String()).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to delete API key")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New(errors.CodeNotFound, "API key not found")
	}

	return nil
}

func (r *apiKeyRepository) List(ctx context.Context, opts ListAPIKeyParams) (*model.PaginatedOutput[*models.APIKey], error) {
	query := r.db.NewSelect().
		Model((*models.APIKey)(nil)).
		Relation("User").
		Relation("Organization").
		Where("deleted_at IS NULL")

	// Apply filters
	if opts.UserID != nil {
		query = query.Where("user_id = ?", opts.UserID.String())
	}
	if opts.OrganizationID != nil {
		query = query.Where("organization_id = ?", opts.OrganizationID.String())
	}
	if opts.Type != "" {
		query = query.Where("type = ?", opts.Type)
	}
	if opts.Environment != "" {
		query = query.Where("environment = ?", opts.Environment)
	}
	if opts.Active != nil {
		query = query.Where("active = ?", *opts.Active)
	}
	if opts.Search != "" {
		query = query.Where("name ILIKE ?", "%"+opts.Search+"%")
	}

	// Count total
	total, err := query.Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to count API keys")
	}

	// Apply pagination
	limit := opts.Limit
	if limit == 0 {
		limit = 20
	}
	query = query.Limit(limit).Offset(opts.Offset)

	// Apply ordering
	query = query.Order("created_at DESC")

	var apiKeys []*models.APIKey
	err = query.Scan(ctx, &apiKeys)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list API keys")
	}

	return &model.PaginatedOutput[*models.APIKey]{
		Data: apiKeys,
		Pagination: &model.Pagination{
			TotalCount: total,
			Limit:      limit,
			Offset:     opts.Offset,
		},
	}, nil
}

func (r *apiKeyRepository) ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*models.APIKey], error) {
	query := r.db.NewSelect().
		Model((*models.APIKey)(nil)).
		Where("user_id = ?", userID.String()).
		Where("deleted_at IS NULL").
		Relation("User").
		Relation("Organization")

	// Count total
	total, err := query.Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to count API keys")
	}

	// Apply pagination
	limit := opts.Limit
	if limit == 0 {
		limit = 20
	}
	query = query.Limit(limit).Offset(opts.Offset).Order("created_at DESC")

	var apiKeys []*models.APIKey
	err = query.Scan(ctx, &apiKeys)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list API keys by user ID")
	}

	return &model.PaginatedOutput[*models.APIKey]{
		Data: apiKeys,
		Pagination: &model.Pagination{
			TotalCount: total,
			Limit:      limit,
			Offset:     opts.Offset,
		},
	}, nil
}

func (r *apiKeyRepository) ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*models.APIKey], error) {
	query := r.db.NewSelect().
		Model((*models.APIKey)(nil)).
		Where("organization_id = ?", orgID.String()).
		Where("deleted_at IS NULL").
		Relation("User").
		Relation("Organization")

	// Count total
	total, err := query.Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to count API keys")
	}

	// Apply pagination
	limit := opts.Limit
	if limit == 0 {
		limit = 20
	}
	query = query.Limit(limit).Offset(opts.Offset).Order("created_at DESC")

	var apiKeys []*models.APIKey
	err = query.Scan(ctx, &apiKeys)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list API keys by organization ID")
	}

	return &model.PaginatedOutput[*models.APIKey]{
		Data: apiKeys,
		Pagination: &model.Pagination{
			TotalCount: total,
			Limit:      limit,
			Offset:     opts.Offset,
		},
	}, nil
}

func (r *apiKeyRepository) ListActiveByUserID(ctx context.Context, userID xid.ID) ([]*models.APIKey, error) {
	var apiKeys []*models.APIKey

	err := r.db.NewSelect().
		Model(&apiKeys).
		Where("user_id = ?", userID.String()).
		Where("active = ?", true).
		Where("deleted_at IS NULL").
		Where("(expires_at IS NULL OR expires_at > ?)", time.Now()).
		Relation("User").
		Relation("Organization").
		Order("created_at DESC").
		Scan(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list active API keys by user ID")
	}

	return apiKeys, nil
}

func (r *apiKeyRepository) UpdateLastUsed(ctx context.Context, id xid.ID) error {
	_, err := r.db.NewUpdate().
		Model((*models.APIKey)(nil)).
		Set("last_used = ?", time.Now()).
		Where("id = ?", id.String()).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to update last used timestamp")
	}

	return nil
}

func (r *apiKeyRepository) DeactivateByUserID(ctx context.Context, userID xid.ID) error {
	_, err := r.db.NewUpdate().
		Model((*models.APIKey)(nil)).
		Set("active = ?", false).
		Where("user_id = ?", userID.String()).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to deactivate API keys for user")
	}

	return nil
}

func (r *apiKeyRepository) CountByUserID(ctx context.Context, userID xid.ID) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.APIKey)(nil)).
		Where("user_id = ?", userID.String()).
		Where("deleted_at IS NULL").
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to count API keys by user ID")
	}

	return count, nil
}
