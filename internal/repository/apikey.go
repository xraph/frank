package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/apikey"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// ApiKeyRepository defines the interface for API key data operations
type ApiKeyRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateApiKeyInput) (*ent.ApiKey, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.ApiKey, error)
	GetByHashedKey(ctx context.Context, hashedKey string) (*ent.ApiKey, error)
	Update(ctx context.Context, id xid.ID, input UpdateApiKeyInput) (*ent.ApiKey, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	List(ctx context.Context, opts ListAPIKeyParams) (*model.PaginatedOutput[*ent.ApiKey], error)
	ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.ApiKey], error)
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.ApiKey], error)
	ListActiveByUserID(ctx context.Context, userID xid.ID) ([]*ent.ApiKey, error)
	ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.ApiKey, error)

	// Utility operations
	UpdateLastUsed(ctx context.Context, id xid.ID) error
	DeactivateByUserID(ctx context.Context, userID xid.ID) error
	DeactivateByOrganizationID(ctx context.Context, orgID xid.ID) error
	CountByUserID(ctx context.Context, userID xid.ID) (int, error)
	CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)

	// Advanced queries
	ListExpired(ctx context.Context, before time.Time) ([]*ent.ApiKey, error)
	ListByType(ctx context.Context, keyType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.ApiKey], error)
	GetActiveByHashedKey(ctx context.Context, hashedKey string) (*ent.ApiKey, error)

	SetActive(ctx context.Context, id xid.ID, active bool) error
	RotateKey(ctx context.Context, oldKeyID xid.ID, newKey *model.APIKey) error
}

// apiKeyRepository implements ApiKeyRepository interface
type apiKeyRepository struct {
	client *ent.Client
}

// NewApiKeyRepository creates a new API key repository
func NewApiKeyRepository(client *ent.Client) ApiKeyRepository {
	return &apiKeyRepository{
		client: client,
	}
}

// CreateApiKeyInput defines the input for creating an API key
type CreateApiKeyInput struct {
	Name           string                  `json:"name"`
	Key            string                  `json:"key"`
	HashedKey      string                  `json:"hashed_key"`
	UserID         xid.ID                  `json:"user_id,omitempty"`
	OrganizationID xid.ID                  `json:"organization_id,omitempty"`
	Type           string                  `json:"type"`
	Active         bool                    `json:"active"`
	Permissions    []string                `json:"permissions,omitempty"`
	Scopes         []string                `json:"scopes,omitempty"`
	Metadata       map[string]any          `json:"metadata,omitempty"`
	ExpiresAt      *time.Time              `json:"expires_at,omitempty"`
	IPWhitelist    []string                `json:"ipWhitelist,omitempty"`
	RateLimits     *model.APIKeyRateLimits `json:"rateLimits,omitempty" doc:"Rate limits"`
}

// UpdateApiKeyInput defines the input for updating an API key
type UpdateApiKeyInput struct {
	Name        *string                 `json:"name,omitempty"`
	Active      *bool                   `json:"active,omitempty"`
	Permissions []string                `json:"permissions,omitempty"`
	Scopes      []string                `json:"scopes,omitempty"`
	Metadata    map[string]any          `json:"metadata,omitempty"`
	LastUsed    *time.Time              `json:"last_used,omitempty"`
	ExpiresAt   *time.Time              `json:"expires_at,omitempty"`
	IPWhitelist *[]string               `json:"ipWhitelist,omitempty"`
	RateLimits  *model.APIKeyRateLimits `json:"rateLimits,omitempty" doc:"Rate limits"`
}

type ListAPIKeyParams struct {
	model.PaginationParams
	UserID         *xid.ID
	OrganizationID *xid.ID
	IncludeUsage   bool
	Type           string
	Active         *bool
	Name           string
	Search         string
	Used           *bool
	Scopes         []string
	Permission     string
}

// Create creates a new API key
func (r *apiKeyRepository) Create(ctx context.Context, input CreateApiKeyInput) (*ent.ApiKey, error) {
	builder := r.client.ApiKey.Create().
		SetName(input.Name).
		SetKey(input.Key).
		SetHashedKey(input.HashedKey).
		SetType(input.Type).
		SetActive(input.Active).
		SetIPWhitelist(input.IPWhitelist).
		SetNillableRateLimits(input.RateLimits)

	if !input.UserID.IsNil() {
		builder.SetUserID(input.UserID)
	}

	if !input.OrganizationID.IsNil() {
		builder.SetOrganizationID(input.OrganizationID)
	}

	if input.Permissions != nil {
		builder.SetPermissions(input.Permissions)
	}

	if input.Scopes != nil {
		builder.SetScopes(input.Scopes)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	if input.ExpiresAt != nil {
		builder.SetExpiresAt(*input.ExpiresAt)
	}

	apiKey, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "API key with this hashed key already exists")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create API key")
	}

	return apiKey, nil
}

// GetByID retrieves an API key by its ID
func (r *apiKeyRepository) GetByID(ctx context.Context, id xid.ID) (*ent.ApiKey, error) {
	apiKey, err := r.client.ApiKey.
		Query().
		Where(apikey.ID(id)).
		WithUser().
		WithOrganization().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "API key not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get API key")
	}

	return apiKey, nil
}

// GetByHashedKey retrieves an API key by its hashed key
func (r *apiKeyRepository) GetByHashedKey(ctx context.Context, hashedKey string) (*ent.ApiKey, error) {
	apiKey, err := r.client.ApiKey.
		Query().
		Where(apikey.HashedKey(hashedKey)).
		WithUser().
		WithOrganization().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "API key not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get API key by hashed key")
	}

	return apiKey, nil
}

// Update updates an API key
func (r *apiKeyRepository) Update(ctx context.Context, id xid.ID, input UpdateApiKeyInput) (*ent.ApiKey, error) {
	builder := r.client.ApiKey.UpdateOneID(id)

	if input.Name != nil {
		builder.SetName(*input.Name)
	}

	if input.Active != nil {
		builder.SetActive(*input.Active)
	}

	if input.Permissions != nil {
		builder.SetPermissions(input.Permissions)
	}

	if input.Scopes != nil {
		builder.SetScopes(input.Scopes)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	if input.LastUsed != nil {
		builder.SetLastUsed(*input.LastUsed)
	}

	if input.ExpiresAt != nil {
		builder.SetExpiresAt(*input.ExpiresAt)
	}

	if input.IPWhitelist != nil {
		builder.SetIPWhitelist(*input.IPWhitelist)
	}

	if input.RateLimits != nil {
		builder.SetRateLimits(*input.RateLimits)
	}

	if input.ExpiresAt != nil {
		builder.SetExpiresAt(*input.ExpiresAt)
	}

	apiKey, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "API key not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update API key")
	}

	return apiKey, nil
}

// Delete deletes an API key
func (r *apiKeyRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.ApiKey.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "API key not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to delete API key")
	}

	return nil
}

func (r *apiKeyRepository) List(ctx context.Context, opts ListAPIKeyParams) (*model.PaginatedOutput[*ent.ApiKey], error) {
	query := r.client.ApiKey.
		Query().
		WithUser().
		WithOrganization()

	if opts.OrderBy == nil || len(opts.OrderBy) == 0 {
		query = query.Order(ent.Desc(apikey.FieldCreatedAt))

	}

	if opts.UserID != nil {
		query = query.Where(apikey.UserID(*opts.UserID))
	}

	if opts.OrganizationID != nil {
		query = query.Where(apikey.OrganizationID(*opts.OrganizationID))
	}

	if opts.Type != "" {
		query = query.Where(apikey.Type(opts.Type))
	}

	if opts.Active != nil {
		query = query.Where(apikey.Active(*opts.Active))
	}

	if opts.Name != "" {
		query = query.Where(apikey.Name(opts.Name))
	}

	if opts.Search != "" {
		query = query.Where(apikey.NameContainsFold(opts.Search))
	}

	if opts.Used != nil {
		query = query.Where(apikey.LastUsedIsNil())
	}

	result, err := model.WithPaginationAndOptions[*ent.ApiKey, *ent.ApiKeyQuery](ctx, query, opts.PaginationParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list API keys by user ID")
	}

	return result, nil
}

// ListByUserID retrieves paginated API keys for a user
func (r *apiKeyRepository) ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.ApiKey], error) {
	query := r.client.ApiKey.
		Query().
		Where(apikey.UserID(userID)).
		WithUser().
		WithOrganization()

	// Apply ordering
	query.Order(ent.Desc(apikey.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.ApiKey, *ent.ApiKeyQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list API keys by user ID")
	}

	return result, nil
}

// ListByOrganizationID retrieves paginated API keys for an organization
func (r *apiKeyRepository) ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.ApiKey], error) {
	query := r.client.ApiKey.
		Query().
		Where(apikey.OrganizationID(orgID)).
		WithUser().
		WithOrganization()

	// Apply ordering
	query.Order(ent.Desc(apikey.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.ApiKey, *ent.ApiKeyQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list API keys by organization ID")
	}

	return result, nil
}

// ListActiveByUserID retrieves all active API keys for a user
func (r *apiKeyRepository) ListActiveByUserID(ctx context.Context, userID xid.ID) ([]*ent.ApiKey, error) {
	apiKeys, err := r.client.ApiKey.
		Query().
		Where(
			apikey.UserID(userID),
			apikey.Active(true),
			apikey.Or(
				apikey.ExpiresAtIsNil(),
				apikey.ExpiresAtGT(time.Now()),
			),
		).
		WithUser().
		WithOrganization().
		Order(ent.Desc(apikey.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list active API keys by user ID")
	}

	return apiKeys, nil
}

// ListActiveByOrganizationID retrieves all active API keys for an organization
func (r *apiKeyRepository) ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.ApiKey, error) {
	apiKeys, err := r.client.ApiKey.
		Query().
		Where(
			apikey.OrganizationID(orgID),
			apikey.Active(true),
			apikey.Or(
				apikey.ExpiresAtIsNil(),
				apikey.ExpiresAtGT(time.Now()),
			),
		).
		WithUser().
		WithOrganization().
		Order(ent.Desc(apikey.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list active API keys by organization ID")
	}

	return apiKeys, nil
}

// UpdateLastUsed updates the last used timestamp for an API key
func (r *apiKeyRepository) UpdateLastUsed(ctx context.Context, id xid.ID) error {
	err := r.client.ApiKey.
		UpdateOneID(id).
		SetLastUsed(time.Now()).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "API key not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to update last used timestamp")
	}

	return nil
}

// DeactivateByUserID deactivates all API keys for a user
func (r *apiKeyRepository) DeactivateByUserID(ctx context.Context, userID xid.ID) error {
	_, err := r.client.ApiKey.
		Update().
		Where(apikey.UserID(userID)).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to deactivate API keys for user")
	}

	return nil
}

// DeactivateByOrganizationID deactivates all API keys for an organization
func (r *apiKeyRepository) DeactivateByOrganizationID(ctx context.Context, orgID xid.ID) error {
	_, err := r.client.ApiKey.
		Update().
		Where(apikey.OrganizationID(orgID)).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to deactivate API keys for organization")
	}

	return nil
}

// CountByUserID counts the number of API keys for a user
func (r *apiKeyRepository) CountByUserID(ctx context.Context, userID xid.ID) (int, error) {
	count, err := r.client.ApiKey.
		Query().
		Where(apikey.UserID(userID)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to count API keys by user ID")
	}

	return count, nil
}

// CountByOrganizationID counts the number of API keys for an organization
func (r *apiKeyRepository) CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error) {
	count, err := r.client.ApiKey.
		Query().
		Where(apikey.OrganizationID(orgID)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to count API keys by organization ID")
	}

	return count, nil
}

// ListExpired retrieves API keys that have expired before the given time
func (r *apiKeyRepository) ListExpired(ctx context.Context, before time.Time) ([]*ent.ApiKey, error) {
	apiKeys, err := r.client.ApiKey.
		Query().
		Where(
			apikey.ExpiresAtNotNil(),
			apikey.ExpiresAtLT(before),
			apikey.Active(true),
		).
		WithUser().
		WithOrganization().
		Order(ent.Asc(apikey.FieldExpiresAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list expired API keys")
	}

	return apiKeys, nil
}

// ListByType retrieves paginated API keys by type
func (r *apiKeyRepository) ListByType(ctx context.Context, keyType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.ApiKey], error) {
	query := r.client.ApiKey.
		Query().
		Where(apikey.Type(keyType)).
		WithUser().
		WithOrganization()

	// Apply ordering
	query.Order(ent.Desc(apikey.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.ApiKey, *ent.ApiKeyQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, fmt.Sprintf("Failed to list API keys by type %s", keyType))
	}

	return result, nil
}

// GetActiveByHashedKey retrieves an active API key by its hashed key
func (r *apiKeyRepository) GetActiveByHashedKey(ctx context.Context, hashedKey string) (*ent.ApiKey, error) {
	apiKey, err := r.client.ApiKey.
		Query().
		Where(
			apikey.HashedKey(hashedKey),
			apikey.Active(true),
			apikey.Or(
				apikey.ExpiresAtIsNil(),
				apikey.ExpiresAtGT(time.Now()),
			),
		).
		WithUser().
		WithOrganization().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Active API key not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get active API key by hashed key")
	}

	return apiKey, nil
}

// Extended implementation with missing methods
func (r *apiKeyRepository) SetActive(ctx context.Context, id xid.ID, active bool) error {
	err := r.client.ApiKey.
		UpdateOneID(id).
		SetActive(active).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "API key not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to update API key active status")
	}

	return nil
}

// RotateKey creates a new API key and deactivates the old one in a transaction
func (r *apiKeyRepository) RotateKey(ctx context.Context, oldKeyID xid.ID, newKey *model.APIKey) error {
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to start transaction")
	}

	// Create new API key
	createInput := CreateApiKeyInput{
		Name:           newKey.Name,
		Key:            newKey.Key,
		HashedKey:      newKey.HashedKey,
		UserID:         newKey.UserID,
		OrganizationID: newKey.OrganizationID,
		Type:           newKey.Type,
		Active:         newKey.Active,
		Permissions:    newKey.Permissions,
		Scopes:         newKey.Scopes,
		Metadata:       newKey.Metadata,
		ExpiresAt:      newKey.ExpiresAt,
		IPWhitelist:    newKey.IPWhitelist,
		RateLimits:     newKey.RateLimits,
	}

	_, err = tx.ApiKey.Create().
		SetID(newKey.ID).
		SetName(createInput.Name).
		SetKey(createInput.Key).
		SetHashedKey(createInput.HashedKey).
		SetType(createInput.Type).
		SetActive(createInput.Active).
		SetIPWhitelist(createInput.IPWhitelist).
		SetNillableRateLimits(createInput.RateLimits).
		SetUserID(createInput.UserID).
		SetOrganizationID(createInput.OrganizationID).
		SetPermissions(createInput.Permissions).
		SetScopes(createInput.Scopes).
		SetMetadata(createInput.Metadata).
		SetNillableExpiresAt(createInput.ExpiresAt).
		Save(ctx)

	if err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to create new API key")
	}

	// Deactivate old API key
	err = tx.ApiKey.
		UpdateOneID(oldKeyID).
		SetActive(false).
		Exec(ctx)

	if err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to deactivate old API key")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to commit rotation transaction")
	}

	return nil
}
