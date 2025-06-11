package apikeys

import (
	"context"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/apikey"
	"github.com/juicycleff/frank/ent/predicate"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/utils"
)

// Repository provides access to API key storage
type Repository interface {
	// Create creates a new API key
	Create(ctx context.Context, input RepositoryCreateInput) (*ent.ApiKey, error)

	// GetByID retrieves an API key by ID
	GetByID(ctx context.Context, id string) (*ent.ApiKey, error)

	// GetByHashedKey retrieves an API key by hashed key
	GetByHashedKey(ctx context.Context, hashedKey string) (*ent.ApiKey, error)

	// List retrieves API keys with pagination
	List(ctx context.Context, input RepositoryListInput) ([]*ent.ApiKey, int, error)

	// Update updates an API key
	Update(ctx context.Context, id string, input RepositoryUpdateInput) (*ent.ApiKey, error)

	// Delete deletes an API key
	Delete(ctx context.Context, id string) error
}

// RepositoryCreateInput represents input for creating an API key
type RepositoryCreateInput struct {
	Name           string
	Key            string
	HashedKey      string
	Type           string
	UserID         string
	OrganizationID string
	Permissions    []string
	Scopes         []string
	Metadata       map[string]interface{}
	ExpiresAt      *time.Time
}

// RepositoryUpdateInput represents input for updating an API key
type RepositoryUpdateInput struct {
	Name        *string
	Active      *bool
	Permissions []string
	Scopes      []string
	Metadata    map[string]interface{}
	ExpiresAt   *time.Time
	LastUsed    *time.Time
}

// RepositoryListInput represents input for listing API keys
type RepositoryListInput struct {
	Offset         int
	Limit          int
	UserID         string
	OrganizationID string
	Type           string
}

type repository struct {
	client *ent.Client
}

// NewRepository creates a new API key repository
func NewRepository(client *ent.Client) Repository {
	return &repository{
		client: client,
	}
}

// Create creates a new API key
func (r *repository) Create(ctx context.Context, input RepositoryCreateInput) (*ent.ApiKey, error) {
	// Generate UUID
	id := utils.NewID()

	// Build API key creation query
	create := r.client.ApiKey.
		Create().
		SetID(id).
		SetName(input.Name).
		SetKey(input.Key).
		SetHashedKey(input.HashedKey).
		SetType(input.Type)

	// Set optional fields
	if input.UserID != "" {
		create = create.SetUserID(input.UserID)
	}

	if input.OrganizationID != "" {
		create = create.SetOrganizationID(input.OrganizationID)
	}

	if len(input.Permissions) > 0 {
		create = create.SetPermissions(input.Permissions)
	}

	if len(input.Scopes) > 0 {
		create = create.SetScopes(input.Scopes)
	}

	if input.Metadata != nil {
		create = create.SetMetadata(input.Metadata)
	}

	if input.ExpiresAt != nil {
		create = create.SetExpiresAt(*input.ExpiresAt)
	}

	// Create API key
	apiKey, err := create.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create API key")
	}

	return apiKey, nil
}

// GetByID retrieves an API key by ID
func (r *repository) GetByID(ctx context.Context, id string) (*ent.ApiKey, error) {
	apiKey, err := r.client.ApiKey.
		Query().
		Where(apikey.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "API key not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get API key")
	}

	return apiKey, nil
}

// GetByHashedKey retrieves an API key by hashed key
func (r *repository) GetByHashedKey(ctx context.Context, hashedKey string) (*ent.ApiKey, error) {
	apiKey, err := r.client.ApiKey.
		Query().
		Where(apikey.HashedKey(hashedKey)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeInvalidAPIKey, "invalid API key")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get API key by hash")
	}

	return apiKey, nil
}

// List retrieves API keys with pagination
func (r *repository) List(ctx context.Context, input RepositoryListInput) ([]*ent.ApiKey, int, error) {
	// Build query predicates
	var predicates []predicate.ApiKey

	if input.UserID != "" {
		predicates = append(predicates, apikey.UserID(input.UserID))
	}

	if input.OrganizationID != "" {
		predicates = append(predicates, apikey.OrganizationID(input.OrganizationID))
	}

	if input.Type != "" {
		predicates = append(predicates, apikey.Type(input.Type))
	}

	// Create query with predicates
	query := r.client.ApiKey.Query()
	if len(predicates) > 0 {
		query = query.Where(apikey.And(predicates...))
	}

	// Count total results
	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count API keys")
	}

	// Apply pagination
	apiKeys, err := query.
		Limit(input.Limit).
		Offset(input.Offset).
		Order(ent.Desc(apikey.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list API keys")
	}

	return apiKeys, total, nil
}

// Update updates an API key
func (r *repository) Update(ctx context.Context, id string, input RepositoryUpdateInput) (*ent.ApiKey, error) {
	// Check if API key exists
	exists, err := r.client.ApiKey.
		Query().
		Where(apikey.ID(id)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check API key existence")
	}

	if !exists {
		return nil, errors.New(errors.CodeNotFound, "API key not found")
	}

	// Build update query
	update := r.client.ApiKey.
		UpdateOneID(id)

	// Apply updates
	if input.Name != nil {
		update = update.SetName(*input.Name)
	}

	if input.Active != nil {
		update = update.SetActive(*input.Active)
	}

	if input.Permissions != nil {
		update = update.SetPermissions(input.Permissions)
	}

	if input.Scopes != nil {
		update = update.SetScopes(input.Scopes)
	}

	if input.Metadata != nil {
		update = update.SetMetadata(input.Metadata)
	}

	if input.ExpiresAt != nil {
		update = update.SetExpiresAt(*input.ExpiresAt)
	}

	if input.LastUsed != nil {
		update = update.SetLastUsed(*input.LastUsed)
	}

	// Execute update
	apiKey, err := update.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update API key")
	}

	return apiKey, nil
}

// Delete deletes an API key
func (r *repository) Delete(ctx context.Context, id string) error {
	// Check if API key exists
	exists, err := r.client.ApiKey.
		Query().
		Where(apikey.ID(id)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to check API key existence")
	}

	if !exists {
		return errors.New(errors.CodeNotFound, "API key not found")
	}

	// Delete API key
	err = r.client.ApiKey.
		DeleteOneID(id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete API key")
	}

	return nil
}
