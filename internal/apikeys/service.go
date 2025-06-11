package apikeys

import (
	"context"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/cryptoold"
	"github.com/juicycleff/frank/pkg/errors"
)

// Service provides API key operations
type Service interface {
	// Create creates a new API key
	Create(ctx context.Context, input CreateAPIKeyRequest) (*APIKeyWithKeyResponse, error)

	// Get retrieves an API key by ID
	Get(ctx context.Context, id string) (*ent.ApiKey, error)

	// List retrieves API keys with pagination
	List(ctx context.Context, params ListParams) ([]*ent.ApiKey, int, error)

	// Update updates an API key
	Update(ctx context.Context, id string, input UpdateAPIKeyRequest) (*ent.ApiKey, error)

	// Delete deletes an API key
	Delete(ctx context.Context, id string) error

	// Validate validates an API key
	Validate(ctx context.Context, key string) (*ent.ApiKey, error)

	// UpdateLastUsed updates the last_used timestamp of an API key
	UpdateLastUsed(ctx context.Context, id string) error
}

// CreateAPIKeyRequest represents input for creating an API key
type CreateAPIKeyRequest struct {
	Name           string                 `json:"name" validate:"required"`
	Type           string                 `json:"type,omitempty"`
	UserID         string                 `json:"user_id,omitempty"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	Permissions    []string               `json:"permissions,omitempty"`
	Scopes         []string               `json:"scopes,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	ExpiresIn      *time.Duration         `json:"expires_in,omitempty"`
}

// UpdateAPIKeyRequest represents input for updating an API key
type UpdateAPIKeyRequest struct {
	Name        *string                `json:"name,omitempty"`
	Active      *bool                  `json:"active,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Scopes      []string               `json:"scopes,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
}

// ListParams represents pagination and filtering parameters
type ListParams struct {
	Offset         int    `json:"offset" query:"offset"`
	Limit          int    `json:"limit" query:"limit"`
	UserID         string `json:"user_id" query:"user_id"`
	OrganizationID string `json:"organization_id" query:"organization_id"`
	Type           string `json:"type" query:"type"`
}

// APIKeyWithKeyResponse represents an API key with its plaintext key
type APIKeyWithKeyResponse struct {
	APIKey *ent.ApiKey `json:"api_key"`
	Key    string      `json:"key"`
}

type service struct {
	repo      Repository
	validator Validator
	config    *config.Config
}

// NewService creates a new API key service
func NewService(repo Repository, validator Validator, cfg *config.Config) Service {
	return &service{
		repo:      repo,
		validator: validator,
		config:    cfg,
	}
}

// Create creates a new API key
func (s *service) Create(ctx context.Context, input CreateAPIKeyRequest) (*APIKeyWithKeyResponse, error) {
	// Validate input
	if input.UserID == "" && input.OrganizationID == "" {
		return nil, errors.New(errors.CodeInvalidInput, "either user_id or organization_id must be provided")
	}

	// Set default values
	if input.Type == "" {
		input.Type = "server"
	}

	// Generate API key
	key, hashedKey, err := cryptoold.GenerateHashedAPIKey("key")
	if err != nil {
		return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate API key")
	}

	// Calculate expires_at if expires_in is provided
	var expiresAt *time.Time
	if input.ExpiresIn != nil {
		t := time.Now().Add(*input.ExpiresIn)
		expiresAt = &t
	}

	// Create API key in repository
	apiKey, err := s.repo.Create(ctx, RepositoryCreateInput{
		Name:           input.Name,
		Key:            key,
		HashedKey:      hashedKey,
		Type:           input.Type,
		UserID:         input.UserID,
		OrganizationID: input.OrganizationID,
		Permissions:    input.Permissions,
		Scopes:         input.Scopes,
		Metadata:       input.Metadata,
		ExpiresAt:      expiresAt,
	})

	if err != nil {
		return nil, err
	}

	return &APIKeyWithKeyResponse{
		APIKey: apiKey,
		Key:    key,
	}, nil
}

// Get retrieves an API key by ID
func (s *service) Get(ctx context.Context, id string) (*ent.ApiKey, error) {
	return s.repo.GetByID(ctx, id)
}

// List retrieves API keys with pagination
func (s *service) List(ctx context.Context, params ListParams) ([]*ent.ApiKey, int, error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	// Map service input to repository input
	repoInput := RepositoryListInput{
		Offset:         params.Offset,
		Limit:          params.Limit,
		UserID:         params.UserID,
		OrganizationID: params.OrganizationID,
		Type:           params.Type,
	}

	return s.repo.List(ctx, repoInput)
}

// Update updates an API key
func (s *service) Update(ctx context.Context, id string, input UpdateAPIKeyRequest) (*ent.ApiKey, error) {
	// Map service input to repository input
	repoInput := RepositoryUpdateInput{}

	if input.Name != nil {
		repoInput.Name = input.Name
	}

	if input.Active != nil {
		repoInput.Active = input.Active
	}

	if input.Permissions != nil {
		repoInput.Permissions = input.Permissions
	}

	if input.Scopes != nil {
		repoInput.Scopes = input.Scopes
	}

	if input.Metadata != nil {
		repoInput.Metadata = input.Metadata
	}

	if input.ExpiresAt != nil {
		repoInput.ExpiresAt = input.ExpiresAt
	}

	return s.repo.Update(ctx, id, repoInput)
}

// Delete deletes an API key
func (s *service) Delete(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

// Validate validates an API key
func (s *service) Validate(ctx context.Context, key string) (*ent.ApiKey, error) {
	// Validate the key format first
	if err := s.validator.ValidateKeyFormat(key); err != nil {
		return nil, err
	}

	// Hash the key to look up in the database
	hashedKey := cryptoold.HashAPIKey(key)

	// Get the API key
	apiKey, err := s.repo.GetByHashedKey(ctx, hashedKey)
	if err != nil {
		return nil, err
	}

	// Check if the key is active
	if !apiKey.Active {
		return nil, errors.New(errors.CodeInvalidAPIKey, "API key is inactive")
	}

	// Check if the key has expired
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return nil, errors.New(errors.CodeInvalidAPIKey, "API key has expired")
	}

	// Update last used time in a separate goroutine to not block the request
	go func() {
		// Create a new context for the update operation
		updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Ignore errors from the background update
		_ = s.UpdateLastUsed(updateCtx, apiKey.ID)
	}()

	return apiKey, nil
}

// UpdateLastUsed updates the last_used timestamp of an API key
func (s *service) UpdateLastUsed(ctx context.Context, id string) error {
	now := time.Now()
	_, err := s.repo.Update(ctx, id, RepositoryUpdateInput{
		LastUsed: &now,
	})
	return err
}
