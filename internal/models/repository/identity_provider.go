package repository

import (
	"context"
	"database/sql"
	errors2 "errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
	"github.com/xraph/frank/internal/models"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/model"
)

// IdentityProviderRepository defines the interface for identity provider data operations
type IdentityProviderRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateIdentityProviderInput) (*models.IdentityProvider, error)
	GetByID(ctx context.Context, id string) (*models.IdentityProvider, error)
	Update(ctx context.Context, id string, input UpdateIdentityProviderInput) (*models.IdentityProvider, error)
	Delete(ctx context.Context, id string) error

	// Query operations
	ListByOrganizationID(ctx context.Context, orgID string, opts model.SSOProviderListRequest) (*models.PaginatedOutput[*models.IdentityProvider], error)
	ListByProviderType(ctx context.Context, providerType string, opts model.SSOProviderListRequest) (*models.PaginatedOutput[*models.IdentityProvider], error)
	ListActiveByOrganizationID(ctx context.Context, orgID string) ([]*models.IdentityProvider, error)
	ListInactiveByOrganizationID(ctx context.Context, orgID string) ([]*models.IdentityProvider, error)

	// Provider management operations
	ActivateProvider(ctx context.Context, id string) error
	DeactivateProvider(ctx context.Context, id string) error
	SetAsPrimary(ctx context.Context, id string) error
	UnsetPrimary(ctx context.Context, orgID string) error

	// Provider lookup operations
	GetPrimaryByOrganizationID(ctx context.Context, orgID string) (*models.IdentityProvider, error)
	GetByOrganizationAndType(ctx context.Context, orgID string, providerType string) ([]*models.IdentityProvider, error)
	GetByDomain(ctx context.Context, domain string) ([]*models.IdentityProvider, error)
	GetActiveByOrganizationAndType(ctx context.Context, orgID string, providerType string) ([]*models.IdentityProvider, error)

	// Domain management
	AddDomain(ctx context.Context, id string, domain string) error
	RemoveDomain(ctx context.Context, id string, domain string) error
	ListProviderDomains(ctx context.Context, id string) ([]string, error)

	// Utility operations
	CountByOrganizationID(ctx context.Context, orgID string) (int, error)
	CountActiveByOrganizationID(ctx context.Context, orgID string) (int, error)
	CountByProviderType(ctx context.Context, providerType string) (int, error)

	// Advanced queries
	ListByMultipleDomains(ctx context.Context, domains []string) ([]*models.IdentityProvider, error)
	GetProviderStats(ctx context.Context, orgID string) (*ProviderStats, error)
	ListRecentlyModified(ctx context.Context, limit int) ([]*models.IdentityProvider, error)

	// Configuration validation
	ValidateConfiguration(ctx context.Context, providerType string, config map[string]any) error
	TestConnection(ctx context.Context, id string) error
}

// identityProviderRepository implements IdentityProviderRepository interface
type identityProviderRepository struct {
	db *bun.DB
}

// NewIdentityProviderRepository creates a new identity provider repository
func NewIdentityProviderRepository(db *bun.DB) IdentityProviderRepository {
	return &identityProviderRepository{
		db: db,
	}
}

// CreateIdentityProviderInput defines the input for creating an identity provider
type CreateIdentityProviderInput struct {
	Name                  string            `json:"name"`
	OrganizationID        string            `json:"organization_id"`
	Type                  string            `json:"type"`
	ClientID              *string           `json:"client_id,omitempty"`
	ClientSecret          *string           `json:"client_secret,omitempty"`
	Issuer                *string           `json:"issuer,omitempty"`
	AuthorizationEndpoint *string           `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         *string           `json:"token_endpoint,omitempty"`
	UserinfoEndpoint      *string           `json:"userinfo_endpoint,omitempty"`
	JWKSURI               *string           `json:"jwks_uri,omitempty"`
	MetadataURL           *string           `json:"metadata_url,omitempty"`
	RedirectURI           *string           `json:"redirect_uri,omitempty"`
	Certificate           *string           `json:"certificate,omitempty"`
	PrivateKey            *string           `json:"private_key,omitempty"`
	Active                bool              `json:"active"`
	Primary               bool              `json:"primary"`
	Domains               []string          `json:"domains,omitempty"`
	AttributesMapping     map[string]string `json:"attributes_mapping,omitempty"`
	Metadata              map[string]any    `json:"metadata,omitempty"`

	Protocol         string            `json:"protocol"`
	Domain           string            `json:"domain,omitempty"`
	AutoProvision    bool              `json:"auto_provision"`
	DefaultRole      string            `json:"default_role,omitempty"`
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`
	IconURL          string            `json:"iconUrl,omitempty"`
	ButtonText       string            `json:"buttonText,omitempty"`
}

// UpdateIdentityProviderInput defines the input for updating an identity provider
type UpdateIdentityProviderInput struct {
	Name                  *string           `json:"name,omitempty"`
	ClientID              *string           `json:"client_id,omitempty"`
	ClientSecret          *string           `json:"client_secret,omitempty"`
	Issuer                *string           `json:"issuer,omitempty"`
	AuthorizationEndpoint *string           `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         *string           `json:"token_endpoint,omitempty"`
	UserinfoEndpoint      *string           `json:"userinfo_endpoint,omitempty"`
	JWKSURI               *string           `json:"jwks_uri,omitempty"`
	MetadataURL           *string           `json:"metadata_url,omitempty"`
	RedirectURI           *string           `json:"redirect_uri,omitempty"`
	Certificate           *string           `json:"certificate,omitempty"`
	PrivateKey            *string           `json:"private_key,omitempty"`
	Active                *bool             `json:"active,omitempty"`
	Primary               *bool             `json:"primary,omitempty"`
	Domains               []string          `json:"domains,omitempty"`
	AttributesMapping     map[string]string `json:"attributes_mapping,omitempty"`
	Metadata              map[string]any    `json:"metadata,omitempty"`

	Domain           *string           `json:"domain,omitempty"`
	Enabled          *bool             `json:"enabled,omitempty"`
	AutoProvision    *bool             `json:"autoProvision,omitempty"`
	DefaultRole      *string           `json:"defaultRole,omitempty"`
	AttributeMapping map[string]string `json:"attributeMapping,omitempty"`
	IconURL          *string           `json:"iconUrl,omitempty"`
	ButtonText       *string           `json:"buttonText,omitempty"`
	Config           map[string]any    `json:"config"`
}

// ProviderStats represents identity provider statistics
type ProviderStats struct {
	TotalProviders  int                      `json:"total_providers"`
	ActiveProviders int                      `json:"active_providers"`
	TypeBreakdown   map[string]int           `json:"type_breakdown"`
	DomainCount     int                      `json:"domain_count"`
	HasPrimary      bool                     `json:"has_primary"`
	PrimaryProvider *models.IdentityProvider `json:"primary_provider"`
}

// Create creates a new identity provider
func (r *identityProviderRepository) Create(ctx context.Context, input CreateIdentityProviderInput) (*models.IdentityProvider, error) {
	// If setting as primary, unset other primary providers in the organization
	if input.Primary {
		err := r.UnsetPrimary(ctx, input.OrganizationID)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to unset primary providers")
		}
	}

	provider := &models.IdentityProvider{
		Name:                  input.Name,
		OrganizationID:        input.OrganizationID,
		ProviderType:          input.Type,
		Active:                input.Active,
		Primary:               input.Primary,
		ClientID:              input.ClientID,
		ClientSecret:          input.ClientSecret,
		Issuer:                input.Issuer,
		AuthorizationEndpoint: input.AuthorizationEndpoint,
		TokenEndpoint:         input.TokenEndpoint,
		UserinfoEndpoint:      input.UserinfoEndpoint,
		JWKSURI:               input.JWKSURI,
		MetadataURL:           input.MetadataURL,
		RedirectURI:           input.RedirectURI,
		Certificate:           input.Certificate,
		PrivateKey:            input.PrivateKey,
		Domains:               input.Domains,
		AttributesMapping:     input.AttributesMapping,
		Metadata:              input.Metadata,
	}

	_, err := r.db.NewInsert().
		Model(provider).
		Exec(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create identity provider")
	}

	return provider, nil
}

// GetByID retrieves an identity provider by its ID
func (r *identityProviderRepository) GetByID(ctx context.Context, id string) (*models.IdentityProvider, error) {
	provider := &models.IdentityProvider{}

	err := r.db.NewSelect().
		Model(provider).
		Relation("Organization").
		Where("idp.id = ?", id).
		Where("idp.deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "Identity provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get identity provider")
	}

	return provider, nil
}

// Update updates an identity provider
func (r *identityProviderRepository) Update(ctx context.Context, id string, input UpdateIdentityProviderInput) (*models.IdentityProvider, error) {
	// Get current provider to check organization
	currentProvider, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// If setting as primary, unset other primary providers in the organization
	if input.Primary != nil && *input.Primary {
		err := r.UnsetPrimary(ctx, currentProvider.OrganizationID)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to unset primary providers")
		}
	}

	query := r.db.NewUpdate().
		Model(&models.IdentityProvider{}).
		Where("id = ?", id)

	if input.Name != nil {
		query = query.Set("name = ?", *input.Name)
	}
	if input.ClientID != nil {
		query = query.Set("client_id = ?", *input.ClientID)
	}
	if input.ClientSecret != nil {
		query = query.Set("client_secret = ?", *input.ClientSecret)
	}
	if input.Issuer != nil {
		query = query.Set("issuer = ?", *input.Issuer)
	}
	if input.AuthorizationEndpoint != nil {
		query = query.Set("authorization_endpoint = ?", *input.AuthorizationEndpoint)
	}
	if input.TokenEndpoint != nil {
		query = query.Set("token_endpoint = ?", *input.TokenEndpoint)
	}
	if input.UserinfoEndpoint != nil {
		query = query.Set("userinfo_endpoint = ?", *input.UserinfoEndpoint)
	}
	if input.JWKSURI != nil {
		query = query.Set("jwks_uri = ?", *input.JWKSURI)
	}
	if input.MetadataURL != nil {
		query = query.Set("metadata_url = ?", *input.MetadataURL)
	}
	if input.RedirectURI != nil {
		query = query.Set("redirect_uri = ?", *input.RedirectURI)
	}
	if input.Certificate != nil {
		query = query.Set("certificate = ?", *input.Certificate)
	}
	if input.PrivateKey != nil {
		query = query.Set("private_key = ?", *input.PrivateKey)
	}
	if input.Active != nil {
		query = query.Set("active = ?", *input.Active)
	}
	if input.Primary != nil {
		query = query.Set("primary = ?", *input.Primary)
	}
	if input.Domains != nil {
		query = query.Set("domains = ?", input.Domains)
	}
	if input.AttributesMapping != nil {
		query = query.Set("attributes_mapping = ?", input.AttributesMapping)
	}
	if input.Metadata != nil {
		query = query.Set("metadata = ?", input.Metadata)
	}

	_, err = query.Exec(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update identity provider")
	}

	return r.GetByID(ctx, id)
}

// Delete deletes an identity provider (soft delete)
func (r *identityProviderRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model(&models.IdentityProvider{}).
		Set("deleted_at = ?", time.Now()).
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to delete identity provider")
	}

	return nil
}

// ListByOrganizationID retrieves paginated identity providers for an organization
func (r *identityProviderRepository) ListByOrganizationID(ctx context.Context, orgID string, opts model.SSOProviderListRequest) (*models.PaginatedOutput[*models.IdentityProvider], error) {
	query := r.db.NewSelect().
		Model((*models.IdentityProvider)(nil)).
		Relation("Organization").
		Where("idp.organization_id = ?", orgID).
		Where("idp.deleted_at IS NULL").
		Order("idp.created_at DESC")

	result, err := models.WithPaginationAndOptions[*models.IdentityProvider](ctx, query, opts.PaginationParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list identity providers by organization ID")
	}

	return result, nil
}

// ListByProviderType retrieves paginated identity providers by type
func (r *identityProviderRepository) ListByProviderType(ctx context.Context, providerType string, opts model.SSOProviderListRequest) (*models.PaginatedOutput[*models.IdentityProvider], error) {
	query := r.db.NewSelect().
		Model((*models.IdentityProvider)(nil)).
		Relation("Organization").
		Where("idp.provider_type = ?", providerType).
		Where("idp.deleted_at IS NULL").
		Order("idp.created_at DESC")

	result, err := models.WithPaginationAndOptions[*models.IdentityProvider](ctx, query, opts.PaginationParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, fmt.Sprintf("Failed to list identity providers by type %s", providerType))
	}

	return result, nil
}

// ListActiveByOrganizationID retrieves all active identity providers for an organization
func (r *identityProviderRepository) ListActiveByOrganizationID(ctx context.Context, orgID string) ([]*models.IdentityProvider, error) {
	var providers []*models.IdentityProvider

	err := r.db.NewSelect().
		Model(&providers).
		Relation("Organization").
		Where("idp.organization_id = ?", orgID).
		Where("idp.active = ?", true).
		Where("idp.deleted_at IS NULL").
		Order("idp.primary DESC", "idp.created_at DESC").
		Scan(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list active identity providers")
	}

	return providers, nil
}

// ListInactiveByOrganizationID retrieves all inactive identity providers for an organization
func (r *identityProviderRepository) ListInactiveByOrganizationID(ctx context.Context, orgID string) ([]*models.IdentityProvider, error) {
	var providers []*models.IdentityProvider

	err := r.db.NewSelect().
		Model(&providers).
		Relation("Organization").
		Where("idp.organization_id = ?", orgID).
		Where("idp.active = ?", false).
		Where("idp.deleted_at IS NULL").
		Order("idp.created_at DESC").
		Scan(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list inactive identity providers")
	}

	return providers, nil
}

// ActivateProvider activates an identity provider
func (r *identityProviderRepository) ActivateProvider(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model(&models.IdentityProvider{}).
		Set("active = ?", true).
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to activate identity provider")
	}

	return nil
}

// DeactivateProvider deactivates an identity provider
func (r *identityProviderRepository) DeactivateProvider(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model(&models.IdentityProvider{}).
		Set("active = ?", false).
		Set("primary = ?", false). // Cannot be primary if inactive
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to deactivate identity provider")
	}

	return nil
}

// SetAsPrimary sets an identity provider as primary (and unsets others)
func (r *identityProviderRepository) SetAsPrimary(ctx context.Context, id string) error {
	// Get the provider to find its organization
	provider, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Unset all primary providers in the organization
	err = r.UnsetPrimary(ctx, provider.OrganizationID)
	if err != nil {
		return err
	}

	// Set this provider as primary
	_, err = r.db.NewUpdate().
		Model(&models.IdentityProvider{}).
		Set("primary = ?", true).
		Set("active = ?", true). // Must be active to be primary
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to set identity provider as primary")
	}

	return nil
}

// UnsetPrimary unsets all primary providers for an organization
func (r *identityProviderRepository) UnsetPrimary(ctx context.Context, orgID string) error {
	_, err := r.db.NewUpdate().
		Model(&models.IdentityProvider{}).
		Set("primary = ?", false).
		Where("organization_id = ?", orgID).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to unset primary identity providers")
	}

	return nil
}

// GetPrimaryByOrganizationID retrieves the primary identity provider for an organization
func (r *identityProviderRepository) GetPrimaryByOrganizationID(ctx context.Context, orgID string) (*models.IdentityProvider, error) {
	provider := &models.IdentityProvider{}

	err := r.db.NewSelect().
		Model(provider).
		Relation("Organization").
		Where("idp.organization_id = ?", orgID).
		Where("idp.primary = ?", true).
		Where("idp.active = ?", true).
		Where("idp.deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "Primary identity provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get primary identity provider")
	}

	return provider, nil
}

// GetByOrganizationAndType retrieves identity providers by organization and type
func (r *identityProviderRepository) GetByOrganizationAndType(ctx context.Context, orgID string, providerType string) ([]*models.IdentityProvider, error) {
	var providers []*models.IdentityProvider

	err := r.db.NewSelect().
		Model(&providers).
		Relation("Organization").
		Where("idp.organization_id = ?", orgID).
		Where("idp.provider_type = ?", providerType).
		Where("idp.deleted_at IS NULL").
		Order("idp.primary DESC", "idp.created_at DESC").
		Scan(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get identity providers by organization and type")
	}

	return providers, nil
}

// GetByDomain retrieves identity providers that handle a specific domain
func (r *identityProviderRepository) GetByDomain(ctx context.Context, domain string) ([]*models.IdentityProvider, error) {
	var providers []*models.IdentityProvider

	err := r.db.NewSelect().
		Model(&providers).
		Relation("Organization").
		Where("idp.active = ?", true).
		Where("idp.deleted_at IS NULL").
		Where("? = ANY(idp.domains)", domain).
		Order("idp.primary DESC", "idp.created_at DESC").
		Scan(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get identity providers by domain")
	}

	return providers, nil
}

// GetActiveByOrganizationAndType retrieves active identity providers by organization and type
func (r *identityProviderRepository) GetActiveByOrganizationAndType(ctx context.Context, orgID string, providerType string) ([]*models.IdentityProvider, error) {
	var providers []*models.IdentityProvider

	err := r.db.NewSelect().
		Model(&providers).
		Relation("Organization").
		Where("idp.organization_id = ?", orgID).
		Where("idp.provider_type = ?", providerType).
		Where("idp.active = ?", true).
		Where("idp.deleted_at IS NULL").
		Order("idp.primary DESC", "idp.created_at DESC").
		Scan(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get active identity providers by organization and type")
	}

	return providers, nil
}

// AddDomain adds a domain to an identity provider
func (r *identityProviderRepository) AddDomain(ctx context.Context, id string, domain string) error {
	// Get current provider
	provider, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Check if domain already exists
	for _, existingDomain := range provider.Domains {
		if existingDomain == domain {
			return nil // Already exists
		}
	}

	// Add the new domain
	newDomains := append(provider.Domains, domain)

	_, err = r.db.NewUpdate().
		Model(&models.IdentityProvider{}).
		Set("domains = ?", newDomains).
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to add domain to identity provider")
	}

	return nil
}

// RemoveDomain removes a domain from an identity provider
func (r *identityProviderRepository) RemoveDomain(ctx context.Context, id string, domain string) error {
	// Get current provider
	provider, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Remove the domain
	var newDomains []string
	for _, existingDomain := range provider.Domains {
		if existingDomain != domain {
			newDomains = append(newDomains, existingDomain)
		}
	}

	_, err = r.db.NewUpdate().
		Model(&models.IdentityProvider{}).
		Set("domains = ?", newDomains).
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to remove domain from identity provider")
	}

	return nil
}

// ListProviderDomains retrieves all domains for an identity provider
func (r *identityProviderRepository) ListProviderDomains(ctx context.Context, id string) ([]string, error) {
	provider, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return provider.Domains, nil
}

// CountByOrganizationID counts identity providers for an organization
func (r *identityProviderRepository) CountByOrganizationID(ctx context.Context, orgID string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.IdentityProvider)(nil)).
		Where("organization_id = ?", orgID).
		Where("deleted_at IS NULL").
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to count identity providers by organization ID")
	}

	return count, nil
}

// CountActiveByOrganizationID counts active identity providers for an organization
func (r *identityProviderRepository) CountActiveByOrganizationID(ctx context.Context, orgID string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.IdentityProvider)(nil)).
		Where("organization_id = ?", orgID).
		Where("active = ?", true).
		Where("deleted_at IS NULL").
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to count active identity providers")
	}

	return count, nil
}

// CountByProviderType counts identity providers by type
func (r *identityProviderRepository) CountByProviderType(ctx context.Context, providerType string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.IdentityProvider)(nil)).
		Where("provider_type = ?", providerType).
		Where("deleted_at IS NULL").
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to count identity providers by type")
	}

	return count, nil
}

// ListByMultipleDomains retrieves identity providers that handle any of the specified domains
func (r *identityProviderRepository) ListByMultipleDomains(ctx context.Context, domains []string) ([]*models.IdentityProvider, error) {
	if len(domains) == 0 {
		return []*models.IdentityProvider{}, nil
	}

	var providers []*models.IdentityProvider

	err := r.db.NewSelect().
		Model(&providers).
		Relation("Organization").
		Where("idp.active = ?", true).
		Where("idp.deleted_at IS NULL").
		Where("idp.domains && ?", bun.In(domains)).
		Scan(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get identity providers by domains")
	}

	return providers, nil
}

// GetProviderStats retrieves identity provider statistics for an organization
func (r *identityProviderRepository) GetProviderStats(ctx context.Context, orgID string) (*ProviderStats, error) {
	stats := &ProviderStats{
		TypeBreakdown: make(map[string]int),
	}

	// Count total providers
	totalProviders, err := r.CountByOrganizationID(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Count active providers
	activeProviders, err := r.CountActiveByOrganizationID(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Get primary provider
	primaryProvider, err := r.GetPrimaryByOrganizationID(ctx, orgID)
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}

	stats.TotalProviders = totalProviders
	stats.ActiveProviders = activeProviders
	stats.HasPrimary = primaryProvider != nil
	stats.PrimaryProvider = primaryProvider

	return stats, nil
}

// ListRecentlyModified retrieves recently modified identity providers
func (r *identityProviderRepository) ListRecentlyModified(ctx context.Context, limit int) ([]*models.IdentityProvider, error) {
	var providers []*models.IdentityProvider

	err := r.db.NewSelect().
		Model(&providers).
		Relation("Organization").
		Where("idp.deleted_at IS NULL").
		Order("idp.updated_at DESC").
		Limit(limit).
		Scan(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list recently modified identity providers")
	}

	return providers, nil
}

// ValidateConfiguration validates identity provider configuration
func (r *identityProviderRepository) ValidateConfiguration(ctx context.Context, providerType string, config map[string]any) error {
	switch providerType {
	case "oauth2", "oidc":
		if _, ok := config["client_id"]; !ok {
			return errors.New(errors.CodeBadRequest, "OAuth2/OIDC providers require client_id")
		}
		if _, ok := config["client_secret"]; !ok {
			return errors.New(errors.CodeBadRequest, "OAuth2/OIDC providers require client_secret")
		}
		if providerType == "oidc" {
			if _, ok := config["issuer"]; !ok {
				return errors.New(errors.CodeBadRequest, "OIDC providers require issuer")
			}
		}
	case "saml":
		if _, ok := config["certificate"]; !ok {
			return errors.New(errors.CodeBadRequest, "SAML providers require certificate")
		}
	default:
		return errors.New(errors.CodeBadRequest, fmt.Sprintf("Unsupported provider type: %s", providerType))
	}

	return nil
}

// TestConnection tests the connection to an identity provider
func (r *identityProviderRepository) TestConnection(ctx context.Context, id string) error {
	provider, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if !provider.Active {
		return errors.New(errors.CodeBadRequest, "Cannot test connection to inactive provider")
	}

	// TODO: Implement actual connection testing based on provider type
	switch provider.ProviderType {
	case "oauth2", "oidc":
		// Test authorization endpoint, token endpoint, etc.
	case "saml":
		// Test SAML metadata endpoint
	default:
		return errors.New(errors.CodeNotImplemented, fmt.Sprintf("Connection testing not implemented for provider type: %s", provider.ProviderType))
	}

	return nil
}
