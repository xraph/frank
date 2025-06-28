package repository

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/identityprovider"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/model"
)

// IdentityProviderRepository defines the interface for identity provider data operations
type IdentityProviderRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateIdentityProviderInput) (*ent.IdentityProvider, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.IdentityProvider, error)
	Update(ctx context.Context, id xid.ID, input UpdateIdentityProviderInput) (*ent.IdentityProvider, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.SSOProviderListRequest) (*model.PaginatedOutput[*ent.IdentityProvider], error)
	ListByProviderType(ctx context.Context, providerType string, opts model.SSOProviderListRequest) (*model.PaginatedOutput[*ent.IdentityProvider], error)
	ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.IdentityProvider, error)
	ListInactiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.IdentityProvider, error)

	// Provider management operations
	ActivateProvider(ctx context.Context, id xid.ID) error
	DeactivateProvider(ctx context.Context, id xid.ID) error
	SetAsPrimary(ctx context.Context, id xid.ID) error
	UnsetPrimary(ctx context.Context, orgID xid.ID) error

	// Provider lookup operations
	GetPrimaryByOrganizationID(ctx context.Context, orgID xid.ID) (*ent.IdentityProvider, error)
	GetByOrganizationAndType(ctx context.Context, orgID xid.ID, providerType string) ([]*ent.IdentityProvider, error)
	GetByDomain(ctx context.Context, domain string) ([]*ent.IdentityProvider, error)
	GetActiveByOrganizationAndType(ctx context.Context, orgID xid.ID, providerType string) ([]*ent.IdentityProvider, error)

	// Domain management
	AddDomain(ctx context.Context, id xid.ID, domain string) error
	RemoveDomain(ctx context.Context, id xid.ID, domain string) error
	ListProviderDomains(ctx context.Context, id xid.ID) ([]string, error)

	// Utility operations
	CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)
	CountActiveByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)
	CountByProviderType(ctx context.Context, providerType string) (int, error)

	// Advanced queries
	ListByMultipleDomains(ctx context.Context, domains []string) ([]*ent.IdentityProvider, error)
	GetProviderStats(ctx context.Context, orgID xid.ID) (*ProviderStats, error)
	ListRecentlyModified(ctx context.Context, limit int) ([]*ent.IdentityProvider, error)

	// Configuration validation
	ValidateConfiguration(ctx context.Context, providerType string, config map[string]any) error
	TestConnection(ctx context.Context, id xid.ID) error
}

// identityProviderRepository implements IdentityProviderRepository interface
type identityProviderRepository struct {
	client *ent.Client
}

// NewIdentityProviderRepository creates a new identity provider repository
func NewIdentityProviderRepository(client *ent.Client) IdentityProviderRepository {
	return &identityProviderRepository{
		client: client,
	}
}

// CreateIdentityProviderInput defines the input for creating an identity provider
type CreateIdentityProviderInput struct {
	Name                  string            `json:"name"`
	OrganizationID        xid.ID            `json:"organization_id"`
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

	Protocol         string                       `json:"protocol" example:"openid_connect" doc:"Authentication protocol"`
	Domain           string                       `json:"domain,omitempty" example:"acme.com" doc:"Email domain"`
	AutoProvision    bool                         `json:"auto_provision" example:"true" doc:"Auto-provision users"`
	DefaultRole      string                       `json:"default_role,omitempty" example:"member" doc:"Default role"`
	AttributeMapping map[string]string            `json:"attribute_mapping,omitempty" doc:"Attribute mappings"`
	Config           model.IdentityProviderConfig `json:"config" doc:"Provider configuration"`
	IconURL          string                       `json:"iconUrl,omitempty" example:"https://example.com/icon.png" doc:"Icon URL"`
	ButtonText       string                       `json:"buttonText,omitempty" example:"Sign in with Provider" doc:"Button text"`
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

	Domain           *string           `json:"domain,omitempty" example:"updated.com" doc:"Updated domain"`
	Enabled          *bool             `json:"enabled,omitempty" example:"true" doc:"Updated enabled status"`
	AutoProvision    *bool             `json:"autoProvision,omitempty" example:"false" doc:"Updated auto-provision"`
	DefaultRole      *string           `json:"defaultRole,omitempty" example:"viewer" doc:"Updated default role"`
	AttributeMapping map[string]string `json:"attributeMapping,omitempty" doc:"Updated attribute mappings"`
	IconURL          *string           `json:"iconUrl,omitempty" example:"https://example.com/new-icon.png" doc:"Updated icon URL"`
	ButtonText       *string           `json:"buttonText,omitempty" example:"Updated button text" doc:"Updated button text"`
	Config           map[string]any    `json:"config" doc:"Updated provider configuration"`
}

// ProviderStats represents identity provider statistics
type ProviderStats struct {
	TotalProviders  int                   `json:"total_providers"`
	ActiveProviders int                   `json:"active_providers"`
	TypeBreakdown   map[string]int        `json:"type_breakdown"`
	DomainCount     int                   `json:"domain_count"`
	HasPrimary      bool                  `json:"has_primary"`
	PrimaryProvider *ent.IdentityProvider `json:"primary_provider"`
}

// Create creates a new identity provider
func (r *identityProviderRepository) Create(ctx context.Context, input CreateIdentityProviderInput) (*ent.IdentityProvider, error) {
	// If setting as primary, unset other primary providers in the organization
	if input.Primary {
		err := r.UnsetPrimary(ctx, input.OrganizationID)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to unset primary providers")
		}
	}

	builder := r.client.IdentityProvider.Create().
		SetName(input.Name).
		SetOrganizationID(input.OrganizationID).
		SetProviderType(input.Type).
		SetActive(input.Active).
		SetPrimary(input.Primary)

	if input.ClientID != nil {
		builder.SetClientID(*input.ClientID)
	}

	if input.ClientSecret != nil {
		builder.SetClientSecret(*input.ClientSecret)
	}

	if input.Issuer != nil {
		builder.SetIssuer(*input.Issuer)
	}

	if input.AuthorizationEndpoint != nil {
		builder.SetAuthorizationEndpoint(*input.AuthorizationEndpoint)
	}

	if input.TokenEndpoint != nil {
		builder.SetTokenEndpoint(*input.TokenEndpoint)
	}

	if input.UserinfoEndpoint != nil {
		builder.SetUserinfoEndpoint(*input.UserinfoEndpoint)
	}

	if input.JWKSURI != nil {
		builder.SetJwksURI(*input.JWKSURI)
	}

	if input.MetadataURL != nil {
		builder.SetMetadataURL(*input.MetadataURL)
	}

	if input.RedirectURI != nil {
		builder.SetRedirectURI(*input.RedirectURI)
	}

	if input.Certificate != nil {
		builder.SetCertificate(*input.Certificate)
	}

	if input.PrivateKey != nil {
		builder.SetPrivateKey(*input.PrivateKey)
	}

	if input.Domains != nil {
		builder.SetDomains(input.Domains)
	}

	if input.AttributesMapping != nil {
		builder.SetAttributesMapping(input.AttributesMapping)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	provider, err := builder.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create identity provider")
	}

	return provider, nil
}

// GetByID retrieves an identity provider by its ID
func (r *identityProviderRepository) GetByID(ctx context.Context, id xid.ID) (*ent.IdentityProvider, error) {
	provider, err := r.client.IdentityProvider.
		Query().
		Where(identityprovider.ID(id)).
		WithOrganization().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Identity provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get identity provider")
	}

	return provider, nil
}

// Update updates an identity provider
func (r *identityProviderRepository) Update(ctx context.Context, id xid.ID, input UpdateIdentityProviderInput) (*ent.IdentityProvider, error) {
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

	builder := r.client.IdentityProvider.UpdateOneID(id)

	if input.Name != nil {
		builder.SetName(*input.Name)
	}

	if input.ClientID != nil {
		builder.SetClientID(*input.ClientID)
	}

	if input.ClientSecret != nil {
		builder.SetClientSecret(*input.ClientSecret)
	}

	if input.Issuer != nil {
		builder.SetIssuer(*input.Issuer)
	}

	if input.AuthorizationEndpoint != nil {
		builder.SetAuthorizationEndpoint(*input.AuthorizationEndpoint)
	}

	if input.TokenEndpoint != nil {
		builder.SetTokenEndpoint(*input.TokenEndpoint)
	}

	if input.UserinfoEndpoint != nil {
		builder.SetUserinfoEndpoint(*input.UserinfoEndpoint)
	}

	if input.JWKSURI != nil {
		builder.SetJwksURI(*input.JWKSURI)
	}

	if input.MetadataURL != nil {
		builder.SetMetadataURL(*input.MetadataURL)
	}

	if input.RedirectURI != nil {
		builder.SetRedirectURI(*input.RedirectURI)
	}

	if input.Certificate != nil {
		builder.SetCertificate(*input.Certificate)
	}

	if input.PrivateKey != nil {
		builder.SetPrivateKey(*input.PrivateKey)
	}

	if input.Active != nil {
		builder.SetActive(*input.Active)
	}

	if input.Primary != nil {
		builder.SetPrimary(*input.Primary)
	}

	if input.Domains != nil {
		builder.SetDomains(input.Domains)
	}

	if input.AttributesMapping != nil {
		builder.SetAttributesMapping(input.AttributesMapping)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	provider, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Identity provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update identity provider")
	}

	return provider, nil
}

// Delete deletes an identity provider
func (r *identityProviderRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.IdentityProvider.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Identity provider not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to delete identity provider")
	}

	return nil
}

// ListByOrganizationID retrieves paginated identity providers for an organization
func (r *identityProviderRepository) ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.SSOProviderListRequest) (*model.PaginatedOutput[*ent.IdentityProvider], error) {
	query := r.client.IdentityProvider.
		Query().
		Where(identityprovider.OrganizationID(orgID)).
		WithOrganization()

	// Apply ordering
	query.Order(ent.Desc(identityprovider.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.IdentityProvider, *ent.IdentityProviderQuery](ctx, query, opts.PaginationParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list identity providers by organization ID")
	}

	return result, nil
}

// ListByProviderType retrieves paginated identity providers by type
func (r *identityProviderRepository) ListByProviderType(ctx context.Context, providerType string, opts model.SSOProviderListRequest) (*model.PaginatedOutput[*ent.IdentityProvider], error) {
	query := r.client.IdentityProvider.
		Query().
		Where(identityprovider.ProviderType(providerType)).
		WithOrganization()

	// Apply ordering
	query.Order(ent.Desc(identityprovider.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.IdentityProvider, *ent.IdentityProviderQuery](ctx, query, opts.PaginationParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, fmt.Sprintf("Failed to list identity providers by type %s", providerType))
	}

	return result, nil
}

// ListActiveByOrganizationID retrieves all active identity providers for an organization
func (r *identityProviderRepository) ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.IdentityProvider, error) {
	providers, err := r.client.IdentityProvider.
		Query().
		Where(
			identityprovider.OrganizationID(orgID),
			identityprovider.Active(true),
		).
		WithOrganization().
		Order(ent.Desc(identityprovider.FieldPrimary), ent.Desc(identityprovider.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list active identity providers")
	}

	return providers, nil
}

// ListInactiveByOrganizationID retrieves all inactive identity providers for an organization
func (r *identityProviderRepository) ListInactiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.IdentityProvider, error) {
	providers, err := r.client.IdentityProvider.
		Query().
		Where(
			identityprovider.OrganizationID(orgID),
			identityprovider.Active(false),
		).
		WithOrganization().
		Order(ent.Desc(identityprovider.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list inactive identity providers")
	}

	return providers, nil
}

// ActivateProvider activates an identity provider
func (r *identityProviderRepository) ActivateProvider(ctx context.Context, id xid.ID) error {
	err := r.client.IdentityProvider.
		UpdateOneID(id).
		SetActive(true).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Identity provider not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to activate identity provider")
	}

	return nil
}

// DeactivateProvider deactivates an identity provider
func (r *identityProviderRepository) DeactivateProvider(ctx context.Context, id xid.ID) error {
	err := r.client.IdentityProvider.
		UpdateOneID(id).
		SetActive(false).
		SetPrimary(false). // Cannot be primary if inactive
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Identity provider not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to deactivate identity provider")
	}

	return nil
}

// SetAsPrimary sets an identity provider as primary (and unsets others)
func (r *identityProviderRepository) SetAsPrimary(ctx context.Context, id xid.ID) error {
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
	err = r.client.IdentityProvider.
		UpdateOneID(id).
		SetPrimary(true).
		SetActive(true). // Must be active to be primary
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Identity provider not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to set identity provider as primary")
	}

	return nil
}

// UnsetPrimary unsets all primary providers for an organization
func (r *identityProviderRepository) UnsetPrimary(ctx context.Context, orgID xid.ID) error {
	_, err := r.client.IdentityProvider.
		Update().
		Where(identityprovider.OrganizationID(orgID)).
		SetPrimary(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to unset primary identity providers")
	}

	return nil
}

// GetPrimaryByOrganizationID retrieves the primary identity provider for an organization
func (r *identityProviderRepository) GetPrimaryByOrganizationID(ctx context.Context, orgID xid.ID) (*ent.IdentityProvider, error) {
	provider, err := r.client.IdentityProvider.
		Query().
		Where(
			identityprovider.OrganizationID(orgID),
			identityprovider.Primary(true),
			identityprovider.Active(true),
		).
		WithOrganization().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Primary identity provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get primary identity provider")
	}

	return provider, nil
}

// GetByOrganizationAndType retrieves identity providers by organization and type
func (r *identityProviderRepository) GetByOrganizationAndType(ctx context.Context, orgID xid.ID, providerType string) ([]*ent.IdentityProvider, error) {
	providers, err := r.client.IdentityProvider.
		Query().
		Where(
			identityprovider.OrganizationID(orgID),
			identityprovider.ProviderType(providerType),
		).
		WithOrganization().
		Order(ent.Desc(identityprovider.FieldPrimary), ent.Desc(identityprovider.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get identity providers by organization and type")
	}

	return providers, nil
}

// GetByDomain retrieves identity providers that handle a specific domain
func (r *identityProviderRepository) GetByDomain(ctx context.Context, domain string) ([]*ent.IdentityProvider, error) {
	providers, err := r.client.IdentityProvider.
		Query().
		Where(
			identityprovider.Active(true),
		).
		Where(func(s *sql.Selector) {
			s.Where(sqljson.ValueContains(identityprovider.FieldDomains, domain))
		}).
		WithOrganization().
		Order(ent.Desc(identityprovider.FieldPrimary), ent.Desc(identityprovider.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get identity providers by domain")
	}

	return providers, nil
}

// GetActiveByOrganizationAndType retrieves active identity providers by organization and type
func (r *identityProviderRepository) GetActiveByOrganizationAndType(ctx context.Context, orgID xid.ID, providerType string) ([]*ent.IdentityProvider, error) {
	providers, err := r.client.IdentityProvider.
		Query().
		Where(
			identityprovider.OrganizationID(orgID),
			identityprovider.ProviderType(providerType),
			identityprovider.Active(true),
		).
		WithOrganization().
		Order(ent.Desc(identityprovider.FieldPrimary), ent.Desc(identityprovider.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get active identity providers by organization and type")
	}

	return providers, nil
}

// AddDomain adds a domain to an identity provider
func (r *identityProviderRepository) AddDomain(ctx context.Context, id xid.ID, domain string) error {
	// Get current domains
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

	err = r.client.IdentityProvider.
		UpdateOneID(id).
		SetDomains(newDomains).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to add domain to identity provider")
	}

	return nil
}

// RemoveDomain removes a domain from an identity provider
func (r *identityProviderRepository) RemoveDomain(ctx context.Context, id xid.ID, domain string) error {
	// Get current domains
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

	err = r.client.IdentityProvider.
		UpdateOneID(id).
		SetDomains(newDomains).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to remove domain from identity provider")
	}

	return nil
}

// ListProviderDomains retrieves all domains for an identity provider
func (r *identityProviderRepository) ListProviderDomains(ctx context.Context, id xid.ID) ([]string, error) {
	provider, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return provider.Domains, nil
}

// CountByOrganizationID counts identity providers for an organization
func (r *identityProviderRepository) CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error) {
	count, err := r.client.IdentityProvider.
		Query().
		Where(identityprovider.OrganizationID(orgID)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to count identity providers by organization ID")
	}

	return count, nil
}

// CountActiveByOrganizationID counts active identity providers for an organization
func (r *identityProviderRepository) CountActiveByOrganizationID(ctx context.Context, orgID xid.ID) (int, error) {
	count, err := r.client.IdentityProvider.
		Query().
		Where(
			identityprovider.OrganizationID(orgID),
			identityprovider.Active(true),
		).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to count active identity providers")
	}

	return count, nil
}

// CountByProviderType counts identity providers by type
func (r *identityProviderRepository) CountByProviderType(ctx context.Context, providerType string) (int, error) {
	count, err := r.client.IdentityProvider.
		Query().
		Where(identityprovider.ProviderType(providerType)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to count identity providers by type")
	}

	return count, nil
}

// ListByMultipleDomains retrieves identity providers that handle any of the specified domains
func (r *identityProviderRepository) ListByMultipleDomains(ctx context.Context, domains []string) ([]*ent.IdentityProvider, error) {
	if len(domains) == 0 {
		return []*ent.IdentityProvider{}, nil
	}

	providers, err := r.client.IdentityProvider.
		Query().
		Where(
			identityprovider.Active(true),
			identityprovider.DomainsNotNil(),
		).
		WithOrganization().
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get identity providers by domains")
	}

	// Filter providers that contain any of the specified domains
	var matchingProviders []*ent.IdentityProvider
	for _, provider := range providers {
		for _, providerDomain := range provider.Domains {
			for _, searchDomain := range domains {
				if providerDomain == searchDomain {
					matchingProviders = append(matchingProviders, provider)
					goto nextProvider
				}
			}
		}
	nextProvider:
	}

	return matchingProviders, nil
}

// GetProviderStats retrieves identity provider statistics for an organization
func (r *identityProviderRepository) GetProviderStats(ctx context.Context, orgID xid.ID) (*ProviderStats, error) {
	stats := &ProviderStats{}

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

	// TODO: Implement additional statistics
	// - TypeBreakdown
	// - DomainCount

	return stats, nil
}

// ListRecentlyModified retrieves recently modified identity providers
func (r *identityProviderRepository) ListRecentlyModified(ctx context.Context, limit int) ([]*ent.IdentityProvider, error) {
	providers, err := r.client.IdentityProvider.
		Query().
		WithOrganization().
		Order(ent.Desc(identityprovider.FieldUpdatedAt)).
		Limit(limit).
		All(ctx)

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
func (r *identityProviderRepository) TestConnection(ctx context.Context, id xid.ID) error {
	provider, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if !provider.Active {
		return errors.New(errors.CodeBadRequest, "Cannot test connection to inactive provider")
	}

	// TODO: Implement actual connection testing based on provider type
	// This would involve making actual HTTP requests to test endpoints

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
