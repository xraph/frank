package organization

import (
	"context"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
	"github.com/rs/xid"
)

// Service provides organization operations
type Service interface {
	// Create creates a new organization
	Create(ctx context.Context, input CreateOrganizationInput) (*ent.Organization, error)

	// Get retrieves an organization by ID
	Get(ctx context.Context, id xid.ID) (*ent.Organization, error)

	// GetBySlug retrieves an organization by slug
	GetBySlug(ctx context.Context, slug string) (*ent.Organization, error)

	// GetByDomain retrieves an organization by domain
	GetByDomain(ctx context.Context, domain string) (*ent.Organization, error)

	// List retrieves organizations with pagination
	List(ctx context.Context, params ListParams) ([]*ent.Organization, int, error)

	// Update updates an organization
	Update(ctx context.Context, id xid.ID, input UpdateOrganizationInput) (*ent.Organization, error)

	// Delete deletes an organization
	Delete(ctx context.Context, id xid.ID) error

	// GetMembers retrieves members of an organization
	GetMembers(ctx context.Context, orgID xid.ID, params ListParams) ([]*ent.User, int, error)

	// AddMember adds a user to an organization
	AddMember(ctx context.Context, orgID, userID xid.ID, roles []string) error

	// RemoveMember removes a user from an organization
	RemoveMember(ctx context.Context, orgID, userID xid.ID) error

	// UpdateMember updates a member's roles in an organization
	UpdateMember(ctx context.Context, orgID, userID xid.ID, roles []string) error

	// IsFeatureEnabled checks if a feature is enabled for an organization
	IsFeatureEnabled(ctx context.Context, orgID xid.ID, featureKey string) (bool, error)

	// GetFeatures retrieves features of an organization
	GetFeatures(ctx context.Context, orgID xid.ID) ([]*ent.OrganizationFeature, error)

	// EnableFeature enables a feature for an organization
	EnableFeature(ctx context.Context, orgID xid.ID, featureKey string, settings map[string]interface{}) error

	// DisableFeature disables a feature for an organization
	DisableFeature(ctx context.Context, orgID xid.ID, featureKey string) error
}

// CreateOrganizationInput represents input for creating an organization
type CreateOrganizationInput struct {
	Name      string                 `json:"name" validate:"required"`
	Slug      string                 `json:"slug,omitempty"`
	Domain    string                 `json:"domain,omitempty"`
	LogoURL   string                 `json:"logo_url,omitempty"`
	Plan      string                 `json:"plan,omitempty"`
	OwnerID   xid.ID                 `json:"owner_id" validate:"required"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	TrialDays int                    `json:"trial_days,omitempty"`
	Features  []string               `json:"features,omitempty"`
}

// UpdateOrganizationInput represents input for updating an organization
type UpdateOrganizationInput struct {
	Name     *string                `json:"name,omitempty"`
	Domain   *string                `json:"domain,omitempty"`
	LogoURL  *string                `json:"logo_url,omitempty"`
	Plan     *string                `json:"plan,omitempty"`
	Active   *bool                  `json:"active,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ListParams represents pagination and filtering parameters
type ListParams struct {
	Offset int    `json:"offset" query:"offset"`
	Limit  int    `json:"limit" query:"limit"`
	Search string `json:"search" query:"search"`
}

type service struct {
	repo   Repository
	logger logging.Logger
}

// NewService creates a new organization service
func NewService(repo Repository, logger logging.Logger) Service {
	return &service{
		repo:   repo,
		logger: logger,
	}
}

// Create creates a new organization
func (s *service) Create(ctx context.Context, input CreateOrganizationInput) (*ent.Organization, error) {
	// Generate slug if not provided
	if input.Slug == "" {
		input.Slug = utils.Slugify(input.Name)
	}

	// Set default plan if not provided
	if input.Plan == "" {
		input.Plan = "free"
	}

	// Calculate trial end date if trial days provided
	var trialEndsAt *time.Time
	if input.TrialDays > 0 {
		t := time.Now().AddDate(0, 0, input.TrialDays)
		trialEndsAt = &t
	}

	// Create organization
	org, err := s.repo.Create(ctx, RepositoryCreateInput{
		Name:        input.Name,
		Slug:        input.Slug,
		Domain:      input.Domain,
		LogoURL:     input.LogoURL,
		Plan:        input.Plan,
		OwnerID:     input.OwnerID,
		Metadata:    input.Metadata,
		TrialEndsAt: trialEndsAt,
	})

	if err != nil {
		return nil, err
	}

	// Enable default features
	for _, featureKey := range input.Features {
		err = s.EnableFeature(ctx, org.ID, featureKey, nil)
		if err != nil {
			// Log error but don't fail
			continue
		}
	}

	return org, nil
}

// Get retrieves an organization by ID
func (s *service) Get(ctx context.Context, id xid.ID) (*ent.Organization, error) {
	return s.repo.GetByID(ctx, id)
}

// GetBySlug retrieves an organization by slug
func (s *service) GetBySlug(ctx context.Context, slug string) (*ent.Organization, error) {
	return s.repo.GetBySlug(ctx, slug)
}

// GetByDomain retrieves an organization by domain
func (s *service) GetByDomain(ctx context.Context, domain string) (*ent.Organization, error) {
	return s.repo.GetByDomain(ctx, domain)
}

// List retrieves organizations with pagination
func (s *service) List(ctx context.Context, params ListParams) ([]*ent.Organization, int, error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	return s.repo.List(ctx, RepositoryListInput{
		Offset: params.Offset,
		Limit:  params.Limit,
		Search: params.Search,
	})
}

// Update updates an organization
func (s *service) Update(ctx context.Context, id xid.ID, input UpdateOrganizationInput) (*ent.Organization, error) {
	// Map service input to repository input
	repoInput := RepositoryUpdateInput{}

	if input.Name != nil {
		repoInput.Name = input.Name
	}

	if input.Domain != nil {
		repoInput.Domain = input.Domain
	}

	if input.LogoURL != nil {
		repoInput.LogoURL = input.LogoURL
	}

	if input.Plan != nil {
		repoInput.Plan = input.Plan
	}

	if input.Active != nil {
		repoInput.Active = input.Active
	}

	if input.Metadata != nil {
		repoInput.Metadata = input.Metadata
	}

	return s.repo.Update(ctx, id, repoInput)
}

// Delete deletes an organization
func (s *service) Delete(ctx context.Context, id xid.ID) error {
	return s.repo.Delete(ctx, id)
}

// GetMembers retrieves members of an organization
func (s *service) GetMembers(ctx context.Context, orgID xid.ID, params ListParams) ([]*ent.User, int, error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	return s.repo.GetMembers(ctx, orgID, RepositoryListInput{
		Offset: params.Offset,
		Limit:  params.Limit,
		Search: params.Search,
	})
}

// AddMember adds a user to an organization
func (s *service) AddMember(ctx context.Context, orgID, userID xid.ID, roles []string) error {
	return s.repo.AddMember(ctx, orgID, userID, roles)
}

// RemoveMember removes a user from an organization
func (s *service) RemoveMember(ctx context.Context, orgID, userID xid.ID) error {
	return s.repo.RemoveMember(ctx, orgID, userID)
}

// UpdateMember updates a member's roles in an organization
func (s *service) UpdateMember(ctx context.Context, orgID, userID xid.ID, roles []string) error {
	return s.repo.UpdateMember(ctx, orgID, userID, roles)
}

// IsFeatureEnabled checks if a feature is enabled for an organization
func (s *service) IsFeatureEnabled(ctx context.Context, orgID xid.ID, featureKey string) (bool, error) {
	return s.repo.IsFeatureEnabled(ctx, orgID, featureKey)
}

// GetFeatures retrieves features of an organization
func (s *service) GetFeatures(ctx context.Context, orgID xid.ID) ([]*ent.OrganizationFeature, error) {
	return s.repo.GetFeatures(ctx, orgID)
}

// EnableFeature enables a feature for an organization
func (s *service) EnableFeature(ctx context.Context, orgID xid.ID, featureKey string, settings map[string]interface{}) error {
	return s.repo.EnableFeature(ctx, orgID, featureKey, settings)
}

// DisableFeature disables a feature for an organization
func (s *service) DisableFeature(ctx context.Context, orgID xid.ID, featureKey string) error {
	return s.repo.DisableFeature(ctx, orgID, featureKey)
}
