package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/xraph/frank/internal/models"
	"github.com/xraph/frank/pkg/model"
)

// OrganizationRepository defines the interface for organization data access
type OrganizationRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateOrganizationInput) (*models.Organization, error)
	GetByID(ctx context.Context, id string) (*models.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*models.Organization, error)
	GetByDomain(ctx context.Context, domain string) (*models.Organization, error)
	GetByAuthDomain(ctx context.Context, authDomain string) (*models.Organization, error)
	Update(ctx context.Context, id string, input UpdateOrganizationInput) (*models.Organization, error)
	Delete(ctx context.Context, id string) error
	SoftDelete(ctx context.Context, id string) error

	// List and search operations
	List(ctx context.Context, params ListOrganizationsParams) (*PaginatedOutput[*models.Organization], error)
	ListActive(ctx context.Context, opts PaginationParams) (*PaginatedOutput[*models.Organization], error)
	ListByPlan(ctx context.Context, plan string, opts PaginationParams) (*PaginatedOutput[*models.Organization], error)
	Search(ctx context.Context, query string, params SearchOrganizationsParams) (*PaginatedOutput[*models.Organization], error)

	// Domain management
	AddDomain(ctx context.Context, id string, domain string, verified bool) error

	// Platform operations
	GetPlatformOrganization(ctx context.Context) (*models.Organization, error)
	GetCustomerOrganizations(ctx context.Context, params ListOrganizationsParams) (*PaginatedOutput[*models.Organization], error)

	// Subscription and billing
	UpdateSubscriptionStatus(ctx context.Context, id string, status models.SubscriptionStatus) error
	UpdateUsage(ctx context.Context, id string, input UpdateUsageInput) error
	GetByCustomerID(ctx context.Context, customerID string) (*models.Organization, error)
	GetBySubscriptionID(ctx context.Context, subscriptionID string) (*models.Organization, error)

	// Trial management
	StartTrial(ctx context.Context, id string, trialEndsAt *time.Time) error
	EndTrial(ctx context.Context, id string) error
	IsTrialActive(ctx context.Context, id string) (bool, error)

	// User limits and quotas
	GetCurrentUserCounts(ctx context.Context, id string) (*UserCounts, error)
	CanAddExternalUser(ctx context.Context, id string) (bool, error)
	CanAddEndUser(ctx context.Context, id string) (bool, error)
	UpdateUserCounts(ctx context.Context, id string, counts UpdateUserCountsInput) error

	// Auth service management
	EnableAuthService(ctx context.Context, id string, config map[string]interface{}) error
	DisableAuthService(ctx context.Context, id string) error
	UpdateAuthConfig(ctx context.Context, id string, config map[string]interface{}) error

	// SSO configuration
	EnableSSO(ctx context.Context, id string, domain string) error
	DisableSSO(ctx context.Context, id string) error

	// Existence checks
	ExistsBySlug(ctx context.Context, slug string) (bool, error)
	ExistsByDomain(ctx context.Context, domain string) (bool, error)
	ExistsByAuthDomain(ctx context.Context, authDomain string) (bool, error)

	// Utility
	GenerateUniqueSlug(ctx context.Context, baseName string) (string, error)
	CountActive(ctx context.Context) (int, error)
}

// Input types
type CreateOrganizationInput struct {
	Name                   string
	Slug                   string
	Domain                 *string
	LogoURL                *string
	Plan                   string
	OwnerID                *string
	OrgType                model.OrgType
	IsPlatformOrganization bool
	ExternalUserLimit      int
	EndUserLimit           int
	SSOEnabled             bool
	SSODomain              *string
	SubscriptionID         *string
	CustomerID             *string
	SubscriptionStatus     models.SubscriptionStatus
	AuthServiceEnabled     bool
	AuthConfig             map[string]interface{}
	AuthDomain             *string
	APIRequestLimit        int
	Metadata               map[string]interface{}
	Active                 bool
	TrialUsed              bool
	CurrentExternalUsers   int
	CurrentEndUsers        int
	TrialEndsAt            *time.Time
}

type UpdateOrganizationInput struct {
	Name               *string
	Slug               *string
	Domain             *string
	LogoURL            *string
	Plan               *string
	Active             *bool
	OwnerID            *string
	ExternalUserLimit  *int
	EndUserLimit       *int
	SSOEnabled         *bool
	SSODomain          *string
	AuthServiceEnabled *bool
	AuthConfig         map[string]interface{}
	AuthDomain         *string
	APIRequestLimit    *int
	Metadata           map[string]interface{}
	CustomerID         *string
	SubscriptionID     *string
	SubscriptionStatus *models.SubscriptionStatus
	TrialEndsAt        *time.Time
}

type ListOrganizationsParams struct {
	PaginationParams
	OrgType            *model.OrgType
	Plan               *string
	Active             *bool
	SubscriptionStatus *models.SubscriptionStatus
	AuthServiceEnabled *bool
	SSOEnabled         *bool
}

type SearchOrganizationsParams struct {
	PaginationParams
	OrgType    *model.OrgType
	ExactMatch bool
}

type UpdateUsageInput struct {
	APIRequestsUsed      *int
	CurrentExternalUsers *int
	CurrentEndUsers      *int
}

type UpdateUserCountsInput struct {
	ExternalUsersDelta int
	EndUsersDelta      int
}

type UserCounts struct {
	CurrentExternalUsers int
	CurrentEndUsers      int
	ExternalUserLimit    int
	EndUserLimit         int
}

// organizationRepository implements OrganizationRepository
type organizationRepository struct {
	db *bun.DB
}

// NewOrganizationRepository creates a new organization repository
func NewOrganizationRepository(db *bun.DB) OrganizationRepository {
	return &organizationRepository{db: db}
}

// Create creates a new organization
func (r *organizationRepository) Create(ctx context.Context, input CreateOrganizationInput) (*models.Organization, error) {
	org := &models.Organization{
		Name:                   input.Name,
		Slug:                   input.Slug,
		Domain:                 input.Domain,
		LogoURL:                input.LogoURL,
		Plan:                   input.Plan,
		OwnerID:                input.OwnerID,
		OrgType:                input.OrgType,
		IsPlatformOrganization: input.IsPlatformOrganization,
		ExternalUserLimit:      input.ExternalUserLimit,
		EndUserLimit:           input.EndUserLimit,
		SSOEnabled:             input.SSOEnabled,
		SSODomain:              input.SSODomain,
		SubscriptionID:         input.SubscriptionID,
		CustomerID:             input.CustomerID,
		SubscriptionStatus:     input.SubscriptionStatus,
		AuthServiceEnabled:     input.AuthServiceEnabled,
		AuthConfig:             input.AuthConfig,
		AuthDomain:             input.AuthDomain,
		APIRequestLimit:        input.APIRequestLimit,
		Metadata:               input.Metadata,
		Active:                 input.Active,
		TrialUsed:              input.TrialUsed,
		CurrentExternalUsers:   input.CurrentExternalUsers,
		CurrentEndUsers:        input.CurrentEndUsers,
		TrialEndsAt:            input.TrialEndsAt,
	}

	_, err := r.db.NewInsert().
		Model(org).
		Exec(ctx)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return nil, NewError(CodeConflict, "Organization with this slug already exists")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to create organization")
	}

	return org, nil
}

// GetByID retrieves an organization by ID
func (r *organizationRepository) GetByID(ctx context.Context, id string) (*models.Organization, error) {
	org := new(models.Organization)
	err := r.db.NewSelect().
		Model(org).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Organization not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get organization by ID")
	}
	return org, nil
}

// GetBySlug retrieves an organization by slug
func (r *organizationRepository) GetBySlug(ctx context.Context, slug string) (*models.Organization, error) {
	org := new(models.Organization)
	err := r.db.NewSelect().
		Model(org).
		Where("slug = ?", slug).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Organization not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get organization by slug")
	}
	return org, nil
}

// GetByDomain retrieves an organization by domain
func (r *organizationRepository) GetByDomain(ctx context.Context, domain string) (*models.Organization, error) {
	org := new(models.Organization)
	err := r.db.NewSelect().
		Model(org).
		Where("domain = ?", domain).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Organization not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get organization by domain")
	}
	return org, nil
}

// GetByAuthDomain retrieves an organization by auth domain
func (r *organizationRepository) GetByAuthDomain(ctx context.Context, authDomain string) (*models.Organization, error) {
	org := new(models.Organization)
	err := r.db.NewSelect().
		Model(org).
		Where("auth_domain = ?", authDomain).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Organization not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get organization by auth domain")
	}
	return org, nil
}

// Update updates an organization
func (r *organizationRepository) Update(ctx context.Context, id string, input UpdateOrganizationInput) (*models.Organization, error) {
	org, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	query := r.db.NewUpdate().
		Model(org).
		Where("id = ?", id).
		Where("deleted_at IS NULL")

	if input.Name != nil {
		query = query.Set("name = ?", *input.Name)
		org.Name = *input.Name
	}
	if input.Slug != nil {
		query = query.Set("slug = ?", *input.Slug)
		org.Slug = *input.Slug
	}
	if input.Domain != nil {
		query = query.Set("domain = ?", *input.Domain)
		org.Domain = input.Domain
	}
	if input.LogoURL != nil {
		query = query.Set("logo_url = ?", *input.LogoURL)
		org.LogoURL = input.LogoURL
	}
	if input.Plan != nil {
		query = query.Set("plan = ?", *input.Plan)
		org.Plan = *input.Plan
	}
	if input.Active != nil {
		query = query.Set("active = ?", *input.Active)
		org.Active = *input.Active
	}
	if input.ExternalUserLimit != nil {
		query = query.Set("external_user_limit = ?", *input.ExternalUserLimit)
		org.ExternalUserLimit = *input.ExternalUserLimit
	}
	if input.EndUserLimit != nil {
		query = query.Set("end_user_limit = ?", *input.EndUserLimit)
		org.EndUserLimit = *input.EndUserLimit
	}
	if input.SSOEnabled != nil {
		query = query.Set("sso_enabled = ?", *input.SSOEnabled)
		org.SSOEnabled = *input.SSOEnabled
	}
	if input.SSODomain != nil {
		query = query.Set("sso_domain = ?", *input.SSODomain)
		org.SSODomain = input.SSODomain
	}
	if input.AuthServiceEnabled != nil {
		query = query.Set("auth_service_enabled = ?", *input.AuthServiceEnabled)
		org.AuthServiceEnabled = *input.AuthServiceEnabled
	}
	if input.AuthConfig != nil {
		query = query.Set("auth_config = ?", input.AuthConfig)
		org.AuthConfig = input.AuthConfig
	}
	if input.APIRequestLimit != nil {
		query = query.Set("api_request_limit = ?", *input.APIRequestLimit)
		org.APIRequestLimit = *input.APIRequestLimit
	}
	if input.Metadata != nil {
		query = query.Set("metadata = ?", input.Metadata)
		org.Metadata = input.Metadata
	}

	_, err = query.Exec(ctx)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return nil, NewError(CodeConflict, "Organization with this slug already exists")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to update organization")
	}

	return org, nil
}

// Delete deletes an organization
func (r *organizationRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.NewDelete().
		Model((*models.Organization)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return WrapError(err, CodeDatabaseError, "failed to delete organization")
	}
	return nil
}

// SoftDelete soft-deletes an organization
func (r *organizationRepository) SoftDelete(ctx context.Context, id string) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Set("active = ?", false).
		Set("deleted_at = ?", now).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Exec(ctx)
	if err != nil {
		return WrapError(err, CodeDatabaseError, "failed to soft delete organization")
	}
	return nil
}

// List retrieves organizations with pagination and filtering
func (r *organizationRepository) List(ctx context.Context, params ListOrganizationsParams) (*PaginatedOutput[*models.Organization], error) {
	query := r.db.NewSelect().
		Model((*models.Organization)(nil)).
		Where("deleted_at IS NULL")

	if params.OrgType != nil {
		query = query.Where("org_type = ?", *params.OrgType)
	}
	if params.Plan != nil {
		query = query.Where("plan = ?", *params.Plan)
	}
	if params.Active != nil {
		query = query.Where("active = ?", *params.Active)
	}
	if params.SubscriptionStatus != nil {
		query = query.Where("subscription_status = ?", *params.SubscriptionStatus)
	}
	if params.AuthServiceEnabled != nil {
		query = query.Where("auth_service_enabled = ?", *params.AuthServiceEnabled)
	}
	if params.SSOEnabled != nil {
		query = query.Where("sso_enabled = ?", *params.SSOEnabled)
	}

	return Paginate[*models.Organization](ctx, query, params.PaginationParams)
}

// ListActive retrieves paginated active organizations
func (r *organizationRepository) ListActive(ctx context.Context, opts PaginationParams) (*PaginatedOutput[*models.Organization], error) {
	query := r.db.NewSelect().
		Model((*models.Organization)(nil)).
		Where("active = ?", true).
		Where("deleted_at IS NULL").
		Order("created_at DESC")

	return Paginate[*models.Organization](ctx, query, opts)
}

// ListByPlan retrieves paginated organizations by plan
func (r *organizationRepository) ListByPlan(ctx context.Context, plan string, opts PaginationParams) (*PaginatedOutput[*models.Organization], error) {
	query := r.db.NewSelect().
		Model((*models.Organization)(nil)).
		Where("plan = ?", plan).
		Where("deleted_at IS NULL").
		Order("created_at DESC")

	return Paginate[*models.Organization](ctx, query, opts)
}

// Search searches for organizations
func (r *organizationRepository) Search(ctx context.Context, query string, params SearchOrganizationsParams) (*PaginatedOutput[*models.Organization], error) {
	q := r.db.NewSelect().
		Model((*models.Organization)(nil)).
		Where("deleted_at IS NULL")

	if params.OrgType != nil {
		q = q.Where("org_type = ?", *params.OrgType)
	}

	if params.ExactMatch {
		q = q.Where("name = ? OR slug = ? OR domain = ?", query, query, query)
	} else {
		searchPattern := "%" + query + "%"
		q = q.Where("name ILIKE ? OR slug ILIKE ? OR domain ILIKE ?", searchPattern, searchPattern, searchPattern)
	}

	return Paginate[*models.Organization](ctx, q, params.PaginationParams)
}

// AddDomain adds a domain to an organization
func (r *organizationRepository) AddDomain(ctx context.Context, id string, domain string, verified bool) error {
	org, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Check if domain already exists
	for _, existingDomain := range org.Domains {
		if existingDomain == domain {
			return nil
		}
	}

	newDomains := append(org.Domains, domain)

	query := r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Set("domains = ?", newDomains).
		Where("id = ?", id)

	if verified {
		verifiedDomains := org.VerifiedDomains
		verifiedDomains = append(verifiedDomains, domain)
		query = query.Set("verified_domains = ?", verifiedDomains)
	}

	_, err = query.Exec(ctx)
	return err
}

// GetPlatformOrganization retrieves the platform organization
func (r *organizationRepository) GetPlatformOrganization(ctx context.Context) (*models.Organization, error) {
	org := new(models.Organization)
	err := r.db.NewSelect().
		Model(org).
		Where("is_platform_organization = ?", true).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Platform organization not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get platform organization")
	}
	return org, nil
}

// GetCustomerOrganizations retrieves customer organizations
func (r *organizationRepository) GetCustomerOrganizations(ctx context.Context, params ListOrganizationsParams) (*PaginatedOutput[*models.Organization], error) {
	orgType := model.OrgTypeCustomer
	params.OrgType = &orgType
	return r.List(ctx, params)
}

// UpdateSubscriptionStatus updates subscription status
func (r *organizationRepository) UpdateSubscriptionStatus(ctx context.Context, id string, status models.SubscriptionStatus) error {
	_, err := r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Set("subscription_status = ?", status).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Exec(ctx)
	return err
}

// UpdateUsage updates usage metrics
func (r *organizationRepository) UpdateUsage(ctx context.Context, id string, input UpdateUsageInput) error {
	query := r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Where("id = ?", id).
		Where("deleted_at IS NULL")

	if input.APIRequestsUsed != nil {
		query = query.Set("api_requests_used = ?", *input.APIRequestsUsed)
	}
	if input.CurrentExternalUsers != nil {
		query = query.Set("current_external_users = ?", *input.CurrentExternalUsers)
	}
	if input.CurrentEndUsers != nil {
		query = query.Set("current_end_users = ?", *input.CurrentEndUsers)
	}

	_, err := query.Exec(ctx)
	return err
}

// GetByCustomerID retrieves organization by customer ID
func (r *organizationRepository) GetByCustomerID(ctx context.Context, customerID string) (*models.Organization, error) {
	org := new(models.Organization)
	err := r.db.NewSelect().
		Model(org).
		Where("customer_id = ?", customerID).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Organization not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get organization by customer ID")
	}
	return org, nil
}

// GetBySubscriptionID retrieves organization by subscription ID
func (r *organizationRepository) GetBySubscriptionID(ctx context.Context, subscriptionID string) (*models.Organization, error) {
	org := new(models.Organization)
	err := r.db.NewSelect().
		Model(org).
		Where("subscription_id = ?", subscriptionID).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Organization not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get organization by subscription ID")
	}
	return org, nil
}

// StartTrial starts a trial
func (r *organizationRepository) StartTrial(ctx context.Context, id string, trialEndsAt *time.Time) error {
	query := r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Set("trial_used = ?", true).
		Where("id = ?", id).
		Where("deleted_at IS NULL")

	if trialEndsAt != nil {
		query = query.Set("trial_ends_at = ?", *trialEndsAt)
	}

	_, err := query.Exec(ctx)
	return err
}

// EndTrial ends a trial
func (r *organizationRepository) EndTrial(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Set("trial_ends_at = NULL").
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Exec(ctx)
	return err
}

// IsTrialActive checks if trial is active
func (r *organizationRepository) IsTrialActive(ctx context.Context, id string) (bool, error) {
	org, err := r.GetByID(ctx, id)
	if err != nil {
		return false, err
	}

	if org.TrialEndsAt == nil {
		return false, nil
	}

	return time.Now().Before(*org.TrialEndsAt), nil
}

// GetCurrentUserCounts retrieves current user counts
func (r *organizationRepository) GetCurrentUserCounts(ctx context.Context, id string) (*UserCounts, error) {
	org, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return &UserCounts{
		CurrentExternalUsers: org.CurrentExternalUsers,
		CurrentEndUsers:      org.CurrentEndUsers,
		ExternalUserLimit:    org.ExternalUserLimit,
		EndUserLimit:         org.EndUserLimit,
	}, nil
}

// CanAddExternalUser checks if can add external user
func (r *organizationRepository) CanAddExternalUser(ctx context.Context, id string) (bool, error) {
	counts, err := r.GetCurrentUserCounts(ctx, id)
	if err != nil {
		return false, err
	}
	return counts.CurrentExternalUsers < counts.ExternalUserLimit, nil
}

// CanAddEndUser checks if can add end user
func (r *organizationRepository) CanAddEndUser(ctx context.Context, id string) (bool, error) {
	counts, err := r.GetCurrentUserCounts(ctx, id)
	if err != nil {
		return false, err
	}
	return counts.CurrentEndUsers < counts.EndUserLimit, nil
}

// UpdateUserCounts updates user counts
func (r *organizationRepository) UpdateUserCounts(ctx context.Context, id string, input UpdateUserCountsInput) error {
	org, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	newExternalUsers := org.CurrentExternalUsers + input.ExternalUsersDelta
	newEndUsers := org.CurrentEndUsers + input.EndUsersDelta

	if newExternalUsers < 0 {
		newExternalUsers = 0
	}
	if newEndUsers < 0 {
		newEndUsers = 0
	}

	_, err = r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Set("current_external_users = ?", newExternalUsers).
		Set("current_end_users = ?", newEndUsers).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// EnableAuthService enables auth service
func (r *organizationRepository) EnableAuthService(ctx context.Context, id string, config map[string]interface{}) error {
	query := r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Set("auth_service_enabled = ?", true).
		Where("id = ?", id).
		Where("deleted_at IS NULL")

	if config != nil {
		query = query.Set("auth_config = ?", config)
	}

	_, err := query.Exec(ctx)
	return err
}

// DisableAuthService disables auth service
func (r *organizationRepository) DisableAuthService(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Set("auth_service_enabled = ?", false).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Exec(ctx)
	return err
}

// UpdateAuthConfig updates auth config
func (r *organizationRepository) UpdateAuthConfig(ctx context.Context, id string, config map[string]interface{}) error {
	_, err := r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Set("auth_config = ?", config).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Exec(ctx)
	return err
}

// EnableSSO enables SSO
func (r *organizationRepository) EnableSSO(ctx context.Context, id string, domain string) error {
	_, err := r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Set("sso_enabled = ?", true).
		Set("sso_domain = ?", domain).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Exec(ctx)
	return err
}

// DisableSSO disables SSO
func (r *organizationRepository) DisableSSO(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.Organization)(nil)).
		Set("sso_enabled = ?", false).
		Set("sso_domain = NULL").
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Exec(ctx)
	return err
}

// ExistsBySlug checks if organization exists by slug
func (r *organizationRepository) ExistsBySlug(ctx context.Context, slug string) (bool, error) {
	count, err := r.db.NewSelect().
		Model((*models.Organization)(nil)).
		Where("slug = ?", slug).
		Where("deleted_at IS NULL").
		Count(ctx)
	return count > 0, err
}

// ExistsByDomain checks if organization exists by domain
func (r *organizationRepository) ExistsByDomain(ctx context.Context, domain string) (bool, error) {
	count, err := r.db.NewSelect().
		Model((*models.Organization)(nil)).
		Where("domain = ?", domain).
		Where("deleted_at IS NULL").
		Count(ctx)
	return count > 0, err
}

// ExistsByAuthDomain checks if organization exists by auth domain
func (r *organizationRepository) ExistsByAuthDomain(ctx context.Context, authDomain string) (bool, error) {
	count, err := r.db.NewSelect().
		Model((*models.Organization)(nil)).
		Where("auth_domain = ?", authDomain).
		Where("deleted_at IS NULL").
		Count(ctx)
	return count > 0, err
}

// GenerateUniqueSlug generates a unique slug
func (r *organizationRepository) GenerateUniqueSlug(ctx context.Context, baseName string) (string, error) {
	baseSlug := strings.ToLower(strings.ReplaceAll(baseName, " ", "-"))
	baseSlug = strings.ReplaceAll(baseSlug, "_", "-")

	var cleanSlug strings.Builder
	for _, r := range baseSlug {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			cleanSlug.WriteRune(r)
		}
	}

	slug := cleanSlug.String()

	exists, err := r.ExistsBySlug(ctx, slug)
	if err != nil {
		return "", err
	}

	if !exists {
		return slug, nil
	}

	for i := 1; i <= 100; i++ {
		candidate := fmt.Sprintf("%s-%d", slug, i)
		exists, err := r.ExistsBySlug(ctx, candidate)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}

	return "", NewError(CodeInternalServer, "Unable to generate unique slug")
}

// CountActive counts active organizations
func (r *organizationRepository) CountActive(ctx context.Context) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.Organization)(nil)).
		Where("active = ?", true).
		Where("deleted_at IS NULL").
		Count(ctx)
	return count, err
}
