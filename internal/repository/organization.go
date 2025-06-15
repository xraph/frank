package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// OrganizationRepository defines the interface for organization data access
type OrganizationRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateOrganizationInput) (*ent.Organization, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*ent.Organization, error)
	GetByDomain(ctx context.Context, domain string) (*ent.Organization, error)
	GetByAuthDomain(ctx context.Context, authDomain string) (*ent.Organization, error)
	Update(ctx context.Context, id xid.ID, input UpdateOrganizationInput) (*ent.Organization, error)
	Delete(ctx context.Context, id xid.ID) error
	SoftDelete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params ListOrganizationsParams) (*model.PaginatedOutput[*ent.Organization], error)
	ListActive(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Organization], error)
	ListByPlan(ctx context.Context, plan string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Organization], error)
	// ListByStatus(ctx context.Context, status string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Organization], error)
	Search(ctx context.Context, query string, params SearchOrganizationsParams) (*model.PaginatedOutput[*ent.Organization], error)

	// Domain management
	AddDomain(ctx context.Context, id xid.ID, domain string, verified bool) error
	// RemoveDomain(ctx context.Context, id xid.ID, domain string) error
	// VerifyDomain(ctx context.Context, id xid.ID, domain string) error
	// ListDomains(ctx context.Context, id xid.ID) ([]string, error)
	// GetByVerifiedDomain(ctx context.Context, domain string) (*ent.Organization, error)

	// // Plan and billing operations
	// UpdatePlan(ctx context.Context, id xid.ID, plan string, maxMembers *int) error
	// UpdateBillingInfo(ctx context.Context, id xid.ID, billing map[string]any) error
	// GetPlanLimits(ctx context.Context, id xid.ID) (*PlanLimits, error)
	// CheckPlanLimit(ctx context.Context, id xid.ID, resource string, count int) (bool, error)

	// Platform operations
	GetPlatformOrganization(ctx context.Context) (*ent.Organization, error)
	GetCustomerOrganizations(ctx context.Context, params ListOrganizationsParams) (*model.PaginatedOutput[*ent.Organization], error)

	// Subscription and billing
	UpdateSubscriptionStatus(ctx context.Context, id xid.ID, status organization.SubscriptionStatus) error
	UpdateUsage(ctx context.Context, id xid.ID, input UpdateUsageInput) error
	GetByCustomerID(ctx context.Context, customerID string) (*ent.Organization, error)
	GetBySubscriptionID(ctx context.Context, subscriptionID string) (*ent.Organization, error)

	// Trial management
	StartTrial(ctx context.Context, id xid.ID, trialEndsAt *time.Time) error
	EndTrial(ctx context.Context, id xid.ID) error
	IsTrialActive(ctx context.Context, id xid.ID) (bool, error)

	// User limits and quotas
	GetCurrentUserCounts(ctx context.Context, id xid.ID) (*UserCounts, error)
	CanAddExternalUser(ctx context.Context, id xid.ID) (bool, error)
	CanAddEndUser(ctx context.Context, id xid.ID) (bool, error)
	UpdateUserCounts(ctx context.Context, id xid.ID, counts UpdateUserCountsInput) error

	// Auth service management
	EnableAuthService(ctx context.Context, id xid.ID, config map[string]interface{}) error
	DisableAuthService(ctx context.Context, id xid.ID) error
	UpdateAuthConfig(ctx context.Context, id xid.ID, config map[string]interface{}) error

	// SSO configuration
	EnableSSO(ctx context.Context, id xid.ID, domain string) error
	DisableSSO(ctx context.Context, id xid.ID) error

	// Existence checks
	ExistsBySlug(ctx context.Context, slug string) (bool, error)
	ExistsByDomain(ctx context.Context, domain string) (bool, error)
	ExistsByAuthDomain(ctx context.Context, authDomain string) (bool, error)
}

// CreateOrganizationInput represents input for creating an organization
type CreateOrganizationInput struct {
	Name                   string                          `json:"name"`
	Slug                   string                          `json:"slug"`
	Domain                 *string                         `json:"domain,omitempty"`
	LogoURL                *string                         `json:"logo_url,omitempty"`
	Plan                   string                          `json:"plan"`
	OwnerID                *xid.ID                         `json:"owner_id,omitempty"`
	OrgType                model.OrgType                   `json:"org_type"`
	IsPlatformOrganization bool                            `json:"is_platform_organization"`
	ExternalUserLimit      int                             `json:"external_user_limit"`
	EndUserLimit           int                             `json:"end_user_limit"`
	SSOEnabled             bool                            `json:"sso_enabled"`
	SSODomain              *string                         `json:"sso_domain,omitempty"`
	SubscriptionID         *string                         `json:"subscription_id,omitempty"`
	CustomerID             *string                         `json:"customer_id,omitempty"`
	SubscriptionStatus     organization.SubscriptionStatus `json:"subscription_status"`
	AuthServiceEnabled     bool                            `json:"auth_service_enabled"`
	AuthConfig             map[string]interface{}          `json:"auth_config,omitempty"`
	AuthDomain             *string                         `json:"auth_domain,omitempty"`
	APIRequestLimit        int                             `json:"api_request_limit"`
	Metadata               map[string]interface{}          `json:"metadata,omitempty"`
	Active                 bool                            `json:"active"`
	TrialUsed              bool                            `json:"trial_used"`
	CurrentExternalUsers   int                             `json:"current_external_user"`
	CurrentEndUsers        int                             `json:"current_end_user"`
	TrialEndsAt            *time.Time                      `json:"trial_ends_at"`
}

// UpdateOrganizationInput represents input for updating an organization
type UpdateOrganizationInput struct {
	Name               *string                `json:"name,omitempty"`
	Slug               *string                `json:"slug,omitempty"`
	Domain             *string                `json:"domain,omitempty"`
	LogoURL            *string                `json:"logo_url,omitempty"`
	Plan               *string                `json:"plan,omitempty"`
	Active             *bool                  `json:"active,omitempty"`
	OwnerID            *xid.ID                `json:"owner_id,omitempty"`
	ExternalUserLimit  *int                   `json:"external_user_limit,omitempty"`
	EndUserLimit       *int                   `json:"end_user_limit,omitempty"`
	SSOEnabled         *bool                  `json:"sso_enabled,omitempty"`
	SSODomain          *string                `json:"sso_domain,omitempty"`
	AuthServiceEnabled *bool                  `json:"auth_service_enabled,omitempty"`
	AuthConfig         map[string]interface{} `json:"auth_config,omitempty"`
	AuthDomain         *string                `json:"auth_domain,omitempty"`
	APIRequestLimit    *int                   `json:"api_request_limit,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`

	CustomerID         *string                          `json:"customer_id,omitempty"`
	SubscriptionID     *string                          `json:"subscription_id,omitempty"`
	SubscriptionStatus *organization.SubscriptionStatus `json:"subscription_status,omitempty"`
	TrialEndsAt        *time.Time                       `json:"trial_ends_at,omitempty"`
}

// ListOrganizationsParams represents parameters for listing organizations
type ListOrganizationsParams struct {
	model.PaginationParams
	OrgType            *model.OrgType                   `json:"org_type,omitempty"`
	Plan               *string                          `json:"plan,omitempty"`
	Active             *bool                            `json:"active,omitempty"`
	SubscriptionStatus *organization.SubscriptionStatus `json:"subscription_status,omitempty"`
	AuthServiceEnabled *bool                            `json:"auth_service_enabled,omitempty"`
	SSOEnabled         *bool                            `json:"sso_enabled,omitempty"`
}

// SearchOrganizationsParams represents parameters for searching organizations
type SearchOrganizationsParams struct {
	model.PaginationParams
	OrgType    *model.OrgType `json:"org_type,omitempty"`
	ExactMatch bool           `json:"exact_match"`
}

// UpdateUsageInput represents input for updating organization usage
type UpdateUsageInput struct {
	APIRequestsUsed      *int `json:"api_requests_used,omitempty"`
	CurrentExternalUsers *int `json:"current_external_users,omitempty"`
	CurrentEndUsers      *int `json:"current_end_users,omitempty"`
}

// UpdateUserCountsInput represents input for updating user counts
type UpdateUserCountsInput struct {
	ExternalUsersDelta int `json:"external_users_delta"`
	EndUsersDelta      int `json:"end_users_delta"`
}

// UserCounts represents current user counts for an organization
type UserCounts struct {
	CurrentExternalUsers int `json:"current_external_users"`
	CurrentEndUsers      int `json:"current_end_users"`
	ExternalUserLimit    int `json:"external_user_limit"`
	EndUserLimit         int `json:"end_user_limit"`
}

// organizationRepository implements OrganizationRepository
type organizationRepository struct {
	client *ent.Client
	logger logging.Logger
}

// NewOrganizationRepository creates a new organization repository
func NewOrganizationRepository(client *ent.Client, logger logging.Logger) OrganizationRepository {
	return &organizationRepository{
		client: client,
		logger: logger,
	}
}

// Create creates a new organization
func (r *organizationRepository) Create(ctx context.Context, input CreateOrganizationInput) (*ent.Organization, error) {
	create := r.client.Organization.Create().
		SetName(input.Name).
		SetSlug(input.Slug).
		SetPlan(input.Plan).
		SetOrgType(input.OrgType).
		SetIsPlatformOrganization(input.IsPlatformOrganization).
		SetExternalUserLimit(input.ExternalUserLimit).
		SetEndUserLimit(input.EndUserLimit).
		SetSSOEnabled(input.SSOEnabled).
		SetSubscriptionStatus(input.SubscriptionStatus).
		SetAuthServiceEnabled(input.AuthServiceEnabled).
		SetAPIRequestLimit(input.APIRequestLimit)

	// Set optional fields
	if input.Domain != nil {
		create.SetDomain(*input.Domain)
	}
	if input.LogoURL != nil {
		create.SetLogoURL(*input.LogoURL)
	}
	if input.OwnerID != nil {
		create.SetOwnerID(*input.OwnerID)
	}
	if input.SSODomain != nil {
		create.SetSSODomain(*input.SSODomain)
	}
	if input.SubscriptionID != nil {
		create.SetSubscriptionID(*input.SubscriptionID)
	}
	if input.CustomerID != nil {
		create.SetCustomerID(*input.CustomerID)
	}
	if input.AuthConfig != nil {
		create.SetAuthConfig(input.AuthConfig)
	}
	if input.AuthDomain != nil {
		create.SetAuthDomain(*input.AuthDomain)
	}
	if input.Metadata != nil {
		create.SetMetadata(input.Metadata)
	}

	org, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "Organization with this slug already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create organization: ")
	}

	return org, nil
}

// GetByID retrieves an organization by ID
func (r *organizationRepository) GetByID(ctx context.Context, id xid.ID) (*ent.Organization, error) {
	org, err := r.client.Organization.Query().
		Where(organization.ID(id)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization by ID: ")
	}
	return org, nil
}

// GetBySlug retrieves an organization by slug
func (r *organizationRepository) GetBySlug(ctx context.Context, slug string) (*ent.Organization, error) {
	org, err := r.client.Organization.Query().
		Where(organization.Slug(slug)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization by slug: ")
	}
	return org, nil
}

// GetByDomain retrieves an organization by domain
func (r *organizationRepository) GetByDomain(ctx context.Context, domain string) (*ent.Organization, error) {
	org, err := r.client.Organization.Query().
		Where(organization.Domain(domain)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization by domain: ")
	}
	return org, nil
}

// GetByAuthDomain retrieves an organization by auth domain
func (r *organizationRepository) GetByAuthDomain(ctx context.Context, authDomain string) (*ent.Organization, error) {
	org, err := r.client.Organization.Query().
		Where(organization.AuthDomain(authDomain)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization by auth domain: ")
	}
	return org, nil
}

// Update updates an organization
func (r *organizationRepository) Update(ctx context.Context, id xid.ID, input UpdateOrganizationInput) (*ent.Organization, error) {
	update := r.client.Organization.UpdateOneID(id)

	if input.Name != nil {
		update.SetName(*input.Name)
	}
	if input.Domain != nil {
		update.SetDomain(*input.Domain)
	}
	if input.LogoURL != nil {
		update.SetLogoURL(*input.LogoURL)
	}
	if input.Plan != nil {
		update.SetPlan(*input.Plan)
	}
	if input.Active != nil {
		update.SetActive(*input.Active)
	}
	if input.OwnerID != nil {
		update.SetOwnerID(*input.OwnerID)
	}
	if input.ExternalUserLimit != nil {
		update.SetExternalUserLimit(*input.ExternalUserLimit)
	}
	if input.EndUserLimit != nil {
		update.SetEndUserLimit(*input.EndUserLimit)
	}
	if input.SSOEnabled != nil {
		update.SetSSOEnabled(*input.SSOEnabled)
	}
	if input.SSODomain != nil {
		update.SetSSODomain(*input.SSODomain)
	}
	if input.AuthServiceEnabled != nil {
		update.SetAuthServiceEnabled(*input.AuthServiceEnabled)
	}
	if input.AuthConfig != nil {
		update.SetAuthConfig(input.AuthConfig)
	}
	if input.AuthDomain != nil {
		update.SetAuthDomain(*input.AuthDomain)
	}
	if input.APIRequestLimit != nil {
		update.SetAPIRequestLimit(*input.APIRequestLimit)
	}
	if input.Metadata != nil {
		update.SetMetadata(input.Metadata)
	}

	org, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Organization not found")
		}
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "Organization with this slug already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update organization: ")
	}
	return org, nil
}

// Delete deletes an organization
func (r *organizationRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.Organization.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete organization: ")
	}
	return nil
}

// SoftDelete soft-deletes an organization
func (r *organizationRepository) SoftDelete(ctx context.Context, id xid.ID) error {
	err := r.client.Organization.
		UpdateOneID(id).
		SetActive(false).
		SetDeletedAt(time.Now()).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to soft delete organization")
	}

	return nil
}

// List retrieves organizations with pagination and filtering
func (r *organizationRepository) List(ctx context.Context, params ListOrganizationsParams) (*model.PaginatedOutput[*ent.Organization], error) {
	query := r.client.Organization.Query()

	// Apply filters
	if params.OrgType != nil {
		query = query.Where(organization.OrgTypeEQ(*params.OrgType))
	}
	if params.Plan != nil {
		query = query.Where(organization.Plan(*params.Plan))
	}
	if params.Active != nil {
		query = query.Where(organization.Active(*params.Active))
	}
	if params.SubscriptionStatus != nil {
		query = query.Where(organization.SubscriptionStatusEQ(*params.SubscriptionStatus))
	}
	if params.AuthServiceEnabled != nil {
		query = query.Where(organization.AuthServiceEnabled(*params.AuthServiceEnabled))
	}
	if params.SSOEnabled != nil {
		query = query.Where(organization.SSOEnabled(*params.SSOEnabled))
	}

	// Apply pagination
	return model.WithPaginationAndOptions[*ent.Organization, *ent.OrganizationQuery](ctx, query, params.PaginationParams)
}

// ListActive retrieves paginated active organizations
func (r *organizationRepository) ListActive(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Organization], error) {
	query := r.client.Organization.
		Query().
		Where(organization.Active(true))

	// Apply ordering
	query.Order(ent.Desc(organization.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.Organization, *ent.OrganizationQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list active organizations")
	}

	return result, nil
}

// ListByPlan retrieves paginated organizations by plan
func (r *organizationRepository) ListByPlan(ctx context.Context, plan string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Organization], error) {
	query := r.client.Organization.
		Query().
		Where(organization.Plan(plan))

	// Apply ordering
	query.Order(ent.Desc(organization.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.Organization, *ent.OrganizationQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list organizations by plan %s", plan))
	}

	return result, nil
}

// Search searches for organizations
func (r *organizationRepository) Search(ctx context.Context, query string, params SearchOrganizationsParams) (*model.PaginatedOutput[*ent.Organization], error) {
	q := r.client.Organization.Query()

	// Apply filters
	if params.OrgType != nil {
		q = q.Where(organization.OrgTypeEQ(*params.OrgType))
	}

	// Apply search conditions
	if params.ExactMatch {
		q = q.Where(organization.Or(
			organization.Name(query),
			organization.Slug(query),
			organization.Domain(query),
		))
	} else {
		q = q.Where(organization.Or(
			organization.NameContains(query),
			organization.SlugContains(query),
			organization.DomainContains(query),
		))
	}

	return model.WithPaginationAndOptions[*ent.Organization, *ent.OrganizationQuery](ctx, q, params.PaginationParams)
}

// Domain operations
// AddDomain adds a domain to an organization
func (r *organizationRepository) AddDomain(ctx context.Context, id xid.ID, domain string, verified bool) error {
	// Get current domains
	org, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Check if domain already exists
	for _, existingDomain := range org.Domains {
		if existingDomain == domain {
			return nil // Already exists
		}
	}

	// Add the new domain
	newDomains := append(org.Domains, domain)

	updateBuilder := r.client.Organization.
		UpdateOneID(id).
		SetDomains(newDomains)

	if verified {
		// Add to verified domains as well
		verifiedDomains := org.VerifiedDomains
		verifiedDomains = append(verifiedDomains, domain)
		updateBuilder.SetVerifiedDomains(verifiedDomains)
	}

	err = updateBuilder.Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to add domain to organization")
	}

	return nil
}

// // UpdatePlan updates an organization's plan
// func (r *organizationRepository) UpdatePlan(ctx context.Context, id xid.ID, plan string, maxMembers *int) error {
// 	builder := r.client.Organization.
// 		UpdateOneID(id).
// 		SetPlan(plan)
//
// 	if maxMembers != nil {
// 		builder.SetMaxMembers(*maxMembers)
// 	}
//
// 	err := builder.Exec(ctx)
// 	if err != nil {
// 		if ent.IsNotFound(err) {
// 			return errors.New(errors.CodeNotFound, "Organization not found")
// 		}
// 		return errors.Wrap( err,errors.CodeDatabaseError, "Failed to update organization plan")
// 	}
//
// 	return nil
// }

// GenerateUniqueSlug generates a unique slug based on organization name
func (r *organizationRepository) GenerateUniqueSlug(ctx context.Context, baseName string) (string, error) {
	// Convert to slug format
	baseSlug := strings.ToLower(strings.ReplaceAll(baseName, " ", "-"))
	baseSlug = strings.ReplaceAll(baseSlug, "_", "-")

	// Remove special characters (simplified)
	var cleanSlug strings.Builder
	for _, r := range baseSlug {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			cleanSlug.WriteRune(r)
		}
	}

	slug := cleanSlug.String()

	// Check if it's unique
	exists, err := r.ExistsBySlug(ctx, slug)
	if err != nil {
		return "", err
	}

	if !exists {
		return slug, nil
	}

	// If not unique, append numbers
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

	return "", errors.New(errors.CodeInternalServer, "Unable to generate unique slug")
}

// Platform operations

func (r *organizationRepository) GetPlatformOrganization(ctx context.Context) (*ent.Organization, error) {
	org, err := r.client.Organization.Query().
		Where(organization.IsPlatformOrganization(true)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Platform organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get platform organization: ")
	}
	return org, nil
}

func (r *organizationRepository) GetCustomerOrganizations(ctx context.Context, params ListOrganizationsParams) (*model.PaginatedOutput[*ent.Organization], error) {
	orgType := model.OrgTypeCustomer
	params.OrgType = &orgType
	return r.List(ctx, params)
}

// Subscription and billing operations

func (r *organizationRepository) UpdateSubscriptionStatus(ctx context.Context, id xid.ID, status organization.SubscriptionStatus) error {
	err := r.client.Organization.UpdateOneID(id).
		SetSubscriptionStatus(status).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update subscription status: ")
	}
	return nil
}

func (r *organizationRepository) UpdateUsage(ctx context.Context, id xid.ID, input UpdateUsageInput) error {
	update := r.client.Organization.UpdateOneID(id)

	if input.APIRequestsUsed != nil {
		update.SetAPIRequestsUsed(*input.APIRequestsUsed)
	}
	if input.CurrentExternalUsers != nil {
		update.SetCurrentExternalUsers(*input.CurrentExternalUsers)
	}
	if input.CurrentEndUsers != nil {
		update.SetCurrentEndUsers(*input.CurrentEndUsers)
	}

	err := update.Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update usage: ")
	}
	return nil
}

func (r *organizationRepository) GetByCustomerID(ctx context.Context, customerID string) (*ent.Organization, error) {
	org, err := r.client.Organization.Query().
		Where(organization.CustomerID(customerID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization by customer ID: ")
	}
	return org, nil
}

func (r *organizationRepository) GetBySubscriptionID(ctx context.Context, subscriptionID string) (*ent.Organization, error) {
	org, err := r.client.Organization.Query().
		Where(organization.SubscriptionID(subscriptionID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization by subscription ID: ")
	}
	return org, nil
}

// Trial management

func (r *organizationRepository) StartTrial(ctx context.Context, id xid.ID, trialEndsAt *time.Time) error {
	update := r.client.Organization.UpdateOneID(id).
		SetTrialUsed(true)

	if trialEndsAt != nil {
		update.SetTrialEndsAt(*trialEndsAt)
	}

	err := update.Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to start trial: ")
	}
	return nil
}

func (r *organizationRepository) EndTrial(ctx context.Context, id xid.ID) error {
	err := r.client.Organization.UpdateOneID(id).
		ClearTrialEndsAt().
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to end trial: ")
	}
	return nil
}

func (r *organizationRepository) IsTrialActive(ctx context.Context, id xid.ID) (bool, error) {
	org, err := r.GetByID(ctx, id)
	if err != nil {
		return false, err
	}

	if org.TrialEndsAt == nil {
		return false, nil
	}

	return time.Now().Before(*org.TrialEndsAt), nil
}

// User limits and quotas

func (r *organizationRepository) GetCurrentUserCounts(ctx context.Context, id xid.ID) (*UserCounts, error) {
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

func (r *organizationRepository) CanAddExternalUser(ctx context.Context, id xid.ID) (bool, error) {
	counts, err := r.GetCurrentUserCounts(ctx, id)
	if err != nil {
		return false, err
	}

	return counts.CurrentExternalUsers < counts.ExternalUserLimit, nil
}

func (r *organizationRepository) CanAddEndUser(ctx context.Context, id xid.ID) (bool, error) {
	counts, err := r.GetCurrentUserCounts(ctx, id)
	if err != nil {
		return false, err
	}

	return counts.CurrentEndUsers < counts.EndUserLimit, nil
}

func (r *organizationRepository) UpdateUserCounts(ctx context.Context, id xid.ID, input UpdateUserCountsInput) error {
	org, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	newExternalUsers := org.CurrentExternalUsers + input.ExternalUsersDelta
	newEndUsers := org.CurrentEndUsers + input.EndUsersDelta

	// Ensure counts don't go negative
	if newExternalUsers < 0 {
		newExternalUsers = 0
	}
	if newEndUsers < 0 {
		newEndUsers = 0
	}

	err = r.client.Organization.UpdateOneID(id).
		SetCurrentExternalUsers(newExternalUsers).
		SetCurrentEndUsers(newEndUsers).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update user counts: ")
	}
	return nil
}

// Auth service management

func (r *organizationRepository) EnableAuthService(ctx context.Context, id xid.ID, config map[string]interface{}) error {
	update := r.client.Organization.UpdateOneID(id).
		SetAuthServiceEnabled(true)

	if config != nil {
		update.SetAuthConfig(config)
	}

	err := update.Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to enable auth service: ")
	}
	return nil
}

func (r *organizationRepository) DisableAuthService(ctx context.Context, id xid.ID) error {
	err := r.client.Organization.UpdateOneID(id).
		SetAuthServiceEnabled(false).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to disable auth service: ")
	}
	return nil
}

func (r *organizationRepository) UpdateAuthConfig(ctx context.Context, id xid.ID, config map[string]interface{}) error {
	err := r.client.Organization.UpdateOneID(id).
		SetAuthConfig(config).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update auth config: ")
	}
	return nil
}

// SSO configuration

func (r *organizationRepository) EnableSSO(ctx context.Context, id xid.ID, domain string) error {
	err := r.client.Organization.UpdateOneID(id).
		SetSSOEnabled(true).
		SetSSODomain(domain).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to enable SSO: ")
	}
	return nil
}

func (r *organizationRepository) DisableSSO(ctx context.Context, id xid.ID) error {
	err := r.client.Organization.UpdateOneID(id).
		SetSSOEnabled(false).
		ClearSSODomain().
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to disable SSO: ")
	}
	return nil
}

// Existence checks

func (r *organizationRepository) ExistsBySlug(ctx context.Context, slug string) (bool, error) {
	exists, err := r.client.Organization.Query().
		Where(organization.Slug(slug)).
		Exist(ctx)
	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "failed to check if organization exists by slug: ")
	}
	return exists, nil
}

func (r *organizationRepository) ExistsByDomain(ctx context.Context, domain string) (bool, error) {
	exists, err := r.client.Organization.Query().
		Where(organization.Domain(domain)).
		Exist(ctx)
	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "failed to check if organization exists by domain: ")
	}
	return exists, nil
}

func (r *organizationRepository) ExistsByAuthDomain(ctx context.Context, authDomain string) (bool, error) {
	exists, err := r.client.Organization.Query().
		Where(organization.AuthDomain(authDomain)).
		Exist(ctx)
	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "failed to check if organization exists by auth domain: ")
	}
	return exists, nil
}

// CountActive counts active organizations
func (r *organizationRepository) CountActive(ctx context.Context) (int, error) {
	count, err := r.client.Organization.
		Query().
		Where(organization.Active(true)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count active organizations")
	}

	return count, nil
}
