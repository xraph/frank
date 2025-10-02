package organization

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/organization"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/contexts"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"github.com/xraph/frank/pkg/services/rbac"
	"github.com/xraph/frank/pkg/services/sso"
)

// Service defines the organization service interface
type Service interface {
	// Organization CRUD operations
	CreateOrganization(ctx context.Context, req model.CreateOrganizationRequest) (*model.Organization, error)
	CreatePlatformOrganization(ctx context.Context, req model.CreateOrganizationPlatformRequest) (*model.Organization, error)
	GetOrganization(ctx context.Context, id xid.ID) (*model.Organization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*model.Organization, error)
	GetOrganizationByDomain(ctx context.Context, domain string) (*model.Organization, error)
	UpdateOrganization(ctx context.Context, id xid.ID, req model.UpdateOrganizationRequest) (*model.Organization, error)
	DeleteOrganization(ctx context.Context, id xid.ID, req model.DeleteOrganizationRequest) error
	ListOrganizations(ctx context.Context, req model.OrganizationListRequest) (*model.OrganizationListResponse, error)
	ListAllOrganizations(ctx context.Context, req model.OrganizationListRequest) (*model.PlatformOrganizationListResponse, error)
	ListUserOrganizations(ctx context.Context, id xid.ID, req model.OrganizationListRequest) (*model.OrganizationListResponse, error)

	// Domain management
	AddDomain(ctx context.Context, orgID xid.ID, domain string) error
	RemoveDomain(ctx context.Context, orgID xid.ID, domain string) error
	VerifyDomain(ctx context.Context, req model.DomainVerificationRequest) (*model.DomainVerificationResponse, error)
	ListDomains(ctx context.Context, orgID xid.ID) ([]string, error)
	GetDomainVerificationStatus(ctx context.Context, orgID xid.ID, domain string) (*model.DomainVerificationResponse, error)

	// Organization settings
	GetOrganizationSettings(ctx context.Context, orgID xid.ID) (*model.OrganizationSettings, error)
	UpdateOrganizationSettings(ctx context.Context, orgID xid.ID, req model.UpdateOrganizationSettingsRequest) (*model.OrganizationSettings, error)

	// Subscription and billing management
	GetOrganizationBilling(ctx context.Context, orgID xid.ID) (*model.OrganizationBilling, error)
	UpdateBilling(ctx context.Context, orgID xid.ID, req model.UpdateBillingRequest) (*model.OrganizationBilling, error)
	GetOrganizationUsage(ctx context.Context, orgID xid.ID) (*model.OrganizationUsage, error)
	UpdateUsage(ctx context.Context, orgID xid.ID, usage model.OrganizationUsage) error

	// Trial management
	StartTrial(ctx context.Context, orgID xid.ID, duration time.Duration) error
	EndTrial(ctx context.Context, orgID xid.ID) error
	ExtendTrial(ctx context.Context, orgID xid.ID, extension time.Duration) error
	GetTrialStatus(ctx context.Context, orgID xid.ID) (*TrialStatus, error)

	// Feature management
	EnableFeature(ctx context.Context, orgID xid.ID, featureName string, config map[string]interface{}) error
	DisableFeature(ctx context.Context, orgID xid.ID, featureName string) error
	IsFeatureEnabled(ctx context.Context, orgID xid.ID, featureName string) (bool, error)
	GetFeatureConfig(ctx context.Context, orgID xid.ID, featureKey string) (map[string]interface{}, error)
	ListEnabledFeatures(ctx context.Context, orgID xid.ID) ([]model.FeatureSummary, error)

	// Auth service management
	EnableAuthService(ctx context.Context, orgID xid.ID, config map[string]interface{}) error
	DisableAuthService(ctx context.Context, orgID xid.ID) error
	UpdateAuthConfig(ctx context.Context, orgID xid.ID, config map[string]interface{}) error
	GetAuthConfig(ctx context.Context, orgID xid.ID) (map[string]interface{}, error)

	// SSO management
	EnableSSO(ctx context.Context, orgID xid.ID, domain string, config map[string]interface{}) error
	DisableSSO(ctx context.Context, orgID xid.ID) error
	UpdateSSOConfig(ctx context.Context, orgID xid.ID, config map[string]interface{}) error

	// User limits and quotas
	GetUserLimits(ctx context.Context, orgID xid.ID) (*UserLimits, error)
	UpdateUserLimits(ctx context.Context, orgID xid.ID, limits UserLimits) error
	CheckUserLimit(ctx context.Context, orgID xid.ID, userType string) (bool, error)
	GetCurrentUserCounts(ctx context.Context, orgID xid.ID) (*UserCounts, error)

	// Ownership management
	TransferOwnership(ctx context.Context, orgID xid.ID, req model.TransferUserOwnershipRequest) error
	GetOwner(ctx context.Context, orgID xid.ID) (*model.UserSummary, error)
	GetOwnershipHistory(ctx context.Context, orgID xid.ID) ([]OwnershipTransfer, error)

	// Organization analytics
	GetOrganizationStats(ctx context.Context, orgID xid.ID) (*model.OrgStats, error)
	GetOrganizationActivity(ctx context.Context, orgID xid.ID, days int) (*OrganizationActivity, error)
	GetGrowthMetrics(ctx context.Context, orgID xid.ID, period string) (*GrowthMetrics, error)
	GetOrganizationAnalytics(ctx context.Context, orgID xid.ID, days int) (*OrganizationAnalytics, error)
	GetComplianceReport(ctx context.Context, orgID xid.ID) (*ComplianceReport, error)

	// Platform operations
	GetPlatformOrganization(ctx context.Context) (*model.Organization, error)
	GetCustomerOrganizations(ctx context.Context, req model.OrganizationListRequest) (*model.OrganizationListResponse, error)

	// Validation and helpers
	ValidateOrganizationName(ctx context.Context, name string, excludeOrgID *xid.ID) error
	ValidateSlug(ctx context.Context, slug string, excludeOrgID *xid.ID) error
	ValidateDomain(ctx context.Context, domain string, excludeOrgID *xid.ID) error
	GenerateSlug(ctx context.Context, name string) (string, error)
	SuggestSimilarOrganizations(ctx context.Context, name string, limit int) ([]model.OrganizationSummary, error)

	// Plan and subscription management
	UpdatePlan(ctx context.Context, orgID xid.ID, plan string) (*model.Organization, error)
	GetPlanLimits(ctx context.Context, orgID xid.ID) (*PlanLimits, error)
	CheckPlanLimit(ctx context.Context, orgID xid.ID, resource string, requestedCount int) (*PlanLimitCheck, error)
	UpdateSubscriptionStatus(ctx context.Context, orgID xid.ID, status organization.SubscriptionStatus) error

	// Organization settings
	GetSettings(ctx context.Context, orgID xid.ID) (*model.OrganizationSettings, error)
	UpdateSettings(ctx context.Context, orgID xid.ID, req model.UpdateOrganizationSettingsRequest) (*model.OrganizationSettings, error)

	// Billing and customer management
	UpdateBillingInfo(ctx context.Context, orgID xid.ID, req model.UpdateBillingRequest) (*model.OrganizationBilling, error)
	GetBillingInfo(ctx context.Context, orgID xid.ID) (*model.OrganizationBilling, error)
	SetCustomerID(ctx context.Context, orgID xid.ID, customerID string) error
	SetSubscriptionID(ctx context.Context, orgID xid.ID, subscriptionID string) error

	GetDefaultLimitsForPlan(plan string) UserLimits
}

// service implements the organization service
type service struct {
	roleSeeder     *rbac.RBACSeeder
	orgRepo        repository.OrganizationRepository
	roleRepo       repository.RoleRepository
	membershipRepo repository.MembershipRepository
	userRepo       repository.UserRepository
	auditRepo      repository.AuditRepository
	ssoService     sso.Service
	memberService  MembershipService
	logger         logging.Logger
}

// NewService creates a new organization service instance
func NewService(
	repo repository.Repository,
	ssoService sso.Service,
	roleSeeder *rbac.RBACSeeder,
	memberService MembershipService,
	logger logging.Logger,
) Service {
	return &service{
		orgRepo:        repo.Organization(),
		roleRepo:       repo.Role(),
		membershipRepo: repo.Membership(),
		userRepo:       repo.User(),
		auditRepo:      repo.Audit(),
		roleSeeder:     roleSeeder,
		ssoService:     ssoService,
		memberService:  memberService,
		logger:         logger,
	}
}

// CreateOrganization creates a new organization
func (s *service) CreateOrganization(ctx context.Context, req model.CreateOrganizationRequest) (*model.Organization, error) {
	s.logger.Info("Creating new organization", logging.String("name", req.Name))

	user, err := contexts.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	// Validate organization name
	if err := s.ValidateOrganizationName(ctx, req.Name, nil); err != nil {
		return nil, err
	}

	// Generate slug if not provided
	slug := req.Slug
	if slug == "" {
		slug = s.generateSlug(req.Name)
	}

	// Validate slug uniqueness
	if err := s.ValidateOrganizationSlug(ctx, slug, nil); err != nil {
		return nil, err
	}

	// Validate domain if provided
	if req.Domain != nil {
		if err := s.ValidateDomain(ctx, *req.Domain, nil); err != nil {
			return nil, err
		}
	}

	// Parse organization type
	orgType := model.OrgTypeCustomer

	// Set default limits based on plan
	limits := s.GetDefaultLimitsForPlan(req.Plan)

	// Create organization input
	input := repository.CreateOrganizationInput{
		Name:                 req.Name,
		Slug:                 slug,
		Domain:               req.Domain,
		LogoURL:              req.LogoURL,
		Plan:                 req.Plan,
		OrgType:              orgType,
		ExternalUserLimit:    6,
		EndUserLimit:         100,
		AuthServiceEnabled:   true,
		Active:               true,
		TrialUsed:            false,
		SubscriptionStatus:   organization.SubscriptionStatusActive,
		APIRequestLimit:      limits.APIRequestLimit,
		CurrentExternalUsers: 0,
		CurrentEndUsers:      0,
		OwnerID:              &user.ID,
	}

	// // Set trial period if requested
	// if req.CreateTrialPeriod {
	// 	trialEnd := time.Now().Add(14 * 24 * time.Hour) // 14 days trial
	// 	input.TrialEndsAt = &trialEnd
	// }

	// Create organization
	entOrg, err := s.orgRepo.Create(ctx, input)
	if err != nil {
		s.logger.Error("Failed to create organization", logging.Error(err))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create organization")
	}

	role, err := s.roleRepo.GetRoleByName(ctx, string(model.RoleOrganizationOwner), xid.NilID())
	if err != nil {
		return nil, err
	}

	_, err = s.membershipRepo.Create(ctx, repository.CreateMembershipInput{
		OrganizationID:   entOrg.ID,
		UserID:           entOrg.OwnerID,
		IsPrimaryContact: true,
		IsBillingContact: true,
		Status:           model.MembershipStatusActive,
		RoleID:           role.ID,
	})
	if err != nil {
		return nil, err
	}

	// Convert to model
	modelOrg := ConvertEntOrgToModel(entOrg)

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.created",
		Resource:       "organization",
		ResourceID:     &modelOrg.ID,
		Status:         "success",
		OrganizationID: &modelOrg.ID,
		Details: map[string]interface{}{
			"name":     req.Name,
			"slug":     slug,
			"org_type": orgType,
			"plan":     req.Plan,
		},
	})

	s.logger.Info("Organization created successfully",
		logging.String("org_id", modelOrg.ID.String()),
		logging.String("name", modelOrg.Name))

	return modelOrg, nil
}

// CreatePlatformOrganization creates a new organization
func (s *service) CreatePlatformOrganization(ctx context.Context, req model.CreateOrganizationPlatformRequest) (*model.Organization, error) {
	s.logger.Info("Creating new organization", logging.String("name", req.Name))

	// Validate organization name
	if err := s.ValidateOrganizationName(ctx, req.Name, nil); err != nil {
		return nil, err
	}

	// Generate slug if not provided
	slug := req.Slug
	if slug == "" {
		slug = s.generateSlug(req.Name)
	}

	// Validate slug uniqueness
	if err := s.ValidateOrganizationSlug(ctx, slug, nil); err != nil {
		return nil, err
	}

	// Validate domain if provided
	if req.Domain != nil {
		if err := s.ValidateDomain(ctx, *req.Domain, nil); err != nil {
			return nil, err
		}
	}

	// Parse organization type
	orgType, err := s.parseOrgType(req.OrgType)
	if err != nil {
		return nil, err
	}

	// Set default limits based on plan
	limits := s.GetDefaultLimitsForPlan(req.Plan)

	// Create organization input
	input := repository.CreateOrganizationInput{
		Name:                 req.Name,
		Slug:                 slug,
		Domain:               req.Domain,
		LogoURL:              req.LogoURL,
		Plan:                 req.Plan,
		OrgType:              orgType,
		ExternalUserLimit:    req.ExternalUserLimit,
		EndUserLimit:         req.EndUserLimit,
		AuthServiceEnabled:   req.EnableAuthService,
		AuthConfig:           req.AuthConfig,
		Metadata:             req.Metadata,
		Active:               true,
		TrialUsed:            false,
		SubscriptionStatus:   organization.SubscriptionStatusActive,
		APIRequestLimit:      limits.APIRequestLimit,
		CurrentExternalUsers: 0,
		CurrentEndUsers:      0,
	}

	// Set trial period if requested
	if req.CreateTrialPeriod {
		trialEnd := time.Now().Add(14 * 24 * time.Hour) // 14 days trial
		input.TrialEndsAt = &trialEnd
	}

	// Create organization
	entOrg, err := s.orgRepo.Create(ctx, input)
	if err != nil {
		s.logger.Error("Failed to create organization", logging.Error(err))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create organization")
	}

	// Create owner if email provided
	if req.OwnerEmail != "" {
		if err := s.createOrganizationOwner(ctx, entOrg.ID, req.OwnerEmail); err != nil {
			s.logger.Warn("Failed to create organization owner", logging.Error(err))
			// Don't fail the organization creation for owner creation failure
		} else {
			entOrg, _ = s.orgRepo.GetByID(ctx, entOrg.ID)
			role, err := s.roleRepo.GetRoleByName(ctx, string(model.RoleOrganizationOwner), xid.NilID())
			if err != nil {
				return nil, err
			}

			_, err = s.membershipRepo.Create(ctx, repository.CreateMembershipInput{
				OrganizationID:   entOrg.ID,
				UserID:           entOrg.OwnerID,
				IsPrimaryContact: true,
				IsBillingContact: true,
				Status:           model.MembershipStatusActive,
				RoleID:           role.ID,
			})
			if err != nil {
				return nil, err
			}
		}

	}

	// Convert to model
	modelOrg := ConvertEntOrgToModel(entOrg)

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.created",
		Resource:       "organization",
		ResourceID:     &modelOrg.ID,
		Status:         "success",
		OrganizationID: &modelOrg.ID,
		Details: map[string]interface{}{
			"name":     req.Name,
			"slug":     slug,
			"org_type": req.OrgType,
			"plan":     req.Plan,
		},
	})

	s.logger.Info("Organization created successfully",
		logging.String("org_id", modelOrg.ID.String()),
		logging.String("name", modelOrg.Name))

	return modelOrg, nil
}

// GetOrganization retrieves an organization by ID
func (s *service) GetOrganization(ctx context.Context, id xid.ID) (*model.Organization, error) {
	entOrg, err := s.orgRepo.GetByID(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	return ConvertEntOrgToModel(entOrg), nil
}

// GetOrganizationBySlug retrieves an organization by slug
func (s *service) GetOrganizationBySlug(ctx context.Context, slug string) (*model.Organization, error) {
	entOrg, err := s.orgRepo.GetBySlug(ctx, slug)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		if errors.IsNotFound(err) {
			return nil, err
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization by slug")
	}

	return ConvertEntOrgToModel(entOrg), nil
}

// GetOrganizationByDomain retrieves an organization by domain
func (s *service) GetOrganizationByDomain(ctx context.Context, domain string) (*model.Organization, error) {
	entOrg, err := s.orgRepo.GetByDomain(ctx, domain)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization by domain")
	}

	return ConvertEntOrgToModel(entOrg), nil
}

// UpdateOrganization updates an organization
func (s *service) UpdateOrganization(ctx context.Context, id xid.ID, req model.UpdateOrganizationRequest) (*model.Organization, error) {
	s.logger.Info("Updating organization", logging.String("org_id", id.String()))

	// Get existing organization
	existingOrg, err := s.orgRepo.GetByID(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	// Track changes for audit log
	changes := make(map[string]interface{})

	// Create update input
	input := repository.UpdateOrganizationInput{}

	if req.Name != nil && *req.Name != existingOrg.Name {
		if err := s.ValidateOrganizationName(ctx, *req.Name, &id); err != nil {
			return nil, err
		}
		input.Name = req.Name
		changes["name"] = map[string]interface{}{
			"old": existingOrg.Name,
			"new": *req.Name,
		}
	}

	if req.Slug != nil && *req.Slug != existingOrg.Slug {
		if err := s.ValidateOrganizationSlug(ctx, *req.Slug, &id); err != nil {
			return nil, err
		}
		input.Slug = req.Slug
		changes["slug"] = map[string]interface{}{
			"old": existingOrg.Slug,
			"new": *req.Slug,
		}
	}

	if req.Domain != nil && *req.Domain != existingOrg.Domain {
		if *req.Domain != "" {
			if err := s.ValidateDomain(ctx, *req.Domain, nil); err != nil {
				return nil, err
			}
		}
		input.Domain = req.Domain
		changes["domain"] = map[string]interface{}{
			"old": existingOrg.Domain,
			"new": *req.Domain,
		}
	}

	if req.LogoURL != nil {
		input.LogoURL = req.LogoURL
		changes["logo_url"] = map[string]interface{}{
			"old": existingOrg.LogoURL,
			"new": *req.LogoURL,
		}
	}

	if req.Plan != nil {
		input.Plan = req.Plan
		changes["plan"] = map[string]interface{}{
			"old": existingOrg.Plan,
			"new": *req.Plan,
		}

		// Update limits based on new plan
		limits := s.GetDefaultLimitsForPlan(*req.Plan)
		input.ExternalUserLimit = &limits.ExternalUserLimit
		input.EndUserLimit = &limits.EndUserLimit
		input.APIRequestLimit = &limits.APIRequestLimit
	}

	if req.ExternalUserLimit != nil {
		input.ExternalUserLimit = req.ExternalUserLimit
		changes["external_user_limit"] = map[string]interface{}{
			"old": existingOrg.ExternalUserLimit,
			"new": *req.ExternalUserLimit,
		}
	}

	if req.EndUserLimit != nil {
		input.EndUserLimit = req.EndUserLimit
		changes["end_user_limit"] = map[string]interface{}{
			"old": existingOrg.EndUserLimit,
			"new": *req.EndUserLimit,
		}
	}

	if req.SSOEnabled != nil {
		input.SSOEnabled = req.SSOEnabled
		changes["sso_enabled"] = map[string]interface{}{
			"old": existingOrg.SSOEnabled,
			"new": *req.SSOEnabled,
		}
	}

	if req.SSODomain != nil {
		input.SSODomain = req.SSODomain
		changes["sso_domain"] = map[string]interface{}{
			"old": existingOrg.SSODomain,
			"new": *req.SSODomain,
		}
	}

	if req.AuthServiceEnabled != nil {
		input.AuthServiceEnabled = req.AuthServiceEnabled
		changes["auth_service_enabled"] = map[string]interface{}{
			"old": existingOrg.AuthServiceEnabled,
			"new": *req.AuthServiceEnabled,
		}
	}

	if req.AuthConfig != nil {
		input.AuthConfig = req.AuthConfig
		changes["auth_config"] = map[string]interface{}{
			"old": existingOrg.AuthConfig,
			"new": req.AuthConfig,
		}
	}

	if req.AuthDomain != nil {
		input.AuthDomain = req.AuthDomain
		changes["auth_domain"] = map[string]interface{}{
			"old": existingOrg.AuthDomain,
			"new": *req.AuthDomain,
		}
	}

	if req.APIRequestLimit != nil {
		input.APIRequestLimit = req.APIRequestLimit
		changes["api_request_limit"] = map[string]interface{}{
			"old": existingOrg.APIRequestLimit,
			"new": *req.APIRequestLimit,
		}
	}

	if req.Active != nil {
		input.Active = req.Active
		changes["active"] = map[string]interface{}{
			"old": existingOrg.Active,
			"new": *req.Active,
		}
	}

	if req.Metadata != nil {
		input.Metadata = req.Metadata
		changes["metadata"] = map[string]interface{}{
			"old": existingOrg.Metadata,
			"new": req.Metadata,
		}
	}

	// Update organization if there are changes
	if len(changes) == 0 {
		return ConvertEntOrgToModel(existingOrg), nil
	}

	updatedOrg, err := s.orgRepo.Update(ctx, id, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update organization")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.updated",
		Resource:       "organization",
		ResourceID:     &id,
		Status:         "success",
		OrganizationID: &id,
		Changes:        changes,
		Details: map[string]interface{}{
			"updated_fields": s.getUpdatedFieldsList(changes),
		},
	})

	s.logger.Info("Organization updated successfully",
		logging.String("org_id", id.String()),
		logging.Int("fields_updated", len(changes)))

	return ConvertEntOrgToModel(updatedOrg), nil
}

// DeleteOrganization deletes an organization
func (s *service) DeleteOrganization(ctx context.Context, id xid.ID, req model.DeleteOrganizationRequest) error {
	s.logger.Info("Deleting organization", logging.String("org_id", id.String()))

	if !req.Confirm {
		return errors.New(errors.CodeBadRequest, "organization deletion must be confirmed")
	}

	// Get organization to validate existence
	existingOrg, err := s.orgRepo.GetByID(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	// Check if organization can be deleted (not platform org, no dependencies, etc.)
	if existingOrg.IsPlatformOrganization {
		return errors.New(errors.CodeBadRequest, "cannot delete platform organization")
	}

	// TODO: Check for active subscriptions, members, etc.
	// TODO: Handle data retention requirements
	// TODO: Notify members if requested

	// Soft delete organization
	if err := s.orgRepo.SoftDelete(ctx, id); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to delete organization")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.deleted",
		Resource:       "organization",
		ResourceID:     &id,
		Status:         "success",
		OrganizationID: &id,
		Details: map[string]interface{}{
			"reason":         req.Reason,
			"data_retention": req.DataRetention,
			"notify_members": req.NotifyMembers,
		},
	})

	s.logger.Info("Organization deleted successfully", logging.String("org_id", id.String()))
	return nil
}

// ValidateOrganizationName validates organization name
func (s *service) ValidateOrganizationName(ctx context.Context, name string, excludeOrgID *xid.ID) error {
	if name == "" {
		return errors.New(errors.CodeBadRequest, "organization name is required")
	}

	if len(strings.TrimSpace(name)) < 2 {
		return errors.New(errors.CodeBadRequest, "organization name must be at least 2 characters")
	}

	if len(name) > 100 {
		return errors.New(errors.CodeBadRequest, "organization name is too long")
	}

	// Additional validation rules can be added here
	return nil
}

// ValidateOrganizationSlug validates organization slug
func (s *service) ValidateOrganizationSlug(ctx context.Context, slug string, excludeOrgID *xid.ID) error {
	if slug == "" {
		return errors.New(errors.CodeBadRequest, "organization slug is required")
	}

	if len(slug) < 2 {
		return errors.New(errors.CodeBadRequest, "organization slug must be at least 2 characters")
	}

	if len(slug) > 50 {
		return errors.New(errors.CodeBadRequest, "organization slug is too long")
	}

	// Validate slug format (alphanumeric, hyphens, underscores)
	if !s.isValidSlug(slug) {
		return errors.New(errors.CodeBadRequest, "organization slug contains invalid characters")
	}

	// Check reserved slugs
	if s.isReservedSlug(slug) {
		return errors.New(errors.CodeBadRequest, "organization slug is reserved")
	}

	// Check uniqueness
	exists, err := s.orgRepo.ExistsBySlug(ctx, slug)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to check slug uniqueness")
	}

	if exists {
		if excludeOrgID != nil {
			existingOrg, err := s.orgRepo.GetBySlug(ctx, slug)
			if err == nil && existingOrg.ID == *excludeOrgID {
				return nil // Same organization, allow update
			}
		}
		return errors.New(errors.CodeConflict, "organization slug already exists")
	}

	return nil
}

// ValidateDomain validates domain format
func (s *service) ValidateDomain(ctx context.Context, domain string, excludeOrgID *xid.ID) error {
	if domain == "" {
		return nil // Domain is optional
	}

	// Basic domain validation
	if len(domain) < 3 || len(domain) > 255 {
		return errors.New(errors.CodeBadRequest, "invalid domain length")
	}

	// Simple domain format validation
	matched, err := regexp.MatchString(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`, domain)
	if err != nil || !matched {
		return errors.New(errors.CodeBadRequest, "invalid domain format")
	}

	return nil
}

// Helper methods

func (s *service) parseOrgType(orgTypeStr model.OrgType) (model.OrgType, error) {
	switch orgTypeStr {
	case model.OrgTypePlatform:
		return model.OrgTypePlatform, nil
	case model.OrgTypeCustomer:
		return model.OrgTypeCustomer, nil
	default:
		return model.OrgTypeCustomer, nil // Default to customer
	}
}

func (s *service) generateSlug(name string) string {
	// Convert to lowercase and replace spaces/special chars with hyphens
	slug := strings.ToLower(name)
	slug = regexp.MustCompile(`[^a-z0-9\-_]`).ReplaceAllString(slug, "-")
	slug = regexp.MustCompile(`-+`).ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")

	// Ensure minimum length
	if len(slug) < 2 {
		slug = "org-" + slug
	}

	// Truncate if too long
	if len(slug) > 50 {
		slug = slug[:50]
	}

	return slug
}

func (s *service) isValidSlug(slug string) bool {
	matched, _ := regexp.MatchString(`^[a-z0-9\-_]+$`, slug)
	return matched
}

func (s *service) isReservedSlug(slug string) bool {
	reserved := []string{
		"api", "www", "admin", "root", "support", "help", "docs", "blog",
		"app", "dashboard", "settings", "profile", "account", "billing",
		"security", "privacy", "terms", "about", "contact", "status",
	}

	for _, reserved := range reserved {
		if slug == reserved {
			return true
		}
	}
	return false
}

func (s *service) GetDefaultLimitsForPlan(plan string) UserLimits {
	switch strings.ToLower(plan) {
	case "free":
		return UserLimits{
			ExternalUserLimit: 5,
			EndUserLimit:      100,
			APIRequestLimit:   10000,
			StorageLimit:      1073741824, // 1GB
			EmailLimit:        500,
			SMSLimit:          100,
		}
	case "starter":
		return UserLimits{
			ExternalUserLimit: 25,
			EndUserLimit:      1000,
			APIRequestLimit:   50000,
			StorageLimit:      5368709120, // 5GB
			EmailLimit:        2500,
			SMSLimit:          500,
		}
	case "pro":
		return UserLimits{
			ExternalUserLimit: 100,
			EndUserLimit:      10000,
			APIRequestLimit:   200000,
			StorageLimit:      21474836480, // 20GB
			EmailLimit:        10000,
			SMSLimit:          2000,
		}
	case "enterprise":
		return UserLimits{
			ExternalUserLimit: 1000,
			EndUserLimit:      100000,
			APIRequestLimit:   1000000,
			StorageLimit:      107374182400, // 100GB
			EmailLimit:        50000,
			SMSLimit:          10000,
		}
	default:
		return s.GetDefaultLimitsForPlan("free")
	}
}

func (s *service) getUpdatedFieldsList(changes map[string]interface{}) []string {
	var fields []string
	for field := range changes {
		fields = append(fields, field)
	}
	return fields
}

func (s *service) createOrganizationOwner(ctx context.Context, orgID xid.ID, ownerEmail string) error {
	// Check if user already exists
	existingUser, err := s.userRepo.GetByEmail(ctx, ownerEmail, model.UserTypeExternal, &orgID)
	if err != nil && !ent.IsNotFound(err) {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to check existing user")
	}

	var userID xid.ID
	if existingUser != nil {
		userID = existingUser.ID
	} else {
		// Create new user
		createUserInput := repository.CreateUserInput{
			Email:          ownerEmail,
			UserType:       model.UserTypeExternal,
			OrganizationID: &orgID,
			EmailVerified:  false,
			Active:         true,
			Blocked:        false,
		}

		newUser, err := s.userRepo.Create(ctx, createUserInput)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternalServer, "failed to create owner user")
		}
		userID = newUser.ID
	}

	// Set as organization owner
	input := repository.UpdateOrganizationInput{
		OwnerID: &userID,
	}

	if _, err := s.orgRepo.Update(ctx, orgID, input); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to set organization owner")
	}

	return nil
}

func (s *service) createAuditLog(ctx context.Context, input *model.CreateAuditLogRequest) {
	// Create audit log asynchronously
	go func() {
		auditInput := repository.CreateAuditInput{
			OrganizationID: input.OrganizationID,
			UserID:         input.UserID,
			SessionID:      input.SessionID,
			Action:         input.Action,
			ResourceType:   input.Resource,
			ResourceID:     input.ResourceID,
			Status:         input.Status,
			IPAddress:      input.IPAddress,
			UserAgent:      input.UserAgent,
			Location:       input.Location,
			Details:        input.Details,
			Changes:        input.Changes,
			Error:          input.Error,
			Duration:       input.Duration,
			RiskLevel:      input.RiskLevel,
			Tags:           input.Tags,
			Source:         input.Source,
		}

		if _, err := s.auditRepo.Create(context.Background(), auditInput); err != nil {
			s.logger.Error("Failed to create audit log", logging.Error(err))
		}
	}()
}

// ListOrganizations retrieves organizations with pagination and filtering
func (s *service) ListOrganizations(ctx context.Context, req model.OrganizationListRequest) (*model.OrganizationListResponse, error) {
	s.logger.Info("Listing organizations", logging.String("search", req.Search))

	// Convert request to repository parameters
	params := repository.ListOrganizationsParams{
		PaginationParams: req.PaginationParams,
	}

	// Apply filters
	if req.OrgType != "" {
		orgType := model.OrgType(req.OrgType)
		params.OrgType = &orgType
	}
	if req.Plan != "" {
		params.Plan = &req.Plan
	}
	if req.Active.IsSet {
		active := req.Active.Value
		params.Active = &active
	}
	if req.SSOEnabled.IsSet {
		ssoEnabled := req.SSOEnabled.Value
		params.SSOEnabled = &ssoEnabled
	}

	var result *model.PaginatedOutput[*ent.Organization]
	var err error

	// Use search if query provided
	if req.Search != "" {
		searchParams := repository.SearchOrganizationsParams{
			PaginationParams: req.PaginationParams,
			OrgType:          params.OrgType,
			ExactMatch:       false,
		}
		result, err = s.orgRepo.Search(ctx, req.Search, searchParams)
	} else {
		result, err = s.orgRepo.List(ctx, params)
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to list organizations")
	}

	// Convert to model response
	summaries := make([]model.OrganizationSummary, len(result.Data))
	for i, org := range result.Data {
		summaries[i] = ConvertEntOrgToSummary(org)
	}

	response := &model.OrganizationListResponse{
		Data:       summaries,
		Pagination: result.Pagination,
	}

	return response, nil
}

// ListAllOrganizations retrieves organizations with pagination and filtering
func (s *service) ListAllOrganizations(ctx context.Context, req model.OrganizationListRequest) (*model.PlatformOrganizationListResponse, error) {
	s.logger.Info("Listing all organizations", logging.String("search", req.Search))

	// Convert request to repository parameters
	params := repository.ListOrganizationsParams{
		PaginationParams: req.PaginationParams,
	}

	// Apply filters
	if req.OrgType != "" {
		orgType := req.OrgType
		params.OrgType = &orgType
	}
	if req.Plan != "" {
		params.Plan = &req.Plan
	}
	if req.Active.IsSet {
		active := req.Active.Value
		params.Active = &active
	}
	if req.SSOEnabled.IsSet {
		ssoEnabled := req.SSOEnabled.Value
		params.SSOEnabled = &ssoEnabled
	}

	var result *model.PaginatedOutput[*ent.Organization]
	var err error

	// Use search if query provided
	if req.Search != "" {
		searchParams := repository.SearchOrganizationsParams{
			PaginationParams: req.PaginationParams,
			OrgType:          params.OrgType,
			ExactMatch:       false,
		}
		result, err = s.orgRepo.Search(ctx, req.Search, searchParams)
	} else {
		result, err = s.orgRepo.List(ctx, params)
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to list organizations")
	}

	// Convert to model response
	summaries := make([]model.PlatformOrganizationSummary, len(result.Data))
	for i, org := range result.Data {
		summaries[i] = ConvertEntOrgToPlatformSummary(org)
	}

	response := &model.PlatformOrganizationListResponse{
		Data:       summaries,
		Pagination: result.Pagination,
		Summary: model.OrganizationSummaryStats{
			Total:     len(summaries),
			Active:    0, // Would calculate from data
			Suspended: 0, // Would calculate from data
			Trial:     0, // Would calculate from data
		},
	}

	return response, nil
}

// ListUserOrganizations retrieves organizations for a specific user
func (s *service) ListUserOrganizations(ctx context.Context, userID xid.ID, req model.OrganizationListRequest) (*model.OrganizationListResponse, error) {
	s.logger.Info("Listing user organizations", logging.String("user_id", userID.String()))

	// Get user memberships first
	memberships, err := s.membershipRepo.ListByUser(ctx, userID, repository.ListMembershipsParams{
		PaginationParams: req.PaginationParams,
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user memberships")
	}

	// Extract organization IDs
	orgIDs := make([]xid.ID, len(memberships.Data))
	for i, membership := range memberships.Data {
		orgIDs[i] = membership.OrganizationID
	}

	if len(orgIDs) == 0 {
		return &model.OrganizationListResponse{
			Data:       []model.OrganizationSummary{},
			Pagination: memberships.Pagination,
		}, nil
	}

	// Get organizations by IDs
	organizations := make([]*ent.Organization, 0, len(orgIDs))
	for _, orgID := range orgIDs {
		org, err := s.orgRepo.GetByID(ctx, orgID)
		if err != nil {
			if !ent.IsNotFound(err) {
				s.logger.Warn("Failed to get organization", logging.String("org_id", orgID.String()), logging.Error(err))
			}
			continue
		}
		organizations = append(organizations, org)
	}

	// Convert to summaries
	summaries := make([]model.OrganizationSummary, len(organizations))
	for i, org := range organizations {
		summaries[i] = ConvertEntOrgToSummary(org)
		membership, err := s.memberService.GetMembership(ctx, org.ID, userID)
		if err != nil {
			return nil, err
		}
		summaries[i].Role = membership.Role.Name
	}

	response := &model.OrganizationListResponse{
		Data: summaries,
		Pagination: &model.Pagination{
			TotalCount: len(organizations),
		},
	}

	return response, nil
}

// Domain management methods

// AddDomain adds a domain to an organization
func (s *service) AddDomain(ctx context.Context, orgID xid.ID, domain string) error {
	s.logger.Info("Adding domain to organization",
		logging.String("org_id", orgID.String()),
		logging.String("domain", domain))

	// Validate domain format
	if err := s.ValidateDomain(ctx, domain, &orgID); err != nil {
		return err
	}

	// Check if domain is already in use by another organization
	exists, err := s.orgRepo.ExistsByDomain(ctx, domain)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to check domain existence")
	}
	if exists {
		return errors.New(errors.CodeConflict, "domain already exists")
	}

	// Add domain to organization
	if err := s.orgRepo.AddDomain(ctx, orgID, domain, false); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to add domain")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.domain.added",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"domain": domain,
		},
	})

	return nil
}

// RemoveDomain removes a domain from an organization
func (s *service) RemoveDomain(ctx context.Context, orgID xid.ID, domain string) error {
	s.logger.Info("Removing domain from organization",
		logging.String("org_id", orgID.String()),
		logging.String("domain", domain))

	// Get organization to check current domains
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	// Check if domain exists in organization
	domainExists := false
	for _, d := range org.Domains {
		if d == domain {
			domainExists = true
			break
		}
	}

	if !domainExists {
		return errors.New(errors.CodeNotFound, "domain not found in organization")
	}

	// Remove from domains list
	newDomains := make([]string, 0, len(org.Domains)-1)
	for _, d := range org.Domains {
		if d != domain {
			newDomains = append(newDomains, d)
		}
	}

	// Remove from verified domains list
	newVerifiedDomains := make([]string, 0, len(org.VerifiedDomains))
	for _, d := range org.VerifiedDomains {
		if d != domain {
			newVerifiedDomains = append(newVerifiedDomains, d)
		}
	}

	// Update organization
	input := repository.UpdateOrganizationInput{}
	// Note: Repository method to update domains would need to be added
	_, err = s.orgRepo.Update(ctx, orgID, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to remove domain")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.domain.removed",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"domain": domain,
		},
	})

	return nil
}

// VerifyDomain verifies a domain for an organization
func (s *service) VerifyDomain(ctx context.Context, req model.DomainVerificationRequest) (*model.DomainVerificationResponse, error) {
	s.logger.Info("Verifying domain", logging.String("domain", req.Domain))

	// Generate verification code
	verificationCode, err := s.generateVerificationCode()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to generate verification code")
	}

	// Create DNS record format
	dnsRecord := fmt.Sprintf("frank-verify=%s", verificationCode)

	// Check DNS for verification record
	verified := s.checkDNSVerification(req.Domain, verificationCode)

	response := &model.DomainVerificationResponse{
		Domain:           req.Domain,
		Verified:         verified,
		DNSRecord:        dnsRecord,
		VerificationCode: verificationCode,
		Instructions:     fmt.Sprintf("Add the following TXT record to your DNS: %s", dnsRecord),
	}

	return response, nil
}

// GetDomainVerificationStatus gets domain verification status
func (s *service) GetDomainVerificationStatus(ctx context.Context, orgID xid.ID, domain string) (*model.DomainVerificationResponse, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	// Check if domain is verified
	verified := false
	for _, d := range org.VerifiedDomains {
		if d == domain {
			verified = true
			break
		}
	}

	response := &model.DomainVerificationResponse{
		Domain:   domain,
		Verified: verified,
	}

	if !verified {
		// Generate verification instructions
		code, _ := s.generateVerificationCode()
		response.DNSRecord = fmt.Sprintf("frank-verify=%s", code)
		response.VerificationCode = code
		response.Instructions = fmt.Sprintf("Add the following TXT record to your DNS: %s", response.DNSRecord)
	}

	return response, nil
}

// Settings methods

// GetOrganizationSettings retrieves organization settings
func (s *service) GetOrganizationSettings(ctx context.Context, orgID xid.ID) (*model.OrganizationSettings, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	// Convert organization metadata to settings
	settings := &model.OrganizationSettings{
		AllowedDomains:           org.Domains,
		RequireEmailVerification: true,  // Default value
		RequirePhoneVerification: false, // Default value
		PasswordPolicy: model.PasswordPolicy{
			MinLength:        8,
			MaxLength:        128,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireDigit:     true,
			RequireSpecial:   false,
			MaxAge:           90,
			PreventReuse:     true,
			ExpiryDays:       30,
		},
		SessionSettings: model.SessionSettings{
			MaxConcurrentSessions: 5,
			SessionTimeout:        3600,
			RememberMeDuration:    2592000,
			RequireReauth:         []string{"sensitive_action"},
		},
		MFASettings: model.MFASettings{
			Required:       false,
			AllowedMethods: []string{"totp", "sms"},
			GracePeriod:    24,
		},
		WebhookSettings: model.WebhookSettings{
			Enabled:        true,
			AllowedEvents:  []string{"user.created", "user.updated", "user.deleted"},
			RetryAttempts:  3,
			TimeoutSeconds: 30,
		},
		AuditSettings: model.AuditSettings{
			Enabled:       true,
			RetentionDays: 365,
			EventTypes:    []string{"login", "logout", "user.created", "user.updated"},
			ExportEnabled: true,
		},
		CustomFields: []model.CustomField{},
		Branding: model.BrandingSettings{
			LogoURL:        org.LogoURL,
			PrimaryColor:   "#007bff",
			SecondaryColor: "#6c757d",
			FontFamily:     "Inter",
		},
	}

	// Override with actual metadata if present
	if org.Metadata != nil {
		// Parse settings from metadata
		s.parseSettingsFromMetadata(org.Metadata, settings)
	}

	return settings, nil
}

// UpdateOrganizationSettings updates organization settings
func (s *service) UpdateOrganizationSettings(ctx context.Context, orgID xid.ID, req model.UpdateOrganizationSettingsRequest) (*model.OrganizationSettings, error) {
	s.logger.Info("Updating organization settings", logging.String("org_id", orgID.String()))

	// Get current organization
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	// Get current settings
	currentSettings, err := s.GetOrganizationSettings(ctx, orgID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get current settings")
	}

	// Apply updates
	if req.AllowedDomains != nil {
		currentSettings.AllowedDomains = req.AllowedDomains
	}
	if req.RequireEmailVerification != nil {
		currentSettings.RequireEmailVerification = *req.RequireEmailVerification
	}
	if req.RequirePhoneVerification != nil {
		currentSettings.RequirePhoneVerification = *req.RequirePhoneVerification
	}
	if req.PasswordPolicy != nil {
		currentSettings.PasswordPolicy = *req.PasswordPolicy
	}
	if req.SessionSettings != nil {
		currentSettings.SessionSettings = *req.SessionSettings
	}
	if req.MFASettings != nil {
		currentSettings.MFASettings = *req.MFASettings
	}
	if req.WebhookSettings != nil {
		currentSettings.WebhookSettings = *req.WebhookSettings
	}
	if req.AuditSettings != nil {
		currentSettings.AuditSettings = *req.AuditSettings
	}
	if req.CustomFields != nil {
		currentSettings.CustomFields = req.CustomFields
	}
	if req.Branding != nil {
		currentSettings.Branding = *req.Branding
	}

	// Convert settings to metadata
	metadata := s.convertSettingsToMetadata(currentSettings)
	if org.Metadata != nil {
		// Merge with existing metadata
		for k, v := range org.Metadata {
			if _, exists := metadata[k]; !exists {
				metadata[k] = v
			}
		}
	}

	// Update organization
	input := repository.UpdateOrganizationInput{
		Metadata: metadata,
	}

	_, err = s.orgRepo.Update(ctx, orgID, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update organization settings")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.settings.updated",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"updated_settings": "organization_settings",
		},
	})

	// Return updated settings
	return s.GetOrganizationSettings(ctx, orgID)
}

// Billing methods

// GetOrganizationBilling retrieves organization billing information
func (s *service) GetOrganizationBilling(ctx context.Context, orgID xid.ID) (*model.OrganizationBilling, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	billing := &model.OrganizationBilling{
		CustomerID:         org.CustomerID,
		SubscriptionID:     org.SubscriptionID,
		Plan:               org.Plan,
		Status:             org.SubscriptionStatus.String(),
		CurrentPeriodStart: time.Now().Truncate(24 * time.Hour), // OnStart of current period
		CurrentPeriodEnd:   time.Now().AddDate(0, 1, 0),         // End of current period
		Amount:             s.getPlanAmount(org.Plan),
		Currency:           "usd",
		PaymentMethod:      "card",
	}

	if org.TrialEndsAt != nil {
		billing.TrialStart = &org.CreatedAt
		billing.TrialEnd = org.TrialEndsAt
	}

	// Calculate next invoice date
	nextInvoice := time.Now().AddDate(0, 1, 0)
	billing.NextInvoiceDate = &nextInvoice

	return billing, nil
}

// UpdateBilling updates organization billing information
func (s *service) UpdateBilling(ctx context.Context, orgID xid.ID, req model.UpdateBillingRequest) (*model.OrganizationBilling, error) {
	s.logger.Info("Updating organization billing", logging.String("org_id", orgID.String()))

	input := repository.UpdateOrganizationInput{}

	if req.Plan != "" {
		input.Plan = &req.Plan
	}

	// Update organization
	_, err := s.orgRepo.Update(ctx, orgID, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update billing")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.billing.updated",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"plan": req.Plan,
		},
	})

	return s.GetOrganizationBilling(ctx, orgID)
}

// Usage methods

// GetOrganizationUsage retrieves organization usage information
func (s *service) GetOrganizationUsage(ctx context.Context, orgID xid.ID) (*model.OrganizationUsage, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	now := time.Now()
	usage := &model.OrganizationUsage{
		Period:            fmt.Sprintf("%d-%02d", now.Year(), now.Month()),
		ExternalUsers:     org.CurrentExternalUsers,
		EndUsers:          org.CurrentEndUsers,
		APIRequests:       org.APIRequestsUsed,
		Storage:           1024000, // Default storage usage
		Bandwidth:         2048000, // Default bandwidth usage
		LoginEvents:       1200,    // Default login events
		EmailsSent:        150,     // Default emails sent
		SMSSent:           50,      // Default SMS sent
		WebhookDeliveries: 800,     // Default webhook deliveries
		LastUpdated:       now,
	}

	return usage, nil
}

// UpdateUsage updates organization usage information
func (s *service) UpdateUsage(ctx context.Context, orgID xid.ID, usage model.OrganizationUsage) error {
	s.logger.Info("Updating organization usage", logging.String("org_id", orgID.String()))

	input := repository.UpdateUsageInput{
		APIRequestsUsed:      &usage.APIRequests,
		CurrentExternalUsers: &usage.ExternalUsers,
		CurrentEndUsers:      &usage.EndUsers,
	}

	err := s.orgRepo.UpdateUsage(ctx, orgID, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to update usage")
	}

	return nil
}

// Trial management methods

// StartTrial starts a trial for an organization
func (s *service) StartTrial(ctx context.Context, orgID xid.ID, duration time.Duration) error {
	s.logger.Info("Starting trial",
		logging.String("org_id", orgID.String()),
		logging.String("duration", duration.String()))

	trialEnd := time.Now().Add(duration)
	if err := s.orgRepo.StartTrial(ctx, orgID, &trialEnd); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to start trial")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.trial.started",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"duration":  duration.String(),
			"trial_end": trialEnd,
		},
	})

	return nil
}

// EndTrial ends a trial for an organization
func (s *service) EndTrial(ctx context.Context, orgID xid.ID) error {
	s.logger.Info("Ending trial", logging.String("org_id", orgID.String()))

	if err := s.orgRepo.EndTrial(ctx, orgID); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to end trial")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.trial.ended",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
	})

	return nil
}

// ExtendTrial extends a trial for an organization
func (s *service) ExtendTrial(ctx context.Context, orgID xid.ID, extension time.Duration) error {
	s.logger.Info("Extending trial",
		logging.String("org_id", orgID.String()),
		logging.String("extension", extension.String()))

	// Get current organization
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	if org.TrialEndsAt == nil {
		return errors.New(errors.CodeBadRequest, "organization does not have an active trial")
	}

	// Extend trial end date
	newTrialEnd := org.TrialEndsAt.Add(extension)
	if err := s.orgRepo.StartTrial(ctx, orgID, &newTrialEnd); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to extend trial")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.trial.extended",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"extension":     extension.String(),
			"new_trial_end": newTrialEnd,
		},
	})

	return nil
}

// GetTrialStatus gets the trial status for an organization
func (s *service) GetTrialStatus(ctx context.Context, orgID xid.ID) (*TrialStatus, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	status := &TrialStatus{
		TrialUsed: org.TrialUsed,
		CanExtend: false, // Would need to track this in metadata
	}

	if org.TrialEndsAt != nil {
		now := time.Now()
		status.IsActive = now.Before(*org.TrialEndsAt)
		status.StartedAt = org.CreatedAt
		status.EndsAt = org.TrialEndsAt

		if status.IsActive {
			daysRemaining := int(org.TrialEndsAt.Sub(now).Hours() / 24)
			if daysRemaining < 0 {
				daysRemaining = 0
			}
			status.DaysRemaining = daysRemaining
		}

		status.DaysTotal = int(org.TrialEndsAt.Sub(org.CreatedAt).Hours() / 24)
	}

	return status, nil
}

func (s *service) generateVerificationCode() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *service) checkDNSVerification(domain, code string) bool {
	// Simplified DNS check - in production, this would do actual DNS lookup
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return false
	}

	expectedRecord := fmt.Sprintf("frank-verify=%s", code)
	for _, record := range txtRecords {
		if record == expectedRecord {
			return true
		}
	}
	return false
}

func (s *service) parseSettingsFromMetadata(metadata map[string]interface{}, settings *model.OrganizationSettings) {
	// Parse settings from metadata - simplified implementation
	if allowedDomains, ok := metadata["allowed_domains"]; ok {
		if domains, ok := allowedDomains.([]string); ok {
			settings.AllowedDomains = domains
		}
	}
}

func (s *service) convertSettingsToMetadata(settings *model.OrganizationSettings) map[string]interface{} {
	return map[string]interface{}{
		"allowed_domains":            settings.AllowedDomains,
		"require_email_verification": settings.RequireEmailVerification,
		"require_phone_verification": settings.RequirePhoneVerification,
		"password_policy":            settings.PasswordPolicy,
		"session_settings":           settings.SessionSettings,
		"mfa_settings":               settings.MFASettings,
		"webhook_settings":           settings.WebhookSettings,
		"audit_settings":             settings.AuditSettings,
		"custom_fields":              settings.CustomFields,
		"branding":                   settings.Branding,
	}
}

func (s *service) getPlanAmount(plan string) int {
	switch strings.ToLower(plan) {
	case "free":
		return 0
	case "starter":
		return 2900 // $29.00
	case "pro":
		return 9900 // $99.00
	case "enterprise":
		return 29900 // $299.00
	default:
		return 0
	}
}

// EnableFeature enables a feature for an organization
func (s *service) EnableFeature(ctx context.Context, orgID xid.ID, featureName string, config map[string]interface{}) error {
	s.logger.Info("Enabling feature",
		logging.String("org_id", orgID.String()),
		logging.String("feature", featureName))

	// Validate feature name
	if err := s.validateFeatureName(featureName); err != nil {
		return err
	}

	// Get organization to check plan limits
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	// Check if feature is available for current plan
	if !s.isFeatureAvailableForPlan(featureName, org.Plan) {
		return errors.New(errors.CodeForbidden, "feature not available for current plan")
	}

	// Get current metadata
	metadata := org.Metadata
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add feature to enabled features
	enabledFeatures, _ := metadata["enabled_features"].(map[string]interface{})
	if enabledFeatures == nil {
		enabledFeatures = make(map[string]interface{})
	}

	enabledFeatures[featureName] = map[string]interface{}{
		"enabled":    true,
		"config":     config,
		"enabled_at": time.Now(),
	}
	metadata["enabled_features"] = enabledFeatures

	// Update organization
	input := repository.UpdateOrganizationInput{
		Metadata: metadata,
	}

	_, err = s.orgRepo.Update(ctx, orgID, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to enable feature")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.feature.enabled",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"feature": featureName,
			"config":  config,
		},
	})

	return nil
}

// DisableFeature disables a feature for an organization
func (s *service) DisableFeature(ctx context.Context, orgID xid.ID, featureName string) error {
	s.logger.Info("Disabling feature",
		logging.String("org_id", orgID.String()),
		logging.String("feature", featureName))

	// Get organization
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	// Get current metadata
	metadata := org.Metadata
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Remove feature from enabled features
	enabledFeatures, _ := metadata["enabled_features"].(map[string]interface{})
	if enabledFeatures == nil {
		return errors.New(errors.CodeNotFound, "feature not found")
	}

	if _, exists := enabledFeatures[featureName]; !exists {
		return errors.New(errors.CodeNotFound, "feature not enabled")
	}

	delete(enabledFeatures, featureName)
	metadata["enabled_features"] = enabledFeatures

	// Update organization
	input := repository.UpdateOrganizationInput{
		Metadata: metadata,
	}

	_, err = s.orgRepo.Update(ctx, orgID, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to disable feature")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.feature.disabled",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"feature": featureName,
		},
	})

	return nil
}

// IsFeatureEnabled checks if a feature is enabled for an organization
func (s *service) IsFeatureEnabled(ctx context.Context, orgID xid.ID, featureName string) (bool, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return false, errors.New(errors.CodeNotFound, "organization not found")
		}
		return false, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	if org.Metadata == nil {
		return false, nil
	}

	enabledFeatures, _ := org.Metadata["enabled_features"].(map[string]interface{})
	if enabledFeatures == nil {
		return false, nil
	}

	feature, exists := enabledFeatures[featureName]
	if !exists {
		return false, nil
	}

	featureMap, ok := feature.(map[string]interface{})
	if !ok {
		return false, nil
	}

	enabled, _ := featureMap["enabled"].(bool)
	return enabled, nil
}

// GetEnabledFeatures returns list of enabled features for an organization
func (s *service) GetEnabledFeatures(ctx context.Context, orgID xid.ID) ([]model.FeatureSummary, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	var features []model.FeatureSummary

	if org.Metadata == nil {
		return features, nil
	}

	enabledFeatures, _ := org.Metadata["enabled_features"].(map[string]interface{})
	if enabledFeatures == nil {
		return features, nil
	}

	for featureName, featureData := range enabledFeatures {
		featureMap, ok := featureData.(map[string]interface{})
		if !ok {
			continue
		}

		enabled, _ := featureMap["enabled"].(bool)
		if !enabled {
			continue
		}

		config, _ := featureMap["config"].(map[string]interface{})
		updatedAt := time.Now()
		if enabledAtStr, ok := featureMap["enabled_at"].(string); ok {
			if parsedTime, err := time.Parse(time.RFC3339, enabledAtStr); err == nil {
				updatedAt = parsedTime
			}
		}

		features = append(features, model.FeatureSummary{
			Name:        featureName,
			DisplayName: s.getFeatureDisplayName(featureName),
			Enabled:     enabled,
			Config:      config,
			UpdatedAt:   updatedAt,
		})
	}

	return features, nil
}

// Auth service management methods

// EnableAuthService enables auth service for an organization
func (s *service) EnableAuthService(ctx context.Context, orgID xid.ID, config map[string]interface{}) error {
	s.logger.Info("Enabling auth service", logging.String("org_id", orgID.String()))

	return s.orgRepo.EnableAuthService(ctx, orgID, config)
}

// DisableAuthService disables auth service for an organization
func (s *service) DisableAuthService(ctx context.Context, orgID xid.ID) error {
	s.logger.Info("Disabling auth service", logging.String("org_id", orgID.String()))

	return s.orgRepo.DisableAuthService(ctx, orgID)
}

// UpdateAuthConfig updates auth service configuration
func (s *service) UpdateAuthConfig(ctx context.Context, orgID xid.ID, config map[string]interface{}) error {
	s.logger.Info("Updating auth config", logging.String("org_id", orgID.String()))

	return s.orgRepo.UpdateAuthConfig(ctx, orgID, config)
}

// GetAuthConfig gets auth service configuration
func (s *service) GetAuthConfig(ctx context.Context, orgID xid.ID) (map[string]interface{}, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	if org.AuthConfig == nil {
		return make(map[string]interface{}), nil
	}

	return org.AuthConfig, nil
}

// ListDomains lists all domains for an organization
func (s *service) ListDomains(ctx context.Context, orgID xid.ID) ([]string, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	return org.Domains, nil
}

// GetFeatureConfig gets configuration for a specific feature
func (s *service) GetFeatureConfig(ctx context.Context, orgID xid.ID, featureKey string) (map[string]interface{}, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	if org.Metadata == nil {
		return nil, errors.New(errors.CodeNotFound, "feature not found")
	}

	enabledFeatures, _ := org.Metadata["enabled_features"].(map[string]interface{})
	if enabledFeatures == nil {
		return nil, errors.New(errors.CodeNotFound, "feature not found")
	}

	feature, exists := enabledFeatures[featureKey]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "feature not found")
	}

	featureMap, ok := feature.(map[string]interface{})
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "invalid feature configuration")
	}

	config, _ := featureMap["config"].(map[string]interface{})
	if config == nil {
		config = make(map[string]interface{})
	}

	return config, nil
}

// ListEnabledFeatures lists all enabled features (alias for GetEnabledFeatures for interface compatibility)
func (s *service) ListEnabledFeatures(ctx context.Context, orgID xid.ID) ([]model.FeatureSummary, error) {
	return s.GetEnabledFeatures(ctx, orgID)
}

// GetOwnershipHistory gets ownership transfer history for an organization
func (s *service) GetOwnershipHistory(ctx context.Context, orgID xid.ID) ([]OwnershipTransfer, error) {
	// This would typically query an ownership_transfers table or audit logs
	// For now, return empty history
	var history []OwnershipTransfer

	// In a real implementation, this would query audit logs for ownership transfers
	// Example:
	// auditLogs, err := s.auditRepo.GetByResourceAndAction(ctx, orgID, "organization.ownership.transferred")
	// if err != nil {
	//     return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get ownership history")
	// }
	//
	// for _, log := range auditLogs {
	//     // Parse audit log details to create OwnershipTransfer records
	// }

	return history, nil
}

// ValidateSlug validates organization slug (alias for ValidateOrganizationSlug)
func (s *service) ValidateSlug(ctx context.Context, slug string, excludeOrgID *xid.ID) error {
	return s.ValidateOrganizationSlug(ctx, slug, excludeOrgID)
}

// GenerateSlug generates a unique slug from organization name
func (s *service) GenerateSlug(ctx context.Context, name string) (string, error) {
	baseSlug := s.generateSlug(name)

	// Check if slug is unique
	exists, err := s.orgRepo.ExistsBySlug(ctx, baseSlug)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to check slug uniqueness")
	}

	if !exists {
		return baseSlug, nil
	}

	// Generate unique slug with counter
	for i := 1; i <= 100; i++ {
		candidate := fmt.Sprintf("%s-%d", baseSlug, i)
		exists, err := s.orgRepo.ExistsBySlug(ctx, candidate)
		if err != nil {
			return "", errors.Wrap(err, errors.CodeInternalServer, "failed to check slug uniqueness")
		}
		if !exists {
			return candidate, nil
		}
	}

	return "", errors.New(errors.CodeInternalServer, "unable to generate unique slug")
}

// SuggestSimilarOrganizations suggests similar organizations based on name
func (s *service) SuggestSimilarOrganizations(ctx context.Context, name string, limit int) ([]model.OrganizationSummary, error) {
	s.logger.Info("Suggesting similar organizations", logging.String("name", name), logging.Int("limit", limit))

	// Search for organizations with similar names
	searchParams := repository.SearchOrganizationsParams{
		PaginationParams: model.PaginationParams{
			Page:    1,
			Limit:   limit,
			OrderBy: []string{"name:asc"},
		},
		ExactMatch: false,
	}

	result, err := s.orgRepo.Search(ctx, name, searchParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to search similar organizations")
	}

	// Convert to summaries
	summaries := make([]model.OrganizationSummary, len(result.Data))
	for i, org := range result.Data {
		summaries[i] = ConvertEntOrgToSummary(org)
	}

	return summaries, nil
}

// UpdatePlan updates organization plan
func (s *service) UpdatePlan(ctx context.Context, orgID xid.ID, plan string) (*model.Organization, error) {
	s.logger.Info("Updating organization plan",
		logging.String("org_id", orgID.String()),
		logging.String("plan", plan))

	// Get current organization
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	oldPlan := org.Plan

	// Get new plan limits
	limits := s.GetDefaultLimitsForPlan(plan)

	// Update organization with new plan and limits
	input := repository.UpdateOrganizationInput{
		Plan:              &plan,
		ExternalUserLimit: &limits.ExternalUserLimit,
		EndUserLimit:      &limits.EndUserLimit,
		APIRequestLimit:   &limits.APIRequestLimit,
	}

	updatedOrg, err := s.orgRepo.Update(ctx, orgID, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update plan")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.plan.updated",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"old_plan": oldPlan,
			"new_plan": plan,
			"new_limits": map[string]interface{}{
				"external_user_limit": limits.ExternalUserLimit,
				"end_user_limit":      limits.EndUserLimit,
				"api_request_limit":   limits.APIRequestLimit,
			},
		},
	})

	return ConvertEntOrgToModel(updatedOrg), nil
}

// GetPlanLimits gets plan limits for an organization
func (s *service) GetPlanLimits(ctx context.Context, orgID xid.ID) (*PlanLimits, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	limits := &PlanLimits{
		Plan:              org.Plan,
		ExternalUserLimit: org.ExternalUserLimit,
		EndUserLimit:      org.EndUserLimit,
		APIRequestLimit:   org.APIRequestLimit,
		StorageLimit:      s.GetDefaultLimitsForPlan(org.Plan).StorageLimit,
		// FeatureEnabled:    s.isFeatureAvailableForPlan("advanced_features", org.Plan),
	}

	return limits, nil
}

// CheckPlanLimit checks if adding resources would exceed plan limits
func (s *service) CheckPlanLimit(ctx context.Context, orgID xid.ID, resource string, requestedCount int) (*PlanLimitCheck, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	var currentUsage, limit int
	var resourceName string

	switch resource {
	case "external_users":
		currentUsage = org.CurrentExternalUsers
		limit = org.ExternalUserLimit
		resourceName = "external_users"
	case "end_users":
		currentUsage = org.CurrentEndUsers
		limit = org.EndUserLimit
		resourceName = "end_users"
	case "api_requests":
		currentUsage = org.APIRequestsUsed
		limit = org.APIRequestLimit
		resourceName = "api_requests"
	default:
		return nil, errors.New(errors.CodeBadRequest, "invalid resource type")
	}

	available := limit - currentUsage
	if available < 0 {
		available = 0
	}

	// percentageUsed := float64(currentUsage) / float64(limit) * 100
	// withinLimit := (currentUsage + requestedCount) <= limit
	// wouldExceed := !withinLimit

	fmt.Println(resourceName)

	check := &PlanLimitCheck{
		// Resource:        resourceName,
		CurrentUsage: currentUsage,
		// RequestedCount:  requestedCount,
		Limit: limit,

		// Available:       available,
		// WithinLimit:     withinLimit,
		// PercentageUsed:  percentageUsed,
		// WouldExceed:     wouldExceed,
	}

	return check, nil
}

// UpdateSubscriptionStatus updates subscription status
func (s *service) UpdateSubscriptionStatus(ctx context.Context, orgID xid.ID, status organization.SubscriptionStatus) error {
	s.logger.Info("Updating subscription status",
		logging.String("org_id", orgID.String()),
		logging.String("status", status.String()))

	err := s.orgRepo.UpdateSubscriptionStatus(ctx, orgID, status)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to update subscription status")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.subscription.status_updated",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"subscription_status": status.String(),
		},
	})

	return nil
}

// GetSettings gets organization settings (alias for GetOrganizationSettings)
func (s *service) GetSettings(ctx context.Context, orgID xid.ID) (*model.OrganizationSettings, error) {
	return s.GetOrganizationSettings(ctx, orgID)
}

// UpdateSettings updates organization settings (alias for UpdateOrganizationSettings)
func (s *service) UpdateSettings(ctx context.Context, orgID xid.ID, req model.UpdateOrganizationSettingsRequest) (*model.OrganizationSettings, error) {
	return s.UpdateOrganizationSettings(ctx, orgID, req)
}

// UpdateBillingInfo updates billing information (alias for UpdateBilling)
func (s *service) UpdateBillingInfo(ctx context.Context, orgID xid.ID, req model.UpdateBillingRequest) (*model.OrganizationBilling, error) {
	return s.UpdateBilling(ctx, orgID, req)
}

// GetBillingInfo gets billing information (alias for GetOrganizationBilling)
func (s *service) GetBillingInfo(ctx context.Context, orgID xid.ID) (*model.OrganizationBilling, error) {
	return s.GetOrganizationBilling(ctx, orgID)
}

// SetCustomerID sets the billing customer ID for an organization
func (s *service) SetCustomerID(ctx context.Context, orgID xid.ID, customerID string) error {
	s.logger.Info("Setting customer ID",
		logging.String("org_id", orgID.String()),
		logging.String("customer_id", customerID))

	input := repository.UpdateOrganizationInput{
		CustomerID: &customerID,
	}

	_, err := s.orgRepo.Update(ctx, orgID, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to set customer ID")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.billing.customer_id_set",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"customer_id": customerID,
		},
	})

	return nil
}

// SetSubscriptionID sets the subscription ID for an organization
func (s *service) SetSubscriptionID(ctx context.Context, orgID xid.ID, subscriptionID string) error {
	s.logger.Info("Setting subscription ID",
		logging.String("org_id", orgID.String()),
		logging.String("subscription_id", subscriptionID))

	input := repository.UpdateOrganizationInput{
		SubscriptionID: &subscriptionID,
	}

	_, err := s.orgRepo.Update(ctx, orgID, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to set subscription ID")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.billing.subscription_id_set",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"subscription_id": subscriptionID,
		},
	})

	return nil
}

// EnableSSO enables SSO for an organization
func (s *service) EnableSSO(ctx context.Context, orgID xid.ID, domain string, config map[string]interface{}) error {
	s.logger.Info("Enabling SSO",
		logging.String("org_id", orgID.String()),
		logging.String("domain", domain))

	// Validate domain
	if err := s.ValidateDomain(ctx, domain, &orgID); err != nil {
		return err
	}

	// Enable SSO using repository
	if err := s.orgRepo.EnableSSO(ctx, orgID, domain); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to enable SSO")
	}

	// Update SSO config in metadata
	if config != nil {
		org, err := s.orgRepo.GetByID(ctx, orgID)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
		}

		metadata := org.Metadata
		if metadata == nil {
			metadata = make(map[string]interface{})
		}
		metadata["sso_config"] = config

		input := repository.UpdateOrganizationInput{
			Metadata: metadata,
		}
		_, err = s.orgRepo.Update(ctx, orgID, input)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternalServer, "failed to update SSO config")
		}
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.sso.enabled",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"domain": domain,
			"config": config,
		},
	})

	return nil
}

// DisableSSO disables SSO for an organization
func (s *service) DisableSSO(ctx context.Context, orgID xid.ID) error {
	s.logger.Info("Disabling SSO", logging.String("org_id", orgID.String()))

	if err := s.orgRepo.DisableSSO(ctx, orgID); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to disable SSO")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.sso.disabled",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
	})

	return nil
}

// UpdateSSOConfig updates SSO configuration
func (s *service) UpdateSSOConfig(ctx context.Context, orgID xid.ID, config map[string]interface{}) error {
	s.logger.Info("Updating SSO config", logging.String("org_id", orgID.String()))

	// Get organization
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	if !org.SSOEnabled {
		return errors.New(errors.CodeBadRequest, "SSO is not enabled for this organization")
	}

	// Update SSO config in metadata
	metadata := org.Metadata
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["sso_config"] = config

	input := repository.UpdateOrganizationInput{
		Metadata: metadata,
	}
	_, err = s.orgRepo.Update(ctx, orgID, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to update SSO config")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.sso.config_updated",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"config": config,
		},
	})

	return nil
}

// User limits and quotas methods

// GetUserLimits gets user limits for an organization
func (s *service) GetUserLimits(ctx context.Context, orgID xid.ID) (*UserLimits, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	limits := s.GetDefaultLimitsForPlan(org.Plan)

	// Override with organization-specific limits
	if org.ExternalUserLimit > 0 {
		limits.ExternalUserLimit = org.ExternalUserLimit
	}
	if org.EndUserLimit > 0 {
		limits.EndUserLimit = org.EndUserLimit
	}
	if org.APIRequestLimit > 0 {
		limits.APIRequestLimit = org.APIRequestLimit
	}

	return &limits, nil
}

// UpdateUserLimits updates user limits for an organization
func (s *service) UpdateUserLimits(ctx context.Context, orgID xid.ID, limits UserLimits) error {
	s.logger.Info("Updating user limits", logging.String("org_id", orgID.String()))

	input := repository.UpdateOrganizationInput{
		ExternalUserLimit: &limits.ExternalUserLimit,
		EndUserLimit:      &limits.EndUserLimit,
		APIRequestLimit:   &limits.APIRequestLimit,
	}

	_, err := s.orgRepo.Update(ctx, orgID, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to update user limits")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.limits.updated",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"external_user_limit": limits.ExternalUserLimit,
			"end_user_limit":      limits.EndUserLimit,
			"api_request_limit":   limits.APIRequestLimit,
		},
	})

	return nil
}

// CheckUserLimit checks if adding a user would exceed limits
func (s *service) CheckUserLimit(ctx context.Context, orgID xid.ID, userType string) (bool, error) {
	switch userType {
	case "external":
		return s.orgRepo.CanAddExternalUser(ctx, orgID)
	case "end_user":
		return s.orgRepo.CanAddEndUser(ctx, orgID)
	default:
		return false, errors.New(errors.CodeBadRequest, "invalid user type")
	}
}

// GetCurrentUserCounts gets current user counts for an organization
func (s *service) GetCurrentUserCounts(ctx context.Context, orgID xid.ID) (*UserCounts, error) {
	counts, err := s.orgRepo.GetCurrentUserCounts(ctx, orgID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user counts")
	}

	return &UserCounts{
		ExternalUsers: counts.CurrentExternalUsers,
		EndUsers:      counts.CurrentEndUsers,
		TotalUsers:    counts.CurrentExternalUsers + counts.CurrentEndUsers,
		ActiveUsers:   0,
		InactiveUsers: 0,
		LastUpdated:   time.Time{},
	}, nil
}

// TransferOwnership transfers organization ownership
func (s *service) TransferOwnership(ctx context.Context, orgID xid.ID, req model.TransferUserOwnershipRequest) error {
	s.logger.Info("Transferring ownership",
		logging.String("org_id", orgID.String()),
		logging.String("new_owner_id", req.NewOwnerID.String()))

	// Validate new owner exists and is member of organization
	_, err := s.userRepo.GetByID(ctx, req.NewOwnerID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "new owner not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get new owner")
	}

	// Check if new owner is member of organization
	isMember, err := s.memberService.IsMember(ctx, orgID, req.NewOwnerID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to check membership")
	}
	if !isMember {
		return errors.New(errors.CodeBadRequest, "new owner must be a member of the organization")
	}

	// Get current owner
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	// Update organization owner
	input := repository.UpdateOrganizationInput{
		OwnerID: &req.NewOwnerID,
	}

	_, err = s.orgRepo.Update(ctx, orgID, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to transfer ownership")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "organization.ownership.transferred",
		Resource:       "organization",
		ResourceID:     &orgID,
		Status:         "success",
		OrganizationID: &orgID,
		Details: map[string]interface{}{
			"from_owner_id": org.OwnerID,
			"to_owner_id":   req.NewOwnerID,
			"reason":        req.Reason,
		},
	})

	return nil
}

// GetOwner gets the organization owner
func (s *service) GetOwner(ctx context.Context, orgID xid.ID) (*model.UserSummary, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	if org.OwnerID.IsNil() {
		return nil, errors.New(errors.CodeNotFound, "organization has no owner")
	}

	owner, err := s.userRepo.GetByID(ctx, org.OwnerID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "owner not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get owner")
	}

	return &model.UserSummary{
		ID:        owner.ID,
		Email:     owner.Email,
		FirstName: owner.FirstName,
		LastName:  owner.LastName,
		UserType:  owner.UserType,
		Active:    owner.Active,
	}, nil
}

// Analytics and stats methods

// GetOrganizationStats gets organization statistics
func (s *service) GetOrganizationStats(ctx context.Context, orgID xid.ID) (*model.OrgStats, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization")
	}

	// Get membership statistics
	memberStats, err := s.membershipRepo.GetMembershipStats(ctx, orgID)
	if err != nil {
		s.logger.Warn("Failed to get member stats", logging.Error(err))
		memberStats = &repository.MembershipStats{
			TotalMembers:   0,
			ActiveMembers:  0,
			PendingMembers: 0,
		}
	}

	stats := &model.OrgStats{
		TotalMembers:       memberStats.TotalMembers,
		ActiveMembers:      memberStats.ActiveMembers,
		PendingInvitations: memberStats.PendingMembers,
		TotalEndUsers:      org.CurrentEndUsers,
		ActiveEndUsers:     org.CurrentEndUsers, // Assume all are active for now
		APICallsThisMonth:  org.APIRequestsUsed,
		LoginThisMonth:     1200,    // Default value - would need actual tracking
		StorageUsed:        1024000, // Default value - would need actual tracking
	}

	// Set last activity time if available
	now := time.Now()
	stats.LastActivity = &now

	return stats, nil
}

// GetOrganizationActivity gets organization activity metrics
func (s *service) GetOrganizationActivity(ctx context.Context, orgID xid.ID, days int) (*OrganizationActivity, error) {
	// This would typically query activity/audit logs
	activity := &OrganizationActivity{
		Period: fmt.Sprintf("%dd", days),
		// Logins:      250, // Default values - would need actual data
		// APIRequests: 5000,
		// NewUsers:    15,
		// ActiveUsers: 75,
	}

	return activity, nil
}

// GetGrowthMetrics gets growth metrics for an organization
func (s *service) GetGrowthMetrics(ctx context.Context, orgID xid.ID, period string) (*GrowthMetrics, error) {
	// This would typically analyze historical data
	metrics := &GrowthMetrics{
		Period:         period,
		UserGrowthRate: 15.5,
		GrowthRate:     25.2,
		NewUsers:       45,
		ChurnRate:      5,
		UserGrowth:     40,
		RevenueGrowth:  12.8,
	}

	return metrics, nil
}

// GetOrganizationAnalytics gets comprehensive analytics
func (s *service) GetOrganizationAnalytics(ctx context.Context, orgID xid.ID, days int) (*OrganizationAnalytics, error) {
	// Get growth metrics
	growth, err := s.GetGrowthMetrics(ctx, orgID, fmt.Sprintf("%dd", days))
	if err != nil {
		return nil, err
	}

	analytics := &OrganizationAnalytics{
		Period: fmt.Sprintf("%dd", days),
		// UserMetrics: map[string]interface{}{
		// 	"total_users":   150,
		// 	"active_users":  125,
		// 	"new_users":     45,
		// 	"churned_users": 5,
		// },
		// UsageMetrics: map[string]interface{}{
		// 	"api_requests":   5000,
		// 	"login_events":   1200,
		// 	"storage_used":   1024000,
		// 	"bandwidth_used": 2048000,
		// },
		RevenueMetrics: RevenueMetrics{
			MonthlyRecurringRevenue: 9900,
			AnnualRecurringRevenue:  118800,
			ChurnRate:               12.8,
		},
		UserGrowth: *growth,
	}

	return analytics, nil
}

// GetComplianceReport gets compliance report for an organization
func (s *service) GetComplianceReport(ctx context.Context, orgID xid.ID) (*ComplianceReport, error) {
	now := time.Now()
	report := &ComplianceReport{
		OrganizationID: orgID,
		// ReportType:          "soc2",
		// Period:              fmt.Sprintf("%d-Q%d", now.Year(), (int(now.Month())-1)/3+1),
		GeneratedAt: now,
		// TotalEvents:         50000,
		// ComplianceScore:     98.5,
		Violations:      []ComplianceViolation{},
		Recommendations: []string{"Enable detailed logging for all admin actions"},
		// CoverageMetrics:     map[string]interface{}{"access_control": 100, "audit_logging": 95},
		// AttestationRequired: true,
		// Status:              "passed",
	}

	return report, nil
}

// Platform operations

// GetPlatformOrganization gets the platform organization
func (s *service) GetPlatformOrganization(ctx context.Context) (*model.Organization, error) {
	entOrg, err := s.orgRepo.GetPlatformOrganization(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "platform organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get platform organization")
	}

	return ConvertEntOrgToModel(entOrg), nil
}

// GetCustomerOrganizations gets customer organizations
func (s *service) GetCustomerOrganizations(ctx context.Context, req model.OrganizationListRequest) (*model.OrganizationListResponse, error) {
	params := repository.ListOrganizationsParams{
		PaginationParams: req.PaginationParams,
	}

	result, err := s.orgRepo.GetCustomerOrganizations(ctx, params)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get customer organizations")
	}

	// Convert to model response
	summaries := make([]model.OrganizationSummary, len(result.Data))
	for i, org := range result.Data {
		summaries[i] = ConvertEntOrgToSummary(org)
	}

	response := &model.OrganizationListResponse{
		Data:       summaries,
		Pagination: result.Pagination,
	}

	return response, nil
}

// Helper methods for validation and feature management

func (s *service) validateFeatureName(featureName string) error {
	validFeatures := []string{
		"sso", "advanced_mfa", "audit_logs", "custom_roles",
		"api_access", "webhooks", "custom_domains", "white_labeling",
		"priority_support", "advanced_analytics",
	}

	for _, valid := range validFeatures {
		if featureName == valid {
			return nil
		}
	}

	return errors.New(errors.CodeBadRequest, "invalid feature name")
}

func (s *service) isFeatureAvailableForPlan(featureName, plan string) bool {
	planFeatures := map[string][]string{
		"free":       {"api_access"},
		"starter":    {"api_access", "webhooks"},
		"pro":        {"api_access", "webhooks", "sso", "advanced_mfa", "audit_logs"},
		"enterprise": {"api_access", "webhooks", "sso", "advanced_mfa", "audit_logs", "custom_roles", "custom_domains", "white_labeling", "priority_support", "advanced_analytics"},
	}

	features, exists := planFeatures[strings.ToLower(plan)]
	if !exists {
		return false
	}

	for _, feature := range features {
		if feature == featureName {
			return true
		}
	}

	return false
}

func (s *service) getFeatureDisplayName(featureName string) string {
	displayNames := map[string]string{
		"sso":                "Single Sign-On",
		"advanced_mfa":       "Advanced MFA",
		"audit_logs":         "Audit Logs",
		"custom_roles":       "Custom Roles",
		"api_access":         "API Access",
		"webhooks":           "Webhooks",
		"custom_domains":     "Custom Domains",
		"white_labeling":     "White Labeling",
		"priority_support":   "Priority Support",
		"advanced_analytics": "Advanced Analytics",
	}

	if displayName, exists := displayNames[featureName]; exists {
		return displayName
	}

	return strings.Title(strings.ReplaceAll(featureName, "_", " "))
}
