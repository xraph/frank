package organization

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// Service defines the organization service interface
type Service interface {
	// Organization CRUD operations
	CreateOrganization(ctx context.Context, req model.CreateOrganizationRequest) (*model.Organization, error)
	GetOrganization(ctx context.Context, id xid.ID) (*model.Organization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*model.Organization, error)
	GetOrganizationByDomain(ctx context.Context, domain string) (*model.Organization, error)
	UpdateOrganization(ctx context.Context, id xid.ID, req model.UpdateOrganizationRequest) (*model.Organization, error)
	DeleteOrganization(ctx context.Context, id xid.ID, req model.DeleteOrganizationRequest) error
	ListOrganizations(ctx context.Context, req model.OrganizationListRequest) (*model.OrganizationListResponse, error)

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
}

// service implements the organization service
type service struct {
	orgRepo        repository.OrganizationRepository
	membershipRepo repository.MembershipRepository
	userRepo       repository.UserRepository
	auditRepo      repository.AuditRepository
	logger         logging.Logger
}

// NewService creates a new organization service instance
func NewService(
	orgRepo repository.OrganizationRepository,
	membershipRepo repository.MembershipRepository,
	userRepo repository.UserRepository,
	auditRepo repository.AuditRepository,
	logger logging.Logger,
) Service {
	return &service{
		orgRepo:        orgRepo,
		membershipRepo: membershipRepo,
		userRepo:       userRepo,
		auditRepo:      auditRepo,
		logger:         logger,
	}
}

// CreateOrganization creates a new organization
func (s *service) CreateOrganization(ctx context.Context, req model.CreateOrganizationRequest) (*model.Organization, error) {
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
	limits := s.getDefaultLimitsForPlan(req.Plan)

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
		}
	}

	// Convert to model
	modelOrg := s.convertEntOrgToModel(entOrg)

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

	return s.convertEntOrgToModel(entOrg), nil
}

// GetOrganizationBySlug retrieves an organization by slug
func (s *service) GetOrganizationBySlug(ctx context.Context, slug string) (*model.Organization, error) {
	entOrg, err := s.orgRepo.GetBySlug(ctx, slug)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization by slug")
	}

	return s.convertEntOrgToModel(entOrg), nil
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

	return s.convertEntOrgToModel(entOrg), nil
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
		limits := s.getDefaultLimitsForPlan(*req.Plan)
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
		return s.convertEntOrgToModel(existingOrg), nil
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

	return s.convertEntOrgToModel(updatedOrg), nil
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

func (s *service) ListDomains(ctx context.Context, orgID xid.ID) ([]string, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) GetFeatureConfig(ctx context.Context, orgID xid.ID, featureKey string) (map[string]interface{}, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) ListEnabledFeatures(ctx context.Context, orgID xid.ID) ([]model.FeatureSummary, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) GetOwnershipHistory(ctx context.Context, orgID xid.ID) ([]OwnershipTransfer, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) GetOrganizationAnalytics(ctx context.Context, orgID xid.ID, days int) (*OrganizationAnalytics, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) GetComplianceReport(ctx context.Context, orgID xid.ID) (*ComplianceReport, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) ValidateSlug(ctx context.Context, slug string, excludeOrgID *xid.ID) error {
	// TODO implement me
	panic("implement me")
}

func (s *service) GenerateSlug(ctx context.Context, name string) (string, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) SuggestSimilarOrganizations(ctx context.Context, name string, limit int) ([]model.OrganizationSummary, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) UpdatePlan(ctx context.Context, orgID xid.ID, plan string) (*model.Organization, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) GetPlanLimits(ctx context.Context, orgID xid.ID) (*PlanLimits, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) CheckPlanLimit(ctx context.Context, orgID xid.ID, resource string, requestedCount int) (*PlanLimitCheck, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) UpdateSubscriptionStatus(ctx context.Context, orgID xid.ID, status organization.SubscriptionStatus) error {
	// TODO implement me
	panic("implement me")
}

func (s *service) GetSettings(ctx context.Context, orgID xid.ID) (*model.OrganizationSettings, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) UpdateSettings(ctx context.Context, orgID xid.ID, req model.UpdateOrganizationSettingsRequest) (*model.OrganizationSettings, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) UpdateBillingInfo(ctx context.Context, orgID xid.ID, req model.UpdateBillingRequest) (*model.OrganizationBilling, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) GetBillingInfo(ctx context.Context, orgID xid.ID) (*model.OrganizationBilling, error) {
	// TODO implement me
	panic("implement me")
}

func (s *service) SetCustomerID(ctx context.Context, orgID xid.ID, customerID string) error {
	// TODO implement me
	panic("implement me")
}

func (s *service) SetSubscriptionID(ctx context.Context, orgID xid.ID, subscriptionID string) error {
	// TODO implement me
	panic("implement me")
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

func (s *service) getDefaultLimitsForPlan(plan string) UserLimits {
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
		return s.getDefaultLimitsForPlan("free")
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

func (s *service) convertEntOrgToModel(entOrg *ent.Organization) *model.Organization {
	return &model.Organization{
		Base: model.Base{
			ID:        entOrg.ID,
			CreatedAt: entOrg.CreatedAt,
			UpdatedAt: entOrg.UpdatedAt,
		},
		Name:                   entOrg.Name,
		Slug:                   entOrg.Slug,
		Domains:                entOrg.Domains,
		VerifiedDomains:        entOrg.VerifiedDomains,
		Domain:                 entOrg.Domain,
		LogoURL:                entOrg.LogoURL,
		Plan:                   entOrg.Plan,
		Active:                 entOrg.Active,
		Metadata:               entOrg.Metadata,
		TrialEndsAt:            entOrg.TrialEndsAt,
		TrialUsed:              entOrg.TrialUsed,
		OwnerID:                &entOrg.OwnerID,
		OrgType:                entOrg.OrgType,
		IsPlatformOrganization: entOrg.IsPlatformOrganization,
		ExternalUserLimit:      entOrg.ExternalUserLimit,
		EndUserLimit:           entOrg.EndUserLimit,
		SSOEnabled:             entOrg.SSOEnabled,
		SSODomain:              entOrg.SSODomain,
		SubscriptionID:         entOrg.SubscriptionID,
		CustomerID:             entOrg.CustomerID,
		SubscriptionStatus:     entOrg.SubscriptionStatus.String(),
		AuthServiceEnabled:     entOrg.AuthServiceEnabled,
		AuthConfig:             entOrg.AuthConfig,
		AuthDomain:             entOrg.AuthDomain,
		APIRequestLimit:        entOrg.APIRequestLimit,
		APIRequestsUsed:        entOrg.APIRequestsUsed,
		CurrentExternalUsers:   entOrg.CurrentExternalUsers,
		CurrentEndUsers:        entOrg.CurrentEndUsers,
	}
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

// Placeholder implementations for remaining methods
func (s *service) ListOrganizations(ctx context.Context, req model.OrganizationListRequest) (*model.OrganizationListResponse, error) {
	// TODO: Implement organization listing with pagination and filtering
	return &model.OrganizationListResponse{}, nil
}

func (s *service) AddDomain(ctx context.Context, orgID xid.ID, domain string) error {
	// TODO: Implement domain addition
	return nil
}

func (s *service) RemoveDomain(ctx context.Context, orgID xid.ID, domain string) error {
	// TODO: Implement domain removal
	return nil
}

func (s *service) VerifyDomain(ctx context.Context, req model.DomainVerificationRequest) (*model.DomainVerificationResponse, error) {
	// TODO: Implement domain verification
	return nil, nil
}

func (s *service) GetDomainVerificationStatus(ctx context.Context, orgID xid.ID, domain string) (*model.DomainVerificationResponse, error) {
	// TODO: Implement get domain verification status
	return nil, nil
}

func (s *service) GetOrganizationSettings(ctx context.Context, orgID xid.ID) (*model.OrganizationSettings, error) {
	// TODO: Implement get organization settings
	return nil, nil
}

func (s *service) UpdateOrganizationSettings(ctx context.Context, orgID xid.ID, req model.UpdateOrganizationSettingsRequest) (*model.OrganizationSettings, error) {
	// TODO: Implement update organization settings
	return nil, nil
}

func (s *service) GetOrganizationBilling(ctx context.Context, orgID xid.ID) (*model.OrganizationBilling, error) {
	// TODO: Implement get organization billing
	return nil, nil
}

func (s *service) UpdateBilling(ctx context.Context, orgID xid.ID, req model.UpdateBillingRequest) (*model.OrganizationBilling, error) {
	// TODO: Implement update billing
	return nil, nil
}

func (s *service) GetOrganizationUsage(ctx context.Context, orgID xid.ID) (*model.OrganizationUsage, error) {
	// TODO: Implement get organization usage
	return nil, nil
}

func (s *service) UpdateUsage(ctx context.Context, orgID xid.ID, usage model.OrganizationUsage) error {
	// TODO: Implement update usage
	return nil
}

func (s *service) StartTrial(ctx context.Context, orgID xid.ID, duration time.Duration) error {
	// TODO: Implement start trial
	return nil
}

func (s *service) EndTrial(ctx context.Context, orgID xid.ID) error {
	// TODO: Implement end trial
	return nil
}

func (s *service) ExtendTrial(ctx context.Context, orgID xid.ID, extension time.Duration) error {
	// TODO: Implement extend trial
	return nil
}

func (s *service) GetTrialStatus(ctx context.Context, orgID xid.ID) (*TrialStatus, error) {
	// TODO: Implement get trial status
	return nil, nil
}

func (s *service) EnableFeature(ctx context.Context, orgID xid.ID, featureName string, config map[string]interface{}) error {
	// TODO: Implement enable feature
	return nil
}

func (s *service) DisableFeature(ctx context.Context, orgID xid.ID, featureName string) error {
	// TODO: Implement disable feature
	return nil
}

func (s *service) IsFeatureEnabled(ctx context.Context, orgID xid.ID, featureName string) (bool, error) {
	// TODO: Implement is feature enabled
	return false, nil
}

func (s *service) GetEnabledFeatures(ctx context.Context, orgID xid.ID) ([]model.FeatureSummary, error) {
	// TODO: Implement get enabled features
	return nil, nil
}

func (s *service) EnableAuthService(ctx context.Context, orgID xid.ID, config map[string]interface{}) error {
	// TODO: Implement enable auth service
	return nil
}

func (s *service) DisableAuthService(ctx context.Context, orgID xid.ID) error {
	// TODO: Implement disable auth service
	return nil
}

func (s *service) UpdateAuthConfig(ctx context.Context, orgID xid.ID, config map[string]interface{}) error {
	// TODO: Implement update auth config
	return nil
}

func (s *service) GetAuthConfig(ctx context.Context, orgID xid.ID) (map[string]interface{}, error) {
	// TODO: Implement get auth config
	return nil, nil
}

func (s *service) EnableSSO(ctx context.Context, orgID xid.ID, domain string, config map[string]interface{}) error {
	// TODO: Implement enable SSO
	return nil
}

func (s *service) DisableSSO(ctx context.Context, orgID xid.ID) error {
	// TODO: Implement disable SSO
	return nil
}

func (s *service) UpdateSSOConfig(ctx context.Context, orgID xid.ID, config map[string]interface{}) error {
	// TODO: Implement update SSO config
	return nil
}

func (s *service) GetUserLimits(ctx context.Context, orgID xid.ID) (*UserLimits, error) {
	// TODO: Implement get user limits
	return nil, nil
}

func (s *service) UpdateUserLimits(ctx context.Context, orgID xid.ID, limits UserLimits) error {
	// TODO: Implement update user limits
	return nil
}

func (s *service) CheckUserLimit(ctx context.Context, orgID xid.ID, userType string) (bool, error) {
	// TODO: Implement check user limit
	return true, nil
}

func (s *service) GetCurrentUserCounts(ctx context.Context, orgID xid.ID) (*UserCounts, error) {
	// TODO: Implement get current user counts
	return nil, nil
}

func (s *service) TransferOwnership(ctx context.Context, orgID xid.ID, req model.TransferUserOwnershipRequest) error {
	// TODO: Implement transfer ownership
	return nil
}

func (s *service) GetOwner(ctx context.Context, orgID xid.ID) (*model.UserSummary, error) {
	// TODO: Implement get owner
	return nil, nil
}

func (s *service) GetOrganizationStats(ctx context.Context, orgID xid.ID) (*model.OrgStats, error) {
	// TODO: Implement get organization stats
	return nil, nil
}

func (s *service) GetOrganizationActivity(ctx context.Context, orgID xid.ID, days int) (*OrganizationActivity, error) {
	// TODO: Implement get organization activity
	return nil, nil
}

func (s *service) GetGrowthMetrics(ctx context.Context, orgID xid.ID, period string) (*GrowthMetrics, error) {
	// TODO: Implement get growth metrics
	return nil, nil
}

func (s *service) GetPlatformOrganization(ctx context.Context) (*model.Organization, error) {
	// TODO: Implement get platform organization
	return nil, nil
}

func (s *service) GetCustomerOrganizations(ctx context.Context, req model.OrganizationListRequest) (*model.OrganizationListResponse, error) {
	// TODO: Implement get customer organizations
	return nil, nil
}
