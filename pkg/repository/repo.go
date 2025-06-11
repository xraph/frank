package repository

import (
	"context"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/membership"
	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/ent/permission"
	"github.com/juicycleff/frank/ent/permissiondependency"
	"github.com/juicycleff/frank/ent/role"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/ent/userrole"
	"github.com/juicycleff/frank/internal/model"
	repository2 "github.com/juicycleff/frank/internal/repository"
	"github.com/rs/xid"
)

// ApiKeyRepository defines the interface for API key data operations
type ApiKeyRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateApiKeyInput) (*ent.ApiKey, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.ApiKey, error)
	GetByHashedKey(ctx context.Context, hashedKey string) (*ent.ApiKey, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateApiKeyInput) (*ent.ApiKey, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
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
}

// AuditRepository defines the interface for audit log data operations
type AuditRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateAuditInput) (*ent.Audit, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Audit, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByAction(ctx context.Context, action string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByResourceType(ctx context.Context, resourceType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByResourceID(ctx context.Context, resourceType string, resourceID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByIPAddress(ctx context.Context, ipAddress string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)

	// Advanced queries
	ListByUserAndOrganization(ctx context.Context, userID, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByTimeRange(ctx context.Context, from, to time.Time, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByStatus(ctx context.Context, status string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListFailedActions(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)

	// Security queries
	ListSuspiciousActivity(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListBySessionID(ctx context.Context, sessionID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	CountByUserAndAction(ctx context.Context, userID xid.ID, action string, since time.Time) (int, error)
	CountByIPAndAction(ctx context.Context, ipAddress, action string, since time.Time) (int, error)

	// Compliance and reporting
	GetComplianceReport(ctx context.Context, orgID xid.ID, from, to time.Time) (*repository2.ComplianceReport, error)
	ExportAuditLogs(ctx context.Context, filters repository2.AuditExportFilters) ([]*ent.Audit, error)

	// Utility operations
	DeleteOldLogs(ctx context.Context, before time.Time) (int, error)
	CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)
	GetMostRecentByUser(ctx context.Context, userID xid.ID, limit int) ([]*ent.Audit, error)

	// Analytics
	GetActionStats(ctx context.Context, orgID xid.ID, since time.Time) (map[string]int, error)
	GetUserActivityStats(ctx context.Context, orgID xid.ID, since time.Time) (*repository2.UserActivityStats, error)
}

// EmailTemplateRepository defines the interface for email template data operations
type EmailTemplateRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateEmailTemplateInput) (*ent.EmailTemplate, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.EmailTemplate, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateEmailTemplateInput) (*ent.EmailTemplate, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	List(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)
	ListByType(ctx context.Context, templateType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)
	ListByLocale(ctx context.Context, locale string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)
	ListActive(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)
	ListSystem(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)

	// Template retrieval operations
	GetByTypeAndOrganization(ctx context.Context, templateType string, orgID *xid.ID, locale string) (*ent.EmailTemplate, error)
	GetByTypeAndLocale(ctx context.Context, templateType, locale string) (*ent.EmailTemplate, error)
	GetSystemTemplate(ctx context.Context, templateType, locale string) (*ent.EmailTemplate, error)
	GetOrganizationTemplate(ctx context.Context, templateType string, orgID xid.ID, locale string) (*ent.EmailTemplate, error)

	// Template management operations
	ActivateTemplate(ctx context.Context, id xid.ID) error
	DeactivateTemplate(ctx context.Context, id xid.ID) error
	CloneTemplate(ctx context.Context, id xid.ID, newName string, orgID *xid.ID) (*ent.EmailTemplate, error)

	// Utility operations
	CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)
	CountByType(ctx context.Context, templateType string) (int, error)
	ListTemplateTypes(ctx context.Context) ([]string, error)
	ListLocales(ctx context.Context) ([]string, error)

	// Advanced queries
	ListByOrganizationAndType(ctx context.Context, orgID xid.ID, templateType string) ([]*ent.EmailTemplate, error)
	GetTemplateHierarchy(ctx context.Context, templateType string, orgID *xid.ID, locale string) ([]*ent.EmailTemplate, error)
	SearchTemplates(ctx context.Context, query string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)

	// Template validation operations
	ValidateTemplate(ctx context.Context, htmlContent, textContent string) error
	GetTemplateVariables(ctx context.Context, templateType string) ([]string, error)
}

// IdentityProviderRepository defines the interface for identity provider data operations
type IdentityProviderRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateIdentityProviderInput) (*ent.IdentityProvider, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.IdentityProvider, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateIdentityProviderInput) (*ent.IdentityProvider, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.IdentityProvider], error)
	ListByProviderType(ctx context.Context, providerType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.IdentityProvider], error)
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
	GetProviderStats(ctx context.Context, orgID xid.ID) (*repository2.ProviderStats, error)
	ListRecentlyModified(ctx context.Context, limit int) ([]*ent.IdentityProvider, error)

	// Configuration validation
	ValidateConfiguration(ctx context.Context, providerType string, config map[string]any) error
	TestConnection(ctx context.Context, id xid.ID) error
}

// MembershipRepository defines the interface for membership data access
type MembershipRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateMembershipInput) (*ent.Membership, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Membership, error)
	GetByUserAndOrganization(ctx context.Context, userID, organizationID xid.ID) (*ent.Membership, error)
	GetByInvitationToken(ctx context.Context, token string) (*ent.Membership, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateMembershipInput) (*ent.Membership, error)
	Delete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params repository2.ListMembershipsParams) (*model.PaginatedOutput[*ent.Membership], error)
	ListByUser(ctx context.Context, userID xid.ID, params repository2.ListMembershipsParams) (*model.PaginatedOutput[*ent.Membership], error)
	ListByOrganization(ctx context.Context, organizationID xid.ID, params repository2.ListMembershipsParams) (*model.PaginatedOutput[*ent.Membership], error)
	// ListByStatus(ctx context.Context, status string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Membership], error)
	ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error)
	ListPendingByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error)

	// // Role-based queries
	// ListByRole(ctx context.Context, role string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Membership], error)
	// ListAdminsByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error)
	// ListOwnersByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error)
	// GetUserRoleInOrganization(ctx context.Context, userID, orgID xid.ID) (string, error)

	// Invitation management
	CreateInvitation(ctx context.Context, input repository2.CreateInvitationInput) (*ent.Membership, error)
	AcceptInvitation(ctx context.Context, token string, acceptedBy xid.ID) (*ent.Membership, error)
	DeclineInvitation(ctx context.Context, token string) error
	ResendInvitation(ctx context.Context, id xid.ID, newToken string, expiresAt time.Time) (*ent.Membership, error)
	GetPendingInvitations(ctx context.Context, organizationID xid.ID) ([]*ent.Membership, error)
	GetExpiredInvitations(ctx context.Context) ([]*ent.Membership, error)
	CleanupExpiredInvitations(ctx context.Context) (int, error)

	// Status management
	Activate(ctx context.Context, id xid.ID) error
	Deactivate(ctx context.Context, id xid.ID) error
	Suspend(ctx context.Context, id xid.ID) error
	UpdateStatus(ctx context.Context, id xid.ID, status membership.Status) error

	// Role management
	UpdateRole(ctx context.Context, id xid.ID, roleID xid.ID) error
	GetMembershipsWithRole(ctx context.Context, organizationID, roleID xid.ID) ([]*ent.Membership, error)

	// Member management
	GetActiveMembers(ctx context.Context, organizationID xid.ID) ([]*ent.Membership, error)
	GetMemberCount(ctx context.Context, organizationID xid.ID, status *membership.Status) (int, error)
	GetBillingContacts(ctx context.Context, organizationID xid.ID) ([]*ent.Membership, error)
	GetPrimaryContact(ctx context.Context, organizationID xid.ID) (*ent.Membership, error)
	SetPrimaryContact(ctx context.Context, id xid.ID) error
	AddBillingContact(ctx context.Context, id xid.ID) error
	RemoveBillingContact(ctx context.Context, id xid.ID) error

	// Analytics and reporting
	GetMembershipStats(ctx context.Context, organizationID xid.ID) (*repository2.MembershipStats, error)
	GetRecentJoins(ctx context.Context, organizationID xid.ID, days int) ([]*ent.Membership, error)
	GetInvitationStats(ctx context.Context, organizationID xid.ID, days int) (*repository2.InvitationStats, error)

	// Existence checks
	ExistsByUserAndOrganization(ctx context.Context, userID, organizationID xid.ID) (bool, error)
	HasActiveMembership(ctx context.Context, userID, organizationID xid.ID) (bool, error)
}

// MFARepository defines the interface for MFA data operations
type MFARepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateMFAInput) (*ent.MFA, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.MFA, error)
	GetByUserIDAndMethod(ctx context.Context, userID xid.ID, method string) (*ent.MFA, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateMFAInput) (*ent.MFA, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.MFA], error)
	ListActiveByUserID(ctx context.Context, userID xid.ID) ([]*ent.MFA, error)
	ListByMethod(ctx context.Context, method string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.MFA], error)

	// Verification operations
	MarkAsVerified(ctx context.Context, id xid.ID) error
	UpdateLastUsed(ctx context.Context, id xid.ID) error

	// Utility operations
	DeactivateByUserID(ctx context.Context, userID xid.ID) error
	DeactivateMethodByUserID(ctx context.Context, userID xid.ID, method string) error
	CountByUserID(ctx context.Context, userID xid.ID) (int, error)
	CountVerifiedByUserID(ctx context.Context, userID xid.ID) (int, error)

	// Advanced queries
	GetVerifiedByUserIDAndMethod(ctx context.Context, userID xid.ID, method string) (*ent.MFA, error)
	HasVerifiedMFA(ctx context.Context, userID xid.ID) (bool, error)
	ListMethodsByUserID(ctx context.Context, userID xid.ID) ([]string, error)
}

// OAuthRepository defines the interface for OAuth data access
type OAuthRepository interface {
	// OAuth Client operations
	CreateClient(ctx context.Context, input repository2.CreateOAuthClientInput) (*ent.OAuthClient, error)
	GetClientByID(ctx context.Context, id xid.ID) (*ent.OAuthClient, error)
	GetClientByClientID(ctx context.Context, clientID string) (*ent.OAuthClient, error)
	UpdateClient(ctx context.Context, id xid.ID, input repository2.UpdateOAuthClientInput) (*ent.OAuthClient, error)
	DeleteClient(ctx context.Context, id xid.ID) error
	ListClients(ctx context.Context, params repository2.ListOAuthClientsParams) (*model.PaginatedOutput[*ent.OAuthClient], error)
	ListClientsByOrganization(ctx context.Context, organizationID xid.ID, params repository2.ListOAuthClientsParams) (*model.PaginatedOutput[*ent.OAuthClient], error)

	// OAuth Token operations
	CreateToken(ctx context.Context, input repository2.CreateOAuthTokenInput) (*ent.OAuthToken, error)
	GetTokenByID(ctx context.Context, id xid.ID) (*ent.OAuthToken, error)
	GetTokenByAccessToken(ctx context.Context, accessToken string) (*ent.OAuthToken, error)
	GetTokenByRefreshToken(ctx context.Context, refreshToken string) (*ent.OAuthToken, error)
	UpdateToken(ctx context.Context, id xid.ID, input repository2.UpdateOAuthTokenInput) (*ent.OAuthToken, error)
	DeleteToken(ctx context.Context, id xid.ID) error
	RevokeToken(ctx context.Context, accessToken string) error
	RevokeTokenByRefreshToken(ctx context.Context, refreshToken string) error
	ListTokens(ctx context.Context, params repository2.ListOAuthTokensParams) (*model.PaginatedOutput[*ent.OAuthToken], error)
	ListUserTokens(ctx context.Context, userID xid.ID, params repository2.ListOAuthTokensParams) (*model.PaginatedOutput[*ent.OAuthToken], error)
	ListClientTokens(ctx context.Context, clientID xid.ID, params repository2.ListOAuthTokensParams) (*model.PaginatedOutput[*ent.OAuthToken], error)

	// OAuth Authorization operations
	CreateAuthorization(ctx context.Context, input repository2.CreateOAuthAuthorizationInput) (*ent.OAuthAuthorization, error)
	GetAuthorizationByCode(ctx context.Context, code string) (*ent.OAuthAuthorization, error)
	DeleteAuthorization(ctx context.Context, id xid.ID) error
	DeleteAuthorizationByCode(ctx context.Context, code string) error
	ListAuthorizations(ctx context.Context, params repository2.ListOAuthAuthorizationsParams) (*model.PaginatedOutput[*ent.OAuthAuthorization], error)

	// OAuth Scope operations
	CreateScope(ctx context.Context, input repository2.CreateOAuthScopeInput) (*ent.OAuthScope, error)
	GetScopeByName(ctx context.Context, name string) (*ent.OAuthScope, error)
	ListScopes(ctx context.Context, params repository2.ListOAuthScopesParams) (*model.PaginatedOutput[*ent.OAuthScope], error)
	GetDefaultScopes(ctx context.Context) ([]*ent.OAuthScope, error)
	GetPublicScopes(ctx context.Context) ([]*ent.OAuthScope, error)
	UpdateScope(ctx context.Context, id xid.ID, input repository2.UpdateOAuthScopeInput) (*ent.OAuthScope, error)
	DeleteScope(ctx context.Context, id xid.ID) error

	// Token validation and cleanup
	ValidateAccessToken(ctx context.Context, accessToken string) (*ent.OAuthToken, error)
	ValidateRefreshToken(ctx context.Context, refreshToken string) (*ent.OAuthToken, error)
	CleanupExpiredTokens(ctx context.Context) (int, error)
	CleanupExpiredAuthorizations(ctx context.Context) (int, error)
	RevokeAllUserTokens(ctx context.Context, userID xid.ID) error
	RevokeAllClientTokens(ctx context.Context, clientID xid.ID) error

	// Analytics and statistics
	GetOAuthStats(ctx context.Context, organizationID *xid.ID) (*repository2.OAuthStats, error)
	GetClientUsageStats(ctx context.Context, clientID xid.ID, days int) (*repository2.ClientUsageStats, error)
	GetTokenUsageStats(ctx context.Context, userID *xid.ID, clientID *xid.ID, days int) (*repository2.TokenUsageStats, error)
}

// OrganizationFeatureRepository defines the interface for organization feature data operations
type OrganizationFeatureRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateOrganizationFeatureInput) (*ent.OrganizationFeature, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.OrganizationFeature, error)
	GetByOrganizationAndFeature(ctx context.Context, orgID, featureID xid.ID) (*ent.OrganizationFeature, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateOrganizationFeatureInput) (*ent.OrganizationFeature, error)
	Delete(ctx context.Context, id xid.ID) error
	DeleteByOrganizationAndFeature(ctx context.Context, orgID, featureID xid.ID) error

	// Query operations
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.OrganizationFeature], error)
	ListByFeatureID(ctx context.Context, featureID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.OrganizationFeature], error)
	ListEnabledByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.OrganizationFeature, error)
	ListDisabledByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.OrganizationFeature, error)

	// Feature checking operations
	IsFeatureEnabled(ctx context.Context, orgID, featureID xid.ID) (bool, error)
	IsFeatureEnabledByKey(ctx context.Context, orgID xid.ID, featureKey string) (bool, error)
	GetFeatureSettings(ctx context.Context, orgID, featureID xid.ID) (map[string]any, error)
	GetFeatureSettingsByKey(ctx context.Context, orgID xid.ID, featureKey string) (map[string]any, error)

	// Bulk operations
	EnableFeature(ctx context.Context, orgID, featureID xid.ID, settings map[string]any) (*ent.OrganizationFeature, error)
	DisableFeature(ctx context.Context, orgID, featureID xid.ID) error
	EnableMultipleFeatures(ctx context.Context, orgID xid.ID, featureIDs []xid.ID) error
	DisableMultipleFeatures(ctx context.Context, orgID xid.ID, featureIDs []xid.ID) error

	// Utility operations
	CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)
	CountEnabledByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)
	CountByFeatureID(ctx context.Context, featureID xid.ID) (int, error)

	// Advanced queries
	ListOrganizationsWithFeature(ctx context.Context, featureID xid.ID, enabled bool) ([]*ent.OrganizationFeature, error)
	GetOrganizationFeatureMatrix(ctx context.Context, orgID xid.ID) (map[string]repository2.OrganizationFeatureStatus, error)
	ListFeatureUsageStats(ctx context.Context) ([]repository2.FeatureUsageStats, error)
}

// OrganizationRepository defines the interface for organization data access
type OrganizationRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateOrganizationInput) (*ent.Organization, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*ent.Organization, error)
	GetByDomain(ctx context.Context, domain string) (*ent.Organization, error)
	GetByAuthDomain(ctx context.Context, authDomain string) (*ent.Organization, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateOrganizationInput) (*ent.Organization, error)
	Delete(ctx context.Context, id xid.ID) error
	SoftDelete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params repository2.ListOrganizationsParams) (*model.PaginatedOutput[*ent.Organization], error)
	ListActive(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Organization], error)
	ListByPlan(ctx context.Context, plan string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Organization], error)
	// ListByStatus(ctx context.Context, status string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Organization], error)
	Search(ctx context.Context, query string, params repository2.SearchOrganizationsParams) (*model.PaginatedOutput[*ent.Organization], error)

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
	GetCustomerOrganizations(ctx context.Context, params repository2.ListOrganizationsParams) (*model.PaginatedOutput[*ent.Organization], error)

	// Subscription and billing
	UpdateSubscriptionStatus(ctx context.Context, id xid.ID, status organization.SubscriptionStatus) error
	UpdateUsage(ctx context.Context, id xid.ID, input repository2.UpdateUsageInput) error
	GetByCustomerID(ctx context.Context, customerID string) (*ent.Organization, error)
	GetBySubscriptionID(ctx context.Context, subscriptionID string) (*ent.Organization, error)

	// Trial management
	StartTrial(ctx context.Context, id xid.ID, trialEndsAt *time.Time) error
	EndTrial(ctx context.Context, id xid.ID) error
	IsTrialActive(ctx context.Context, id xid.ID) (bool, error)

	// User limits and quotas
	GetCurrentUserCounts(ctx context.Context, id xid.ID) (*repository2.UserCounts, error)
	CanAddExternalUser(ctx context.Context, id xid.ID) (bool, error)
	CanAddEndUser(ctx context.Context, id xid.ID) (bool, error)
	UpdateUserCounts(ctx context.Context, id xid.ID, counts repository2.UpdateUserCountsInput) error

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

// PasskeyRepository defines the interface for passkey data access
type PasskeyRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreatePasskeyInput) (*ent.Passkey, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Passkey, error)
	GetByCredentialID(ctx context.Context, credentialID string) (*ent.Passkey, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdatePasskeyInput) (*ent.Passkey, error)
	Delete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params repository2.ListPasskeysParams) (*model.PaginatedOutput[*ent.Passkey], error)
	ListByUser(ctx context.Context, userID xid.ID, params repository2.ListPasskeysParams) (*model.PaginatedOutput[*ent.Passkey], error)
	Search(ctx context.Context, query string, params repository2.SearchPasskeysParams) (*model.PaginatedOutput[*ent.Passkey], error)

	// Passkey management
	GetUserPasskeys(ctx context.Context, userID xid.ID, activeOnly bool) ([]*ent.Passkey, error)
	GetActivePasskeys(ctx context.Context, userID xid.ID) ([]*ent.Passkey, error)
	GetPasskeysByDevice(ctx context.Context, userID xid.ID, deviceType string) ([]*ent.Passkey, error)
	GetPasskeysByAAGUID(ctx context.Context, aaguid string) ([]*ent.Passkey, error)

	// Authentication operations
	UpdateSignCount(ctx context.Context, credentialID string, signCount int) error
	UpdateLastUsed(ctx context.Context, credentialID string) error
	IncrementUsage(ctx context.Context, credentialID string, signCount int) error
	ValidateCredentialID(ctx context.Context, credentialID string) (*ent.Passkey, error)

	// Passkey status management
	Activate(ctx context.Context, id xid.ID) error
	Deactivate(ctx context.Context, id xid.ID) error
	DeactivateAllUserPasskeys(ctx context.Context, userID xid.ID) error
	DeactivateByDevice(ctx context.Context, userID xid.ID, deviceType string) error

	// Analytics and reporting
	GetPasskeyStats(ctx context.Context, userID *xid.ID) (*repository2.PasskeyStats, error)
	GetDeviceUsageStats(ctx context.Context, userID *xid.ID) (map[string]*repository2.DeviceUsageStats, error)
	GetAAGUIDStats(ctx context.Context) (map[string]*repository2.AAGUIDStats, error)
	GetUsageAnalytics(ctx context.Context, userID *xid.ID, days int) (*repository2.PasskeyUsageAnalytics, error)

	// Device and authenticator management
	GetUserDevices(ctx context.Context, userID xid.ID) ([]string, error)
	GetUniqueAAGUIDs(ctx context.Context, userID *xid.ID) ([]string, error)
	GetAuthenticatorModels(ctx context.Context, userID *xid.ID) (map[string]int, error)
	GetRecentlyUsedPasskeys(ctx context.Context, userID xid.ID, limit int) ([]*ent.Passkey, error)

	// Security and monitoring
	GetSuspiciousActivity(ctx context.Context, userID xid.ID, days int) ([]*repository2.PasskeySecurityEvent, error)
	GetUnusedPasskeys(ctx context.Context, userID xid.ID, days int) ([]*ent.Passkey, error)
	GetHighUsagePasskeys(ctx context.Context, userID xid.ID, threshold int) ([]*ent.Passkey, error)

	// Bulk operations
	BulkDeactivate(ctx context.Context, ids []xid.ID) error
	BulkDelete(ctx context.Context, ids []xid.ID) error
	CleanupUnusedPasskeys(ctx context.Context, days int) (int, error)

	// Existence checks
	ExistsByCredentialID(ctx context.Context, credentialID string) (bool, error)
	UserHasPasskeys(ctx context.Context, userID xid.ID) (bool, error)
	UserHasActivePasskeys(ctx context.Context, userID xid.ID) (bool, error)
}

// PermissionRepository defines the interface for permission data access
type PermissionRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreatePermissionInput) (*ent.Permission, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Permission, error)
	GetByName(ctx context.Context, name string) (*ent.Permission, error)
	GetByResourceAndAction(ctx context.Context, resource, action string) (*ent.Permission, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdatePermissionInput) (*ent.Permission, error)
	Delete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params repository2.ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	Search(ctx context.Context, query string, params repository2.SearchPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)

	// Category and grouping operations
	GetByCategory(ctx context.Context, category permission.Category, params repository2.ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	GetByGroup(ctx context.Context, group string, params repository2.ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	GetByResource(ctx context.Context, resource string, params repository2.ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	GetSystemPermissions(ctx context.Context, params repository2.ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	GetDangerousPermissions(ctx context.Context, params repository2.ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)

	// Role operations
	GetRolesWithPermission(ctx context.Context, permissionID xid.ID) ([]*ent.Role, error)
	GetPermissionsByRole(ctx context.Context, roleID xid.ID) ([]*ent.Permission, error)

	// User operations
	GetUsersWithPermission(ctx context.Context, permissionID xid.ID) ([]*ent.User, error)
	GetUserPermissions(ctx context.Context, userID xid.ID, contextType userrole.ContextType, contextID *xid.ID) ([]*ent.Permission, error)
	GetEffectiveUserPermissions(ctx context.Context, userID xid.ID, contextType userrole.ContextType, contextID *xid.ID) ([]*ent.Permission, error)

	// Permission dependencies
	GetDependencies(ctx context.Context, permissionID xid.ID) ([]*ent.Permission, error)
	GetDependents(ctx context.Context, permissionID xid.ID) ([]*ent.Permission, error)
	AddDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID, dependencyType permissiondependency.DependencyType) error
	RemoveDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID) error

	// Permission validation and checks
	CanDelete(ctx context.Context, permissionID xid.ID) (bool, error)
	IsInUse(ctx context.Context, permissionID xid.ID) (bool, error)
	ExistsByName(ctx context.Context, name string) (bool, error)
	ExistsByResourceAndAction(ctx context.Context, resource, action string) (bool, error)

	// Bulk operations
	BulkCreate(ctx context.Context, inputs []repository2.CreatePermissionInput) ([]*ent.Permission, error)
	BulkDelete(ctx context.Context, ids []xid.ID) error

	// Permission analysis
	GetPermissionStats(ctx context.Context) (*repository2.PermissionStats, error)
	GetMostUsedPermissions(ctx context.Context, limit int) ([]*repository2.PermissionUsage, error)
	GetUnusedPermissions(ctx context.Context) ([]*ent.Permission, error)
}

// RoleRepository defines the interface for role data access
type RoleRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateRoleInput) (*ent.Role, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Role, error)
	GetByName(ctx context.Context, name string, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) (*ent.Role, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateRoleInput) (*ent.Role, error)
	Delete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params repository2.ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)
	ListByOrganization(ctx context.Context, organizationID xid.ID, params repository2.ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)
	ListByApplication(ctx context.Context, applicationID xid.ID, params repository2.ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)
	Search(ctx context.Context, query string, params repository2.SearchRolesParams) (*model.PaginatedOutput[*ent.Role], error)

	// Role type specific operations
	GetSystemRoles(ctx context.Context, params repository2.ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)
	GetOrganizationRoles(ctx context.Context, organizationID xid.ID, params repository2.ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)
	GetApplicationRoles(ctx context.Context, applicationID xid.ID, params repository2.ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)

	// Default role operations
	GetDefaultRoles(ctx context.Context, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) ([]*ent.Role, error)
	SetAsDefault(ctx context.Context, id xid.ID) error
	UnsetAsDefault(ctx context.Context, id xid.ID) error

	// Permission operations
	AddPermission(ctx context.Context, roleID, permissionID xid.ID) error
	RemovePermission(ctx context.Context, roleID, permissionID xid.ID) error
	GetPermissions(ctx context.Context, roleID xid.ID) ([]*ent.Permission, error)
	HasPermission(ctx context.Context, roleID, permissionID xid.ID) (bool, error)
	GetRolesWithPermission(ctx context.Context, permissionID xid.ID) ([]*ent.Role, error)

	// Role hierarchy operations
	GetChildren(ctx context.Context, roleID xid.ID) ([]*ent.Role, error)
	GetParent(ctx context.Context, roleID xid.ID) (*ent.Role, error)
	GetAncestors(ctx context.Context, roleID xid.ID) ([]*ent.Role, error)
	GetDescendants(ctx context.Context, roleID xid.ID) ([]*ent.Role, error)
	SetParent(ctx context.Context, roleID, parentID xid.ID) error
	RemoveParent(ctx context.Context, roleID xid.ID) error

	// User assignment operations
	GetUsersWithRole(ctx context.Context, roleID xid.ID) ([]*ent.User, error)
	GetUserCount(ctx context.Context, roleID xid.ID) (int, error)

	// Role validation and checks
	CanDelete(ctx context.Context, roleID xid.ID) (bool, error)
	IsInUse(ctx context.Context, roleID xid.ID) (bool, error)
	ExistsByName(ctx context.Context, name string, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) (bool, error)

	// Bulk operations
	BulkCreate(ctx context.Context, inputs []repository2.CreateRoleInput) ([]*ent.Role, error)
	BulkDelete(ctx context.Context, ids []xid.ID) error
}

// SessionRepository defines the interface for session data access
type SessionRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateSessionInput) (*ent.Session, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Session, error)
	GetByToken(ctx context.Context, token string) (*ent.Session, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateSessionInput) (*ent.Session, error)
	Delete(ctx context.Context, id xid.ID) error
	DeleteByToken(ctx context.Context, token string) error

	// List and search operations
	List(ctx context.Context, params repository2.ListSessionsParams) (*model.PaginatedOutput[*ent.Session], error)
	ListByUser(ctx context.Context, userID xid.ID, params repository2.ListSessionsParams) (*model.PaginatedOutput[*ent.Session], error)
	ListByOrganization(ctx context.Context, organizationID xid.ID, params repository2.ListSessionsParams) (*model.PaginatedOutput[*ent.Session], error)

	// Session management
	GetActiveSessions(ctx context.Context, userID xid.ID) ([]*ent.Session, error)
	GetActiveSessionsCount(ctx context.Context, userID xid.ID) (int, error)
	RefreshSession(ctx context.Context, token string, newExpiresAt time.Time) (*ent.Session, error)
	ExtendSession(ctx context.Context, token string, duration time.Duration) (*ent.Session, error)
	UpdateLastActive(ctx context.Context, token string) error

	// Session validation
	IsValidSession(ctx context.Context, token string) (bool, error)
	IsActiveSession(ctx context.Context, token string) (bool, error)
	ValidateAndRefresh(ctx context.Context, token string) (*ent.Session, error)

	// Bulk operations
	InvalidateAllUserSessions(ctx context.Context, userID xid.ID) error
	InvalidateAllOrganizationSessions(ctx context.Context, organizationID xid.ID) error
	InvalidateExpiredSessions(ctx context.Context) (int, error)
	CleanupOldSessions(ctx context.Context, olderThan time.Time) (int, error)

	// Session analysis
	GetSessionStats(ctx context.Context, userID *xid.ID, organizationID *xid.ID) (*repository2.SessionStats, error)
	GetActiveSessionsByDevice(ctx context.Context, userID xid.ID) (map[string][]*ent.Session, error)
	// GetSessionsByLocation(ctx context.Context, userID xid.ID) (map[string][]*ent.Session, error)
	GetSuspiciousSessions(ctx context.Context, userID xid.ID) ([]*ent.Session, error)

	// Device management
	GetSessionsByDevice(ctx context.Context, userID xid.ID, deviceID string) ([]*ent.Session, error)
	InvalidateDeviceSessions(ctx context.Context, userID xid.ID, deviceID string) error
	GetUniqueDevices(ctx context.Context, userID xid.ID) ([]string, error)

	// IP and location tracking
	GetSessionsByIP(ctx context.Context, userID xid.ID, ipAddress string) ([]*ent.Session, error)
	GetRecentIPs(ctx context.Context, userID xid.ID, since time.Time) ([]string, error)
	GetSessionsByLocation(ctx context.Context, userID xid.ID, location string) ([]*ent.Session, error)
}

// SSOStateRepository defines the interface for SSO state data operations
type SSOStateRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateSSOStateInput) (*ent.SSOState, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.SSOState, error)
	GetByState(ctx context.Context, state string) (*ent.SSOState, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateSSOStateInput) (*ent.SSOState, error)
	Delete(ctx context.Context, id xid.ID) error
	DeleteByState(ctx context.Context, state string) error

	// Query operations
	List(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SSOState], error)
	ListExpired(ctx context.Context, before time.Time) ([]*ent.SSOState, error)

	// Utility operations
	CleanupExpired(ctx context.Context, before time.Time) (int, error)
	IsValid(ctx context.Context, state string) (bool, error)
	Count(ctx context.Context) (int, error)

	// Advanced queries
	GetValidState(ctx context.Context, state string) (*ent.SSOState, error)
	ListExpiringBefore(ctx context.Context, before time.Time, limit int) ([]*ent.SSOState, error)
}

// UserRepository defines the interface for user data access
type UserRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateUserInput) (*ent.User, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.User, error)
	GetByEmail(ctx context.Context, email string, userType user.UserType, organizationID *xid.ID) (*ent.User, error)
	GetByUsername(ctx context.Context, username string, userType user.UserType, organizationID *xid.ID) (*ent.User, error)
	GetUserByPhone(ctx context.Context, username string, userType user.UserType, organizationID *xid.ID) (*ent.User, error)
	GetByExternalID(ctx context.Context, externalID string, provider string, userType user.UserType, organizationID *xid.ID) (*ent.User, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateUserInput) (*ent.User, error)
	Delete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params repository2.ListUsersParams) (*model.PaginatedOutput[*ent.User], error)
	ListByOrganization(ctx context.Context, organizationID xid.ID, params repository2.ListUsersParams) (*model.PaginatedOutput[*ent.User], error)
	Search(ctx context.Context, query string, params repository2.SearchUsersParams) (*model.PaginatedOutput[*ent.User], error)

	// Authentication related
	GetByPasswordResetToken(ctx context.Context, token string) (*ent.User, error)
	UpdatePassword(ctx context.Context, id xid.ID, passwordHash string) error
	UpdateLastLogin(ctx context.Context, id xid.ID, ip string) error
	IncrementLoginCount(ctx context.Context, id xid.ID) error

	// Verification
	MarkEmailVerified(ctx context.Context, id xid.ID) error
	MarkPhoneVerified(ctx context.Context, id xid.ID) error

	// User management
	Block(ctx context.Context, id xid.ID) error
	Unblock(ctx context.Context, id xid.ID) error
	Activate(ctx context.Context, id xid.ID) error
	Deactivate(ctx context.Context, id xid.ID) error

	// Organization context
	GetPlatformAdmins(ctx context.Context) ([]*ent.User, error)
	GetOrganizationMembers(ctx context.Context, organizationID xid.ID, activeOnly bool) ([]*ent.User, error)
	CountByOrganization(ctx context.Context, organizationID xid.ID, userType user.UserType) (int, error)

	// Existence checks
	ExistsByEmail(ctx context.Context, email string, userType user.UserType, organizationID *xid.ID) (bool, error)
	ExistsByUsername(ctx context.Context, username string, userType user.UserType, organizationID *xid.ID) (bool, error)
}

// VerificationRepository defines the interface for verification data operations
type VerificationRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateVerificationInput) (*ent.Verification, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Verification, error)
	GetByToken(ctx context.Context, token string) (*ent.Verification, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateVerificationInput) (*ent.Verification, error)
	Delete(ctx context.Context, id xid.ID) error
	DeleteByToken(ctx context.Context, token string) error

	// Query operations
	ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Verification], error)
	ListByType(ctx context.Context, verificationType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Verification], error)
	ListByEmail(ctx context.Context, email string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Verification], error)
	ListByPhoneNumber(ctx context.Context, phoneNumber string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Verification], error)

	// Verification operations
	MarkAsUsed(ctx context.Context, id xid.ID) error
	MarkTokenAsUsed(ctx context.Context, token string) error
	IncrementAttempts(ctx context.Context, id xid.ID) error
	IncrementTokenAttempts(ctx context.Context, token string) error

	// Validation operations
	IsTokenValid(ctx context.Context, token string) (bool, error)
	GetValidToken(ctx context.Context, token string) (*ent.Verification, error)
	GetValidTokenByTypeAndUser(ctx context.Context, verificationType string, userID xid.ID) (*ent.Verification, error)

	// Utility operations
	CleanupExpired(ctx context.Context, before time.Time) (int, error)
	CleanupUsed(ctx context.Context, olderThan time.Time) (int, error)
	CountByUserAndType(ctx context.Context, userID xid.ID, verificationType string) (int, error)
	CountAttemptsByIP(ctx context.Context, ipAddress string, since time.Time) (int, error)

	// Advanced queries
	ListExpired(ctx context.Context) ([]*ent.Verification, error)
	ListExpiringBefore(ctx context.Context, before time.Time, limit int) ([]*ent.Verification, error)
	ListRecentByUser(ctx context.Context, userID xid.ID, limit int) ([]*ent.Verification, error)
	ListSuspiciousAttempts(ctx context.Context, maxAttempts int, since time.Time) ([]*ent.Verification, error)

	// Security operations
	GetVerificationStats(ctx context.Context, since time.Time) (*repository2.VerificationStats, error)
	ListHighVolumeIPs(ctx context.Context, minCount int, since time.Time) ([]repository2.IPVerificationActivity, error)
}

// WebhookRepository defines the interface for webhook data operations
type WebhookRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input repository2.CreateWebhookInput) (*ent.Webhook, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Webhook, error)
	Update(ctx context.Context, id xid.ID, input repository2.UpdateWebhookInput) (*ent.Webhook, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Webhook], error)
	ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Webhook, error)
	ListByEventType(ctx context.Context, eventType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Webhook], error)

	// Utility operations
	DeactivateByOrganizationID(ctx context.Context, orgID xid.ID) error
	CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)

	// Advanced queries
	GetActiveByOrganizationIDAndEventType(ctx context.Context, orgID xid.ID, eventType string) ([]*ent.Webhook, error)
	ListByURL(ctx context.Context, url string) ([]*ent.Webhook, error)
}
