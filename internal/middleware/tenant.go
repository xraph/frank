package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/repository"
	contexts2 "github.com/juicycleff/frank/pkg/contexts"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// TenantResolutionStrategy defines how tenants are resolved
type TenantResolutionStrategy string

const (
	// ResolutionByPath resolves tenant from URL path (/org/{slug}/...)
	ResolutionByPath TenantResolutionStrategy = "path"
	// ResolutionBySubdomain resolves tenant from subdomain (tenant.example.com)
	ResolutionBySubdomain TenantResolutionStrategy = "subdomain"
	// ResolutionByHeader resolves tenant from HTTP header
	ResolutionByHeader TenantResolutionStrategy = "header"
	// ResolutionByQuery resolves tenant from query parameter
	ResolutionByQuery TenantResolutionStrategy = "query"
	// ResolutionByAuth resolves tenant from authenticated user context
	ResolutionByAuth TenantResolutionStrategy = "auth"
)

// TenantConfig represents tenant middleware configuration
type TenantConfig struct {
	Strategy            TenantResolutionStrategy
	PathPrefix          string   // e.g., "/org" for /org/{slug}/...
	SubdomainSuffix     string   // e.g., ".example.com"
	HeaderName          string   // e.g., "X-Organization-ID"
	QueryParam          string   // e.g., "org"
	SkipPaths           []string // Paths to skip tenant resolution
	RequireTenant       bool     // Whether tenant is required
	AllowPlatformAccess bool     // Allow access to platform organization
	EnableTenantCache   bool     // Enable tenant caching
	CacheTTL            int      // Cache TTL in seconds
	Logger              logging.Logger
}

// TenantContext represents the current tenant context
type TenantContext struct {
	Organization *model.Organization `json:"organization"`
	Plan         string              `json:"plan"`
	Type         model.OrgType       `json:"type"`
	Features     []string            `json:"features,omitempty"`
	Limits       *TenantLimits       `json:"limits,omitempty"`
	Settings     map[string]any      `json:"settings,omitempty"`
	Active       bool                `json:"active"`
	Trial        *TrialInfo          `json:"trial,omitempty"`
}

// TenantLimits represents tenant-specific limits
type TenantLimits struct {
	ExternalUsers  int   `json:"external_users"`
	EndUsers       int   `json:"end_users"`
	APIRequests    int   `json:"api_requests"`
	Storage        int64 `json:"storage"` // bytes
	EmailsPerMonth int   `json:"emails_per_month"`
	SMSPerMonth    int   `json:"sms_per_month"`
	Webhooks       int   `json:"webhooks"`
	SSO            bool  `json:"sso"`
	CustomDomains  int   `json:"custom_domains"`
}

// TrialInfo represents trial information
type TrialInfo struct {
	Active    bool       `json:"active"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	DaysLeft  int        `json:"days_left"`
	Used      bool       `json:"used"`
}

// TenantMiddleware handles multi-tenant context and isolation
type TenantMiddleware struct {
	api      huma.API
	config   *TenantConfig
	orgRepo  repository.OrganizationRepository
	userRepo repository.UserRepository
	logger   logging.Logger
}

// NewTenantMiddleware creates a new tenant middleware
func NewTenantMiddleware(api huma.API, di di.Container, config *TenantConfig) *TenantMiddleware {
	if config.Logger == nil {
		config.Logger = di.Logger().Named("tenant-middleware")
	}

	return &TenantMiddleware{
		api:      api,
		config:   config,
		orgRepo:  di.Repo().Organization(),
		userRepo: di.Repo().User(),
		logger:   config.Logger,
	}
}

// DefaultTenantConfig returns default tenant configuration
func DefaultTenantConfig() *TenantConfig {
	return &TenantConfig{
		Strategy:            ResolutionByHeader,
		PathPrefix:          "api/v1/organizations",
		HeaderName:          "X-Org-ID",
		QueryParam:          "orgId",
		RequireTenant:       false,
		AllowPlatformAccess: true,
		EnableTenantCache:   true,
		CacheTTL:            300, // 5 minutes
		SkipPaths: []string{
			"/health",
			"/ready",
			"/metrics",
			"/favicon.ico",
			"/robots.txt",
			"/api/v1/auth/login",
			"/api/v1/auth/register",
			"/api/v1/auth/forgot-password",
			"/api/v1/auth/reset-password",
			// "/api/v1/organizations", // Organization creation
		},
	}
}

// Middleware returns the tenant middleware handler
func (tm *TenantMiddleware) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Skip tenant resolution for certain paths
			if tm.shouldSkipPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Resolve tenant based on strategy
			tenant, err := tm.resolveTenant(ctx, r)
			if err != nil {
				tm.logger.Error("Failed to resolve tenant", logging.Error(err))

				if tm.config.RequireTenant {
					tm.respondError(w, r, errors.New(errors.CodeBadRequest, "tenant resolution failed"))
					return
				}
			}

			// If tenant is required but not found
			if tm.config.RequireTenant && tenant == nil {
				tm.respondError(w, r, errors.New(errors.CodeBadRequest, "tenant is required"))
				return
			}

			// Set tenant context
			if tenant != nil {
				ctx = tm.setTenantContext(ctx, tenant)

				// Validate tenant access
				if !tm.validateTenantAccess(ctx, r, tenant) {
					tm.respondError(w, r, errors.New(errors.CodeForbidden, "access denied to tenant"))
					return
				}

				// Check tenant status
				if !tenant.Active {
					tm.respondError(w, r, errors.New(errors.CodeForbidden, "tenant is inactive"))
					return
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// HumaMiddleware returns the tenant middleware handler
func (tm *TenantMiddleware) HumaMiddleware() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		rctx := ctx.Context()
		r := contexts2.GetRequestFromContext(rctx)

		// Skip tenant resolution for certain paths
		if tm.shouldSkipPath(ctx.URL().Path) {
			next(ctx)
			return
		}

		// Resolve tenant based on strategy
		tenant, err := tm.resolveTenant(rctx, r)
		if err != nil {
			tm.logger.Error("Failed to resolve tenant", logging.Error(err))

			if tm.config.RequireTenant {
				huma.WriteErr(tm.api, ctx, http.StatusBadRequest, "tenant resolution failed", errors.New(errors.CodeBadRequest, "tenant resolution failed"))
				return
			}
		}

		// If tenant is required but not found
		if tm.config.RequireTenant && tenant == nil {
			huma.WriteErr(tm.api, ctx, http.StatusBadRequest, "tenant is required", errors.New(errors.CodeBadRequest, "tenant is required"))
			return
		}

		// Set tenant context
		if tenant != nil {
			ctx = tm.setTenantContextHuma(ctx, tenant)

			// Validate tenant access
			if !tm.validateTenantAccess(rctx, r, tenant) {
				huma.WriteErr(tm.api, ctx, http.StatusForbidden, "access denied to tenant", errors.New(errors.CodeForbidden, "access denied to tenant"))
				return
			}

			// Check tenant status
			if !tenant.Active {
				huma.WriteErr(tm.api, ctx, http.StatusForbidden, "tenant is inactive", errors.New(errors.CodeForbidden, "tenant is inactive"))
				return
			}
		}

		// Update context and continue
		next(ctx)
	}
}

// RequireTenant middleware that requires tenant context
func (tm *TenantMiddleware) RequireTenant() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := GetTenantFromContext(r.Context())
			if tenant == nil {
				tm.respondError(w, r, errors.New(errors.CodeBadRequest, "tenant context is required"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireActiveTenant middleware that requires an active tenant
func (tm *TenantMiddleware) RequireActiveTenant() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := GetTenantFromContext(r.Context())
			if tenant == nil || !tenant.Active {
				tm.respondError(w, r, errors.New(errors.CodeForbidden, "active tenant is required"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePlan middleware that requires specific subscription plan
func (tm *TenantMiddleware) RequirePlan(plans ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := GetTenantFromContext(r.Context())
			if tenant == nil {
				tm.respondError(w, r, errors.New(errors.CodeBadRequest, "tenant context is required"))
				return
			}

			for _, plan := range plans {
				if tenant.Plan == plan {
					next.ServeHTTP(w, r)
					return
				}
			}

			tm.respondError(w, r, errors.New(errors.CodeForbidden, "plan upgrade required"))
		})
	}
}

// RequireFeature middleware that requires a specific feature
func (tm *TenantMiddleware) RequireFeature(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := GetTenantFromContext(r.Context())
			if tenant == nil {
				tm.respondError(w, r, errors.New(errors.CodeBadRequest, "tenant context is required"))
				return
			}

			if !tm.hasFeature(tenant, feature) {
				tm.respondError(w, r, errors.New(errors.CodeForbidden, "feature not available"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// TenantIsolation middleware that enforces data isolation
func (tm *TenantMiddleware) TenantIsolation() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			tenant := GetTenantFromContext(ctx)
			currentUser := GetUserFromContext(ctx)

			// Ensure user belongs to the tenant organization
			if tenant != nil && currentUser != nil {
				if currentUser.UserType == model.UserTypeExternal || currentUser.UserType == model.UserTypeEndUser {
					// External and end users must belong to the same organization
					if currentUser.OrganizationID == nil || *currentUser.OrganizationID != tenant.Organization.ID {
						tm.respondError(w, r, errors.New(errors.CodeForbidden, "user does not belong to tenant organization"))
						return
					}
				}
				// Internal users can access any organization
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireTenantHuma middleware that requires tenant context
func (tm *TenantMiddleware) RequireTenantHuma() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		tenant := GetTenantFromContext(ctx.Context())
		if tenant == nil {
			tm.respondErrorHuma(ctx, errors.New(errors.CodeForbidden, "tenant context is required"))
			return
		}

		next(ctx)
	}
}

// RequireActiveTenantHuma middleware that requires an active tenant
func (tm *TenantMiddleware) RequireActiveTenantHuma() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		tenant := GetTenantFromContext(ctx.Context())
		if tenant == nil || !tenant.Active {
			tm.respondErrorHuma(ctx, errors.New(errors.CodeForbidden, "active tenant is required"))
			return
		}

		next(ctx)
	}
}

// RequirePlanHuma middleware that requires specific subscription plan
func (tm *TenantMiddleware) RequirePlanHuma(plans ...string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		tenant := GetTenantFromContext(ctx.Context())
		if tenant == nil {
			tm.respondErrorHuma(ctx, errors.New(errors.CodeBadRequest, "tenant context is required"))
			return
		}

		for _, plan := range plans {
			if tenant.Plan == plan {
				next(ctx)
				return
			}
		}

		tm.respondErrorHuma(ctx, errors.New(errors.CodeForbidden, "plan upgrade required"))
	}
}

// RequireFeatureHuma middleware that requires a specific feature
func (tm *TenantMiddleware) RequireFeatureHuma(feature string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		tenant := GetTenantFromContext(ctx.Context())
		if tenant == nil {
			tm.respondErrorHuma(ctx, errors.New(errors.CodeBadRequest, "tenant context is required"))
			return
		}

		if !tm.hasFeature(tenant, feature) {
			tm.respondErrorHuma(ctx, errors.New(errors.CodeForbidden, "feature not available"))
			return
		}

		next(ctx)
	}
}

// TenantIsolationHuma middleware that enforces data isolation
func (tm *TenantMiddleware) TenantIsolationHuma() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		rctx := ctx.Context()
		tenant := GetTenantFromContext(rctx)
		currentUser := GetUserFromContext(rctx)

		// Ensure user belongs to the tenant organization
		if tenant != nil && currentUser != nil {
			if currentUser.UserType == model.UserTypeExternal || currentUser.UserType == model.UserTypeEndUser {
				// External and end users must belong to the same organization
				if currentUser.OrganizationID == nil || *currentUser.OrganizationID != tenant.Organization.ID {
					tm.respondErrorHuma(ctx, errors.New(errors.CodeForbidden, "user does not belong to tenant organization"))
					return
				}
			}
			// Internal users can access any organization
		}

		next(ctx)
	}
}

// Tenant resolution methods

func (tm *TenantMiddleware) resolveTenant(ctx context.Context, r *http.Request) (*TenantContext, error) {
	switch tm.config.Strategy {
	case ResolutionByPath:
		return tm.resolveTenantByPath(ctx, r)
	case ResolutionBySubdomain:
		return tm.resolveTenantBySubdomain(ctx, r)
	case ResolutionByHeader:
		return tm.resolveTenantByHeader(ctx, r)
	case ResolutionByQuery:
		return tm.resolveTenantByQuery(ctx, r)
	case ResolutionByAuth:
		return tm.resolveTenantByAuth(ctx, r)
	default:
		return nil, errors.New(errors.CodeInternalServer, "unknown tenant resolution strategy")
	}
}

func (tm *TenantMiddleware) resolveTenantByPath(ctx context.Context, r *http.Request) (*TenantContext, error) {
	// Extract organization ID from URL path parameter
	orgID := chi.URLParam(r, "orgId")
	if orgID == "" {
		return nil, nil
	}

	// Parse organization ID
	parsedOrgID, err := xid.FromString(orgID)
	if err != nil {
		return nil, errors.New(errors.CodeBadRequest, "invalid organization ID")
	}

	return tm.loadTenantByID(ctx, parsedOrgID)
}

func (tm *TenantMiddleware) resolveTenantBySubdomain(ctx context.Context, r *http.Request) (*TenantContext, error) {
	host := r.Host
	if tm.config.SubdomainSuffix != "" && strings.HasSuffix(host, tm.config.SubdomainSuffix) {
		subdomain := strings.TrimSuffix(host, tm.config.SubdomainSuffix)
		if subdomain != "" && subdomain != "www" && subdomain != "api" {
			return tm.loadTenantBySlug(ctx, subdomain)
		}
	}
	return nil, nil
}

func (tm *TenantMiddleware) resolveTenantByHeader(ctx context.Context, r *http.Request) (*TenantContext, error) {
	orgID := r.Header.Get(tm.config.HeaderName)
	if orgID == "" {
		return nil, nil
	}

	// Try to parse as XID first, then as slug
	if parsedOrgID, err := xid.FromString(orgID); err == nil {
		return tm.loadTenantByID(ctx, parsedOrgID)
	}

	return tm.loadTenantBySlug(ctx, orgID)
}

func (tm *TenantMiddleware) resolveTenantByQuery(ctx context.Context, r *http.Request) (*TenantContext, error) {
	orgParam := r.URL.Query().Get(tm.config.QueryParam)
	if orgParam == "" {
		return nil, nil
	}

	// Try to parse as XID first, then as slug
	if parsedOrgID, err := xid.FromString(orgParam); err == nil {
		return tm.loadTenantByID(ctx, parsedOrgID)
	}

	return tm.loadTenantBySlug(ctx, orgParam)
}

func (tm *TenantMiddleware) resolveTenantByAuth(ctx context.Context, r *http.Request) (*TenantContext, error) {
	user := GetUserFromContext(ctx)
	if user == nil || user.OrganizationID == nil {
		return nil, nil
	}

	return tm.loadTenantByID(ctx, *user.OrganizationID)
}

// Tenant loading methods

func (tm *TenantMiddleware) loadTenantByID(ctx context.Context, orgID xid.ID) (*TenantContext, error) {
	org, err := tm.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return tm.convertToTenantContext(org), nil
}

func (tm *TenantMiddleware) loadTenantBySlug(ctx context.Context, slug string) (*TenantContext, error) {
	org, err := tm.orgRepo.GetBySlug(ctx, slug)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return tm.convertToTenantContext(org), nil
}

func (tm *TenantMiddleware) convertToTenantContext(org *ent.Organization) *TenantContext {
	tenant := &TenantContext{
		Organization: tm.convertOrgToModel(org),
		Plan:         org.Plan,
		Type:         org.OrgType,
		Active:       org.Active,
		Settings:     org.Metadata,
		Limits: &TenantLimits{
			ExternalUsers: org.ExternalUserLimit,
			EndUsers:      org.EndUserLimit,
			APIRequests:   org.APIRequestLimit,
			SSO:           org.SSOEnabled,
		},
	}

	// Set trial information
	if org.TrialEndsAt != nil {
		tenant.Trial = &TrialInfo{
			Active:    org.TrialEndsAt.After(time.Now()),
			ExpiresAt: org.TrialEndsAt,
			Used:      org.TrialUsed,
		}

		if tenant.Trial.Active {
			tenant.Trial.DaysLeft = int(time.Until(*org.TrialEndsAt).Hours() / 24)
		}
	}

	// TODO: Load features from database
	tenant.Features = tm.loadTenantFeatures(org)

	return tenant
}

func (tm *TenantMiddleware) convertOrgToModel(org *ent.Organization) *model.Organization {
	return &model.Organization{
		Base: model.Base{
			ID:        org.ID,
			CreatedAt: org.CreatedAt,
			UpdatedAt: org.UpdatedAt,
		},
		Name:                   org.Name,
		Slug:                   org.Slug,
		Domain:                 org.Domain,
		LogoURL:                org.LogoURL,
		Plan:                   org.Plan,
		Active:                 org.Active,
		Metadata:               org.Metadata,
		TrialEndsAt:            org.TrialEndsAt,
		TrialUsed:              org.TrialUsed,
		OrgType:                org.OrgType,
		IsPlatformOrganization: org.IsPlatformOrganization,
		ExternalUserLimit:      org.ExternalUserLimit,
		EndUserLimit:           org.EndUserLimit,
		SSOEnabled:             org.SSOEnabled,
		SSODomain:              org.SSODomain,
		SubscriptionID:         org.SubscriptionID,
		CustomerID:             org.CustomerID,
		SubscriptionStatus:     org.SubscriptionStatus.String(),
		AuthServiceEnabled:     org.AuthServiceEnabled,
		AuthConfig:             org.AuthConfig,
		AuthDomain:             org.AuthDomain,
		APIRequestLimit:        org.APIRequestLimit,
		APIRequestsUsed:        org.APIRequestsUsed,
		CurrentExternalUsers:   org.CurrentExternalUsers,
		CurrentEndUsers:        org.CurrentEndUsers,
	}
}

func (tm *TenantMiddleware) loadTenantFeatures(org *ent.Organization) []string {
	// TODO: Load from organization_features table
	features := []string{}

	// Add features based on plan
	switch strings.ToLower(org.Plan) {
	case "free":
		features = append(features, "basic_auth", "email_verification")
	case "starter":
		features = append(features, "basic_auth", "email_verification", "mfa", "webhooks")
	case "pro":
		features = append(features, "basic_auth", "email_verification", "mfa", "webhooks", "sso", "custom_domains")
	case "enterprise":
		features = append(features, "basic_auth", "email_verification", "mfa", "webhooks", "sso", "custom_domains", "audit_logs", "advanced_security")
	}

	return features
}

// Validation methods

func (tm *TenantMiddleware) validateTenantAccess(ctx context.Context, r *http.Request, tenant *TenantContext) bool {
	currentUser := GetUserFromContext(ctx)

	// Allow access if no user context (public endpoints)
	if currentUser == nil {
		return true
	}

	// Internal users can access any tenant
	if currentUser.UserType == model.UserTypeInternal {
		return true
	}

	// Platform organization access
	if tenant.Organization.IsPlatformOrganization {
		return tm.config.AllowPlatformAccess && currentUser.UserType == model.UserTypeInternal
	}

	// User must belong to the tenant organization
	if currentUser.OrganizationID == nil || *currentUser.OrganizationID != tenant.Organization.ID {
		return false
	}

	return true
}

func (tm *TenantMiddleware) hasFeature(tenant *TenantContext, feature string) bool {
	for _, f := range tenant.Features {
		if f == feature {
			return true
		}
	}
	return false
}

func (tm *TenantMiddleware) shouldSkipPath(path string) bool {
	for _, skipPath := range tm.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// Context helper methods

func (tm *TenantMiddleware) setTenantContext(ctx context.Context, tenant *TenantContext) context.Context {
	ctx = context.WithValue(ctx, contexts2.TenantContextKey, tenant)
	ctx = context.WithValue(ctx, contexts2.TenantIDContextKey, tenant.Organization.ID)
	ctx = context.WithValue(ctx, contexts2.TenantSlugContextKey, tenant.Organization.Slug)
	ctx = context.WithValue(ctx, contexts2.TenantPlanContextKey, tenant.Plan)
	ctx = context.WithValue(ctx, contexts2.TenantTypeContextKey, tenant.Type)

	// Also set organization context for backward compatibility
	ctx = context.WithValue(ctx, contexts2.OrganizationContextKey, tenant.Organization)
	ctx = context.WithValue(ctx, contexts2.OrganizationIDContextKey, tenant.Organization.ID)

	return ctx
}

func (tm *TenantMiddleware) setTenantContextHuma(ctx huma.Context, tenant *TenantContext) huma.Context {
	ctx = huma.WithValue(ctx, contexts2.TenantContextKey, tenant)
	ctx = huma.WithValue(ctx, contexts2.TenantIDContextKey, tenant.Organization.ID)
	ctx = huma.WithValue(ctx, contexts2.TenantSlugContextKey, tenant.Organization.Slug)
	ctx = huma.WithValue(ctx, contexts2.TenantPlanContextKey, tenant.Plan)
	ctx = huma.WithValue(ctx, contexts2.TenantTypeContextKey, tenant.Type)

	// Also set organization context for backward compatibility
	ctx = huma.WithValue(ctx, contexts2.OrganizationContextKey, tenant.Organization)
	ctx = huma.WithValue(ctx, contexts2.OrganizationIDContextKey, tenant.Organization.ID)

	return ctx
}

func (tm *TenantMiddleware) respondError(w http.ResponseWriter, r *http.Request, err error) {
	var errResp *errors.ErrorResponse
	if e, ok := err.(*errors.Error); ok {
		errResp = errors.NewErrorResponse(e)
	} else {
		errResp = errors.NewErrorResponse(errors.New(errors.CodeInternalServer, err.Error()))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errResp.StatusCode())

	jsonResp := fmt.Sprintf(`{"code":"%s","message":"%s"}`, errResp.Code, errResp.Message)
	_, _ = w.Write([]byte(jsonResp))
}

func (tm *TenantMiddleware) respondErrorHuma(ctx huma.Context, err error) {
	var errResp *errors.ErrorResponse
	if e, ok := err.(*errors.Error); ok {
		errResp = errors.NewErrorResponse(e)
	} else {
		errResp = errors.NewErrorResponse(errors.New(errors.CodeInternalServer, err.Error()))
	}

	huma.WriteErr(tm.api, ctx, errResp.StatusCode(), errResp.Message)
}

// Context getter functions

// GetTenantFromContext retrieves the tenant from request context
func GetTenantFromContext(ctx context.Context) *TenantContext {
	if tenant, ok := ctx.Value(contexts2.TenantContextKey).(*TenantContext); ok {
		return tenant
	}
	return nil
}

// GetTenantIDFromContext retrieves the tenant ID from request context
func GetTenantIDFromContext(ctx context.Context) *xid.ID {
	if tenantID, ok := ctx.Value(contexts2.TenantIDContextKey).(xid.ID); ok {
		return &tenantID
	}
	return nil
}

// GetTenantSlugFromContext retrieves the tenant slug from request context
func GetTenantSlugFromContext(ctx context.Context) string {
	if slug, ok := ctx.Value(contexts2.TenantSlugContextKey).(string); ok {
		return slug
	}
	return ""
}

// GetTenantPlanFromContext retrieves the tenant plan from request context
func GetTenantPlanFromContext(ctx context.Context) string {
	if plan, ok := ctx.Value(contexts2.TenantPlanContextKey).(string); ok {
		return plan
	}
	return ""
}

// GetTenantTypeFromContext retrieves the tenant type from request context
func GetTenantTypeFromContext(ctx context.Context) model.OrgType {
	if tenantType, ok := ctx.Value(contexts2.TenantTypeContextKey).(model.OrgType); ok {
		return tenantType
	}
	return ""
}

// Utility functions

// HasTenant checks if there's a tenant in the context
func HasTenant(ctx context.Context) bool {
	return GetTenantFromContext(ctx) != nil
}

// IsPlatformTenant checks if the current tenant is the platform organization
func IsPlatformTenant(ctx context.Context) bool {
	tenant := GetTenantFromContext(ctx)
	return tenant != nil && tenant.Organization.IsPlatformOrganization
}

// IsActiveTenant checks if the current tenant is active
func IsActiveTenant(ctx context.Context) bool {
	tenant := GetTenantFromContext(ctx)
	return tenant != nil && tenant.Active
}

// HasPlan checks if the tenant has a specific plan
func HasPlan(ctx context.Context, plan string) bool {
	return GetTenantPlanFromContext(ctx) == plan
}

// HasFeature checks if the tenant has a specific feature enabled
func HasFeature(ctx context.Context, feature string) bool {
	tenant := GetTenantFromContext(ctx)
	if tenant == nil {
		return false
	}

	for _, f := range tenant.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// IsTrialActive checks if the tenant's trial is active
func IsTrialActive(ctx context.Context) bool {
	tenant := GetTenantFromContext(ctx)
	return tenant != nil && tenant.Trial != nil && tenant.Trial.Active
}

// GetTrialDaysLeft returns the number of days left in the trial
func GetTrialDaysLeft(ctx context.Context) int {
	tenant := GetTenantFromContext(ctx)
	if tenant != nil && tenant.Trial != nil && tenant.Trial.Active {
		return tenant.Trial.DaysLeft
	}
	return 0
}

// CheckLimit checks if a tenant limit has been exceeded
func CheckLimit(ctx context.Context, limitType string, current int) bool {
	tenant := GetTenantFromContext(ctx)
	if tenant == nil || tenant.Limits == nil {
		return true // Allow if no tenant context
	}

	switch limitType {
	case "external_users":
		return current < tenant.Limits.ExternalUsers
	case "end_users":
		return current < tenant.Limits.EndUsers
	case "api_requests":
		return current < tenant.Limits.APIRequests
	case "storage":
		return int64(current) < tenant.Limits.Storage
	case "emails":
		return current < tenant.Limits.EmailsPerMonth
	case "sms":
		return current < tenant.Limits.SMSPerMonth
	case "webhooks":
		return current < tenant.Limits.Webhooks
	default:
		return true
	}
}

// PathBasedTenantMiddleware Path-based tenant middleware specifically for API routes
func PathBasedTenantMiddleware(api huma.API, di di.Container) func(http.Handler) http.Handler {
	config := DefaultTenantConfig()
	config.Strategy = ResolutionByPath
	config.RequireTenant = true

	tm := NewTenantMiddleware(api, di, config)
	return tm.Middleware()
}

// SubdomainBasedTenantMiddleware Subdomain-based tenant middleware for SaaS applications
func SubdomainBasedTenantMiddleware(api huma.API, di di.Container, suffix string) func(http.Handler) http.Handler {
	config := DefaultTenantConfig()
	config.Strategy = ResolutionBySubdomain
	config.SubdomainSuffix = suffix
	config.RequireTenant = true

	tm := NewTenantMiddleware(api, di, config)
	return tm.Middleware()
}

// HeaderBasedTenantMiddleware Header-based tenant middleware for API clients
func HeaderBasedTenantMiddleware(api huma.API, di di.Container) func(http.Handler) http.Handler {
	config := DefaultTenantConfig()
	config.Strategy = ResolutionByHeader
	config.RequireTenant = false

	tm := NewTenantMiddleware(api, di, config)
	return tm.Middleware()
}
