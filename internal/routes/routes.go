// Package routes implements the main HTTP router for the Frank Authentication SaaS platform.
// This router provides a comprehensive, multi-tenant authentication system with Clerk.js compatibility,
// supporting JWT, OAuth2, session-based auth, API keys, MFA, SSO, passkeys, and comprehensive RBAC.
package routes

import (
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/juicycleff/frank/internal/di"
	customMiddleware "github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/juicycleff/frank/pkg/server"
)

// Router represents the main application router with support for:
// - Three-tier user system (Internal, External, End Users)
// - Multi-tenant architecture with organization isolation
// - Multiple authentication methods (JWT, OAuth2, API Keys, Sessions)
// - Comprehensive RBAC with context-aware permissions
// - Advanced security features (MFA, SSO, Passkeys)
// - Real-time features (WebSockets, SSE) compatibility
// - Production-ready middleware stack
type Router struct {
	di           di.Container
	router       chi.Router
	api          huma.API
	authMw       *customMiddleware.AuthMiddleware
	tenantMw     *customMiddleware.TenantMiddleware
	orgContextMw *customMiddleware.OrganizationContextMiddleware
	smartOrgMw   *customMiddleware.SmartOrganizationMiddleware
	unifiedOrgMw *customMiddleware.UnifiedRegistrationMiddleware
	logger       logging.Logger
	mountOpts    *server.MountOptions
	isEmbedded   bool
}

// NewRouter creates a new router instance with all middleware and route configurations
func NewRouter(di di.Container, existingRouter chi.Router) server.Router {
	return NewRouterWithOptions(di, existingRouter, nil)
}

// NewRouterWithOptions creates a new router with custom mounting options
func NewRouterWithOptions(di di.Container, existingRouter chi.Router, opts *server.MountOptions) server.Router {
	logger := di.Logger().Named("router")

	if opts == nil {
		opts = server.DefaultMountOptions()
		opts.BasePath = "" // No base path for standalone usage
	}

	// Create or use existing Chi router
	var r chi.Router
	if existingRouter == nil {
		r = chi.NewRouter()
		setupMiddleware(r, di, logger)
	} else {
		logger.Debug("Using existing Chi router")
		r = existingRouter
	}

	// Create Huma API configuration
	api := createHumaAPI(r, di, logger, opts)

	tenantConfig := customMiddleware.DefaultTenantConfig()
	tenantConfig.EnableTenantCache = true
	tenantConfig.Logger = di.Logger()

	orgContextConfig := customMiddleware.DefaultOrganizationContextConfig()
	orgContextConfig.Logger = di.Logger()
	orgContextConfig.BasePath = opts.BasePath

	// Create auth middleware with mount options
	authMw := customMiddleware.NewAuthMiddleware(di, api, opts)

	// Create tenant middleware with mount options
	tenantMw := customMiddleware.NewTenantMiddleware(api, di, tenantConfig, opts)

	// Create organization context middleware with mount options
	orgContextMw := customMiddleware.NewOrganizationContextMiddleware(api, di, authMw, orgContextConfig)

	// Create smart organization middleware with mount options
	smartOrgMw := customMiddleware.NewSmartOrganizationMiddleware(api, di, opts, orgContextConfig)

	// Create unified registration middleware with mount options
	unifiedOrgMw := customMiddleware.NewUnifiedRegistrationMiddleware(api, di, opts, orgContextConfig)

	router := &Router{
		di:           di,
		router:       r,
		api:          api,
		authMw:       authMw,
		tenantMw:     tenantMw,
		orgContextMw: orgContextMw,
		smartOrgMw:   smartOrgMw,
		unifiedOrgMw: unifiedOrgMw,
		logger:       logger,
		mountOpts:    opts,
		isEmbedded:   existingRouter != nil,
	}

	if opts.EnableDocs {
		router.setupDocsRoutes()
	}

	// Apply custom middleware if provided
	for _, mw := range opts.CustomMiddleware {
		router.Use(mw)
	}

	// Register all routes
	router.RegisterRoutes()

	return router
}

// NewEmbeddedRouter creates a router optimized for embedding in larger applications
func NewEmbeddedRouter(parentRouter chi.Router, di di.Container, basePath string) server.Router {
	opts := server.EmbeddedMountOptions(basePath)
	return NewRouterWithOptions(di, parentRouter, opts)
}

// setupMiddleware configures all Chi middleware for the router
func setupMiddleware(r chi.Router, di di.Container, logger logging.Logger) {
	// Core Chi middleware (WebSocket and SSE compatible)
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)

	// Conditional timeout middleware (skip for WebSockets and SSE)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if customMiddleware.IsWebSocketRequest(r) || customMiddleware.IsSSERequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			chimw.Timeout(60*time.Second)(next).ServeHTTP(w, r)
		})
	})

	// Basic Chi middleware
	r.Use(chimw.Heartbeat("/health"))
	r.Use(chimw.StripSlashes)

	// Conditional throttling (skip for WebSockets and SSE)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if customMiddleware.IsWebSocketRequest(r) || customMiddleware.IsSSERequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			chimw.Throttle(5000)(next).ServeHTTP(w, r)
		})
	})

	// Backlog throttling (skip for WebSockets and SSE)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if customMiddleware.IsWebSocketRequest(r) || customMiddleware.IsSSERequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			chimw.ThrottleBacklog(10, 50, time.Second*10)(next).ServeHTTP(w, r)
		})
	})

	// Production logging middleware
	if di.Config().App.Environment == "production" {
		r.Use(customMiddleware.ProductionLogging(logger))
	} else {
		r.Use(customMiddleware.DevelopmentLogging(logger))
	}

	// Security and request enhancement middleware
	r.Use(customMiddleware.AddRequestInfo())
	r.Use(customMiddleware.AddHeader())

	// Rate limiting with configuration
	if di.Config().Security.RateLimitEnabled {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if customMiddleware.IsWebSocketRequest(r) || customMiddleware.IsSSERequest(r) {
					next.ServeHTTP(w, r)
					return
				}

				customMiddleware.RateLimiter(
					di.Config().Security.RateLimitPerSecond,
					di.Config().Security.RateLimitBurst,
				)(next).ServeHTTP(w, r)
			})
		})
	}

	// Recovery and error handling
	r.Use(customMiddleware.Recovery(logger))
	r.Use(customMiddleware.ErrorHandler(logger))

	// CORS configuration // r.Use(customMiddleware.CORS(di.Config()))
	if di.Config().App.Environment == "development" {
		r.Use(customMiddleware.DevelopmentCORS())
	} else {
		r.Use(customMiddleware.CORS(di.Config()))
	}

	// Security headers
	if di.Config().Security.SecHeadersEnabled {
		r.Use(customMiddleware.SecurityHeaders(di.Config()))
	}

	// Mount debug routes in development
	if di.Config().App.Environment == "development" {
		r.Mount("/debug", chimw.Profiler())
	}
}

// createHumaAPI creates and configures the Huma API instance
func createHumaAPI(r chi.Router, di di.Container, logger logging.Logger, opts *server.MountOptions) huma.API {
	config := huma.DefaultConfig("Frank Auth API", "1.0.0")

	// Configure OpenAPI documentation
	if opts.CustomAPIInfo != nil {
		config.Info = opts.CustomAPIInfo
	} else {
		config.Info = &huma.Info{
			Title:       "Frank Authentication API",
			Description: "Multi-tenant authentication SaaS platform API with Clerk.js compatibility",
			Version:     "1.0.0",
			Contact: &huma.Contact{
				Name:  "Frank Auth Support",
				Email: "support@frankauth.com",
				URL:   "https://frankauth.com/support",
			},
			License: &huma.License{
				Name: "MIT",
				URL:  "https://opensource.org/licenses/MIT",
			},
		}
	}

	// Configure server URLs based on mount options
	config.Servers = buildServerConfigurations(opts, di.Config().Server.BaseURL)

	// Security schemes supporting the three-tier user system and multi-tenant architecture
	config.Components = &huma.Components{
		SecuritySchemes: map[string]*huma.SecurityScheme{
			"BearerAuth": {
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "JWT",
				Description:  "JWT-based authentication supporting all user types with organization context",
			},
			"OAuth2": {
				Type:        "oauth2",
				Description: "OAuth2 authentication with multi-tenant support and granular scopes",
				Flows: &huma.OAuthFlows{
					AuthorizationCode: &huma.OAuthFlow{
						AuthorizationURL: buildURL(opts.BasePath, "/v1/oauth/authorize"),
						TokenURL:         buildURL(opts.BasePath, "/v1/oauth/token"),
						RefreshURL:       buildURL(opts.BasePath, "/v1/oauth/refresh"),
						Scopes: map[string]string{
							// Standard OpenID Connect scopes
							"profile":        "Access user profile information",
							"email":          "Access user email address",
							"openid":         "OpenID Connect scope",
							"offline_access": "Request refresh token",

							// Application-specific scopes
							"admin": "Full administrative access (internal users only)",

							// User management scopes
							"read:users":   "Read user information within organization context",
							"write:users":  "Create and update users within organization context",
							"delete:users": "Delete users within organization context",

							// Organization management scopes
							"read:orgs":   "Read organization information",
							"write:orgs":  "Create and update organizations",
							"delete:orgs": "Delete organizations (internal users only)",

							// RBAC scopes
							"read:roles":  "Read role information within organization context",
							"write:roles": "Create and update roles within organization context",
							"read:perms":  "Read permission information",
							"write:perms": "Manage permissions (internal users only)",

							// Advanced feature scopes
							"read:audit":     "Read audit logs within organization context",
							"write:webhooks": "Manage webhooks within organization context",
							"read:analytics": "Read analytics data within organization context",
						},
					},
					ClientCredentials: &huma.OAuthFlow{
						TokenURL: buildURL(opts.BasePath, "/v1/oauth/token"),
						Scopes: map[string]string{
							"api":            "General API access for server-to-server communication",
							"read:users":     "Read user information (server-to-server)",
							"read:orgs":      "Read organization information (server-to-server)",
							"write:webhooks": "Send webhook notifications",
						},
					},
				},
			},
			"ApiKeyAuth": {
				Type:        "apiKey",
				In:          "header",
				Name:        "X-API-Key",
				Description: "API key-based authentication for server-to-server communication with organization-scoped access",
			},
			"SessionAuth": {
				Type:        "apiKey",
				In:          "cookie",
				Name:        "session_token",
				Description: "Session-based authentication via secure HTTP-only cookies",
			},
		},
	}

	// Custom error handler
	huma.NewError = func(status int, message string, errs ...error) huma.StatusError {
		details := make([]string, len(errs))
		for i, err := range errs {
			details[i] = err.Error()
		}
		return &errors.Error{
			StatusCode: status,
			Message:    message,
			Details:    details,
		}
	}

	// Create Huma API with Chi adapter
	adapter := humachi.NewAdapter(r)
	api := huma.NewAPI(config, adapter)
	api.UseMiddleware(customMiddleware.AddRequestToContextHuma())

	return api
}

// buildServerConfigurations creates server configurations based on mount options
func buildServerConfigurations(opts *server.MountOptions, baseURL string) []*huma.Server {
	servers := []*huma.Server{}

	// Development server
	servers = append(servers, &huma.Server{
		URL:         "http://localhost:{port}" + opts.BasePath,
		Description: "Local development server",
		Variables: map[string]*huma.ServerVariable{
			"port": {
				Default:     "8998",
				Description: "API port",
			},
		},
	})

	// Production servers with custom base path
	if opts.OpenAPIBasePath != "" {
		servers = append(servers, &huma.Server{
			URL:         "https://api.frankauth.com" + opts.OpenAPIBasePath + "/{version}",
			Description: "Production server",
			Variables: map[string]*huma.ServerVariable{
				"version": {
					Default:     "v1",
					Enum:        []string{"v1", "v2"},
					Description: "API version",
				},
			},
		})
	} else {
		servers = append(servers, &huma.Server{
			URL:         "https://api.frankauth.com/{version}",
			Description: "Production server",
			Variables: map[string]*huma.ServerVariable{
				"version": {
					Default:     "v1",
					Enum:        []string{"v1", "v2"},
					Description: "API version",
				},
			},
		})
	}

	return servers
}

// buildURL helper function to construct URLs with base paths
func buildURL(basePath, path string) string {
	if basePath == "" {
		return path
	}
	return strings.TrimSuffix(basePath, "/") + path
}

// RegisterRoutes registers all API routes and route groups
func (router *Router) RegisterRoutes() {
	// Create API version groups with base path consideration
	var apiGroup, v1Group huma.API

	if router.mountOpts.BasePath != "" {
		baseGroup := huma.NewGroup(router.api, router.mountOpts.BasePath)
		apiGroup = huma.NewGroup(baseGroup, "/api")
	} else {
		apiGroup = huma.NewGroup(router.api, "/api")
	}

	v1Group = huma.NewGroup(apiGroup, "/v1")

	// Setup route groups based on mount options
	if router.mountOpts.IncludeRoutes.Public && !router.mountOpts.ExcludeRoutes.Public {
		router.setupPublicRoutes(v1Group)
	}

	if router.mountOpts.IncludeRoutes.Protected && !router.mountOpts.ExcludeRoutes.Protected {
		router.setupPersonalRoutes(v1Group)
		router.setupProtectedRoutes(v1Group)
	}

	if router.mountOpts.IncludeRoutes.Internal && !router.mountOpts.ExcludeRoutes.Internal {
		router.setupInternalRoutes(v1Group)
	}

	if router.mountOpts.IncludeRoutes.Webhooks && !router.mountOpts.ExcludeRoutes.Webhooks {
		router.setupWebhookRoutes(v1Group)
	}

	if router.mountOpts.IncludeRoutes.Health && !router.mountOpts.ExcludeRoutes.Health {
		// Health routes at the base API level (not versioned)
		var healthAPI huma.API
		if router.mountOpts.BasePath != "" {
			healthAPI = huma.NewGroup(router.api, router.mountOpts.BasePath)
		} else {
			healthAPI = router.api
		}
		router.setupHealthRoutes(healthAPI)
	}
}

// setupPublicRoutes configures routes that don't require authentication
func (router *Router) setupPublicRoutes(v1Group huma.API) {
	publicGroup := huma.NewGroup(v1Group, "/public")

	// Apply organization context detection (NOT enforcement) for public routes
	// This allows organization context to be detected without requiring authentication
	publicGroup.UseMiddleware(router.orgContextMw.UserTypeDetectionHumaMiddleware(true))
	publicGroup.UseMiddleware(router.authMw.OptionalAuthHuma())
	publicGroup.UseMiddleware(router.orgContextMw.RequireOrganizationForUserTypeHuma(true))

	// Apply unified registration flow detection
	publicGroup.UseMiddleware(router.unifiedOrgMw.UnifiedRegistrationMiddleware())

	// Authentication routes (login, register, etc.)
	RegisterPublicAuthAPI(publicGroup, router.di)

	// OAuth2 authorization endpoints
	RegisterOAuthPublicAPI(publicGroup, router.di)

	// SSO endpoints
	RegisterSSOPublicAPI(publicGroup, router.di)

	// Passkey registration/authentication endpoints
	RegisterPasskeyPublicAPI(publicGroup, router.di)

	// Public webhook endpoints (for receiving webhooks from external services)
	RegisterWebhookPublicAPI(publicGroup, router.di)
}

// setupProtectedRoutes configures routes that require authentication
func (router *Router) setupProtectedRoutes(v1Group huma.API) {
	// Base protected group - only requires authentication, no organization context
	authOnlyGroup := huma.NewGroup(v1Group)
	authOnlyGroup.UseMiddleware(router.authMw.RequireAuthHuma())

	// Organization-aware group - applies user type detection and organization context
	orgAwareGroup := huma.NewGroup(v1Group)
	orgAwareGroup.UseMiddleware(router.orgContextMw.UserTypeDetectionHumaMiddleware(false))
	orgAwareGroup.UseMiddleware(router.authMw.RequireAuthHuma())
	// orgAwareGroup.UseMiddleware(router.orgContextMw.RequireOrganizationForUserTypeHuma(false))

	// Use more lenient organization context enforcement
	// This allows internal users and personal operations to proceed without strict org validation
	orgAwareGroup.UseMiddleware(router.orgContextMw.OptionalOrganizationContextHuma())

	// Tenant-scoped group - full multi-tenant isolation
	tenantGroup := huma.NewGroup(v1Group)
	tenantGroup.UseMiddleware(router.orgContextMw.UserTypeDetectionHumaMiddleware(false))
	tenantGroup.UseMiddleware(router.authMw.RequireAuthHuma())
	tenantGroup.UseMiddleware(router.orgContextMw.RequireOrganizationForUserTypeHuma(false))

	tenantGroup.UseMiddleware(router.tenantMw.HumaMiddleware())
	tenantGroup.UseMiddleware(router.tenantMw.RequireTenantHuma())
	tenantGroup.UseMiddleware(router.tenantMw.TenantIsolationHuma())

	// Auth management endpoints (logout, refresh, profile, etc.)
	RegisterAuthAPI(authOnlyGroup, router.di)

	// === ORGANIZATION-AWARE ROUTES (Organization context validated for external/end users) ===

	// OAuth2 client management endpoints (can work with or without org context)
	RegisterOAuthAPI(orgAwareGroup, router.di)

	// === TENANT-SCOPED ROUTES (Full organization isolation required) ===

	// Organization management endpoints
	RegisterOrganizationAPI(tenantGroup, router.di)

	// Membership management endpoints
	RegisterMembershipAPI(tenantGroup, router.di)

	// User management endpoints (organization-scoped)
	RegisterUserAPI(tenantGroup, router.di)

	// RBAC endpoints (roles and permissions)
	RegisterRBACAPI(tenantGroup, router.di)

	// MFA management endpoints (organization-scoped)
	RegisterMFAAPI(tenantGroup, router.di)

	// SSO configuration endpoints
	RegisterSSOAPI(tenantGroup, router.di)

	// Passkey management endpoints
	RegisterPasskeyAPI(tenantGroup, router.di)

	// Webhook management endpoints
	RegisterWebhookAPI(tenantGroup, router.di)

	// Activity management endpoints
	RegisterActivityAPI(tenantGroup, router.di)

	// API Key management endpoints
	RegisterAPIKeyAPI(tenantGroup, router.di)
}

// setupProtectedRoutes configures routes that require authentication
func (router *Router) setupPersonalRoutes(v1Group huma.API) {
	personalGroup := huma.NewGroup(v1Group, "/me")
	personalGroup.UseMiddleware(router.orgContextMw.UserTypeDetectionHumaMiddleware(false))
	personalGroup.UseMiddleware(router.authMw.RequireAuthHuma())
	personalGroup.UseMiddleware(router.authMw.RequireUserTypeHuma(
		model.UserTypeInternal,
		model.UserTypeExternal,
		model.UserTypeEndUser,
	))
	// Auth management endpoints (logout, refresh, profile, etc.)
	// These should NOT require organization context
	RegisterPersonalAuthAPI(personalGroup, router.di)
	// Personal organization operations (list my orgs, switch org context, etc.)
	RegisterPersonalOrganizationAPI(personalGroup, router.di)
	// Personal user management endpoints (profile, password change, personal MFA, etc.)
	RegisterPersonalUserAPI(personalGroup, router.di)
}

// setupInternalRoutes configures routes for internal platform users only
func (router *Router) setupInternalRoutes(v1Group huma.API) {
	internalGroup := huma.NewGroup(v1Group, "/internal")

	// Note: Authentication and authorization middleware for internal users
	internalGroup.UseMiddleware(
		router.authMw.RequireAuthHuma(),
		router.authMw.RequireUserTypeHuma(model.UserTypeInternal),
	)

	// Platform administration endpoints
	RegisterPlatformAdminAPI(internalGroup, router.di)

	// System monitoring and metrics
	RegisterSystemAPI(internalGroup, router.di)

	// Compliance and audit endpoints
	RegisterComplianceAPI(internalGroup, router.di)
}

// setupWebhookRoutes configures webhook-specific routes with special handling
func (router *Router) setupWebhookRoutes(v1Group huma.API) {
	webhookGroup := huma.NewGroup(v1Group)

	// Apply webhook-specific CORS middleware
	webhookGroup.UseMiddleware(customMiddleware.HumaWebhookCORSMiddleware(router.api))

	// Note: Webhook signature verification middleware should be applied here

	// Register webhook endpoints
	RegisterWebhookEndpointsAPI(webhookGroup, router.di)
}

// setupHealthRoutes configures health check and monitoring routes
func (router *Router) setupHealthRoutes(api huma.API) {
	// Health check endpoints (no authentication required)
	RegisterHealthAPI(api, router.di)

	// Metrics endpoints (may require authentication in production)
	if router.di.Config().Monitoring.Enabled {
		RegisterMetricsAPI(api, router.di)
	}
}

// MountOn mounts this router on a parent router with advanced options
func (router *Router) MountOn(parent chi.Router, opts *server.MountOptions) {
	if opts == nil {
		opts = server.DefaultMountOptions()
	}

	// Create a new sub-router with the specified options
	subRouter := NewRouterWithOptions(router.di, parent, opts)
	parent.Mount(opts.BasePath, subRouter.Handler())
}

// MountSubset mounts only specific route groups on a parent router
func (router *Router) MountSubset(parent chi.Router, basePath string, routeGroups server.RouteGroups) {
	opts := &server.MountOptions{
		BasePath:              basePath,
		IncludeRoutes:         routeGroups,
		SkipBuiltinMiddleware: true,
		EnableDocs:            false,
		TenantAware:           true,
	}

	subRouter := NewRouterWithOptions(router.di, parent, opts)
	parent.Mount(basePath, subRouter.Handler())
}

// MountAuthOnly mounts only authentication-related routes
func (router *Router) MountAuthOnly(parent chi.Router, basePath string) {
	router.MountSubset(parent, basePath, server.RouteGroups{
		Public:    true,
		Protected: false,
		Internal:  false,
		Webhooks:  false,
		Health:    false,
		Docs:      false,
	})
}

// MountUserManagement mounts user and organization management routes
func (router *Router) MountUserManagement(parent chi.Router, basePath string) {
	router.MountSubset(parent, basePath, server.RouteGroups{
		Public:    true,
		Protected: true,
		Internal:  false,
		Webhooks:  false,
		Health:    false,
		Docs:      false,
	})
}

// CreateEmbeddedHandler creates an HTTP handler optimized for embedding
func (router *Router) CreateEmbeddedHandler(basePath string, customMiddleware ...func(http.Handler) http.Handler) http.Handler {
	opts := server.EmbeddedMountOptions(basePath)
	opts.CustomMiddleware = customMiddleware

	embeddedRouter := NewRouterWithOptions(router.di, nil, opts)
	return embeddedRouter.Handler()
}

// Handler returns the HTTP handler
func (router *Router) Handler() http.Handler {
	return router.router
}

// Group adds a new route group
func (router *Router) Group(fn func(r chi.Router)) {
	router.router.Group(fn)
}

// Route adds a new route group with a pattern
func (router *Router) Route(pattern string, fn func(r chi.Router)) {
	router.router.Route(pattern, fn)
}

// Use appends a middleware to the chain
func (router *Router) Use(middleware ...func(http.Handler) http.Handler) {
	router.router.Use(middleware...)
}

// Method adds a method-specific route
func (router *Router) Method(method, pattern string, handler http.HandlerFunc) {
	router.router.Method(method, pattern, handler)
}

// NotFound sets the not found handler
func (router *Router) NotFound(handler http.HandlerFunc) {
	router.router.NotFound(handler)
}

// MethodNotAllowed sets the method not allowed handler
func (router *Router) MethodNotAllowed(handler http.HandlerFunc) {
	router.router.MethodNotAllowed(handler)
}

// HandleFunc adds a route with a handler function
func (router *Router) HandleFunc(pattern string, handler http.HandlerFunc) {
	router.router.HandleFunc(pattern, handler)
}

// Mount mounts this router on a parent router with a given path prefix
func (router *Router) Mount(parent chi.Router, mountPath string) {
	parent.Mount(mountPath, router.router)
}

// Handle adds a method-specific route with a handler
func (router *Router) Handle(pattern string, h http.Handler) {
	router.router.Handle(pattern, h)
}

// HumaAPI returns the Huma API instance
func (router *Router) HumaAPI() huma.API {
	return router.api
}

// Chi returns the Chi router instance
func (router *Router) Chi() chi.Router {
	return router.router
}

// GetMountOptions returns the current mount options
func (router *Router) GetMountOptions() *server.MountOptions {
	return router.mountOpts
}

// IsEmbedded returns whether this router is running in embedded mode
func (router *Router) IsEmbedded() bool {
	return router.isEmbedded
}

// CreateExternalUserGroup creates a group specifically for external users with organization context
func (router *Router) CreateExternalUserGroup(parent huma.API, path string) huma.API {
	group := huma.NewGroup(parent, path)
	group.UseMiddleware(router.orgContextMw.UserTypeDetectionHumaMiddleware(false))
	group.UseMiddleware(router.authMw.RequireAuthHuma())
	group.UseMiddleware(router.authMw.RequireUserTypeHuma(model.UserTypeExternal))
	group.UseMiddleware(router.orgContextMw.RequireOrganizationForUserTypeHuma(false))
	group.UseMiddleware(router.tenantMw.HumaMiddleware())
	group.UseMiddleware(router.tenantMw.RequireActiveTenantHuma())
	group.UseMiddleware(router.tenantMw.TenantIsolationHuma())
	return group
}

// CreateEndUserGroup creates a group specifically for end users with organization context
func (router *Router) CreateEndUserGroup(parent huma.API, path string) huma.API {
	group := huma.NewGroup(parent, path)
	group.UseMiddleware(router.orgContextMw.UserTypeDetectionHumaMiddleware(false))
	group.UseMiddleware(router.authMw.RequireAuthHuma())
	group.UseMiddleware(router.authMw.RequireUserTypeHuma(model.UserTypeEndUser))
	group.UseMiddleware(router.orgContextMw.RequireOrganizationForUserTypeHuma(false))
	group.UseMiddleware(router.tenantMw.HumaMiddleware())
	group.UseMiddleware(router.tenantMw.RequireActiveTenantHuma())
	group.UseMiddleware(router.tenantMw.TenantIsolationHuma())
	return group
}

// CreateInternalUserGroup creates a group specifically for internal users (no organization context required)
func (router *Router) CreateInternalUserGroup(parent huma.API, path string) huma.API {
	group := huma.NewGroup(parent, path)
	group.UseMiddleware(router.authMw.RequireAuthHuma())
	group.UseMiddleware(router.authMw.RequireUserTypeHuma(model.UserTypeInternal))
	return group
}

// CreateMultiTenantGroup creates a group that handles all user types with proper organization context enforcement
func (router *Router) CreateMultiTenantGroup(parent huma.API, path string) huma.API {
	group := huma.NewGroup(parent, path)
	group.UseMiddleware(router.orgContextMw.UserTypeDetectionHumaMiddleware(false))
	group.UseMiddleware(router.authMw.RequireAuthHuma())
	group.UseMiddleware(router.orgContextMw.RequireOrganizationForUserTypeHuma(false))
	group.UseMiddleware(router.tenantMw.HumaMiddleware())
	group.UseMiddleware(router.tenantMw.RequireActiveTenantHuma())
	group.UseMiddleware(router.tenantMw.TenantIsolationHuma())
	return group
}

// Helper function to create appropriate middleware chain for different route types
func (router *Router) createMiddlewareChain(routeType string) []func(huma.Context, func(huma.Context)) {
	switch routeType {
	case "public":
		return []func(huma.Context, func(huma.Context)){
			router.orgContextMw.UserTypeDetectionHumaMiddleware(false),
			router.orgContextMw.RequireOrganizationForUserTypeHuma(true),
			router.authMw.OptionalAuthHuma(),
		}
	case "protected":
		return []func(huma.Context, func(huma.Context)){
			router.orgContextMw.UserTypeDetectionHumaMiddleware(false),
			router.authMw.RequireAuthHuma(),
			router.orgContextMw.RequireOrganizationForUserTypeHuma(false),
			router.tenantMw.HumaMiddleware(),
			router.tenantMw.RequireActiveTenantHuma(),
			router.tenantMw.TenantIsolationHuma(),
		}
	case "internal":
		return []func(huma.Context, func(huma.Context)){
			router.authMw.RequireAuthHuma(),
			router.authMw.RequireUserTypeHuma(model.UserTypeInternal),
		}
	case "external":
		return []func(huma.Context, func(huma.Context)){
			router.orgContextMw.UserTypeDetectionHumaMiddleware(false),
			router.authMw.RequireAuthHuma(),
			router.authMw.RequireUserTypeHuma(model.UserTypeExternal),
			router.orgContextMw.RequireOrganizationForUserTypeHuma(false),
			router.tenantMw.HumaMiddleware(),
			router.tenantMw.RequireActiveTenantHuma(),
			router.tenantMw.TenantIsolationHuma(),
		}
	case "enduser":
		return []func(huma.Context, func(huma.Context)){
			router.orgContextMw.UserTypeDetectionHumaMiddleware(false),
			router.authMw.RequireAuthHuma(),
			router.authMw.RequireUserTypeHuma(model.UserTypeEndUser),
			router.orgContextMw.RequireOrganizationForUserTypeHuma(false),
			router.tenantMw.HumaMiddleware(),
			router.tenantMw.RequireActiveTenantHuma(),
			router.tenantMw.TenantIsolationHuma(),
		}
	default:
		return nil
	}
}
