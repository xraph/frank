package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/apikeys"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/internal/organization"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// RouteProtectionOptions configures how the web route protection middleware behaves
type RouteProtectionOptions struct {
	// Required determines if authentication is required
	RequireAuth bool

	// PublicPaths defines routes that are accessible without authentication
	PublicPaths []string

	// RequireCSRF determines if CSRF protection is enabled
	RequireCSRF bool

	// CSRFExemptPaths defines routes that are exempt from CSRF protection
	CSRFExemptPaths []string

	// RateLimitEnabled enables rate limiting
	RateLimitEnabled bool

	// RequireOrganization determines if an organization context is required
	RequireOrganization bool

	// FeatureRequired specifies a feature that must be enabled to access routes
	FeatureRequired string

	// AllowAPIKey allows authentication via API key
	AllowAPIKey bool

	// AllowSession allows authentication via session
	AllowSession bool

	// AllowBearerToken allows authentication via JWT bearer token
	AllowBearerToken bool

	// RequiredRoles specifies roles that are required to access the routes
	RequiredRoles []string

	// RequiredPermissions specifies permissions that are required to access the routes
	RequiredPermissions []string
}

// DefaultRouteProtectionOptions returns the default route protection options
func DefaultRouteProtectionOptions() RouteProtectionOptions {
	return RouteProtectionOptions{
		RequireAuth:      true,
		PublicPaths:      []string{"/", "/index.html", "/_astro/", "/assets/", "/redoc", "/docs", "/swagger.json"},
		RequireCSRF:      true,
		CSRFExemptPaths:  []string{"/v1/auth/login", "/v1/auth/register", "/v1/auth/signup"},
		RateLimitEnabled: true,
		AllowAPIKey:      true,
		AllowSession:     true,
		AllowBearerToken: true,
	}
}

// WebRouteProtection provides unified protection for web routes
type WebRouteProtection struct {
	config             *config.Config
	logger             logging.Logger
	sessionManager     *session.Manager
	cookieHandler      *session.CookieHandler
	apiKeyService      apikeys.Service
	organizationSvc    organization.Service
	options            RouteProtectionOptions
	protectedPaths     map[string]bool
	csrfExemptPaths    map[string]bool
	publicPaths        map[string]bool
	staticFilePrefixes []string
}

// NewWebRouteProtection creates a new web route protection middleware
func NewWebRouteProtection(
	cfg *config.Config,
	logger logging.Logger,
	sessionManager *session.Manager,
	cookieHandler *session.CookieHandler,
	apiKeyService apikeys.Service,
	organizationSvc organization.Service,
) *WebRouteProtection {
	options := DefaultRouteProtectionOptions()

	// Convert paths to maps for faster lookup
	publicPaths := make(map[string]bool)
	for _, path := range options.PublicPaths {
		publicPaths[path] = true
	}

	csrfExemptPaths := make(map[string]bool)
	for _, path := range options.CSRFExemptPaths {
		csrfExemptPaths[path] = true
	}

	return &WebRouteProtection{
		config:             cfg,
		logger:             logger,
		sessionManager:     sessionManager,
		cookieHandler:      cookieHandler,
		apiKeyService:      apiKeyService,
		organizationSvc:    organizationSvc,
		options:            options,
		publicPaths:        publicPaths,
		csrfExemptPaths:    csrfExemptPaths,
		staticFilePrefixes: []string{"/_astro/", "/assets/"},
	}
}

// WithOptions sets custom options for the middleware
func (w *WebRouteProtection) WithOptions(options RouteProtectionOptions) *WebRouteProtection {
	w.options = options

	// Update maps from options
	w.publicPaths = make(map[string]bool)
	for _, path := range options.PublicPaths {
		w.publicPaths[path] = true
	}

	w.csrfExemptPaths = make(map[string]bool)
	for _, path := range options.CSRFExemptPaths {
		w.csrfExemptPaths[path] = true
	}

	return w
}

// ProtectRoutes returns a middleware that applies all configured protections
func (w *WebRouteProtection) ProtectRoutes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Skip protection for static files
		for _, prefix := range w.staticFilePrefixes {
			if strings.HasPrefix(path, prefix) {
				next.ServeHTTP(wr, r)
				return
			}
		}

		// Skip protection for explicitly defined public paths
		if w.publicPaths[path] {
			next.ServeHTTP(wr, r)
			return
		}

		// Check if this is an API route (prefixed with /v1)
		isAPIRoute := strings.HasPrefix(path, "/v1/")

		// Get the logger for this request
		reqLogger := logging.FromContext(r.Context())
		ctx := r.Context()
		authenticated := false

		// Apply authentication if required
		if w.options.RequireAuth && isAPIRoute {
			// Try different authentication methods
			if w.options.AllowBearerToken {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					token := strings.TrimPrefix(authHeader, "Bearer ")
					if userID, orgID, err := validateBearerToken(ctx, token, w.config); err == nil {
						// Add user and organization info to context
						ctx = context.WithValue(ctx, UserIDKey, userID)
						if orgID != "" {
							ctx = context.WithValue(ctx, OrganizationIDKey, orgID)
						}
						authenticated = true
					}
				}
			}

			// Try API key authentication
			if !authenticated && w.options.AllowAPIKey && w.apiKeyService != nil {
				apiKey := r.Header.Get("X-API-Key")
				if apiKey == "" {
					// Check query params as fallback
					apiKey = r.URL.Query().Get("api_key")
				}

				if apiKey != "" {
					if apiKeyInfo, err := w.apiKeyService.Validate(ctx, apiKey); err == nil {
						if apiKeyInfo.UserID != "" {
							ctx = context.WithValue(ctx, UserIDKey, apiKeyInfo.UserID)
						}
						if apiKeyInfo.OrganizationID != "" {
							ctx = context.WithValue(ctx, OrganizationIDKey, apiKeyInfo.OrganizationID)
						}
						authenticated = true

						// Update last used timestamp asynchronously
						go func(id string) {
							bgCtx, cancel := context.WithTimeout(context.Background(), w.config.Server.ShutdownTimeout)
							defer cancel()
							if err := w.apiKeyService.UpdateLastUsed(bgCtx, id); err != nil {
								w.logger.Error("Failed to update API key last used timestamp",
									logging.String("key_id", id),
									logging.Error(err))
							}
						}(apiKeyInfo.ID)
					}
				}
			}

			// Try session authentication
			if !authenticated && w.options.AllowSession && w.sessionManager != nil {
				sess, err := utils.GetSession(r, w.config)
				if err == nil {
					if userID, ok := sess.Values["user_id"].(string); ok && userID != "" {
						ctx = context.WithValue(ctx, UserIDKey, userID)

						if orgID, ok := sess.Values["organization_id"].(string); ok && orgID != "" {
							ctx = context.WithValue(ctx, OrganizationIDKey, orgID)
						}
						authenticated = true
					}
				}
			}

			// If auth is required but not provided, return error
			if !authenticated {
				reqLogger.Warn("Authentication required but not provided",
					logging.String("path", path),
					logging.String("method", r.Method))
				utils.RespondError(wr, errors.New(errors.CodeUnauthorized, "authentication required"))
				return
			}

			// Add authentication status to context
			ctx = context.WithValue(ctx, AuthenticatedKey, authenticated)
		}

		// Apply CSRF protection for non-GET API routes
		if w.options.RequireCSRF && isAPIRoute && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			// Skip for exempt paths
			if !w.csrfExemptPaths[path] {
				// Get CSRF token from cookie
				cookieToken, err := w.cookieHandler.GetCSRFCookie(r)
				if err != nil {
					reqLogger.Warn("CSRF token cookie missing",
						logging.String("path", path),
						logging.String("method", r.Method))
					utils.RespondError(wr, errors.New(errors.CodeForbidden, "CSRF token cookie missing or invalid"))
					return
				}

				// Get token from request
				requestToken := extractCSRFToken(r)

				// Validate tokens
				if cookieToken == "" || requestToken == "" || cookieToken != requestToken {
					reqLogger.Warn("CSRF validation failed",
						logging.String("path", path),
						logging.String("method", r.Method),
						logging.Bool("cookie_token_empty", cookieToken == ""),
						logging.Bool("request_token_empty", requestToken == ""))
					utils.RespondError(wr, errors.New(errors.CodeForbidden, "CSRF token validation failed"))
					return
				}

				// Add token to context
				ctx = context.WithValue(ctx, CSRFTokenKey, cookieToken)
			}
		}

		// Apply rate limiting if enabled
		if w.options.RateLimitEnabled && isAPIRoute {
			// Get key for rate limiting
			var key string

			// Try to use user ID first
			if userID, ok := ctx.Value(UserIDKey).(string); ok && userID != "" {
				key = "user:" + userID
			} else {
				// Try API key
				apiKey := r.Header.Get("X-API-Key")
				if apiKey != "" {
					key = "apikey:" + apiKey
				} else {
					// Fall back to IP
					key = "ip:" + utils.GetRealIP(r)
				}
			}

			// Add path for path-specific rate limiting
			key = key + ":" + path

			// Apply rate limiting (implement in-memory limiter here if needed)
			// This is just a placeholder - you would implement actual rate limiting logic
			if key != "" {
				// Rate limiting logic would go here
				// For now, we're relying on your existing RateLimiter middleware
			}
		}

		// Check organization context if required
		if w.options.RequireOrganization && authenticated && isAPIRoute {
			orgID, hasOrg := ctx.Value(OrganizationIDKey).(string)

			// If no org in context, try to get from header or query
			if !hasOrg || orgID == "" {
				orgID = r.Header.Get("X-Organization-ID")
				if orgID == "" {
					orgID = r.URL.Query().Get("organization_id")
				}

				if orgID == "" {
					reqLogger.Warn("Organization ID required but not provided",
						logging.String("path", path),
						logging.String("method", r.Method))
					utils.RespondError(wr, errors.New(errors.CodeMissingRequiredField, "organization ID is required"))
					return
				}

				// Add org ID to context
				ctx = context.WithValue(ctx, OrganizationIDKey, orgID)
			}

			// Check if org exists and is active (if organization service is provided)
			if w.organizationSvc != nil {
				org, err := w.organizationSvc.Get(ctx, orgID)
				if err != nil {
					reqLogger.Warn("Failed to get organization",
						logging.String("organization_id", orgID),
						logging.String("path", path),
						logging.String("method", r.Method),
						logging.Error(err))
					utils.RespondError(wr, err)
					return
				}

				if !org.Active {
					reqLogger.Warn("Organization is inactive",
						logging.String("organization_id", orgID),
						logging.String("path", path),
						logging.String("method", r.Method))
					utils.RespondError(wr, errors.New(errors.CodeForbidden, "organization is inactive"))
					return
				}

				// Check feature flag if required
				if w.options.FeatureRequired != "" {
					enabled, err := w.organizationSvc.IsFeatureEnabled(ctx, orgID, w.options.FeatureRequired)
					if err != nil {
						reqLogger.Warn("Failed to check feature flag",
							logging.String("feature", w.options.FeatureRequired),
							logging.String("organization_id", orgID),
							logging.String("path", path),
							logging.String("method", r.Method),
							logging.Error(err))
						utils.RespondError(wr, err)
						return
					}

					if !enabled {
						reqLogger.Warn("Required feature not enabled",
							logging.String("feature", w.options.FeatureRequired),
							logging.String("organization_id", orgID),
							logging.String("path", path),
							logging.String("method", r.Method))
						utils.RespondError(wr, errors.New(errors.CodeFeatureNotEnabled, "required feature is not enabled for this organization"))
						return
					}
				}
			}
		}

		// Check for required roles if specified
		if len(w.options.RequiredRoles) > 0 && authenticated && isAPIRoute {
			rolesData := ctx.Value(RolesKey)
			if rolesData == nil {
				reqLogger.Warn("Missing role information",
					logging.String("path", path),
					logging.String("method", r.Method))
				utils.RespondError(wr, errors.New(errors.CodeForbidden, "access denied: missing role information"))
				return
			}

			roles, ok := rolesData.([]string)
			if !ok {
				reqLogger.Warn("Invalid role information",
					logging.String("path", path),
					logging.String("method", r.Method))
				utils.RespondError(wr, errors.New(errors.CodeForbidden, "access denied: invalid role information"))
				return
			}

			// Check if user has any of the required roles
			hasRequiredRole := false
			for _, requiredRole := range w.options.RequiredRoles {
				for _, userRole := range roles {
					if requiredRole == userRole {
						hasRequiredRole = true
						break
					}
				}
				if hasRequiredRole {
					break
				}
			}

			if !hasRequiredRole {
				reqLogger.Warn("Missing required role",
					logging.String("path", path),
					logging.String("method", r.Method))
				utils.RespondError(wr, errors.New(errors.CodeForbidden, "access denied: missing required role"))
				return
			}
		}

		// Check for required permissions if specified
		if len(w.options.RequiredPermissions) > 0 && authenticated && isAPIRoute {
			permsData := ctx.Value(PermissionsKey)
			if permsData == nil {
				reqLogger.Warn("Missing permission information",
					logging.String("path", path),
					logging.String("method", r.Method))
				utils.RespondError(wr, errors.New(errors.CodeForbidden, "access denied: missing permission information"))
				return
			}

			permissions, ok := permsData.([]string)
			if !ok {
				reqLogger.Warn("Invalid permission information",
					logging.String("path", path),
					logging.String("method", r.Method))
				utils.RespondError(wr, errors.New(errors.CodeForbidden, "access denied: invalid permission information"))
				return
			}

			// Check if user has any of the required permissions
			hasRequiredPermission := false
			for _, requiredPerm := range w.options.RequiredPermissions {
				for _, userPerm := range permissions {
					if requiredPerm == userPerm {
						hasRequiredPermission = true
						break
					}
				}
				if hasRequiredPermission {
					break
				}
			}

			if !hasRequiredPermission {
				reqLogger.Warn("Missing required permission",
					logging.String("path", path),
					logging.String("method", r.Method))
				utils.RespondError(wr, errors.New(errors.CodeForbidden, "access denied: missing required permission"))
				return
			}
		}

		// All checks passed, call next handler with updated context
		next.ServeHTTP(wr, r.WithContext(ctx))
	})
}

// RegisterProtectedRoutes registers the web route protection middleware on a Chi router
func (w *WebRouteProtection) RegisterProtectedRoutes(r chi.Router, routes ...string) {
	// Create a map of protected routes
	w.protectedPaths = make(map[string]bool)
	for _, route := range routes {
		w.protectedPaths[route] = true
	}

	// Use the middleware for all routes
	r.Use(w.ProtectRoutes)
}

// RegisterGroup registers the protection for a group of routes
func (w *WebRouteProtection) RegisterGroup(r chi.Router, fn func(r chi.Router)) {
	group := chi.NewRouter()
	group.Use(w.ProtectRoutes)
	fn(group)
	r.Mount("/", group)
}

// WithRequiredRole sets required roles for routes
func (w *WebRouteProtection) WithRequiredRole(role string) *WebRouteProtection {
	opts := w.options
	opts.RequiredRoles = []string{role}
	return w.WithOptions(opts)
}

// WithRequiredPermission sets required permissions for routes
func (w *WebRouteProtection) WithRequiredPermission(permission string) *WebRouteProtection {
	opts := w.options
	opts.RequiredPermissions = []string{permission}
	return w.WithOptions(opts)
}

// WithRequiredFeature sets a required feature for routes
func (w *WebRouteProtection) WithRequiredFeature(feature string) *WebRouteProtection {
	opts := w.options
	opts.FeatureRequired = feature
	return w.WithOptions(opts)
}

// SetPublicPaths specifies paths that should be accessible without authentication
func (w *WebRouteProtection) SetPublicPaths(paths ...string) *WebRouteProtection {
	opts := w.options
	opts.PublicPaths = paths
	return w.WithOptions(opts)
}

// SetCSRFExemptPaths specifies paths that should be exempt from CSRF protection
func (w *WebRouteProtection) SetCSRFExemptPaths(paths ...string) *WebRouteProtection {
	opts := w.options
	opts.CSRFExemptPaths = paths
	return w.WithOptions(opts)
}

// RequireOrganization sets whether an organization context is required
func (w *WebRouteProtection) RequireOrganization(required bool) *WebRouteProtection {
	opts := w.options
	opts.RequireOrganization = required
	return w.WithOptions(opts)
}

// SetStaticFilePrefixes specifies prefixes for static files that should bypass protection
func (w *WebRouteProtection) SetStaticFilePrefixes(prefixes ...string) *WebRouteProtection {
	w.staticFilePrefixes = prefixes
	return w
}
