package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/xid"
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/di"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/contexts"
	"github.com/xraph/frank/pkg/crypto"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"github.com/xraph/frank/pkg/server"
)

// AuthMethod represents the authentication method used
type AuthMethod = contexts.AuthMethod

// UserContext represents the authenticated user context
type UserContext = contexts.UserContext

// SessionContext represents the session context
type SessionContext = contexts.SessionContext

// APIKeyContext represents the API key context
type APIKeyContext = contexts.APIKeyContext

// JWTClaims represents JWT token claims
type JWTClaims struct {
	UserID         xid.ID   `json:"user_id"`
	OrganizationID *xid.ID  `json:"organization_id"`
	SessionID      *xid.ID  `json:"session_id"`
	UserType       string   `json:"user_type"`
	Permissions    []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// APIKeyValidationRequest represents the API key validation request
type APIKeyValidationRequest struct {
	Key       string
	IPAddress string
	UserAgent string
	Endpoint  string
	Method    string
}

// AuthMiddleware provides authentication middleware functions
type AuthMiddleware struct {
	config           *config.Config
	userRepo         repository.UserRepository
	sessionRepo      repository.SessionRepository
	apiKeyRepo       repository.ApiKeyRepository
	organizationRepo repository.OrganizationRepository
	di               di.Container
	crypto           crypto.Util
	api              huma.API
	logger           logging.Logger
	mountOpts        *server.MountOptions // Add mount options
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(di di.Container, api huma.API, mountOpts *server.MountOptions) *AuthMiddleware {
	return &AuthMiddleware{
		api:              api,
		di:               di,
		config:           di.Config(),
		userRepo:         di.Repo().User(),
		sessionRepo:      di.Repo().Session(),
		apiKeyRepo:       di.Repo().APIKey(),
		organizationRepo: di.Repo().Organization(),
		crypto:           di.Crypto(),
		logger:           di.Logger().Named("auth-middleware"),
		mountOpts:        mountOpts,
	}
}

// RequireAuth middleware that requires authentication via JWT, API key, or session
func (m *AuthMiddleware) RequireAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Try different authentication methods in order of preference
			authenticated := false
			var authContext *contexts.AuthenticationContext

			// 1. Try JWT authentication
			if m.config.Auth.AllowBearerToken {
				if session, user, err := m.authenticateJWT(ctx, r); err == nil && user != nil {
					authContext = &contexts.AuthenticationContext{
						User:    user,
						Session: session,
						Method:  contexts.AuthMethodJWT,
					}
					authenticated = true
				}
			}

			// 2. Try API Key authentication
			if !authenticated && m.config.Auth.AllowAPIKey {
				if apiKey, user, err := m.authenticateAPIKey(ctx, r); err == nil && apiKey != nil {
					authContext = &contexts.AuthenticationContext{
						User:   user,
						APIKey: apiKey,
						Method: contexts.AuthMethodAPIKey,
					}
					authenticated = true
				}
			}

			// 3. Try Session authentication
			if !authenticated && m.config.Auth.AllowSession {
				if session, user, err := m.authenticateSession(ctx, r); err == nil && session != nil && user != nil {
					authContext = &contexts.AuthenticationContext{
						User:    user,
						Session: session,
						Method:  contexts.AuthMethodSession,
					}
					authenticated = true
				}
			}

			if !authenticated {
				m.respondUnauthorized(w, r, "authentication required")
				return
			}

			// Validate organization context compatibility
			if err := m.validateOrganizationContextCompatibility(ctx, r, authContext); err != nil {
				m.logger.Warn("Organization context compatibility check failed",
					logging.Error(err),
					logging.String("method", string(authContext.Method)),
					logging.String("path", r.URL.Path))
				m.respondForbidden(w, r, err.Error())
				return
			}

			// Set authentication context
			ctx = m.setAuthenticationContext(ctx, authContext)

			// Add request metadata
			ctx = m.addRequestMetadata(ctx, r)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuthHuma middleware that requires authentication via JWT, API key, or session
func (m *AuthMiddleware) RequireAuthHuma() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r := contexts.GetRequestFromContext(ctx.Context())
		rctx := ctx.Context()

		// Try different authentication methods in order of preference
		authenticated := false
		var authContext *contexts.AuthenticationContext

		// 1. Try JWT authentication
		if m.config.Auth.AllowBearerToken {
			if session, user, err := m.authenticateJWT(rctx, r); err == nil && user != nil {
				authContext = &contexts.AuthenticationContext{
					User:    user,
					Session: session,
					Method:  contexts.AuthMethodJWT,
				}
				authenticated = true
			}
		}

		// 2. Try API Key authentication
		usedAPIKey := false
		if !authenticated && m.config.Auth.AllowAPIKey {
			if apiKey, user, err := m.authenticateAPIKey(rctx, r); err == nil && apiKey != nil {
				authContext = &contexts.AuthenticationContext{
					User:   user,
					APIKey: apiKey,
					Method: contexts.AuthMethodAPIKey,
				}
				authenticated = true
				usedAPIKey = true
			}
		}

		// 3. Try Session authentication
		if (!authenticated || (authenticated && authContext.User == nil && usedAPIKey)) && m.config.Auth.AllowSession {
			if session, user, err := m.authenticateSession(rctx, r); err == nil && session != nil && user != nil {
				authContext = &contexts.AuthenticationContext{
					User:    user,
					Session: session,
					Method:  contexts.AuthMethodSession,
				}
				authenticated = true
			}
		}

		if !authenticated {
			m.respondUnauthorizedHuma(ctx, "authentication required")
			return
		}

		// Validate organization context compatibility
		if err := m.validateOrganizationContextCompatibility(rctx, r, authContext); err != nil {
			m.logger.Warn("Organization context compatibility check failed",
				logging.Error(err),
				logging.String("method", string(authContext.Method)),
				logging.String("path", ctx.URL().Path),
			)
			m.respondForbiddenHuma(ctx, err.Error())
			return
		}

		// Set authentication context
		ctx = m.setAuthenticationContextHuma(ctx, authContext)

		// Add request metadata
		ctx = m.addRequestMetadataHuma(ctx, r)
		next(ctx)
	}
}

// validateOrganizationContextCompatibility validates that the authenticated user context
// is compatible with the requested organization context
func (m *AuthMiddleware) validateOrganizationContextCompatibility(ctx context.Context, r *http.Request, authCtx *contexts.AuthenticationContext) error {
	// Skip validation for personal/auth operations that don't need org context
	if m.shouldSkipOrgValidationForPath(r.URL.Path) {
		m.logger.Debug("Skipping org validation for path", logging.String("path", r.URL.Path))
		return nil
	}

	// Get requested organization context from various sources
	requestedOrgID := m.getRequestedOrganizationID(ctx, r)

	// For API key authentication, ensure organization compatibility
	if authCtx.APIKey != nil {
		return m.validateAPIKeyOrganizationCompatibility(requestedOrgID, authCtx)
	}

	// For user authentication (JWT/Session), validate user-organization relationship
	if authCtx.User != nil {
		return m.validateUserOrganizationCompatibility(ctx, requestedOrgID, authCtx)
	}

	return nil
}

// getRequestedOrganizationID gets the organization ID from various request sources
func (m *AuthMiddleware) getRequestedOrganizationID(ctx context.Context, r *http.Request) *xid.ID {
	// Priority order: API Key org > X-Org-ID header > URL parameter > query parameter

	// 1. From API key context (highest priority)
	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil && apiKey.OrganizationID != nil {
		return apiKey.OrganizationID
	}

	// 2. From X-Org-ID header
	if orgIDStr := r.Header.Get("X-Org-ID"); orgIDStr != "" {
		if orgID, err := xid.FromString(orgIDStr); err == nil {
			return &orgID
		}
	}

	// 3. From URL parameter (chi route parameter)
	if orgIDStr := chi.URLParam(r, "orgId"); orgIDStr != "" {
		if orgID, err := xid.FromString(orgIDStr); err == nil {
			return &orgID
		}
	}

	// 4. From query parameter
	if orgIDStr := r.URL.Query().Get("orgId"); orgIDStr != "" {
		if orgID, err := xid.FromString(orgIDStr); err == nil {
			return &orgID
		}
	}

	return nil
}

// shouldSkipOrgValidationForPath checks if organization validation should be skipped for this path
func (m *AuthMiddleware) shouldSkipOrgValidationForPath(path string) bool {
	// Build base path prefix
	basePath := ""
	if m.mountOpts != nil && m.mountOpts.BasePath != "" {
		basePath = strings.TrimSuffix(m.mountOpts.BasePath, "/")
	}

	// Helper function to build full path with base path
	buildPath := func(p string) string {
		return basePath + p
	}

	// Paths where organization context validation should be skipped
	skipPaths := []string{
		// Personal auth operations - these should work for all user types without org context
		buildPath("/api/v1/me/auth/logout"),
		buildPath("/api/v1/me/auth/refresh"),
		buildPath("/api/v1/me/auth/status"),
		buildPath("/api/v1/me/auth/mfa/setup"),
		buildPath("/api/v1/me/auth/mfa/verify"),
		buildPath("/api/v1/me/auth/mfa/disable"),
		buildPath("/api/v1/me/auth/mfa/backup-codes"),
		buildPath("/api/v1/me/auth/sessions"),
		buildPath("/api/v1/me/auth/sessions/"), // For session management
		buildPath("/api/v1/me/auth/passkeys"),  // Personal passkey operations
		buildPath("/api/v1/me/auth/passkeys/"),

		// Personal user operations
		buildPath("/api/v1/me/profile"),
		buildPath("/api/v1/me/change-password"),
		buildPath("/api/v1/me/organizations"), // List user's organizations
		buildPath("/api/v1/me/memberships"),   // List user's memberships

		// Organization creation and listing (external users should be able to do these)
		buildPath("/api/v1/organizations"), // POST to create, GET to list user's orgs

		// Health checks and static endpoints
		buildPath("/health"),
		buildPath("/ready"),
		buildPath("/metrics"),
		buildPath("/favicon.ico"),
		buildPath("/robots.txt"),

		// Public auth endpoints (already handled elsewhere but included for completeness)
		buildPath("/api/v1/public/auth/"),

		// Internal user endpoints (internal users should never be restricted by org context)
		buildPath("/api/v1/internal/"),
	}

	// Check exact matches and prefix matches
	for _, skipPath := range skipPaths {
		if path == skipPath || strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	// Additional logic for internal users - they should never be restricted by org context
	// This will be handled in validateUserOrganizationCompatibility, but we log it here
	return false
}

// validateAPIKeyOrganizationCompatibility validates API key organization context
func (m *AuthMiddleware) validateAPIKeyOrganizationCompatibility(requestedOrgID *xid.ID, authCtx *contexts.AuthenticationContext) error {
	apiKey := authCtx.APIKey

	// For client API keys, organization context is always from the API key
	if apiKey.Type == model.APIKeyTypeClient {
		if requestedOrgID != nil && apiKey.OrganizationID != nil && *requestedOrgID != *apiKey.OrganizationID {
			return errors.New(errors.CodeForbidden, "API key organization does not match requested organization context")
		}
		return nil
	}

	// For server/admin API keys with user context
	if authCtx.User != nil {
		return m.validateUserOrganizationCompatibility(context.Background(), requestedOrgID, authCtx)
	}

	// For organization-scoped API keys without user context
	if apiKey.OrganizationID != nil {
		if requestedOrgID != nil && *requestedOrgID != *apiKey.OrganizationID {
			return errors.New(errors.CodeForbidden, "API key organization does not match requested organization context")
		}
	}

	return nil
}

// validateUserOrganizationCompatibility validates user organization context
func (m *AuthMiddleware) validateUserOrganizationCompatibility(ctx context.Context, requestedOrgID *xid.ID, authCtx *contexts.AuthenticationContext) error {
	user := authCtx.User

	// Internal users can access any organization (or no organization)
	if user.UserType == model.UserTypeInternal {
		m.logger.Debug("Internal user bypassing org validation",
			logging.String("userId", user.ID.String()))
		return nil
	}

	// If no organization context is requested, check if it's allowed for this user type
	if requestedOrgID == nil {
		switch user.UserType {
		case model.UserTypeExternal:
			// External users can operate without organization context for personal operations
			m.logger.Debug("External user allowed without org context for personal operation",
				logging.String("userId", user.ID.String()))
			return nil
		case model.UserTypeEndUser:
			// End users may not require organization context for personal operations only
			// The organization context middleware will handle endpoint-specific requirements
			m.logger.Debug("End user allowed without org context for personal operation",
				logging.String("userId", user.ID.String()))
			return nil
		}
		return nil
	}

	// External and end users must belong to the requested organization for org-scoped operations
	if user.UserType == model.UserTypeExternal || user.UserType == model.UserTypeEndUser {
		// Check if user belongs to the requested organization
		if user.OrganizationID == nil {
			// User doesn't belong to any organization
			if user.UserType == model.UserTypeEndUser {
				// End users MUST have organization context for most operations
				return errors.New(errors.CodeBadRequest, "end user must have organization context")
			}
			// External users can exist without organization for personal operations
			return nil
		}

		if *user.OrganizationID != *requestedOrgID {
			// For sessions, check if this might be a stale session from a different organization
			if authCtx.Session != nil {
				m.logger.Warn("Session organization mismatch detected",
					logging.String("sessionOrgId", user.OrganizationID.String()),
					logging.String("requestedOrgId", requestedOrgID.String()),
					logging.String("userId", user.ID.String()))
				return errors.New(errors.CodeUnauthorized, "session organization context mismatch - please log in again")
			}
			return errors.New(errors.CodeForbidden, "user does not belong to the requested organization")
		}
	}

	return nil
}

// setAuthenticationContext sets the authentication context in the request context
func (m *AuthMiddleware) setAuthenticationContext(ctx context.Context, authCtx *contexts.AuthenticationContext) context.Context {
	if authCtx.User != nil {
		ctx = m.setUserContext(ctx, authCtx.User, authCtx.Method)
	}
	if authCtx.Session != nil {
		ctx = m.setSessionContext(ctx, authCtx.Session)
	}
	if authCtx.APIKey != nil {
		ctx = m.setAPIKeyContext(ctx, authCtx.APIKey)
	}
	return ctx
}

// setAuthenticationContextHuma sets the authentication context in the Huma context
func (m *AuthMiddleware) setAuthenticationContextHuma(ctx huma.Context, authCtx *contexts.AuthenticationContext) huma.Context {
	if authCtx.User != nil {
		ctx = m.setUserContextHuma(ctx, authCtx.User, authCtx.Method)
	}
	if authCtx.Session != nil {
		ctx = m.setSessionContextHuma(ctx, authCtx.Session)
	}
	if authCtx.APIKey != nil {
		ctx = m.setAPIKeyContextHuma(ctx, authCtx.APIKey)
	}

	return ctx
}

// isStandaloneMode checks if the application is running in standalone mode
func (m *AuthMiddleware) isStandaloneMode() bool {
	return m.config.Standalone.Enabled
}

// setAPIKeyOnlyContext sets only the API key context without user context
func (m *AuthMiddleware) setAPIKeyOnlyContext(ctx context.Context, apiKey *APIKeyContext) context.Context {
	ctx = context.WithValue(ctx, contexts.APIKeyContextKey, apiKey)
	ctx = context.WithValue(ctx, contexts.APIKeyIDContextKey, apiKey.ID)
	ctx = context.WithValue(ctx, contexts.AuthMethodContextKey, contexts.AuthMethodAPIKey)

	// Set organization context if available from API key
	if apiKey.OrganizationID != nil {
		ctx = context.WithValue(ctx, contexts.OrganizationIDContextKey, *apiKey.OrganizationID)
	}

	return ctx
}

// Enhanced organization context detection for end users
func (m *AuthMiddleware) enhanceOrganizationContextForEndUsers(ctx context.Context, r *http.Request) context.Context {
	// Skip enhancement for personal operations
	if m.shouldSkipOrgValidationForPath(r.URL.Path) {
		return ctx
	}

	// Check if this is an end user request without X-Org-ID
	userType := GetDetectedUserTypeFromContext(ctx)
	if userType == "" || userType != model.UserTypeEndUser {
		return ctx
	}

	// Check if organization context is already set
	if GetOrganizationIDFromContext(ctx) != nil {
		return ctx
	}

	// Try to get organization context from API key
	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil && apiKey.OrganizationID != nil {
		m.logger.Debug("Setting organization context from API key for end user",
			logging.String("orgId", apiKey.OrganizationID.String()))
		ctx = context.WithValue(ctx, contexts.OrganizationIDContextKey, *apiKey.OrganizationID)

		// Also set the X-Org-ID header for downstream processing
		r.Header.Set("X-Org-ID", apiKey.OrganizationID.String())
	}

	return ctx
}

// OptionalAuth middleware that allows both authenticated and unauthenticated requests
func (m *AuthMiddleware) OptionalAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			authenticated := false
			var authContext *contexts.AuthenticationContext

			// Try JWT authentication first
			if m.config.Auth.AllowBearerToken {
				if session, user, err := m.authenticateJWT(ctx, r); err == nil && user != nil {
					authContext = &contexts.AuthenticationContext{
						User:    user,
						Session: session,
						Method:  contexts.AuthMethodJWT,
					}
					authenticated = true
				}
			}

			// Try API Key authentication if not already authenticated
			if !authenticated && m.config.Auth.AllowAPIKey {
				if apiKey, user, err := m.authenticateAPIKey(ctx, r); err == nil && apiKey != nil {
					authContext = &contexts.AuthenticationContext{
						User:   user,
						APIKey: apiKey,
						Method: contexts.AuthMethodAPIKey,
					}
					// Handle different API key types
					if user != nil {
						// Server/Admin API key - act as authenticated user
						authenticated = true
					} else {
						// Client API key - provide API access but don't act as authenticated user
						authenticated = false // Explicitly remain unauthenticated for client keys
					}
				}
			}

			// Try Session authentication if not already authenticated
			if !authenticated && m.config.Auth.AllowSession {
				if session, user, err := m.authenticateSession(ctx, r); err == nil && session != nil && user != nil {
					authContext = &contexts.AuthenticationContext{
						User:    user,
						Session: session,
						Method:  contexts.AuthMethodSession,
					}
					authenticated = true
				}
			}

			// If authenticated, validate organization context compatibility
			if authenticated && authContext != nil {
				if err := m.validateOrganizationContextCompatibility(ctx, r, authContext); err != nil {
					m.logger.Warn("Organization context compatibility check failed in optional auth",
						logging.Error(err),
						logging.String("method", string(authContext.Method)),
						logging.String("path", r.URL.Path))
					// For optional auth, we don't fail the request but clear the authentication
					authContext = &contexts.AuthenticationContext{
						APIKey: authContext.APIKey, // Keep API key for client access
						Method: authContext.Method,
					}
					authenticated = false
				}
			}

			// Set authentication context if available
			if authContext != nil {
				ctx = m.setAuthenticationContext(ctx, authContext)
			}

			// Enhance organization context for end users
			ctx = m.enhanceOrganizationContextForEndUsers(ctx, r)

			// Add request metadata regardless of authentication status
			ctx = m.addRequestMetadata(ctx, r)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuthHuma middleware that allows both authenticated and unauthenticated requests
func (m *AuthMiddleware) OptionalAuthHuma() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		rctx := ctx.Context()
		r := contexts.GetRequestFromContext(rctx)

		var authContext *contexts.AuthenticationContext
		authenticated := false

		// Try JWT authentication first
		if m.config.Auth.AllowBearerToken {
			if session, user, err := m.authenticateJWT(rctx, r); err == nil && user != nil {
				authContext = &contexts.AuthenticationContext{
					User:    user,
					Session: session,
					Method:  contexts.AuthMethodJWT,
				}
				authenticated = true
			}
		}

		// Try API Key authentication if not already authenticated
		if !authenticated && m.config.Auth.AllowAPIKey {
			if apiKey, user, err := m.authenticateAPIKey(rctx, r); err == nil && apiKey != nil {
				authContext = &contexts.AuthenticationContext{
					User:   user,
					APIKey: apiKey,
					Method: contexts.AuthMethodAPIKey,
				}
				// Handle different API key types
				if user != nil {
					// Server/Admin API key - act as authenticated user
					authenticated = true
				} else {
					// Client API key - provide API access but don't act as authenticated user
					authenticated = false // Explicitly set to false for client keys
				}
			}
		}

		// Try Session authentication if not already authenticated
		if !authenticated && m.config.Auth.AllowSession {
			if session, user, err := m.authenticateSession(rctx, r); err == nil && session != nil && user != nil {
				authContext = &contexts.AuthenticationContext{
					User:    user,
					Session: session,
					Method:  contexts.AuthMethodSession,
				}
				authenticated = true
			}
		}

		// If authenticated, validate organization context compatibility
		if authenticated && authContext != nil {
			if err := m.validateOrganizationContextCompatibility(rctx, r, authContext); err != nil {
				m.logger.Warn("Organization context compatibility check failed in optional auth",
					logging.Error(err),
					logging.String("method", string(authContext.Method)),
					logging.String("path", ctx.URL().Path))
				// For optional auth, we don't fail the request but clear the authentication
				authContext = &contexts.AuthenticationContext{
					APIKey: authContext.APIKey, // Keep API key for client access
					Method: authContext.Method,
				}
				authenticated = false
			}
		}

		// Set authentication context if available
		if authContext != nil {
			ctx = m.setAuthenticationContextHuma(ctx, authContext)
		}

		// Enhance organization context for end users
		newCtx := m.enhanceOrganizationContextForEndUsers(rctx, r)
		if newCtx != rctx {
			// Update the Huma context with enhanced organization context
			for key, value := range extractContextValues(newCtx) {
				ctx = huma.WithValue(ctx, key, value)
			}
		}

		// Add request metadata regardless of authentication status
		ctx = m.addRequestMetadataHuma(ctx, r)

		next(ctx)
	}
}

// Helper function to extract context values for transfer
func extractContextValues(ctx context.Context) map[interface{}]interface{} {
	values := make(map[interface{}]interface{})

	if orgID := GetOrganizationIDFromContext(ctx); orgID != nil {
		values[contexts.OrganizationIDContextKey] = *orgID
	}

	return values
}

// RequireUserType middleware that requires a specific user type
func (m *AuthMiddleware) RequireUserType(userTypes ...model.UserType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				m.respondUnauthorized(w, r, "authentication required user")
				return
			}

			for _, allowedType := range userTypes {
				if user.UserType == allowedType {
					next.ServeHTTP(w, r)
					return
				}
			}

			m.respondForbidden(w, r, "insufficient permissions")
		})
	}
}

// RequireUserTypeHuma middleware that requires a specific user type
func (m *AuthMiddleware) RequireUserTypeHuma(userTypes ...model.UserType) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		user := GetUserFromContext(ctx.Context())
		if user == nil {
			m.respondUnauthorizedHuma(ctx, "authentication required 5")
			return
		}

		for _, allowedType := range userTypes {
			if user.UserType == allowedType {
				next(ctx)
				return
			}
		}

		m.respondForbiddenHuma(ctx, "insufficient permissions")
	}
}

// RequireOrganization middleware that requires organization context
func (m *AuthMiddleware) RequireOrganization() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			orgID := GetOrganizationIDFromContext(r.Context())
			if orgID == nil {
				m.respondForbidden(w, r, "organization context required")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireOrganizationHuma middleware that requires organization context
func (m *AuthMiddleware) RequireOrganizationHuma() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		orgID := GetOrganizationIDFromContext(ctx.Context())
		if orgID == nil {
			m.respondForbiddenHuma(ctx, "organization context required")
			return
		}

		next(ctx)
	}
}

// HumaAuth Huma Authentication Middleware for API handlers
func (m *AuthMiddleware) HumaAuth() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r := contexts.GetRequestFromContext(ctx.Context())

		// Try authentication
		authenticated := false
		rctx := ctx.Context()

		if m.config.Auth.AllowBearerToken {
			if session, currentUser, err := m.authenticateJWT(rctx, r); err == nil && currentUser != nil {
				ctx = m.setUserContextHuma(ctx, currentUser, contexts.AuthMethodJWT)
				ctx = m.setSessionContextHuma(ctx, session)
				authenticated = true
			}
		}

		if !authenticated && m.config.Auth.AllowAPIKey {
			if apiKey, currentUser, err := m.authenticateAPIKey(rctx, r); err == nil && apiKey != nil && currentUser != nil {
				ctx = m.setUserContextHuma(ctx, currentUser, contexts.AuthMethodAPIKey)
				ctx = m.setAPIKeyContextHuma(ctx, apiKey)
				authenticated = true
			}
		}

		if !authenticated && m.config.Auth.AllowSession {
			if session, currentUser, err := m.authenticateSession(rctx, r); err == nil && session != nil && currentUser != nil {
				ctx = m.setUserContextHuma(ctx, currentUser, contexts.AuthMethodSession)
				ctx = m.setSessionContextHuma(ctx, session)
				authenticated = true
			}
		}

		if !authenticated {
			ctx.SetStatus(http.StatusUnauthorized)
			ctx.SetHeader("Content-Type", "application/json")
			errResp := errors.NewErrorResponse(errors.New(errors.CodeUnauthorized, "authentication required"))
			huma.WriteErr(m.api, ctx, errResp.StatusCode(), errResp.Error())
			return
		}

		// Update context and continue
		ctx = m.addRequestMetadataHuma(ctx, r)
		next(ctx)
	}
}

// Authentication methods

func (m *AuthMiddleware) authenticateJWT(ctx context.Context, r *http.Request) (*SessionContext, *UserContext, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, nil, errors.New(errors.CodeUnauthorized, "no authorization header")
	}

	// Extract Bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, nil, errors.New(errors.CodeUnauthorized, "invalid authorization header format")
	}

	tokenString := parts[1]

	// Parse and validate JWT token
	claims, err := m.crypto.JWT().ValidateAccessToken(tokenString)
	if err != nil {
		return nil, nil, errors.Wrap(err, errors.CodeUnauthorized, "invalid token")
	}

	// Check token expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, nil, errors.New(errors.CodeUnauthorized, "token expired")
	}

	// Get user from database
	userCtx, err := m.buildUserContext(ctx, claims.UserID, r, claims.Permissions)
	if err != nil {
		return nil, nil, err
	}

	// Validate session
	session, err := m.sessionRepo.GetByID(ctx, claims.SessionID)
	if err != nil {
		return nil, nil, errors.New(errors.CodeUnauthorized, "invalid session")
	}

	sessionCtx := &SessionContext{
		ID:           session.ID,
		Token:        session.Token,
		UserID:       session.UserID,
		ExpiresAt:    session.ExpiresAt,
		LastActiveAt: session.LastActiveAt,
		IPAddress:    session.IPAddress,
		UserAgent:    session.UserAgent,
		DeviceID:     session.DeviceID,
	}
	userCtx.SessionID = session.ID

	return sessionCtx, userCtx, nil
}

func (m *AuthMiddleware) allowReadonlyOpsForAuthRoutes(path string) bool {
	// Build base path prefix
	basePath := ""
	if m.mountOpts != nil && m.mountOpts.BasePath != "" {
		basePath = strings.TrimSuffix(m.mountOpts.BasePath, "/")
	}

	// Helper function to build full path with base path
	buildPath := func(p string) string {
		return basePath + p
	}

	// Paths where organization context validation should be skipped
	skipPaths := []string{
		// Personal auth operations - these should work for all user types without org context
		buildPath("/api/v1/public/auth/register"),
		buildPath("/api/v1/public/auth/login"),
		buildPath("/api/v1/me/auth/logout"),
		buildPath("/api/v1/me/auth/refresh"),
		buildPath("/api/v1/me/auth/status"),
		buildPath("/api/v1/me/auth/mfa/setup"),
		buildPath("/api/v1/me/auth/mfa/verify"),
		buildPath("/api/v1/me/auth/mfa/disable"),
		buildPath("/api/v1/me/auth/mfa/backup-codes"),
		buildPath("/api/v1/me/auth/sessions"),
		buildPath("/api/v1/me/auth/sessions/"), // For session management
		buildPath("/api/v1/me/auth/passkeys"),  // Personal passkey operations
		buildPath("/api/v1/me/auth/passkeys/"),

		// Personal user operations
		buildPath("/api/v1/me/profile"),
		buildPath("/api/v1/me/change-password"),
		buildPath("/api/v1/me/organizations"), // List user's organizations
		buildPath("/api/v1/me/memberships"),   // List user's memberships
	}

	// Check exact matches and prefix matches
	for _, skipPath := range skipPaths {
		if path == skipPath || strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	return false
}

// authenticateStandaloneAPIKey handles standalone mode API key authentication
func (m *AuthMiddleware) authenticateStandaloneAPIKey(ctx context.Context, r *http.Request) (*APIKeyContext, *UserContext, error) {
	keyValue, keyType, err := m.extractAPIKey(r)
	if err != nil {
		return nil, nil, err
	}

	// Validate key format and determine environment
	if !m.isValidAPIKeyFormat(keyValue) {
		return nil, nil, errors.New(errors.CodeUnauthorized, "invalid API key format")
	}

	// For public keys, only allow read operations
	if keyType == "public" && !m.isReadOnlyOperation(r.Method) && !m.allowReadonlyOpsForAuthRoutes(r.URL.Path) {
		return nil, nil, errors.New(errors.CodeForbidden, "public keys can only be used for read operations")
	}

	// Validate key format
	if !m.isStandaloneKey(keyValue) {
		return nil, nil, errors.New(errors.CodeUnauthorized, "invalid standalone key format")
	}

	// Get standalone context from DI container
	if !m.di.IsStandaloneMode() {
		return nil, nil, errors.New(errors.CodeUnauthorized, "standalone mode not enabled")
	}

	standaloneCtx := m.di.StandaloneContext()
	if standaloneCtx == nil {
		return nil, nil, errors.New(errors.CodeInternalServer, "standalone context not initialized")
	}

	// Verify public key matches
	if (keyType == "public" && keyValue != standaloneCtx.PublicKey) || (keyType == "secret" && keyValue != standaloneCtx.SecretKey) {
		return nil, nil, errors.New(errors.CodeUnauthorized, "invalid standalone public key")
	}

	// Update last used timestamp
	go func() {
		_ = m.apiKeyRepo.UpdateLastUsed(context.Background(), standaloneCtx.APIKey.ID)
	}()

	// Create API key context
	apiKeyCtx := &APIKeyContext{
		ID:             standaloneCtx.APIKey.ID,
		Name:           standaloneCtx.APIKey.Name,
		Type:           standaloneCtx.APIKey.Type,
		OrganizationID: &standaloneCtx.Organization.ID,
		Permissions:    standaloneCtx.APIKey.Permissions,
		Scopes:         standaloneCtx.APIKey.Scopes,
		Environment:    standaloneCtx.APIKey.Environment,
		PublicKey:      standaloneCtx.APIKey.PublicKey,
		KeyType:        "standalone",
	}

	m.logger.Debug("Standalone API key authenticated",
		logging.String("keyValue", keyValue),
		logging.String("orgId", standaloneCtx.Organization.ID.String()))

	// Return API key context without user context (like client keys)
	// This allows the API to work without requiring user authentication
	return apiKeyCtx, nil, nil
}

// isStandaloneKey checks if a key is a standalone key
func (m *AuthMiddleware) isStandaloneKey(key string) bool {
	return strings.HasPrefix(key, "pk_standalone_") || strings.HasPrefix(key, "sk_standalone_")
}

// authenticateAPIKey handles both public and secret API key authentication
func (m *AuthMiddleware) authenticateAPIKey(ctx context.Context, r *http.Request) (*APIKeyContext, *UserContext, error) {
	// Check for standalone mode first
	if m.isStandaloneMode() {
		// Try standalone authentication
		if apiKeyCtx, userCtx, err := m.authenticateStandaloneAPIKey(ctx, r); err == nil {
			return apiKeyCtx, userCtx, nil
		}

		// If standalone auth fails, fall through to normal auth
	}

	keyValue, keyType, err := m.extractAPIKey(r)
	if err != nil {
		return nil, nil, err
	}

	// Validate key format and determine environment
	if !m.isValidAPIKeyFormat(keyValue) {
		return nil, nil, errors.New(errors.CodeUnauthorized, "invalid API key format")
	}

	// For public keys, only allow read operations
	if keyType == "public" && !m.isReadOnlyOperation(r.Method) && !m.allowReadonlyOpsForAuthRoutes(r.URL.Path) {
		return nil, nil, errors.New(errors.CodeForbidden, "public keys can only be used for read operations")
	}

	// Get API key from database
	apiKey, err := m.getAPIKeyFromDatabase(ctx, keyValue, keyType)
	if err != nil {
		return nil, nil, err
	}

	// Validate API key
	if err := m.validateAPIKey(apiKey, keyValue, r); err != nil {
		return nil, nil, err
	}

	// Update last used (async)
	go func() {
		_ = m.apiKeyRepo.UpdateLastUsed(context.Background(), apiKey.ID)
	}()

	// Create API key context
	apiKeyCtx := &APIKeyContext{
		ID:             apiKey.ID,
		Name:           apiKey.Name,
		Type:           apiKey.Type,
		UserID:         &apiKey.UserID,
		OrganizationID: &apiKey.OrganizationID,
		Permissions:    apiKey.Permissions,
		Scopes:         apiKey.Scopes,
		LastUsed:       apiKey.LastUsed,
		Environment:    apiKey.Environment,
		PublicKey:      apiKey.PublicKey,
		KeyType:        keyType,
	}

	// Handle different API key types with different authentication behaviors
	switch apiKey.Type {
	case model.APIKeyTypeClient:
		// Client keys provide organization context but DO NOT act as logged-in users
		// This allows frontend SDKs to access auth endpoints without appearing authenticated
		return apiKeyCtx, nil, nil

	case model.APIKeyTypeServer, model.APIKeyTypeAdmin:
		// Server and admin keys act as logged-in users
		var userCtx *UserContext
		if !apiKey.UserID.IsNil() {
			// Get user-scoped key user context
			userCtx, err = m.buildUserContext(ctx, apiKey.UserID, r, apiKey.Permissions)
			if err != nil {
				return nil, nil, err
			}
		} else {
			// Organization-level API key without specific user - create synthetic user context
			userCtx = &UserContext{
				ID:             xid.New(), // Synthetic ID for organization key
				UserType:       model.UserTypeExternal,
				OrganizationID: &apiKey.OrganizationID,
				Active:         true,
				EmailVerified:  true,
				Permissions:    apiKey.Permissions,
			}
		}
		return apiKeyCtx, userCtx, nil

	default:
		// Unknown key type - treat as server key for backward compatibility
		var userCtx *UserContext
		if !apiKey.UserID.IsNil() {
			userCtx, err = m.buildUserContext(ctx, apiKey.UserID, r, apiKey.Permissions)
			if err != nil {
				return nil, nil, err
			}
		} else {
			userCtx = &UserContext{
				ID:             xid.New(),
				UserType:       model.UserTypeExternal,
				OrganizationID: &apiKey.OrganizationID,
				Active:         true,
				EmailVerified:  true,
				Permissions:    apiKey.Permissions,
			}
		}
		return apiKeyCtx, userCtx, nil
	}
}

// extractAPIKey extracts the API key from request headers/query parameters
func (m *AuthMiddleware) extractAPIKey(r *http.Request) (string, string, error) {
	// Try secret key from X-API-Key header
	if secretKey := r.Header.Get("X-API-Key"); secretKey != "" {
		if m.isSecretKey(secretKey) {
			return secretKey, "secret", nil
		}
		return "", "", errors.New(errors.CodeUnauthorized, "invalid secret key format")
	}

	// Try secret key from query parameter
	if secretKey := r.URL.Query().Get("api_key"); secretKey != "" {
		if m.isSecretKey(secretKey) {
			return secretKey, "secret", nil
		}
		return "", "", errors.New(errors.CodeUnauthorized, "invalid secret key format")
	}

	// Try public key from X-Publishable-Key header
	if publicKey := r.Header.Get("X-Publishable-Key"); publicKey != "" {
		if m.isPublicKey(publicKey) {
			return publicKey, "public", nil
		}
		return "", "", errors.New(errors.CodeUnauthorized, "invalid public key format")
	}

	// Try public key from query parameter
	if publicKey := r.URL.Query().Get("publishable_key"); publicKey != "" {
		if m.isPublicKey(publicKey) {
			return publicKey, "public", nil
		}
		return "", "", errors.New(errors.CodeUnauthorized, "invalid public key format")
	}

	return "", "", errors.New(errors.CodeUnauthorized, "no API key provided")
}

// getAPIKeyFromDatabase retrieves the API key from database based on key type
func (m *AuthMiddleware) getAPIKeyFromDatabase(ctx context.Context, keyValue, keyType string) (*ent.ApiKey, error) {
	switch keyType {
	case "public":
		// For public keys, lookup by public key directly
		apiKey, err := m.apiKeyRepo.GetByPublicKey(ctx, keyValue)
		if err != nil {
			return nil, errors.New(errors.CodeUnauthorized, "invalid public key")
		}
		return apiKey, nil

	case "secret":
		// For secret keys, hash and lookup by hashed secret key
		hashedKey := m.crypto.Hasher().HashAPIKey(keyValue)
		apiKey, err := m.apiKeyRepo.GetBySecretKey(ctx, hashedKey)
		if err != nil {
			return nil, errors.New(errors.CodeUnauthorized, "invalid secret key")
		}
		return apiKey, nil

	default:
		return nil, errors.New(errors.CodeUnauthorized, "unknown key type")
	}
}

// validateAPIKey validates the API key
func (m *AuthMiddleware) validateAPIKey(apiKey *ent.ApiKey, keyValue string, r *http.Request) error {
	// Check if key is active
	if !apiKey.Active {
		return errors.New(errors.CodeUnauthorized, "API key is inactive")
	}

	// Check expiration
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return errors.New(errors.CodeUnauthorized, "API key expired")
	}

	// Check IP whitelist
	if len(apiKey.IPWhitelist) > 0 {
		clientIP := GetClientIP(r)
		if !m.isIPAllowed(clientIP, apiKey.IPWhitelist) {
			return errors.New(errors.CodeForbidden, "IP address not allowed")
		}
	}

	// Validate environment consistency
	keyEnvironment := m.getKeyEnvironment(keyValue)
	if keyEnvironment != "" && apiKey.Environment != keyEnvironment {
		return errors.New(errors.CodeUnauthorized, "key environment mismatch")
	}

	return nil
}

// Key validation helper methods

func (m *AuthMiddleware) isValidAPIKeyFormat(key string) bool {
	return m.isPublicKey(key) || m.isSecretKey(key) || m.isLegacyKey(key)
}

func (m *AuthMiddleware) isPublicKey(key string) bool {
	return strings.HasPrefix(key, "pk_test_") || strings.HasPrefix(key, "pk_live_") || strings.HasPrefix(key, "pk_standalone_")
}

func (m *AuthMiddleware) isSecretKey(key string) bool {
	return strings.HasPrefix(key, "sk_test_") || strings.HasPrefix(key, "sk_live_") || strings.HasPrefix(key, "sk_standalone_")
}

func (m *AuthMiddleware) isLegacyKey(key string) bool {
	return strings.HasPrefix(key, "frank_sk_")
}

func (m *AuthMiddleware) getKeyEnvironment(key string) model.Environment {
	switch {
	case strings.HasPrefix(key, "pk_test_") || strings.HasPrefix(key, "sk_test_"):
		return model.EnvironmentTest
	case strings.HasPrefix(key, "pk_live_") || strings.HasPrefix(key, "pk_standalone_") || strings.HasPrefix(key, "sk_live_") || strings.HasPrefix(key, "sk_standalone_"):
		return model.EnvironmentLive
	case strings.HasPrefix(key, "frank_sk_"):
		return model.EnvironmentTest // Default for legacy keys
	default:
		return ""
	}
}

func (m *AuthMiddleware) isReadOnlyOperation(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func (m *AuthMiddleware) isIPAllowed(clientIP string, whitelist []string) bool {
	// Implementation would check IP against whitelist
	// This is a simplified version - in production you'd want proper CIDR support
	for _, allowedIP := range whitelist {
		if clientIP == allowedIP {
			return true
		}
		// TODO: Add CIDR range checking
	}
	return false
}

func (m *AuthMiddleware) buildUserContext(ctx context.Context, userId xid.ID, r *http.Request, permission []string) (*UserContext, error) {
	// Get user
	user, err := m.userRepo.GetByID(ctx, userId)
	if err != nil {
		return nil, errors.New(errors.CodeUnauthorized, "user not found")
	}

	if !user.Active || user.Blocked {
		return nil, errors.New(errors.CodeUnauthorized, "user account is disabled")
	}

	orgID := user.OrganizationID
	if r.Header.Get("X-Org-ID") != "" {
		if id, err := xid.FromString(r.Header.Get("X-Org-ID")); err == nil {
			orgID = id
		}
	}

	userCtx := m.convertToUserContext(user, permission)

	if !orgID.IsNil() {
		if membership, err := m.di.MembershipService().GetMembership(ctx, orgID, userId); err == nil {
			userCtx.OrganizationID = &orgID
			userCtx.Membership = membership
		}
	}

	return userCtx, nil
}

func (m *AuthMiddleware) authenticateSession(ctx context.Context, r *http.Request) (*SessionContext, *UserContext, error) {
	// Try session cookie
	cookie, err := r.Cookie(m.config.Auth.SessionName)
	if err != nil {
		return nil, nil, errors.New(errors.CodeUnauthorized, "no session cookie")
	}

	sessionToken := cookie.Value
	if sessionToken == "" {
		return nil, nil, errors.New(errors.CodeUnauthorized, "empty session token")
	}

	// Validate session
	session, err := m.sessionRepo.GetByToken(ctx, sessionToken)
	if err != nil {
		return nil, nil, errors.New(errors.CodeUnauthorized, "invalid session")
	}

	// Check session validity
	if !session.Active || time.Now().After(session.ExpiresAt) {
		return nil, nil, errors.New(errors.CodeUnauthorized, "session expired")
	}

	// Get user
	user, err := m.buildUserContext(ctx, session.UserID, r, nil)
	if err != nil {
		return nil, nil, err
	}

	// Update session activity (async)
	go func() {
		_ = m.sessionRepo.UpdateLastActive(context.Background(), sessionToken)
	}()

	sessionCtx := &SessionContext{
		ID:           session.ID,
		Token:        session.Token,
		UserID:       session.UserID,
		ExpiresAt:    session.ExpiresAt,
		LastActiveAt: session.LastActiveAt,
		IPAddress:    session.IPAddress,
		UserAgent:    session.UserAgent,
		DeviceID:     session.DeviceID,
	}

	return sessionCtx, user, nil
}

// Context helper methods

func (m *AuthMiddleware) setUserContext(ctx context.Context, user *UserContext, authMethod AuthMethod) context.Context {
	ctx = context.WithValue(ctx, contexts.UserContextKey, user)
	ctx = context.WithValue(ctx, contexts.UserIDContextKey, user.ID)
	ctx = context.WithValue(ctx, contexts.UserTypeContextKey, user.UserType)
	ctx = context.WithValue(ctx, contexts.AuthMethodContextKey, authMethod)

	if user.OrganizationID != nil {
		ctx = context.WithValue(ctx, contexts.OrganizationIDContextKey, *user.OrganizationID)
	}

	if len(user.Permissions) > 0 {
		ctx = context.WithValue(ctx, contexts.PermissionsContextKey, user.Permissions)
	}

	if len(user.Roles) > 0 {
		ctx = context.WithValue(ctx, contexts.RolesContextKey, user.Roles)
	}

	return ctx
}

func (m *AuthMiddleware) setSessionContext(ctx context.Context, session *SessionContext) context.Context {
	ctx = context.WithValue(ctx, contexts.SessionContextKey, session)
	ctx = context.WithValue(ctx, contexts.SessionIDContextKey, session.ID)
	return ctx
}

func (m *AuthMiddleware) setAPIKeyContext(ctx context.Context, apiKey *APIKeyContext) context.Context {
	ctx = context.WithValue(ctx, contexts.APIKeyContextKey, apiKey)
	ctx = context.WithValue(ctx, contexts.APIKeyIDContextKey, apiKey.ID)

	// Set organization context if available from API key
	if apiKey.OrganizationID != nil {
		ctx = context.WithValue(ctx, contexts.OrganizationIDContextKey, *apiKey.OrganizationID)
	}

	// Set permissions and scopes from API key
	if len(apiKey.Permissions) > 0 {
		ctx = context.WithValue(ctx, contexts.PermissionsContextKey, apiKey.Permissions)
	}

	if len(apiKey.Scopes) > 0 {
		ctx = context.WithValue(ctx, contexts.ScopesContextKey, apiKey.Scopes)
	}

	return ctx
}

func (m *AuthMiddleware) addRequestMetadata(ctx context.Context, r *http.Request) context.Context {
	// Extract request ID from chi middleware
	if requestID := chi.URLParam(r, "request_id"); requestID != "" {
		ctx = context.WithValue(ctx, contexts.RequestIDContextKey, requestID)
	}

	// Add IP address
	ctx = context.WithValue(ctx, contexts.IPAddressContextKey, GetClientIP(r))

	// Add User Agent
	ctx = context.WithValue(ctx, contexts.UserAgentContextKey, r.UserAgent())

	ctx = m.setOrgIDContext(ctx, r)

	return ctx
}

func (m *AuthMiddleware) setOrgIDContext(ctx context.Context, r *http.Request) context.Context {
	// Try header first
	keyValue := r.Header.Get("X-Org-ID")
	if keyValue != "" {
		id, err := xid.FromString(keyValue)
		if err != nil {
			return ctx
		}
		ctx = context.WithValue(ctx, contexts.OrganizationIDContextKey, id)
	}

	return ctx
}

func (m *AuthMiddleware) setUserContextHuma(ctx huma.Context, user *UserContext, authMethod AuthMethod) huma.Context {
	ctx = huma.WithValue(ctx, contexts.UserContextKey, user)
	ctx = huma.WithValue(ctx, contexts.UserIDContextKey, user.ID)
	ctx = huma.WithValue(ctx, contexts.UserTypeContextKey, user.UserType)
	ctx = huma.WithValue(ctx, contexts.AuthMethodContextKey, authMethod)

	if user.OrganizationID != nil {
		ctx = huma.WithValue(ctx, contexts.OrganizationIDContextKey, *user.OrganizationID)
	}

	if len(user.Permissions) > 0 {
		ctx = huma.WithValue(ctx, contexts.PermissionsContextKey, user.Permissions)
	}

	if len(user.Roles) > 0 {
		ctx = huma.WithValue(ctx, contexts.RolesContextKey, user.Roles)
	}

	return ctx
}

func (m *AuthMiddleware) setSessionContextHuma(ctx huma.Context, session *SessionContext) huma.Context {
	ctx = huma.WithValue(ctx, contexts.SessionContextKey, session)
	ctx = huma.WithValue(ctx, contexts.SessionIDContextKey, session.ID)
	return ctx
}

func (m *AuthMiddleware) setAPIKeyContextHuma(ctx huma.Context, apiKey *APIKeyContext) huma.Context {
	ctx = huma.WithValue(ctx, contexts.APIKeyContextKey, apiKey)
	ctx = huma.WithValue(ctx, contexts.APIKeyIDContextKey, apiKey.ID)

	// Set organization context if available from API key
	if apiKey.OrganizationID != nil {
		ctx = huma.WithValue(ctx, contexts.OrganizationIDContextKey, *apiKey.OrganizationID)
	}

	// Set permissions and scopes from API key
	if len(apiKey.Permissions) > 0 {
		ctx = huma.WithValue(ctx, contexts.PermissionsContextKey, apiKey.Permissions)
	}

	if len(apiKey.Scopes) > 0 {
		ctx = huma.WithValue(ctx, contexts.ScopesContextKey, apiKey.Scopes)
	}

	return ctx
}

func (m *AuthMiddleware) addRequestMetadataHuma(ctx huma.Context, r *http.Request) huma.Context {
	// Extract request ID from chi middleware
	if requestID := chi.URLParam(r, "request_id"); requestID != "" {
		ctx = huma.WithValue(ctx, contexts.RequestIDContextKey, requestID)
	}

	// Add IP address
	ctx = huma.WithValue(ctx, contexts.IPAddressContextKey, GetClientIP(r))

	// Add User Agent
	ctx = huma.WithValue(ctx, contexts.UserAgentContextKey, r.UserAgent())

	ctx = m.setOrgIDContextHuma(ctx, r)

	return ctx
}

func (m *AuthMiddleware) setOrgIDContextHuma(ctx huma.Context, r *http.Request) huma.Context {
	// Try header first
	keyValue := r.Header.Get("X-Org-ID")
	if keyValue != "" {
		id, err := xid.FromString(keyValue)
		if err != nil {
			return ctx
		}
		ctx = huma.WithValue(ctx, contexts.OrganizationIDContextKey, id)
	}

	return ctx
}

func (m *AuthMiddleware) convertToUserContext(user *ent.User, permissions []string) *UserContext {
	return &UserContext{
		ID:             user.ID,
		Email:          user.Email,
		Username:       user.Username,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		UserType:       user.UserType,
		OrganizationID: &user.OrganizationID,
		Active:         user.Active,
		EmailVerified:  user.EmailVerified,
		Permissions:    permissions,
		Metadata:       user.Metadata,
	}
}

// Response helpers

func (m *AuthMiddleware) respondUnauthorized(w http.ResponseWriter, r *http.Request, message string) {
	errResp := errors.NewErrorResponse(errors.New(errors.CodeUnauthorized, message))
	m.respondError(w, r, errResp)
}

func (m *AuthMiddleware) respondForbidden(w http.ResponseWriter, r *http.Request, message string) {
	errResp := errors.NewErrorResponse(errors.New(errors.CodeForbidden, message))
	m.respondError(w, r, errResp)
}

func (m *AuthMiddleware) respondError(w http.ResponseWriter, r *http.Request, errResp *errors.ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errResp.StatusCode())
	// Simple JSON error response
	jsonResp := `{"code":"` + errResp.Code + `","message":"` + errResp.Message + `"}`
	_, _ = w.Write([]byte(jsonResp))
}

func (m *AuthMiddleware) respondUnauthorizedHuma(ctx huma.Context, message string) {
	errResp := errors.NewErrorResponse(errors.New(errors.CodeUnauthorized, message))
	m.respondErrorHuma(ctx, errResp)
}

func (m *AuthMiddleware) respondForbiddenHuma(ctx huma.Context, message string) {
	errResp := errors.NewErrorResponse(errors.New(errors.CodeForbidden, message))
	m.respondErrorHuma(ctx, errResp)
}

func (m *AuthMiddleware) respondErrorHuma(ctx huma.Context, errResp *errors.ErrorResponse) {
	huma.WriteErr(m.api, ctx, errResp.StatusCode(), errResp.Message)
}

// Context getter functions

// GetUserFromContextSafe retrieves the user from request context
func GetUserFromContextSafe(ctx context.Context) (*UserContext, error) {
	if user, ok := ctx.Value(contexts.UserContextKey).(*UserContext); ok {
		return user, nil
	}
	return nil, errors.New(errors.CodeUnauthorized, "user not authorized")
}

// GetUserFromContext retrieves the user from request context
func GetUserFromContext(ctx context.Context) *UserContext {
	if user, ok := ctx.Value(contexts.UserContextKey).(*UserContext); ok {
		return user
	}
	return nil
}

// GetUserIDFromContext retrieves the user ID from request context
func GetUserIDFromContext(ctx context.Context) *xid.ID {
	if userID, ok := ctx.Value(contexts.UserIDContextKey).(xid.ID); ok {
		return &userID
	}
	return nil
}

// GetUserTypeFromContext retrieves the user type from request context
func GetUserTypeFromContext(ctx context.Context) *model.UserType {
	if userType, ok := ctx.Value(contexts.UserTypeContextKey).(model.UserType); ok {
		return &userType
	}
	return nil
}

// GetOrganizationIDFromContext retrieves the organization ID from request context
func GetOrganizationIDFromContext(ctx context.Context) *xid.ID {
	if orgID, ok := ctx.Value(contexts.OrganizationIDContextKey).(xid.ID); ok {
		return &orgID
	}
	return nil
}

// GetSessionFromContext retrieves the session from request context
func GetSessionFromContext(ctx context.Context) *SessionContext {
	if session, ok := ctx.Value(contexts.SessionContextKey).(*SessionContext); ok {
		return session
	}
	return nil
}

// GetAPIKeyFromContext retrieves the API key from request context
func GetAPIKeyFromContext(ctx context.Context) *APIKeyContext {
	if apiKey, ok := ctx.Value(contexts.APIKeyContextKey).(*APIKeyContext); ok {
		return apiKey
	}
	return nil
}

// GetAuthMethodFromContext retrieves the authentication method from request context
func GetAuthMethodFromContext(ctx context.Context) AuthMethod {
	if method, ok := ctx.Value(contexts.AuthMethodContextKey).(AuthMethod); ok {
		return method
	}
	return contexts.AuthMethodNone
}

// GetPermissionsFromContext retrieves permissions from request context
func GetPermissionsFromContext(ctx context.Context) []string {
	if permissions, ok := ctx.Value(contexts.PermissionsContextKey).([]string); ok {
		return permissions
	}
	return nil
}

// GetRolesFromContext retrieves roles from request context
func GetRolesFromContext(ctx context.Context) []model.RoleInfo {
	if roles, ok := ctx.Value(contexts.RolesContextKey).([]model.RoleInfo); ok {
		return roles
	}
	return nil
}

// GetClientIP extracts the client IP address from the request
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Use remote address
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

// GetClientUserAgent extracts the client User-Agent from the request
func GetClientUserAgent(r *http.Request) string {
	return r.UserAgent()
}

// IsAuthenticated checks if the request is authenticated
func IsAuthenticated(ctx context.Context) bool {
	return GetUserFromContext(ctx) != nil
}

// HasPermission checks if the user has a specific permission
func HasPermission(ctx context.Context, permission string) bool {
	permissions := GetPermissionsFromContext(ctx)
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the user has any of the specified permissions
func HasAnyPermission(ctx context.Context, permissions ...string) bool {
	userPermissions := GetPermissionsFromContext(ctx)
	for _, required := range permissions {
		for _, userPerm := range userPermissions {
			if userPerm == required {
				return true
			}
		}
	}
	return false
}

// HasRole checks if the user has a specific role
func HasRole(ctx context.Context, roleName string) bool {
	roles := GetRolesFromContext(ctx)
	for _, role := range roles {
		if role.Name == roleName {
			return true
		}
	}
	return false
}

// IsUserType checks if the user is of a specific type
func IsUserType(ctx context.Context, userType model.UserType) bool {
	currentType := GetUserTypeFromContext(ctx)
	return currentType != nil && *currentType == userType
}

// IsInternalUser checks if the user is an internal user
func IsInternalUser(ctx context.Context) bool {
	return IsUserType(ctx, model.UserTypeInternal)
}

// IsExternalUser checks if the user is an external user
func IsExternalUser(ctx context.Context) bool {
	return IsUserType(ctx, model.UserTypeExternal)
}

// IsEndUser checks if the user is an end user
func IsEndUser(ctx context.Context) bool {
	return IsUserType(ctx, model.UserTypeEndUser)
}

// HasAPIKeyAccess Helper function to check if request has API key access (regardless of user authentication)
func HasAPIKeyAccess(ctx context.Context) bool {
	return GetAPIKeyFromContext(ctx) != nil
}

// IsClientAPIKey Helper function to check if request is using client-type API key
func IsClientAPIKey(ctx context.Context) bool {
	apiKey := GetAPIKeyFromContext(ctx)
	return apiKey != nil && apiKey.Type == model.APIKeyTypeClient
}

// IsUnauthenticatedUser (useful for auth endpoints that need to distinguish between no auth and client API key)
func IsUnauthenticatedUser(ctx context.Context) bool {
	user := GetUserFromContext(ctx)
	apiKey := GetAPIKeyFromContext(ctx)
	// User is unauthenticated if no user context but may have client API key access
	return user == nil && (apiKey == nil || apiKey.Type == model.APIKeyTypeClient)
}

// HasAnyAccess checks if the request has any form of access (user authentication or API key)
func HasAnyAccess(ctx context.Context) bool {
	return IsAuthenticated(ctx) || HasAPIKeyAccess(ctx)
}

// GetAuthenticationLevel returns the level of authentication for the request
type AuthenticationLevel int

const (
	AuthLevelNone AuthenticationLevel = iota
	AuthLevelAPIKeyOnly
	AuthLevelUserAuthenticated
)

func GetAuthenticationLevel(ctx context.Context) AuthenticationLevel {
	if IsAuthenticated(ctx) {
		return AuthLevelUserAuthenticated
	}
	if HasAPIKeyAccess(ctx) {
		return AuthLevelAPIKeyOnly
	}
	return AuthLevelNone
}

// GetEffectivePermissions returns permissions from either user context or API key context
func GetEffectivePermissions(ctx context.Context) []string {
	// Try user permissions first
	if userPermissions := GetPermissionsFromContext(ctx); len(userPermissions) > 0 {
		return userPermissions
	}

	// Fall back to API key permissions
	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil {
		return apiKey.Permissions
	}

	return nil
}

// GetEffectiveOrganizationID returns organization ID from user, API key, or context
func GetEffectiveOrganizationID(ctx context.Context) *xid.ID {
	// Try user organization first
	if orgID := GetOrganizationIDFromContext(ctx); orgID != nil {
		return orgID
	}

	// Try API key organization
	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil && apiKey.OrganizationID != nil {
		return apiKey.OrganizationID
	}

	return nil
}

// CanAccessEndpoint checks if the request can access a specific endpoint based on permissions
func CanAccessEndpoint(ctx context.Context, requiredPermission string) bool {
	permissions := GetEffectivePermissions(ctx)
	for _, perm := range permissions {
		if perm == requiredPermission {
			return true
		}
	}
	return false
}

// IsPublicAPIAccess checks if this is a public API access (client key or no auth)
// Useful for determining if certain sensitive operations should be allowed
func IsPublicAPIAccess(ctx context.Context) bool {
	// No authentication at all
	if !HasAnyAccess(ctx) {
		return true
	}

	// Client API key access (considered public)
	if IsClientAPIKey(ctx) {
		return true
	}

	return false
}

// IsPrivateAPIAccess checks if this is private API access (server/admin key or user auth)
func IsPrivateAPIAccess(ctx context.Context) bool {
	return !IsPublicAPIAccess(ctx)
}

// GetAPIKeyType returns the type of API key being used, if any
func GetAPIKeyType(ctx context.Context) *model.APIKeyType {
	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil {
		return &apiKey.Type
	}
	return nil
}

// RequiresUserAuthentication checks if an operation requires actual user authentication
// (not just API key access)
func RequiresUserAuthentication(ctx context.Context) bool {
	return GetAuthenticationLevel(ctx) == AuthLevelUserAuthenticated
}

// AccessSummary GetAccessSummary returns a summary of the current access level for debugging/logging
type AccessSummary struct {
	HasUserAccess   bool              `json:"hasUserAccess"`
	HasAPIKeyAccess bool              `json:"hasApiKeyAccess"`
	APIKeyType      *model.APIKeyType `json:"apiKeyType,omitempty"`
	AuthMethod      AuthMethod        `json:"authMethod"`
	OrganizationID  *xid.ID           `json:"organizationId,omitempty"`
	Permissions     []string          `json:"permissions,omitempty"`
}

func GetAccessSummary(ctx context.Context) AccessSummary {
	return AccessSummary{
		HasUserAccess:   IsAuthenticated(ctx),
		HasAPIKeyAccess: HasAPIKeyAccess(ctx),
		APIKeyType:      GetAPIKeyType(ctx),
		AuthMethod:      GetAuthMethodFromContext(ctx),
		OrganizationID:  GetEffectiveOrganizationID(ctx),
		Permissions:     GetEffectivePermissions(ctx),
	}
}
