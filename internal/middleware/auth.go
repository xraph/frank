package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/apikeys"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
	"github.com/rs/xid"
)

// contextKey is a private type for context keys
type contextKey string

const (
	// UserIDKey is the key for user ID in the request context
	UserIDKey contextKey = "user_id"

	// OrganizationIDKey is the key for organization ID in the request context
	OrganizationIDKey contextKey = "organization_id"

	// RolesKey is the key for user roles in the request context
	RolesKey contextKey = "roles"

	// PermissionsKey is the key for user permissions in the request context
	PermissionsKey contextKey = "permissions"

	// ScopesKey is the key for token scopes in the request context
	ScopesKey contextKey = "scopes"

	// AuthenticatedKey is the key for the authenticated flag in the request context
	AuthenticatedKey contextKey = "authenticated"

	// SessionKey is the key for session information in the request context
	SessionKey contextKey = "session"

	// SubdomainKey is the key for subdomain information in the request context
	SubdomainKey contextKey = "subdomain"

	// HeadersKey is the key for headers included in the request context.
	HeadersKey contextKey = "headers-included"

	// RequestInfoKey is the key for storing request-specific information in the context.
	RequestInfoKey contextKey = "req-info-frank"
)

// AuthOptions configures how the Auth middleware behaves
type AuthOptions struct {
	// Required determines if authentication is required
	Required bool

	// AllowAPIKey allows API key authentication
	AllowAPIKey bool

	// AllowSession allows session-based authentication
	AllowSession bool

	// AllowBearerToken allows bearer token authentication
	AllowBearerToken bool

	// AllowedScopes limits access to requests with specific scopes
	AllowedScopes []string

	// RequiredRoles specifies roles the user must have to access
	RequiredRoles []string

	// RequiredPermissions specifies permissions the user must have to access
	RequiredPermissions []string

	// SessionManager is used for session-based authentication
	SessionManager *session.Manager

	// SessionManagerStore is used for session-based authentication
	SessionStore sessions.Store

	// APIKeyService is used for API key authentication
	APIKeyService apikeys.Service

	CookieHandler *session.CookieHandler
}

// DefaultAuthOptions returns the default auth options
func DefaultAuthOptions() AuthOptions {
	return AuthOptions{
		Required:         true,
		AllowAPIKey:      true,
		AllowSession:     true,
		AllowBearerToken: true,
	}
}

// Auth middleware extracts and validates authentication information
func Auth(
	cfg *config.Config,
	logger logging.Logger,
	sessionManager *session.Manager,
	sessionStore sessions.Store,
	apiKeyService apikeys.Service,
	required bool,
) func(http.Handler) http.Handler {
	options := DefaultAuthOptions()
	options.Required = required
	options.AllowAPIKey = cfg.Auth.AllowAPIKey
	options.AllowSession = cfg.Auth.AllowSession
	options.AllowBearerToken = cfg.Auth.AllowBearerToken

	options.SessionManager = sessionManager
	options.SessionStore = sessionStore
	options.APIKeyService = apiKeyService

	return AuthWithOptions(cfg, logger, &options)
}

// AuthWithOptions returns an Auth middleware with custom options
func AuthWithOptions(cfg *config.Config, logger logging.Logger, options *AuthOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authenticated, ctx, err := PrefillAuthWithOptions(r, r.Context(), cfg, logger, options)

			// Check if authentication is required but not provided
			if options.Required && !authenticated {
				utils.RespondError(w, err)
				return
			}

			// Pass to the next handler with updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// PrefillAuthWithOptions returns an Auth middleware with custom options
func PrefillAuthWithOptions(
	r *http.Request,
	ctx context.Context,
	cfg *config.Config,
	logger logging.Logger,
	options *AuthOptions,
) (bool, context.Context, error) {
	authenticated := false

	// Try to authenticate using bearer tokens
	if options.AllowBearerToken {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			userID, orgID, err := validateBearerToken(ctx, token, cfg)
			if err == nil {
				// Valid JWT token
				ctx = context.WithValue(ctx, UserIDKey, userID)
				if orgID != "" {
					ctx = context.WithValue(ctx, OrganizationIDKey, orgID)
				}
				authenticated = true
				logger.Debug("Authenticated via Bearer token")
			} else {
				// If not a valid JWT, check if it's a session token
				if options.SessionManager != nil {
					sess, err := options.SessionManager.GetSession(ctx, token)
					if err == nil {
						ctx = context.WithValue(ctx, UserIDKey, sess.UserID)
						if sess.OrganizationID != "" {
							ctx = context.WithValue(ctx, OrganizationIDKey, sess.OrganizationID)
						}
						authenticated = true
						logger.Debug("Authenticated via session token in Authorization header")
					}
				}
			}
		}
	}

	// Try API key authentication
	if !authenticated && options.AllowAPIKey && options.APIKeyService != nil {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Check in query params as a fallback
			apiKey = r.URL.Query().Get("api_key")
		}

		if apiKey != "" {
			if apiKeyInfo, err := options.APIKeyService.Validate(ctx, apiKey); err == nil {
				// API key is valid
				if !apiKeyInfo.UserID.IsNil() {
					ctx = context.WithValue(ctx, UserIDKey, apiKeyInfo.UserID)
				}
				if !apiKeyInfo.OrganizationID.IsNil() {
					ctx = context.WithValue(ctx, OrganizationIDKey, apiKeyInfo.OrganizationID)
				}
				authenticated = true
				logger.Debug("Authenticated via API key")

				// Update last used timestamp in a goroutine
				go func(id xid.ID) {
					bgCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
					defer cancel()
					if err := options.APIKeyService.UpdateLastUsed(bgCtx, id.String()); err != nil {
						logger.Error("Failed to update API key last used timestamp",
							logging.String("key_id", id.String()),
							logging.Error(err))
					}
				}(apiKeyInfo.ID)
			}
		}
	}

	// Try session authentication
	if !authenticated && options.AllowSession {
		// Get session via the helper
		sess, err := session.GetSessionHelper(r, cfg, options.CookieHandler, options.SessionStore, logger)
		if err == nil {
			// Check if user is authenticated in session
			if userID, ok := sess.Values["user_id"].(string); ok && userID != "" {
				ctx = context.WithValue(ctx, UserIDKey, userID)

				// Also check for organization in session
				if orgID, ok := sess.Values["organization_id"].(string); ok && orgID != "" {
					ctx = context.WithValue(ctx, OrganizationIDKey, orgID)
				}
				authenticated = true
				logger.Debug("Authenticated via session cookie")
			}
		}
	}

	// Add authentication status to context
	ctx = context.WithValue(ctx, AuthenticatedKey, authenticated)

	// Check if authentication is required but not provided
	if options.Required && !authenticated {
		return authenticated, ctx, errors.New(errors.CodeUnauthorized, "authentication required")
	}

	return authenticated, ctx, nil
}

// AuthHuma middleware extracts and validates authentication information
func AuthHuma(cfg *config.Config, logger logging.Logger, sessionManager *session.Manager, apiKeyService apikeys.Service) func(huma.Context, func(huma.Context)) {
	options := DefaultAuthOptions()
	options.SessionManager = sessionManager
	options.APIKeyService = apiKeyService

	return AuthWithOptionsHuma(cfg, logger, options)
}

// AuthWithOptionsHuma returns an Auth middleware with custom options
func AuthWithOptionsHuma(cfg *config.Config, logger logging.Logger, options AuthOptions) func(huma.Context, func(huma.Context)) {
	return func(hctx huma.Context, next func(huma.Context)) {

		// Unwrap the request and response objects.
		r, w := humachi.Unwrap(hctx)
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			authenticated := false

			// Get the route pattern from Chi's context
			routePattern := chi.RouteContext(r.Context()).RoutePattern()

			// Skip authentication for public routes (modify this based on your requirements)
			for _, path := range cfg.Security.PublicPaths {
				if routePattern == path {
					next(hctx)
					return
				}
			}

			// Try to authenticate using various methods
			if options.AllowBearerToken {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					token := strings.TrimPrefix(authHeader, "Bearer ")
					if userID, orgID, err := validateBearerToken(ctx, token, cfg); err == nil {
						// Token is valid, add info to context
						ctx = context.WithValue(ctx, UserIDKey, userID)
						if orgID != "" {
							ctx = context.WithValue(ctx, OrganizationIDKey, orgID)
						}
						authenticated = true
					}
				}
			}

			// Try API key authentication
			if !authenticated && options.AllowAPIKey && options.APIKeyService != nil {
				apiKey := r.Header.Get("X-API-Key")
				if apiKey == "" {
					// Check in query params as a fallback
					apiKey = r.URL.Query().Get("api_key")
				}

				if apiKey != "" {
					if apiKeyInfo, err := options.APIKeyService.Validate(ctx, apiKey); err == nil {
						// API key is valid, add info to context
						if !apiKeyInfo.UserID.IsNil() {
							ctx = context.WithValue(ctx, UserIDKey, apiKeyInfo.UserID)
						}
						if !apiKeyInfo.OrganizationID.IsNil() {
							ctx = context.WithValue(ctx, OrganizationIDKey, apiKeyInfo.OrganizationID)
						}
						authenticated = true

						// Update last used timestamp in a goroutine
						go func(id xid.ID) {
							bgCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
							defer cancel()
							if err := options.APIKeyService.UpdateLastUsed(bgCtx, id.String()); err != nil {
								logger.Error("Failed to update API key last used timestamp",
									logging.String("key_id", id.String()),
									logging.Error(err))
							}
						}(apiKeyInfo.ID)
					}
				}
			}

			// Try session authentication
			if !authenticated && options.AllowSession && options.SessionManager != nil {
				// Try to get token from session cookie
				sess, err := session.GetSessionHelper(r, cfg, options.CookieHandler, options.SessionStore, logger)
				if err == nil {
					// Check if user is authenticated in session
					if userID, ok := sess.Values["user_id"].(string); ok && userID != "" {
						ctx = context.WithValue(ctx, UserIDKey, userID)

						// Also check for organization in session
						if orgID, ok := sess.Values["organization_id"].(string); ok && orgID != "" {
							ctx = context.WithValue(ctx, OrganizationIDKey, orgID)
						}
						authenticated = true
					}
				}
			}

			// Check if authentication is required but not provided
			if options.Required && !authenticated {
				utils.RespondError(w, errors.New(errors.CodeUnauthorized, "authentication required"))
				return
			}

			// Add authentication status to context
			ctx = context.WithValue(ctx, AuthenticatedKey, authenticated)

			// Pass to the next handler with updated context
			next(hctx)
		}).ServeHTTP(w, r)
	}
}

// validateBearerToken validates a JWT token and extracts the user ID
func validateBearerToken(ctx context.Context, token string, cfg *config.Config) (string, string, error) {
	// Initialize JWT config
	jwtConfig := &crypto.JWTConfig{
		SigningMethod: cfg.Auth.TokenSigningMethod,
		SignatureKey:  []byte(cfg.Auth.TokenSecretKey),
		ValidationKey: []byte(cfg.Auth.TokenSecretKey),
		Issuer:        cfg.Auth.TokenIssuer,
		Audience:      cfg.Auth.TokenAudience,
	}

	// Validate token and get claims
	claims, err := jwtConfig.ValidateToken(token)
	if err != nil {
		return "", "", err
	}

	// Extract user ID from subject claim
	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		return "", "", errors.New(errors.CodeInvalidToken, "invalid token: missing subject claim")
	}

	// Extract organization ID if present
	var orgID string
	if org, ok := claims["organization_id"].(string); ok && org != "" {
		orgID = org
	}

	return userID, orgID, nil
}

// RequireAuthentication returns a middleware that requires authentication
func RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authenticated, _ := ctx.Value(AuthenticatedKey).(bool)

		if !authenticated {
			utils.RespondError(w, errors.New(errors.CodeUnauthorized, "authentication required"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireAuthenticationHuma returns a middleware that requires authentication
func RequireAuthenticationHuma(ctx huma.Context, next func(huma.Context)) {
	// Unwrap the request and response objects.
	r, w := humachi.Unwrap(ctx)

	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated, _ := ctx.Context().Value(AuthenticatedKey).(bool)

		if !authenticated {
			utils.RespondError(w, errors.New(errors.CodeUnauthorized, "authentication required"))
			return
		}

		next(ctx)
	}).ServeHTTP(w, r)
}

// RequireRole returns a middleware that requires a specific role
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Check if user is authenticated
			authenticated, _ := ctx.Value(AuthenticatedKey).(bool)
			if !authenticated {
				utils.RespondError(w, errors.New(errors.CodeUnauthorized, "authentication required"))
				return
			}

			// Get roles from context
			rolesData := ctx.Value(RolesKey)
			if rolesData == nil {
				utils.RespondError(w, errors.New(errors.CodeForbidden, "access denied: missing role information"))
				return
			}

			roles, ok := rolesData.([]string)
			if !ok {
				utils.RespondError(w, errors.New(errors.CodeForbidden, "access denied: invalid role information"))
				return
			}

			// Check if user has the required role
			hasRole := false
			for _, r := range roles {
				if r == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				utils.RespondError(w, errors.New(errors.CodeForbidden, "access denied: missing required role"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission returns a middleware that requires a specific permission
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Check if user is authenticated
			authenticated, _ := ctx.Value(AuthenticatedKey).(bool)
			if !authenticated {
				utils.RespondError(w, errors.New(errors.CodeUnauthorized, "authentication required"))
				return
			}

			// Get permissions from context
			permsData := ctx.Value(PermissionsKey)
			if permsData == nil {
				utils.RespondError(w, errors.New(errors.CodeForbidden, "access denied: missing permission information"))
				return
			}

			permissions, ok := permsData.([]string)
			if !ok {
				utils.RespondError(w, errors.New(errors.CodeForbidden, "access denied: invalid permission information"))
				return
			}

			// Check if user has the required permission
			hasPermission := false
			for _, p := range permissions {
				if p == permission {
					hasPermission = true
					break
				}
			}

			if !hasPermission {
				utils.RespondError(w, errors.New(errors.CodeForbidden, "access denied: missing required permission"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserIDReq gets the user ID from the request context
func GetUserIDReq(r *http.Request) (xid.ID, bool) {
	userID, ok := r.Context().Value(UserIDKey).(xid.ID)
	return userID, ok
}

// NewLoggedInUserIDCtx .
func NewLoggedInUserIDCtx(ctx context.Context, userID xid.ID) context.Context {
	ctx = context.WithValue(ctx, UserIDKey, userID)
	return ctx
}

// GetUserID gets the user ID from the request context
func GetUserID(ctx context.Context) (xid.ID, bool) {
	userID, ok := ctx.Value(UserIDKey).(xid.ID)
	return userID, ok
}

// GetUserIDFromContext gets the user ID from the request context
func GetUserIDFromContext(ctx context.Context) (xid.ID, error) {
	userID, ok := ctx.Value(UserIDKey).(xid.ID)
	if !ok {
		return xid.NilID(), errors.New(errors.CodeForbidden, "user not logged in")
	}
	return userID, nil
}

// GetOrganizationIDReq gets the organization ID from the request context
func GetOrganizationIDReq(r *http.Request) (string, bool) {
	return GetOrganizationID(r.Context())
}

// GetOrganizationID gets the organization ID from the request context
func GetOrganizationID(ctx context.Context) (string, bool) {
	orgID, ok := ctx.Value(OrganizationIDKey).(string)
	return orgID, ok
}
