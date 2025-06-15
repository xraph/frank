package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/contexts"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// AuthMethod represents the authentication method used
type AuthMethod string

const (
	AuthMethodJWT     AuthMethod = "jwt"
	AuthMethodAPIKey  AuthMethod = "api_key"
	AuthMethodSession AuthMethod = "session"
	AuthMethodNone    AuthMethod = "none"
)

// UserContext represents the authenticated user context
type UserContext struct {
	ID             xid.ID           `json:"id"`
	Email          string           `json:"email"`
	Username       string           `json:"username,omitempty"`
	FirstName      string           `json:"firstName,omitempty"`
	LastName       string           `json:"lastName,omitempty"`
	UserType       model.UserType   `json:"userType"`
	OrganizationID *xid.ID          `json:"organizationId,omitempty"`
	Active         bool             `json:"active"`
	EmailVerified  bool             `json:"emailVerified"`
	Permissions    []string         `json:"permissions,omitempty"`
	Roles          []model.RoleInfo `json:"roles,omitempty"`
	Metadata       map[string]any   `json:"metadata,omitempty"`
	SessionID      xid.ID           `json:"sessionId,omitempty"`
}

// SessionContext represents the session context
type SessionContext struct {
	ID           xid.ID    `json:"id"`
	Token        string    `json:"token"`
	UserID       xid.ID    `json:"userId"`
	ExpiresAt    time.Time `json:"expiresAt"`
	LastActiveAt time.Time `json:"lastActiveAt"`
	IPAddress    string    `json:"ipAddress,omitempty"`
	UserAgent    string    `json:"userAgent,omitempty"`
	DeviceID     string    `json:"deviceId,omitempty"`
}

// APIKeyContext represents the API key context
type APIKeyContext struct {
	ID             xid.ID                  `json:"id"`
	Name           string                  `json:"name"`
	Type           string                  `json:"type"`
	UserID         *xid.ID                 `json:"userId,omitempty"`
	OrganizationID *xid.ID                 `json:"organizationId,omitempty"`
	Permissions    []string                `json:"permissions,omitempty"`
	Scopes         []string                `json:"scopes,omitempty"`
	LastUsed       *time.Time              `json:"lastUsed,omitempty"`
	RateLimits     *model.APIKeyRateLimits `json:"rateLimits,omitempty"`
}

// JWTClaims represents JWT token claims
type JWTClaims struct {
	UserID         xid.ID   `json:"user_id"`
	OrganizationID *xid.ID  `json:"organization_id"`
	SessionID      *xid.ID  `json:"session_id"`
	UserType       string   `json:"user_type"`
	Permissions    []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// AuthMiddleware provides authentication middleware functions
type AuthMiddleware struct {
	config           *config.Config
	userRepo         repository.UserRepository
	sessionRepo      repository.SessionRepository
	apiKeyRepo       repository.ApiKeyRepository
	organizationRepo repository.OrganizationRepository
	crypto           crypto.Util
	api              huma.API
	logger           logging.Logger
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(di di.Container, api huma.API) *AuthMiddleware {
	return &AuthMiddleware{
		api:              api,
		config:           di.Config(),
		userRepo:         di.Repo().User(),
		sessionRepo:      di.Repo().Session(),
		apiKeyRepo:       di.Repo().APIKey(),
		organizationRepo: di.Repo().Organization(),
		crypto:           di.Crypto(),
		logger:           di.Logger().Named("auth-middleware"),
	}
}

// RequireAuth middleware that requires authentication via JWT, API key, or session
func (m *AuthMiddleware) RequireAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Try different authentication methods in order of preference
			authenticated := false

			// 1. Try JWT authentication
			if m.config.Auth.AllowBearerToken {
				if session, user, err := m.authenticateJWT(ctx, r); err == nil && user != nil {
					ctx = m.setUserContext(ctx, user, AuthMethodJWT)
					ctx = m.setSessionContext(ctx, session)
					authenticated = true
				}
			}

			// 2. Try API Key authentication
			if !authenticated && m.config.Auth.AllowAPIKey {
				if apiKey, user, err := m.authenticateAPIKey(ctx, r); err == nil && apiKey != nil && user != nil {
					ctx = m.setUserContext(ctx, user, AuthMethodAPIKey)
					ctx = m.setAPIKeyContext(ctx, apiKey)
					authenticated = true
				}
			}

			// 3. Try Session authentication
			if !authenticated && m.config.Auth.AllowSession {
				if session, user, err := m.authenticateSession(ctx, r); err == nil && session != nil && user != nil {
					ctx = m.setUserContext(ctx, user, AuthMethodSession)
					ctx = m.setSessionContext(ctx, session)
					authenticated = true
				}
			}

			if !authenticated {
				m.respondUnauthorized(w, r, "authentication required")
				return
			}

			// Add request metadata
			ctx = m.addRequestMetadata(ctx, r)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuthHuma middleware that requires authentication via JWT, API key, or session
func (m *AuthMiddleware) RequireAuthHuma() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		info, _ := GetRequestInfoFromContext(ctx.Context())
		r := info.Req
		rctx := ctx.Context()

		// Try different authentication methods in order of preference
		authenticated := false

		// 1. Try JWT authentication
		if m.config.Auth.AllowBearerToken {
			if session, user, err := m.authenticateJWT(rctx, r); err == nil && user != nil {
				ctx = m.setUserContextHuma(ctx, user, AuthMethodJWT)
				ctx = m.setSessionContextHuma(ctx, session)
				authenticated = true
			}
		}

		// 2. Try API Key authentication
		if !authenticated && m.config.Auth.AllowAPIKey {
			if apiKey, user, err := m.authenticateAPIKey(rctx, r); err == nil && apiKey != nil && user != nil {
				ctx = m.setUserContextHuma(ctx, user, AuthMethodAPIKey)
				ctx = m.setAPIKeyContextHuma(ctx, apiKey)
				authenticated = true
			}
		}

		// 3. Try Session authentication
		if !authenticated && m.config.Auth.AllowSession {
			if session, user, err := m.authenticateSession(rctx, r); err == nil && session != nil && user != nil {
				ctx = m.setUserContextHuma(ctx, user, AuthMethodSession)
				ctx = m.setSessionContextHuma(ctx, session)
				authenticated = true
			}
		}

		if !authenticated {
			m.respondUnauthorizedHuma(ctx, "authentication required")
			return
		}

		// Add request metadata
		ctx = m.addRequestMetadataHuma(ctx, r)

		next(ctx)
	}
}

// OptionalAuth middleware that allows both authenticated and unauthenticated requests
func (m *AuthMiddleware) OptionalAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Try authentication but don't fail if none found
			if m.config.Auth.AllowBearerToken {
				if session, user, err := m.authenticateJWT(ctx, r); err == nil && user != nil {
					ctx = m.setUserContext(ctx, user, AuthMethodJWT)
					ctx = m.setSessionContext(ctx, session)
				}
			}

			if GetUserFromContext(ctx) == nil && m.config.Auth.AllowAPIKey {
				if apiKey, user, err := m.authenticateAPIKey(ctx, r); err == nil && apiKey != nil && user != nil {
					ctx = m.setUserContext(ctx, user, AuthMethodAPIKey)
					ctx = m.setAPIKeyContext(ctx, apiKey)
				}
			}

			if GetUserFromContext(ctx) == nil && m.config.Auth.AllowSession {
				if session, user, err := m.authenticateSession(ctx, r); err == nil && session != nil && user != nil {
					ctx = m.setUserContext(ctx, user, AuthMethodSession)
					ctx = m.setSessionContext(ctx, session)
				}
			}

			// Add request metadata regardless of authentication
			ctx = m.addRequestMetadata(ctx, r)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuthHuma middleware that allows both authenticated and unauthenticated requests
func (m *AuthMiddleware) OptionalAuthHuma() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		info, _ := GetRequestInfoFromContext(ctx.Context())
		r := info.Req

		// Try authentication but don't fail if none found
		if m.config.Auth.AllowBearerToken {
			if session, user, err := m.authenticateJWT(ctx.Context(), r); err == nil && user != nil {
				ctx = m.setUserContextHuma(ctx, user, AuthMethodJWT)
				ctx = m.setSessionContextHuma(ctx, session)
			}
		}

		if GetUserFromContext(ctx.Context()) == nil && m.config.Auth.AllowAPIKey {
			if apiKey, user, err := m.authenticateAPIKey(ctx.Context(), r); err == nil && apiKey != nil && user != nil {
				ctx = m.setUserContextHuma(ctx, user, AuthMethodAPIKey)
				ctx = m.setAPIKeyContextHuma(ctx, apiKey)
			}
		}

		if GetUserFromContext(ctx.Context()) == nil && m.config.Auth.AllowSession {
			if session, user, err := m.authenticateSession(ctx.Context(), r); err == nil && session != nil && user != nil {
				ctx = m.setUserContextHuma(ctx, user, AuthMethodSession)
				ctx = m.setSessionContextHuma(ctx, session)
			}
		}

		// Add request metadata regardless of authentication
		ctx = m.addRequestMetadataHuma(ctx, r)

		next(ctx)
	}
}

// RequireUserType middleware that requires a specific user type
func (m *AuthMiddleware) RequireUserType(userTypes ...model.UserType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				m.respondUnauthorized(w, r, "authentication required")
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
			m.respondUnauthorizedHuma(ctx, "authentication required")
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
		r := ctx.Context().Value(contexts.HTTPRequestContextKey).(*http.Request)
		// w := ctx.Context().Value("http_writer").(http.ResponseWriter)

		// Try authentication
		authenticated := false
		reqCtx := r.Context()

		if m.config.Auth.AllowBearerToken {
			if session, currentUser, err := m.authenticateJWT(reqCtx, r); err == nil && currentUser != nil {
				ctx = m.setUserContextHuma(ctx, currentUser, AuthMethodJWT)
				ctx = m.setSessionContextHuma(ctx, session)
				authenticated = true
			}
		}

		if !authenticated && m.config.Auth.AllowAPIKey {
			if apiKey, currentUser, err := m.authenticateAPIKey(reqCtx, r); err == nil && apiKey != nil && currentUser != nil {
				ctx = m.setUserContextHuma(ctx, currentUser, AuthMethodAPIKey)
				ctx = m.setAPIKeyContextHuma(ctx, apiKey)
				authenticated = true
			}
		}

		if !authenticated && m.config.Auth.AllowSession {
			if session, currentUser, err := m.authenticateSession(reqCtx, r); err == nil && session != nil && currentUser != nil {
				ctx = m.setUserContextHuma(ctx, currentUser, AuthMethodSession)
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
	user, err := m.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, nil, errors.New(errors.CodeUnauthorized, "user not found")
	}

	if !user.Active || user.Blocked {
		return nil, nil, errors.New(errors.CodeUnauthorized, "user account is disabled")
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
	userCtx := m.convertToUserContext(user, nil)
	userCtx.SessionID = session.ID

	return sessionCtx, userCtx, nil
}

func (m *AuthMiddleware) authenticateAPIKey(ctx context.Context, r *http.Request) (*APIKeyContext, *UserContext, error) {
	// Try header first
	keyValue := r.Header.Get("X-API-Key")
	if keyValue == "" {
		// Try query parameter
		keyValue = r.URL.Query().Get("api_key")
	}

	if keyValue == "" {
		return nil, nil, errors.New(errors.CodeUnauthorized, "no api key provided")
	}

	// Hash the key for lookup
	hashedKey := m.crypto.Hasher().HashAPIKey(keyValue)

	// Get API key from database
	apiKey, err := m.apiKeyRepo.GetActiveByHashedKey(ctx, hashedKey)
	if err != nil {
		return nil, nil, errors.New(errors.CodeUnauthorized, "invalid api key")
	}

	// Check expiration
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return nil, nil, errors.New(errors.CodeUnauthorized, "api key expired")
	}

	// Update last used (async)
	go func() {
		_ = m.apiKeyRepo.UpdateLastUsed(context.Background(), apiKey.ID)
	}()

	// Get associated user if user-scoped key
	var currentUser *ent.User
	if !apiKey.UserID.IsNil() {
		currentUser, err = m.userRepo.GetByID(ctx, apiKey.UserID)
		if err != nil {
			return nil, nil, errors.New(errors.CodeUnauthorized, "associated user not found")
		}

		if !currentUser.Active || currentUser.Blocked {
			return nil, nil, errors.New(errors.CodeUnauthorized, "associated user account is disabled")
		}
	}

	apiKeyCtx := &APIKeyContext{
		ID:             apiKey.ID,
		Name:           apiKey.Name,
		Type:           apiKey.Type,
		UserID:         &apiKey.UserID,
		OrganizationID: &apiKey.OrganizationID,
		Permissions:    apiKey.Permissions,
		Scopes:         apiKey.Scopes,
		LastUsed:       apiKey.LastUsed,
	}

	var userCtx *UserContext
	if currentUser != nil {
		userCtx = m.convertToUserContext(currentUser, apiKey.Permissions)
	} else {
		// Organization-level API key without specific user
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
	user, err := m.userRepo.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, nil, errors.New(errors.CodeUnauthorized, "user not found")
	}

	if !user.Active || user.Blocked {
		return nil, nil, errors.New(errors.CodeUnauthorized, "user account is disabled")
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

	userCtx := m.convertToUserContext(user, nil)

	return sessionCtx, userCtx, nil
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
	return AuthMethodNone
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
