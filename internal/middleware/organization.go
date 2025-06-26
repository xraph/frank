package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/contexts"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// UserTypeDetectionStrategy defines how user types are detected
type UserTypeDetectionStrategy string

const (
	DetectionByAPIKey       UserTypeDetectionStrategy = "api_key"
	DetectionByOrganization UserTypeDetectionStrategy = "organization"
	DetectionByAuth         UserTypeDetectionStrategy = "auth"
	DetectionByHeader       UserTypeDetectionStrategy = "header"
)

// OrganizationContextConfig represents organization context middleware configuration
type OrganizationContextConfig struct {
	EnforceForExternalUsers bool     // Enforce organization context for external users
	EnforceForEndUsers      bool     // Enforce organization context for end users
	AllowInternalAccess     bool     // Allow internal users to access without organization
	SkipPaths               []string // Paths to skip organization context enforcement
	Logger                  logging.Logger
}

// OrganizationContextMiddleware handles organization context enforcement based on user types
type OrganizationContextMiddleware struct {
	authMiddleware *AuthMiddleware
	config         *OrganizationContextConfig
	orgRepo        repository.OrganizationRepository
	userRepo       repository.UserRepository
	apiKeyRepo     repository.ApiKeyRepository
	logger         logging.Logger
	api            huma.API
	detectionOrder []UserTypeDetectionStrategy
}

// NewOrganizationContextMiddleware creates a new organization context middleware
func NewOrganizationContextMiddleware(api huma.API, di di.Container, authMiddleware *AuthMiddleware, config *OrganizationContextConfig) *OrganizationContextMiddleware {
	if config == nil {
		config = DefaultOrganizationContextConfig()
	}

	if config.Logger == nil {
		config.Logger = di.Logger().Named("org-context-middleware")
	}

	return &OrganizationContextMiddleware{
		config:         config,
		orgRepo:        di.Repo().Organization(),
		userRepo:       di.Repo().User(),
		apiKeyRepo:     di.Repo().APIKey(),
		logger:         config.Logger,
		api:            api,
		authMiddleware: authMiddleware,
		detectionOrder: []UserTypeDetectionStrategy{
			DetectionByAuth,
			DetectionByAPIKey,
			DetectionByOrganization,
			DetectionByHeader,
		},
	}
}

// DefaultOrganizationContextConfig returns default configuration
func DefaultOrganizationContextConfig() *OrganizationContextConfig {
	return &OrganizationContextConfig{
		EnforceForExternalUsers: true,
		EnforceForEndUsers:      true,
		AllowInternalAccess:     true,
		SkipPaths: []string{
			"/health",
			"/ready",
			"/metrics",
			"/favicon.ico",
			"/robots.txt",
		},
	}
}

// UserTypeDetectionMiddleware detects user type before authentication
func (ocm *OrganizationContextMiddleware) UserTypeDetectionMiddleware(skipExternal bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Skip detection for certain paths
			if ocm.shouldSkipPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Detect user type using various strategies
			userType, orgID, err := ocm.detectUserType(ctx, r, skipExternal)
			if err != nil {
				ocm.logger.Debug("Failed to detect user type", logging.Error(err))
			}

			// Set detected user type and organization in context
			if userType != "" {
				ctx = context.WithValue(ctx, contexts.DetectedUserTypeKey, userType)
			}
			if orgID != nil {
				ctx = context.WithValue(ctx, contexts.DetectedOrganizationIDKey, *orgID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserTypeDetectionHumaMiddleware detects user type for Huma routes
func (ocm *OrganizationContextMiddleware) UserTypeDetectionHumaMiddleware(skipExternal bool) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r := contexts.GetRequestFromContext(ctx.Context())
		rctx := ctx.Context()

		// Skip detection for certain paths
		if ocm.shouldSkipPath(ctx.URL().Path) {
			next(ctx)
			return
		}

		// Detect user type using various strategies
		userType, orgID, err := ocm.detectUserType(rctx, r, skipExternal)
		if err != nil {
			ocm.logger.Debug("Failed to detect user type", logging.Error(err))
		}

		// Set detected user type and organization in context
		if userType != "" {
			ctx = huma.WithValue(ctx, contexts.DetectedUserTypeKey, userType)
		}
		if orgID != nil {
			ctx = huma.WithValue(ctx, contexts.DetectedOrganizationIDKey, *orgID)
		}

		next(ctx)
	}
}

// RequireOrganizationForUserType middleware that enforces organization context based on user type
func (ocm *OrganizationContextMiddleware) RequireOrganizationForUserType(skipForExternal bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Skip for certain paths
			if ocm.shouldSkipPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Get current user from context (if authenticated)
			currentUser := GetUserFromContext(ctx)
			orgID := GetOrganizationIDFromContext(ctx)

			// Determine user type (from authenticated user or detected)
			var userType model.UserType

			if currentUser != nil {
				// Use authenticated user's type
				userType = currentUser.UserType

				if orgID == nil {
					orgID = currentUser.OrganizationID
				}
			} else {
				// Use detected user type
				if detectedType, ok := ctx.Value(contexts.DetectedUserTypeKey).(string); ok {
					userType = model.UserType(detectedType)
				}

				if orgID == nil {
					if detectedOrgID, ok := ctx.Value(contexts.DetectedOrganizationIDKey).(xid.ID); ok {
						orgID = &detectedOrgID
					}
				}
			}

			// Check if organization context is required for this user type
			if ocm.requiresOrganizationContext(userType, skipForExternal) {
				if orgID == nil {
					ocm.respondError(w, r, errors.New(errors.CodeBadRequest, "organization context is required for this user type"))
					return
				}

				// Validate organization exists and is accessible
				if err := ocm.validateOrganizationAccess(ctx, *orgID, userType); err != nil {
					ocm.respondError(w, r, err)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireOrganizationForUserTypeHuma middleware for Huma routes
func (ocm *OrganizationContextMiddleware) RequireOrganizationForUserTypeHuma(skipForExternal bool) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		rctx := ctx.Context()
		// Skip for certain paths
		if ocm.shouldSkipPath(ctx.URL().Path) {
			next(ctx)
			return
		}

		// Get current user from context (if authenticated)
		currentUser := GetUserFromContext(rctx)
		orgID := GetOrganizationIDFromContext(rctx)

		// Determine user type (from authenticated user or detected)
		var userType model.UserType

		if currentUser != nil {
			// Use authenticated user's type
			userType = currentUser.UserType
			if orgID == nil {
				orgID = currentUser.OrganizationID
			}
		} else {
			// Use detected user type
			if detectedType := contexts.GetUserTypeFromDetectedOrAuth(rctx); detectedType != "" {
				userType = detectedType
			}
			if orgID == nil {
				if detectedOrgID, ok := rctx.Value(contexts.DetectedOrganizationIDKey).(xid.ID); ok {
					orgID = &detectedOrgID
				}
			}
		}

		// Check if organization context is required for this user type
		if ocm.requiresOrganizationContext(userType, skipForExternal) {
			if orgID == nil {
				ocm.respondErrorHuma(ctx, errors.New(errors.CodeBadRequest, "organization context is required for this user type"))
				return
			}

			// Validate organization exists and is accessible
			if err := ocm.validateOrganizationAccess(rctx, *orgID, userType); err != nil {
				ocm.respondErrorHuma(ctx, err)
				return
			}
		}

		next(ctx)
	}
}

// detectUserType detects user type from various sources
func (ocm *OrganizationContextMiddleware) detectUserType(ctx context.Context, r *http.Request, skipExternal bool) (string, *xid.ID, error) {
	for _, strategy := range ocm.detectionOrder {
		userType, orgID, err := ocm.detectUserTypeByStrategy(ctx, r, strategy, skipExternal)
		if err == nil && userType != "" {
			return userType, orgID, nil
		}
	}
	return "", nil, errors.New(errors.CodeBadRequest, "unable to detect user type")
}

// detectUserTypeByStrategy detects user type using specific strategy
func (ocm *OrganizationContextMiddleware) detectUserTypeByStrategy(ctx context.Context, r *http.Request, strategy UserTypeDetectionStrategy, skipExternal bool) (string, *xid.ID, error) {
	switch strategy {
	case DetectionByAuth:
		return ocm.detectByAuth(ctx, r)
	case DetectionByAPIKey:
		return ocm.detectByAPIKey(ctx, r)
	case DetectionByOrganization:
		return ocm.detectByOrganization(ctx, r)
	case DetectionByHeader:
		return ocm.detectByHeader(ctx, r, skipExternal)
	default:
		return "", nil, errors.New(errors.CodeInternalServer, "unknown detection strategy")
	}
}

// detectByAuth detects user type from authenticated user
func (ocm *OrganizationContextMiddleware) detectByAuth(ctx context.Context, r *http.Request) (string, *xid.ID, error) {
	user := GetUserFromContext(ctx)
	if user != nil {
		return string(user.UserType), user.OrganizationID, nil
	}
	return "", nil, errors.New(errors.CodeUnauthorized, "no authenticated user")
}

// detectByAPIKey detects user type from API key
func (ocm *OrganizationContextMiddleware) detectByAPIKey(ctx context.Context, r *http.Request) (string, *xid.ID, error) {
	// Extract API key from headers
	var apiKey string
	if key := r.Header.Get("X-API-Key"); key != "" {
		apiKey = key
	} else if key := r.Header.Get("X-Publishable-Key"); key != "" {
		apiKey = key
	} else if key := r.URL.Query().Get("api_key"); key != "" {
		apiKey = key
	} else if key := r.URL.Query().Get("publishable_key"); key != "" {
		apiKey = key
	}

	if apiKey == "" {
		return "", nil, errors.New(errors.CodeBadRequest, "no API key found")
	}

	// Determine user type based on key prefix
	var userType string
	var orgID *xid.ID

	keyContext, _, err := ocm.authMiddleware.authenticateAPIKey(ctx, r)
	if err != nil {
		return "", nil, err
	}

	if keyContext != nil {
		orgID = keyContext.OrganizationID
	}

	if strings.HasPrefix(apiKey, "pk_") {
		// Public key - end users
		userType = string(model.UserTypeEndUser)
		// // Get organization from public key
		// if keyData, err := ocm.apiKeyRepo.GetByPublicKey(ctx, apiKey); err == nil {
		// 	orgID = &keyData.OrganizationID
		// }
	} else if strings.HasPrefix(apiKey, "sk_") {
		// Secret key - external users (organization scoped)
		userType = string(model.UserTypeExternal)
		// // Get organization from secret key
		// if keyData, err := ocm.getAPIKeyBySecret(ctx, apiKey); err == nil {
		// 	orgID = &keyData.OrganizationID
		// }
	}
	// else if strings.HasPrefix(apiKey, "frank_sk_") {
	// 	// Legacy secret key - could be internal or external
	// 	userType = string(model.UserTypeExternal) // Default to external
	// 	if keyData, err := ocm.getAPIKeyBySecret(ctx, apiKey); err == nil {
	// 		orgID = &keyData.OrganizationID
	// 		// Check if this is a platform organization key
	// 		if org, err := ocm.orgRepo.GetByID(ctx, keyData.OrganizationID); err == nil {
	// 			if org.IsPlatformOrganization {
	// 				userType = string(model.UserTypeInternal)
	// 				orgID = nil // Internal users don't need org context
	// 			}
	// 		}
	// 	}
	// }

	if userType == "" {
		return "", nil, errors.New(errors.CodeBadRequest, "invalid API key format")
	}

	return userType, orgID, nil
}

// detectByOrganization detects user type from organization context
func (ocm *OrganizationContextMiddleware) detectByOrganization(ctx context.Context, r *http.Request) (string, *xid.ID, error) {
	// Try to get organization ID from various sources
	var orgID xid.ID
	var err error

	// From URL path parameter
	if orgIDStr := chi.URLParam(r, "orgId"); orgIDStr != "" {
		orgID, err = xid.FromString(orgIDStr)
		if err != nil {
			return "", nil, errors.New(errors.CodeBadRequest, "invalid organization ID in path")
		}
	} else if orgIDStr := r.Header.Get("X-Org-ID"); orgIDStr != "" {
		// From header
		orgID, err = xid.FromString(orgIDStr)
		if err != nil {
			return "", nil, errors.New(errors.CodeBadRequest, "invalid organization ID in header")
		}
	} else if orgIDStr := r.URL.Query().Get("org"); orgIDStr != "" {
		// From query parameter
		orgID, err = xid.FromString(orgIDStr)
		if err != nil {
			return "", nil, errors.New(errors.CodeBadRequest, "invalid organization ID in query")
		}
	} else {
		return "", nil, errors.New(errors.CodeBadRequest, "no organization context found")
	}

	// Check if organization exists and determine user type based on org type
	org, err := ocm.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return "", nil, errors.New(errors.CodeNotFound, "organization not found")
	}

	var userType string
	if org.IsPlatformOrganization {
		userType = string(model.UserTypeInternal)
		return userType, nil, nil // Internal users don't need org context
	} else {
		// For customer organizations, default to external user type
		// This could be refined based on additional context
		userType = string(model.UserTypeExternal)
	}

	return userType, &orgID, nil
}

// detectByHeader detects user type from explicit header
func (ocm *OrganizationContextMiddleware) detectByHeader(ctx context.Context, r *http.Request, skipExternal bool) (string, *xid.ID, error) {
	userType := r.Header.Get("X-User-Type")
	if userType == "" {
		return "", nil, errors.New(errors.CodeBadRequest, "no user type header found")
	}

	// Validate user type
	switch userType {
	case string(model.UserTypeInternal):
		return userType, nil, nil
	case string(model.UserTypeExternal):
		if skipExternal {
			return userType, nil, nil
		}
		// These user types require organization context
		orgIDStr := r.Header.Get("X-Org-ID")
		if orgIDStr == "" {
			return "", nil, errors.New(errors.CodeBadRequest, "organization ID required for this user type")
		}
		orgID, err := xid.FromString(orgIDStr)
		if err != nil {
			return "", nil, errors.New(errors.CodeBadRequest, "invalid organization ID")
		}
		return userType, &orgID, nil
	case string(model.UserTypeEndUser):
		// These user types require organization context
		orgIDStr := r.Header.Get("X-Org-ID")
		if orgIDStr == "" {
			return "", nil, errors.New(errors.CodeBadRequest, "organization ID required for this user type")
		}
		orgID, err := xid.FromString(orgIDStr)
		if err != nil {
			return "", nil, errors.New(errors.CodeBadRequest, "invalid organization ID")
		}
		return userType, &orgID, nil
	default:
		return "", nil, errors.New(errors.CodeBadRequest, "invalid user type")
	}
}

// requiresOrganizationContext checks if user type requires organization context
func (ocm *OrganizationContextMiddleware) requiresOrganizationContext(userType model.UserType, skipForExternal bool) bool {
	switch userType {
	case model.UserTypeInternal:
		return false // Internal users don't require organization context
	case model.UserTypeExternal:
		if skipForExternal {
			return false
		}
		return ocm.config.EnforceForExternalUsers
	case model.UserTypeEndUser:
		return ocm.config.EnforceForEndUsers
	default:
		return true // Unknown user types require organization context by default
	}
}

// validateOrganizationAccess validates organization access for user type
func (ocm *OrganizationContextMiddleware) validateOrganizationAccess(ctx context.Context, orgID xid.ID, userType model.UserType) error {
	// Get organization
	org, err := ocm.orgRepo.GetByID(ctx, orgID)

	if err != nil {
		if repository.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to validate organization")
	}

	// Check if organization is active
	if !org.Active {
		return errors.New(errors.CodeForbidden, "organization is inactive")
	}

	// Internal users can access platform organizations
	if userType == model.UserTypeInternal && org.IsPlatformOrganization {
		return nil
	}

	// External and end users cannot access platform organizations
	if org.IsPlatformOrganization && (userType == model.UserTypeExternal || userType == model.UserTypeEndUser) {
		return errors.New(errors.CodeForbidden, "access denied to platform organization")
	}

	return nil
}

// shouldSkipPath checks if path should be skipped
func (ocm *OrganizationContextMiddleware) shouldSkipPath(path string) bool {
	for _, skipPath := range ocm.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// Response helpers
func (ocm *OrganizationContextMiddleware) respondError(w http.ResponseWriter, r *http.Request, err error) {
	var errResp *errors.ErrorResponse
	if e, ok := err.(*errors.Error); ok {
		errResp = errors.NewErrorResponse(e)
	} else {
		errResp = errors.NewErrorResponse(errors.New(errors.CodeInternalServer, err.Error()))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errResp.StatusCode())

	jsonResp := `{"code":"` + errResp.Code + `","message":"` + errResp.Message + `"}`
	_, _ = w.Write([]byte(jsonResp))
}

func (ocm *OrganizationContextMiddleware) respondErrorHuma(ctx huma.Context, err error) {
	var errResp *errors.ErrorResponse
	if e, ok := err.(*errors.Error); ok {
		errResp = errors.NewErrorResponse(e)
	} else {
		errResp = errors.NewErrorResponse(errors.New(errors.CodeInternalServer, err.Error()))
	}

	huma.WriteErr(ocm.api, ctx, errResp.StatusCode(), errResp.Message)
}

// Context getter functions

// GetDetectedUserTypeFromContext retrieves detected user type from context
func GetDetectedUserTypeFromContext(ctx context.Context) string {
	if userType, ok := ctx.Value(contexts.DetectedUserTypeKey).(string); ok {
		return userType
	}
	return ""
}

// GetDetectedOrganizationIDFromContext retrieves detected organization ID from context
func GetDetectedOrganizationIDFromContext(ctx context.Context) *xid.ID {
	if orgID, ok := ctx.Value(contexts.DetectedOrganizationIDKey).(xid.ID); ok {
		return &orgID
	}
	return nil
}

// Utility functions

// RequireOrganizationForExternalUsers creates middleware specifically for external users
func RequireOrganizationForExternalUsers(api huma.API, di di.Container, authMiddleware *AuthMiddleware) func(huma.Context, func(huma.Context)) {
	config := DefaultOrganizationContextConfig()
	config.EnforceForExternalUsers = true
	config.EnforceForEndUsers = false
	config.AllowInternalAccess = true

	ocm := NewOrganizationContextMiddleware(api, di, authMiddleware, config)
	return ocm.RequireOrganizationForUserTypeHuma(false)
}

// RequireOrganizationForEndUsers creates middleware specifically for end users
func RequireOrganizationForEndUsers(api huma.API, di di.Container, authMiddleware *AuthMiddleware) func(huma.Context, func(huma.Context)) {
	config := DefaultOrganizationContextConfig()
	config.EnforceForExternalUsers = false
	config.EnforceForEndUsers = true
	config.AllowInternalAccess = true

	ocm := NewOrganizationContextMiddleware(api, di, authMiddleware, config)
	return ocm.RequireOrganizationForUserTypeHuma(false)
}

// RequireOrganizationForNonInternal creates middleware for all non-internal users
func RequireOrganizationForNonInternal(api huma.API, di di.Container, authMiddleware *AuthMiddleware) func(huma.Context, func(huma.Context)) {
	config := DefaultOrganizationContextConfig()
	config.EnforceForExternalUsers = true
	config.EnforceForEndUsers = true
	config.AllowInternalAccess = true

	ocm := NewOrganizationContextMiddleware(api, di, authMiddleware, config)
	return ocm.RequireOrganizationForUserTypeHuma(false)
}
