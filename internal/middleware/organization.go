package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/rs/xid"
	"github.com/xraph/frank/internal/di"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/contexts"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"github.com/xraph/frank/pkg/server"
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
	Logger                  logging.Logger
	EnforceForExternalUsers bool
	EnforceForEndUsers      bool
	AllowPersonalOperations bool
	BasePath                string // Add base path support
	AutoDetectFromAPIKey    bool
	AutoDetectFromDomain    bool
}

// DefaultOrganizationContextConfig returns default configuration
func DefaultOrganizationContextConfig() *OrganizationContextConfig {
	return &OrganizationContextConfig{
		EnforceForExternalUsers: false, // External users can exist without org context
		EnforceForEndUsers:      true,  // End users must have org context
		AllowPersonalOperations: true,  // Allow personal operations without org context
		AutoDetectFromAPIKey:    true,
		AutoDetectFromDomain:    true,
		BasePath:                "", // No base path by default
	}
}

// OrganizationContextMiddleware handles organization context enforcement based on user types
type OrganizationContextMiddleware struct {
	authMW         *AuthMiddleware
	config         *OrganizationContextConfig
	orgRepo        repository.OrganizationRepository
	userRepo       repository.UserRepository
	apiKeyRepo     repository.ApiKeyRepository
	logger         logging.Logger
	api            huma.API
	detectionOrder []UserTypeDetectionStrategy
}

// NewOrganizationContextMiddleware creates a new organization context middleware
func NewOrganizationContextMiddleware(
	api huma.API,
	di di.Container,
	authMw *AuthMiddleware,
	config *OrganizationContextConfig,
	mountOptions ...*server.MountOptions) *OrganizationContextMiddleware {

	if config == nil {
		config = DefaultOrganizationContextConfig()
	}

	if config.Logger == nil {
		config.Logger = di.Logger().Named("org-context-middleware")
	}

	// Set base path from mount options if provided
	if len(mountOptions) > 0 && mountOptions[0] != nil && mountOptions[0].BasePath != "" {
		config.BasePath = strings.TrimSuffix(mountOptions[0].BasePath, "/")
	}

	return &OrganizationContextMiddleware{
		config:     config,
		orgRepo:    di.Repo().Organization(),
		userRepo:   di.Repo().User(),
		apiKeyRepo: di.Repo().APIKey(),
		logger:     config.Logger,
		api:        api,
		authMW:     authMw,
		detectionOrder: []UserTypeDetectionStrategy{
			DetectionByAuth,
			DetectionByAPIKey,
			DetectionByOrganization,
			DetectionByHeader,
		},
	}
}

// UserTypeDetectionMiddleware detects user type before authentication
func (ocm *OrganizationContextMiddleware) UserTypeDetectionMiddleware(allowMissing bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Skip for certain paths
			if ocm.shouldSkipPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Detect user type from various sources
			userType := ocm.detectUserType(ctx, r)

			if userType == "" && !allowMissing {
				ocm.respondError(w, r, errors.New(errors.CodeBadRequest, "unable to determine user type"))
				return
			}

			// Set detected user type in context
			if userType != "" {
				ctx = context.WithValue(ctx, contexts.DetectedUserTypeKey, userType)
				ocm.logger.Debug("Detected user type",
					logging.String("userType", userType.String()),
					logging.String("path", r.URL.Path))
			}

			// Auto-detect organization context from API key if enabled
			if ocm.config.AutoDetectFromAPIKey {
				if orgID := ocm.detectOrganizationFromAPIKey(ctx); orgID != nil {
					ctx = context.WithValue(ctx, contexts.DetectedOrganizationIDKey, *orgID)

					// Set X-Org-ID header for downstream processing if missing
					if r.Header.Get("X-Org-ID") == "" {
						r.Header.Set("X-Org-ID", orgID.String())
						ocm.logger.Debug("Set X-Org-ID from API key",
							logging.String("orgId", orgID.String()),
							logging.String("userType", userType.String()))
					}
				}
			}

			// Auto-detect organization context from email domain if enabled
			if ocm.config.AutoDetectFromDomain && userType == model.UserTypeEndUser {
				if orgID := ocm.detectOrganizationFromEmailDomain(ctx, r); orgID != nil {
					// Only set if not already detected from API key
					if existing := ctx.Value(contexts.DetectedOrganizationIDKey); existing == nil {
						ctx = context.WithValue(ctx, contexts.DetectedOrganizationIDKey, *orgID)
						ocm.logger.Debug("Detected organization from email domain",
							logging.String("orgId", orgID.String()))
					}
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserTypeDetectionHumaMiddleware detects user type for Huma routes
func (ocm *OrganizationContextMiddleware) UserTypeDetectionHumaMiddleware(isPublic bool) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		rctx := ctx.Context()
		r := contexts.GetRequestFromContext(rctx)

		// Skip for certain paths
		if ocm.shouldSkipPath(ctx.URL().Path) {
			next(ctx)
			return
		}

		// Detect user type from various sources
		detectedUserType := ocm.detectUserType(rctx, r)
		if detectedUserType != "" {
			ctx = huma.WithValue(ctx, contexts.DetectedUserTypeKey, detectedUserType)
		}

		var detectedOrgID *xid.ID

		// Auto-detect organization context from API key if enabled
		if ocm.config.AutoDetectFromAPIKey {
			if detectedOrgID = ocm.detectOrganizationFromAPIKey(rctx); detectedOrgID != nil {
				ctx = huma.WithValue(ctx, contexts.DetectedOrganizationIDKey, *detectedOrgID)

				// Set X-Org-ID header for downstream processing if missing
				if r.Header.Get("X-Org-ID") == "" {
					r.Header.Set("X-Org-ID", detectedOrgID.String())
					ocm.logger.Debug("Set X-Org-ID from API key",
						logging.String("orgId", detectedOrgID.String()),
						logging.String("userType", detectedUserType.String()))
				}
			}
		}

		// Auto-detect organization context from email domain if enabled
		if ocm.config.AutoDetectFromDomain && detectedUserType == model.UserTypeEndUser {
			if detectedOrgID = ocm.detectOrganizationFromEmailDomain(rctx, r); detectedOrgID != nil {
				// Only set if not already detected from API key
				if existing := rctx.Value(contexts.DetectedOrganizationIDKey); existing == nil {
					ctx = huma.WithValue(ctx, contexts.DetectedOrganizationIDKey, *detectedOrgID)
				}
			}
		}

		ocm.logger.Debug("User type detection completed",
			logging.String("path", ctx.URL().Path),
			logging.String("detectedUserType", detectedUserType.String()),
			logging.Any("detectedOrgID", detectedOrgID),
			logging.Bool("isPublic", isPublic))

		next(ctx)
	}
}

func (ocm *OrganizationContextMiddleware) updateOrganizationContext(ctx huma.Context, orgID xid.ID, r *http.Request) huma.Context {
	organization, err := ocm.orgRepo.GetByID(ctx.Context(), orgID)
	if err == nil {
		ctx = contexts.SetOrganizationContextHuma(ctx, &contexts.OrganizationContext{
			ID:                     organization.ID,
			Name:                   organization.Name,
			Slug:                   organization.Slug,
			Domain:                 organization.Domain,
			Active:                 organization.Active,
			Plan:                   organization.Plan,
			OrgType:                organization.OrgType,
			IsPlatformOrganization: organization.IsPlatformOrganization,
			Metadata:               organization.Metadata,
		})
		ocm.logger.Debug("Detected organization from user type",
			logging.String("orgId", orgID.String()))

		// Set X-Org-ID header for downstream processing if missing
		if r.Header.Get("X-Org-ID") == "" {
			r.Header.Set("X-Org-ID", orgID.String())
			ocm.logger.Debug("Set X-Org-ID from API key",
				logging.String("orgId", orgID.String()))
		}
	}

	return ctx
}

// RequireOrganizationForUserType middleware that enforces organization context based on user type
func (ocm *OrganizationContextMiddleware) RequireOrganizationForUserType(allowMissing bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Skip for certain paths
			if ocm.shouldSkipPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Get detected or authenticated user type
			userType := ocm.getEffectiveUserType(ctx)

			if userType == "" {
				if allowMissing {
					next.ServeHTTP(w, r)
					return
				}
				ocm.respondError(w, r, errors.New(errors.CodeBadRequest, "user type is required"))
				return
			}

			// Get organization context
			orgID := ocm.getEffectiveOrganizationID(ctx, r)

			// Validate organization requirements based on user type
			switch userType {
			case model.UserTypeInternal:
				return
			case model.UserTypeExternal:
				// External users may require organization context based on configuration
				if ocm.config.EnforceForExternalUsers && orgID == nil {
					ocm.respondError(w, r, errors.New(errors.CodeBadRequest, "organization context is required for external users. Provide organization context via API key (X-API-Key) or headers (X-Org-ID)."))
					return
				}

			case model.UserTypeEndUser:
				// End users require organization context
				if ocm.config.EnforceForEndUsers && orgID == nil {
					ocm.respondError(w, r, errors.New(errors.CodeBadRequest, "organization context is required for end users. Provide organization context via API key (X-Publishable-Key) or headers (X-Org-ID)."))
					return
				}

			default:
				if !allowMissing {
					ocm.respondError(w, r, errors.New(errors.CodeBadRequest, "unknown user type"))
					return
				}
			}

			// Validate organization context if present
			if orgID != nil {
				if err := ocm.validateOrganizationContext(ctx, *orgID, model.UserType(userType), allowMissing); err != nil {
					ocm.respondError(w, r, err)
					return
				}

				// Set organization context for downstream middleware
				ctx = context.WithValue(ctx, contexts.OrganizationIDContextKey, *orgID)
			}

			ocm.logger.Debug("Organization context validation passed",
				logging.String("userType", userType.String()),
				logging.String("orgId", orgID.String()),
				logging.String("path", r.URL.Path))

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireOrganizationForUserTypeHuma middleware for Huma routes
func (ocm *OrganizationContextMiddleware) RequireOrganizationForUserTypeHuma(isPublic bool) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		rctx := ctx.Context()
		r := contexts.GetRequestFromContext(rctx)

		// Skip for certain paths
		if ocm.shouldSkipPath(ctx.URL().Path) {
			next(ctx)
			return
		}

		// Get current user if authenticated
		currentUser := GetUserFromContext(rctx)

		// Determine the effective user type
		var userType model.UserType
		if currentUser != nil {
			userType = currentUser.UserType
		} else {
			// Use detected user type for unauthenticated requests
			detectedType := GetDetectedUserTypeFromContext(rctx)
			if detectedType != "" {
				userType = model.UserType(detectedType)
			} else {
				// Default for public endpoints
				if isPublic {
					userType = model.UserTypeExternal // Default assumption for public
				} else {
					// For protected endpoints, skip if no type detected
					next(ctx)
					return
				}
			}
		}

		// Check if organization context is required for this user type and path
		if ocm.requiresOrganizationContext(userType, ctx.URL().Path, isPublic) {
			orgID := ocm.getEffectiveOrganizationID(rctx, r)

			if orgID == nil {
				errorMsg := ocm.buildOrganizationRequiredError(userType, isPublic)
				ocm.respondErrorHuma(ctx, errors.New(errors.CodeBadRequest, errorMsg))
				return
			}

			// Validate organization access
			if err := ocm.validateOrganizationAccess(rctx, *orgID, userType); err != nil {
				ocm.respondErrorHuma(ctx, err)
				return
			}

			// Set organization context
			ctx = huma.WithValue(ctx, contexts.OrganizationIDContextKey, *orgID)
		}

		ocm.logger.Debug("Organization context validation completed",
			logging.String("path", ctx.URL().Path),
			logging.String("userType", string(userType)),
			logging.Bool("isPublic", isPublic),
			logging.Any("orgID", ocm.getEffectiveOrganizationID(rctx, r)))

		next(ctx)
	}
}

// OptionalOrganizationContextHuma provides organization context if available but doesn't require it
func (ocm *OrganizationContextMiddleware) OptionalOrganizationContextHuma() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		rctx := ctx.Context()
		r := contexts.GetRequestFromContext(rctx)

		// Try to get organization context from various sources
		orgID := ocm.getEffectiveOrganizationID(rctx, r)
		if orgID != nil {
			// Validate organization if found
			userType := ocm.getEffectiveUserType(rctx)
			if err := ocm.validateOrganizationAccess(rctx, *orgID, userType); err != nil {
				ocm.logger.Warn("Invalid organization context in optional middleware",
					logging.Error(err),
					logging.String("orgId", orgID.String()))
			} else {
				// Set valid organization context
				ctx = huma.WithValue(ctx, contexts.OrganizationIDContextKey, *orgID)
			}
		}

		next(ctx)
	}
}

// detectUserType detects user type from various request sources
func (ocm *OrganizationContextMiddleware) detectUserType(ctx context.Context, r *http.Request) model.UserType {
	// 1. From authenticated user context
	if user := GetUserFromContext(ctx); user != nil {
		return user.UserType
	}

	// 2. From API key type
	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil {
		switch apiKey.Type {
		case model.APIKeyTypeClient:
			return model.UserTypeEndUser // Client keys are for end users
		case model.APIKeyTypeServer, model.APIKeyTypeAdmin:
			if apiKey.UserID != nil {
				// Server/admin keys with user context - get user type from user
				user, err := ocm.userRepo.GetByID(ctx, *apiKey.UserID)
				if err == nil {
					return user.UserType
				}
			}
			return model.UserTypeExternal // Default for server keys
		}
	}

	// 3. From explicit headers
	if userType := r.Header.Get("X-User-Type"); userType != "" {
		switch strings.ToLower(userType) {
		case "internal", "external", "end_user", "enduser", "endUser":
			if userType == "enduser" || userType == "endUser" {
				return model.UserTypeEndUser
			}
			return model.UserType(userType)
		}
	}

	// 4. From query parameters
	if userType := r.URL.Query().Get("user_type"); userType != "" {
		switch strings.ToLower(userType) {
		case "internal", "external", "end_user", "enduser", "endUser":
			if userType == "enduser" || userType == "endUser" {
				return model.UserTypeEndUser
			}
			return model.UserType(userType)
		}
	}

	// 5. From registration type indicators
	if regType := r.URL.Query().Get("registration_type"); regType != "" {
		switch regType {
		case "organization_owner", "organization_creator":
			return model.UserTypeExternal
		case "end_user":
			return model.UserTypeEndUser
		}
	}

	// 6. Detect from API key prefix patterns
	if apiKey := ocm.extractAPIKeyValue(r); apiKey != "" {
		if strings.HasPrefix(apiKey, "pk_") {
			return model.UserTypeEndUser // Publishable keys are for end users
		}
		if strings.HasPrefix(apiKey, "sk_") {
			return model.UserTypeExternal // Secret keys are for external users
		}
	}

	return "" // Unable to detect
}

// validateOrganizationContext validates organization context
func (ocm *OrganizationContextMiddleware) validateOrganizationContext(ctx context.Context, orgID xid.ID, userType model.UserType, allowMissing bool) error {
	org, err := ocm.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if allowMissing && userType != model.UserTypeEndUser {
			return nil
		}

		if repository.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to validate organization 2")
	}

	if !org.Active {
		return errors.New(errors.CodeForbidden, "organization is inactive")
	}

	// Additional validation based on user type
	switch userType {
	case model.UserTypeEndUser:
		// End users cannot access platform organizations
		if org.IsPlatformOrganization {
			return errors.New(errors.CodeForbidden, "end users cannot access platform organization")
		}

		// Validate end user limits
		if org.CurrentEndUsers >= org.EndUserLimit {
			return errors.New(errors.CodeForbidden, "organization has reached end user limit")
		}

	case model.UserTypeExternal:
		// External users cannot access platform organizations unless explicitly allowed
		if org.IsPlatformOrganization && org.OrgType != model.OrgTypePlatform {
			return errors.New(errors.CodeForbidden, "external users cannot access platform organization")
		}

	case model.UserTypeInternal:
		// Internal users can access any organization
		break
	}

	return nil
}

// getEffectiveUserType gets user type from authenticated user or detected type
func (ocm *OrganizationContextMiddleware) getEffectiveUserType(ctx context.Context) model.UserType {
	// Try authenticated user first
	if user := GetUserFromContext(ctx); user != nil {
		return user.UserType
	}

	// Try detected user type
	if detectedType := GetDetectedUserTypeFromContext(ctx); detectedType != "" {
		return detectedType
	}

	// Default to external
	return model.UserTypeExternal
}

// getEffectiveOrganizationID gets organization ID from various sources
func (ocm *OrganizationContextMiddleware) getEffectiveOrganizationID(ctx context.Context, r *http.Request) *xid.ID {
	// Priority order:
	// 1. From current organization context
	if orgID := GetOrganizationIDFromContext(ctx); orgID != nil {
		return orgID
	}

	// 2. From detected organization context
	if orgID := GetDetectedOrganizationIDFromContext(ctx); orgID != nil {
		return orgID
	}

	// 3. From API key
	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil && apiKey.OrganizationID != nil {
		return apiKey.OrganizationID
	}

	// 4. From authenticated user
	if user := GetUserFromContext(ctx); user != nil && user.OrganizationID != nil {
		return user.OrganizationID
	}

	// 5. From X-Org-ID header
	if orgIDStr := r.Header.Get("X-Org-ID"); orgIDStr != "" {
		if orgID, err := xid.FromString(orgIDStr); err == nil {
			return &orgID
		}
	}

	return nil
}

// extractAPIKeyValue extracts API key value from request
func (ocm *OrganizationContextMiddleware) extractAPIKeyValue(r *http.Request) string {
	// Check various API key sources
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}
	if key := r.Header.Get("X-Publishable-Key"); key != "" {
		return key
	}
	if key := r.URL.Query().Get("api_key"); key != "" {
		return key
	}
	if key := r.URL.Query().Get("publishable_key"); key != "" {
		return key
	}
	return ""
}

// extractEmailFromRequest extracts email from request body or parameters
func (ocm *OrganizationContextMiddleware) extractEmailFromRequest(r *http.Request) string {
	// Try query parameter first
	if email := r.URL.Query().Get("email"); email != "" {
		return email
	}

	// Try to extract from request path for magic link verification
	if strings.Contains(r.URL.Path, "/verify/") && r.URL.Query().Get("email") != "" {
		return r.URL.Query().Get("email")
	}

	// For POST requests, we would need to parse the body, but that's more complex
	// and should be handled at the handler level
	return ""
}

// detectUserType detects user type from various sources
func (ocm *OrganizationContextMiddleware) detectUserTypeWithOrg(ctx context.Context, r *http.Request, skipExternal bool) (string, *xid.ID, error) {
	for _, strategy := range ocm.detectionOrder {
		userType, orgID, err := ocm.detectUserTypeByStrategy(ctx, r, strategy, skipExternal)
		if err == nil && userType != "" {
			return userType, orgID, nil
		}
	}
	return "", nil, errors.New(errors.CodeBadRequest, "unable to detect user type")
}

// detectOrganizationFromAPIKey detects organization ID from API key context
func (ocm *OrganizationContextMiddleware) detectOrganizationFromAPIKey(ctx context.Context) *xid.ID {
	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil && apiKey.OrganizationID != nil {
		return apiKey.OrganizationID
	}
	return nil
}

// detectOrganizationFromEmailDomain detects organization from email domain
func (ocm *OrganizationContextMiddleware) detectOrganizationFromEmailDomain(ctx context.Context, r *http.Request) *xid.ID {
	email := ocm.extractEmailFromRequest(r)
	if email == "" {
		return nil
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil
	}

	domain := parts[1]

	// Try to find organization by domain
	org, err := ocm.orgRepo.GetByDomain(ctx, domain)
	if err != nil {
		return nil
	}

	if !org.Active {
		return nil
	}

	return &org.ID
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

	keyContext, _, err := ocm.authMW.authenticateAPIKey(ctx, r)
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
func (ocm *OrganizationContextMiddleware) requiresOrganizationContext(userType model.UserType, path string, isPublic bool) bool {
	// Check if this is a personal operation that doesn't need org context
	if ocm.isPersonalOperation(path) && ocm.config.AllowPersonalOperations {
		return false
	}

	// Check if this is an operation that external users can do without org context
	if userType == model.UserTypeExternal && ocm.isExternalUserAllowedOperation(path, isPublic) {
		return false
	}

	// Apply user type specific rules
	switch userType {
	case model.UserTypeInternal:
		// Internal users never require organization context
		return false

	case model.UserTypeExternal:
		// External users require org context based on configuration and path
		return ocm.config.EnforceForExternalUsers && !ocm.isExternalUserAllowedOperation(path, isPublic)

	case model.UserTypeEndUser:
		// End users require org context for most operations
		return ocm.config.EnforceForEndUsers && !ocm.isPersonalOperation(path)

	default:
		// Unknown user type - be conservative and require org context
		return true
	}
}

// isPersonalOperation checks if this is a personal operation that doesn't need org context
func (ocm *OrganizationContextMiddleware) isPersonalOperation(path string) bool {
	// Build full path with base path
	basePath := ocm.config.BasePath
	buildPath := func(p string) string {
		return basePath + p
	}

	personalPaths := []string{
		buildPath("/api/v1/auth/logout"),
		buildPath("/api/v1/auth/refresh"),
		buildPath("/api/v1/auth/status"),
		buildPath("/api/v1/auth/mfa/"),
		buildPath("/api/v1/auth/sessions"),
		buildPath("/api/v1/auth/passkeys"),
		buildPath("/api/v1/user/profile"),
		buildPath("/api/v1/user/change-password"),
		buildPath("/api/v1/user/organizations"),
		buildPath("/api/v1/user/memberships"),
	}

	for _, personalPath := range personalPaths {
		if path == personalPath || strings.HasPrefix(path, personalPath+"/") {
			return true
		}
	}

	return false
}

// isExternalUserAllowedOperation checks if external users can perform this operation without org context
func (ocm *OrganizationContextMiddleware) isExternalUserAllowedOperation(path string, isPublic bool) bool {
	// Build full path with base path
	basePath := ocm.config.BasePath
	buildPath := func(p string) string {
		return basePath + p
	}

	// External users can do these operations without org context
	allowedPaths := []string{
		// Organization creation and listing
		buildPath("/api/v1/organizations"),

		// Public auth operations
		buildPath("/api/v1/public/auth/"),

		// Personal operations (already handled in isPersonalOperation)
	}

	// For public endpoints, external users have more freedom
	if isPublic {
		publicAllowedPaths := []string{
			buildPath("/api/v1/public/"),
		}
		allowedPaths = append(allowedPaths, publicAllowedPaths...)
	}

	for _, allowedPath := range allowedPaths {
		if path == allowedPath || strings.HasPrefix(path, allowedPath) {
			return true
		}
	}

	// Check for organization creation (POST to /organizations)
	if strings.HasSuffix(path, buildPath("/api/v1/organizations")) {
		return true
	}

	return false
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

	// Additional checks based on user type
	switch userType {
	case model.UserTypeEndUser:
		// End users cannot access platform organizations
		if org.IsPlatformOrganization {
			return errors.New(errors.CodeForbidden, "end users cannot access platform organization")
		}

	case model.UserTypeExternal:
		// External users cannot access platform organizations
		if org.IsPlatformOrganization {
			return errors.New(errors.CodeForbidden, "external users cannot access platform organization")
		}

	case model.UserTypeInternal:
		// Internal users can access any organization
		break
	}

	return nil
}

// buildOrganizationRequiredError builds an appropriate error message for missing org context
func (ocm *OrganizationContextMiddleware) buildOrganizationRequiredError(userType model.UserType, isPublic bool) string {
	switch userType {
	case model.UserTypeEndUser:
		if isPublic {
			return "Organization context is required for end users. Provide organization context via publishable API key (X-Publishable-Key) or headers (X-Org-ID)."
		}
		return "Organization context is required for end users. Provide organization context via API key or headers (X-Org-ID)."

	case model.UserTypeExternal:
		if isPublic {
			return "Organization context is required for this operation. Provide organization context via API key (X-API-Key) or headers (X-Org-ID)."
		}
		return "Organization context is required for external users accessing this resource. Provide organization context via API key or headers (X-Org-ID)."

	default:
		return "Organization context is required for this operation. Provide organization context via API key or headers (X-Org-ID)."
	}
}

// shouldSkipPath checks if this path should skip organization context processing entirely
func (ocm *OrganizationContextMiddleware) shouldSkipPath(path string) bool {
	// Build full path with base path
	basePath := ocm.config.BasePath
	buildPath := func(p string) string {
		return basePath + p
	}

	skipPaths := []string{
		buildPath("/health"),
		buildPath("/ready"),
		buildPath("/metrics"),
		buildPath("/favicon.ico"),
		buildPath("/robots.txt"),
		// Skip OpenAPI docs
		buildPath("/docs"),
		buildPath("/openapi.json"),
		// Skip static assets
		buildPath("/static/"),
	}

	for _, skipPath := range skipPaths {
		if path == skipPath || strings.HasPrefix(path, skipPath) {
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

// GetDetectedUserTypeFromContext retrieves detected user type from context
func GetDetectedUserTypeFromContext(ctx context.Context) model.UserType {
	if userType, ok := ctx.Value(contexts.DetectedUserTypeKey).(string); ok {
		return model.UserType(userType)
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

	ocm := NewOrganizationContextMiddleware(api, di, authMiddleware, config)
	return ocm.RequireOrganizationForUserTypeHuma(false)
}

// RequireOrganizationForEndUsers creates middleware specifically for end users
func RequireOrganizationForEndUsers(api huma.API, di di.Container, authMiddleware *AuthMiddleware) func(huma.Context, func(huma.Context)) {
	config := DefaultOrganizationContextConfig()
	config.EnforceForExternalUsers = false
	config.EnforceForEndUsers = true

	ocm := NewOrganizationContextMiddleware(api, di, authMiddleware, config)
	return ocm.RequireOrganizationForUserTypeHuma(false)
}

// RequireOrganizationForNonInternal creates middleware for all non-internal users
func RequireOrganizationForNonInternal(api huma.API, di di.Container, authMiddleware *AuthMiddleware) func(huma.Context, func(huma.Context)) {
	config := DefaultOrganizationContextConfig()
	config.EnforceForExternalUsers = true
	config.EnforceForEndUsers = true

	ocm := NewOrganizationContextMiddleware(api, di, authMiddleware, config)
	return ocm.RequireOrganizationForUserTypeHuma(false)
}
