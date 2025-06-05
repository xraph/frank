package middleware

import (
	"context"
	"net/http"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/organization"
	"github.com/juicycleff/frank/pkg/utils"
)

// OrganizationMiddleware provides middleware functions for organization-related checks
type OrganizationMiddleware struct {
	config     *config.Config
	orgService organization.Service
	logger     logging.Logger
}

// NewOrganizationMiddleware creates a new organization middleware
func NewOrganizationMiddleware(cfg *config.Config, orgService organization.Service, logger logging.Logger) *OrganizationMiddleware {
	return &OrganizationMiddleware{
		config:     cfg,
		orgService: orgService,
		logger:     logger,
	}
}

// RequireOrganization middleware ensures the request has an organization context
func (m *OrganizationMiddleware) RequireOrganization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check if user is authenticated
		authenticated, _ := ctx.Value(AuthenticatedKey).(bool)
		if !authenticated {
			utils.RespondError(w, errors.New(errors.CodeUnauthorized, "authentication required"))
			return
		}

		// Get organization ID from context
		orgID, ok := GetOrganizationIDReq(r)
		if !ok || orgID == "" {
			// Try to get from header
			orgID = r.Header.Get("X-Organization-ID")

			if orgID == "" {
				// Try to get from query parameter
				orgID = r.URL.Query().Get("organization_id")
			}

			if orgID == "" {
				utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "organization ID is required"))
				return
			}

			// Store organization ID in context for downstream handlers
			ctx = context.WithValue(ctx, OrganizationIDKey, orgID)
			r = r.WithContext(ctx)
		}

		// Verify that the organization exists and is active
		org, err := m.orgService.Get(ctx, orgID)
		if err != nil {
			utils.RespondError(w, err)
			return
		}

		if !org.Active {
			utils.RespondError(w, errors.New(errors.CodeForbidden, "organization is inactive"))
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireOrganizationMember middleware ensures the user is a member of the organization
func (m *OrganizationMiddleware) RequireOrganizationMember(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check if user is authenticated
		userID, ok := GetUserIDReq(r)
		if !ok || userID == "" {
			utils.RespondError(w, errors.New(errors.CodeUnauthorized, "authentication required"))
			return
		}

		// Get organization ID from context
		orgID, ok := GetOrganizationIDReq(r)
		if !ok || orgID == "" {
			utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "organization ID is required"))
			return
		}

		// Check if user is a member of the organization
		members, _, err := m.orgService.GetMembers(ctx, orgID, organization.ListParams{})
		if err != nil {
			utils.RespondError(w, err)
			return
		}

		isMember := false
		for _, member := range members {
			if member.ID == userID {
				isMember = true
				break
			}
		}

		if !isMember {
			utils.RespondError(w, errors.New(errors.CodeForbidden, "user is not a member of this organization"))
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// RequireFeatureEnabled middleware checks if a feature is enabled for the organization
func (m *OrganizationMiddleware) RequireFeatureEnabled(featureKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get organization ID from context
			orgID, ok := GetOrganizationIDReq(r)
			if !ok || orgID == "" {
				utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "organization ID is required"))
				return
			}

			// Check if the feature is enabled
			enabled, err := m.orgService.IsFeatureEnabled(ctx, orgID, featureKey)
			if err != nil {
				utils.RespondError(w, err)
				return
			}

			if !enabled {
				utils.RespondError(w, errors.New(errors.CodeFeatureNotEnabled, "feature is not enabled for this organization"))
				return
			}

			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// SetOrganizationFromHeader middleware sets the organization ID from the header if not already in context
func (m *OrganizationMiddleware) SetOrganizationFromHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Skip if organization ID is already in context
		if _, ok := ctx.Value(OrganizationIDKey).(string); ok {
			next.ServeHTTP(w, r)
			return
		}

		// Get organization ID from header
		orgID := r.Header.Get("X-Organization-ID")
		if orgID != "" {
			// Store organization ID in context
			ctx = context.WithValue(ctx, OrganizationIDKey, orgID)
			r = r.WithContext(ctx)
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// WithOrganizationContext middleware adds organization data to the request context
func (m *OrganizationMiddleware) WithOrganizationContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get organization ID from context
		orgID, ok := GetOrganizationIDReq(r)
		if !ok || orgID == "" {
			// No organization context, continue without it
			next.ServeHTTP(w, r)
			return
		}

		// Get organization data
		org, err := m.orgService.Get(ctx, orgID)
		if err != nil {
			// Log error but continue without organization context
			logger := logging.FromContext(ctx)
			logger.Warn("Failed to get organization data",
				logging.String("organization_id", orgID),
				logging.Error(err),
			)
			next.ServeHTTP(w, r)
			return
		}

		// Add organization data to context
		ctx = context.WithValue(ctx, "organization", org)

		// Get organization features
		features, err := m.orgService.GetFeatures(ctx, orgID)
		if err == nil && features != nil {
			// Add features to context
			ctx = context.WithValue(ctx, "organization_features", features)
		}

		// Call the next handler with enriched context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
