package contexts

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/model"
)

// // GetOrganizationFromContext retrieves the organization from request context
// func GetOrganizationFromContext(ctx context.Context) *model.Organization {
// 	if org, ok := ctx.Value(contexts.OrganizationContextKey).(*model.Organization); ok {
// 		return org
// 	}
// 	return nil
// }

// GetDetectedOrganizationIDFromContext retrieves detected organization ID from context
func GetDetectedOrganizationIDFromContext(ctx context.Context) *xid.ID {
	if orgID, ok := ctx.Value(DetectedOrganizationIDKey).(xid.ID); ok {
		return &orgID
	}
	return nil
}

// RequireUserTypeMiddleware creates middleware that requires specific user types
func RequireUserTypeMiddleware(userTypes ...model.UserType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}

			for _, allowedType := range userTypes {
				if user.UserType == allowedType {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "insufficient permissions", http.StatusForbidden)
		})
	}
}

// RequireOrganizationMiddleware creates middleware that requires organization context
func RequireOrganizationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			orgID := GetOrganizationIDFromContext(r.Context())
			if orgID == nil {
				http.Error(w, "organization context required", http.StatusBadRequest)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ValidateUserOrganizationAccess validates that a user has access to an organization
func ValidateUserOrganizationAccess(ctx context.Context, userType model.UserType, userOrgID *xid.ID, targetOrgID xid.ID) bool {
	// Internal users can access any organization
	if userType == model.UserTypeInternal {
		return true
	}

	// External and end users must belong to the target organization
	if userType == model.UserTypeExternal || userType == model.UserTypeEndUser {
		return userOrgID != nil && *userOrgID == targetOrgID
	}

	return false
}

// GetUserTypeFromDetectedOrAuth gets user type from authenticated user or detected context
func GetUserTypeFromDetectedOrAuth(ctx context.Context) model.UserType {
	// First try authenticated user
	if user := GetUserFromContext(ctx); user != nil {
		return user.UserType
	}

	// Then try detected user type
	if detectedType := GetDetectedUserTypeFromContext(ctx); detectedType != nil {
		return *detectedType
	}

	return ""
}

// GetOrganizationIDFromDetectedOrAuth gets organization ID from authenticated user or detected context
func GetOrganizationIDFromDetectedOrAuth(ctx context.Context) *xid.ID {
	// First try authenticated user
	if user := GetUserFromContext(ctx); user != nil && user.OrganizationID != nil {
		return user.OrganizationID
	}

	// Then try detected organization ID
	if detectedOrgID := GetDetectedOrganizationIDFromContext(ctx); detectedOrgID != nil {
		return detectedOrgID
	}

	// Finally try organization context
	if orgID := GetOrganizationIDFromContext(ctx); orgID != nil {
		return orgID
	}

	return nil
}

// CreateContextualErrorResponse creates error response with context information
func CreateContextualErrorResponse(ctx context.Context, code string, message string) map[string]interface{} {
	response := map[string]interface{}{
		"code":    code,
		"message": message,
	}

	// Add context information for debugging (in development)
	if userType := GetDetectedUserTypeFromContext(ctx); userType != nil {
		response["detected_user_type"] = userType
	}

	if orgID := GetDetectedOrganizationIDFromContext(ctx); orgID != nil {
		response["detected_organization_id"] = orgID.String()
	}

	if user := GetUserFromContext(ctx); user != nil {
		response["authenticated_user_type"] = string(user.UserType)
		if user.OrganizationID != nil {
			response["user_organization_id"] = user.OrganizationID.String()
		}
	}

	return response
}

// GetOrganizationFromContext retrieves the organization from request context
func GetOrganizationFromContext(ctx context.Context) *OrganizationContext {
	if org, ok := ctx.Value(OrganizationContextKey).(*OrganizationContext); ok {
		return org
	}
	return nil
}

// GetOrganizationIDFromContext retrieves the organization ID from request context
func GetOrganizationIDFromContext(ctx context.Context) *xid.ID {
	if orgID, ok := ctx.Value(OrganizationIDContextKey).(xid.ID); ok {
		return &orgID
	}
	return nil
}

// Enhanced detection context getters

// GetDetectedUserTypeFromContext retrieves the detected user type from request context
func GetDetectedUserTypeFromContext(ctx context.Context) *model.UserType {
	if userType, ok := ctx.Value(DetectedUserTypeKey).(string); ok {
		ut := model.UserType(userType)
		return &ut
	}
	return nil
}

// GetScopesFromContext retrieves scopes from request context
func GetScopesFromContext(ctx context.Context) []string {
	if scopes, ok := ctx.Value(ScopesContextKey).([]string); ok {
		return scopes
	}
	return nil
}

// Enhanced helper functions for organization context management

// HasOrganizationContext checks if organization context is available
func HasOrganizationContext(ctx context.Context) bool {
	return GetOrganizationFromContext(ctx) != nil || GetOrganizationIDFromContext(ctx) != nil
}

// GetEffectiveOrganizationID returns the organization ID from any available source
func GetEffectiveOrganizationID(ctx context.Context) *xid.ID {
	// Try organization context first
	if orgID := GetOrganizationIDFromContext(ctx); orgID != nil {
		return orgID
	}

	// Try detected organization ID
	if orgID := GetDetectedOrganizationIDFromContext(ctx); orgID != nil {
		return orgID
	}

	// Try user's organization
	if user := GetUserFromContext(ctx); user != nil && user.OrganizationID != nil {
		return user.OrganizationID
	}

	// Try API key organization
	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil && apiKey.OrganizationID != nil {
		return apiKey.OrganizationID
	}

	return nil
}

// GetEffectiveUserType returns the user type from any available source
func GetEffectiveUserType(ctx context.Context) *model.UserType {
	// Try authenticated user first
	if user := GetUserFromContext(ctx); user != nil {
		return &user.UserType
	}

	// Try detected user type
	return GetDetectedUserTypeFromContext(ctx)
}

// IsUserInOrganization checks if the authenticated user belongs to the specified organization
func IsUserInOrganization(ctx context.Context, orgID xid.ID) bool {
	user := GetUserFromContext(ctx)
	if user == nil || user.OrganizationID == nil {
		return false
	}
	return *user.OrganizationID == orgID
}

// RequiresOrganizationContext checks if the current user type requires organization context
func RequiresOrganizationContext(ctx context.Context) bool {
	userType := GetEffectiveUserType(ctx)
	if userType == nil {
		return false
	}

	switch *userType {
	case model.UserTypeEndUser:
		return true // End users always require organization context
	case model.UserTypeExternal:
		return false // External users may or may not require organization context
	case model.UserTypeInternal:
		return false // Internal users don't require organization context
	default:
		return false
	}
}

// ValidateOrganizationAccess validates that the user can access the specified organization
func ValidateOrganizationAccess(ctx context.Context, orgID xid.ID) bool {
	user := GetUserFromContext(ctx)
	if user == nil {
		return false
	}

	// Internal users can access any organization
	if user.UserType == model.UserTypeInternal {
		return true
	}

	// External and end users must belong to the organization
	if user.OrganizationID == nil {
		return false
	}

	return *user.OrganizationID == orgID
}

// GetOrganizationContextSummary returns a summary of the organization context for debugging
type OrganizationContextSummary struct {
	HasOrgContext          bool            `json:"hasOrgContext"`
	OrganizationID         *xid.ID         `json:"organizationId,omitempty"`
	DetectedOrganizationID *xid.ID         `json:"detectedOrganizationId,omitempty"`
	UserOrganizationID     *xid.ID         `json:"userOrganizationId,omitempty"`
	APIKeyOrganizationID   *xid.ID         `json:"apiKeyOrganizationId,omitempty"`
	UserType               *model.UserType `json:"userType,omitempty"`
	DetectedUserType       *model.UserType `json:"detectedUserType,omitempty"`
	RequiresOrgContext     bool            `json:"requiresOrgContext"`
}

func GetOrganizationContextSummary(ctx context.Context) OrganizationContextSummary {
	summary := OrganizationContextSummary{
		HasOrgContext:      HasOrganizationContext(ctx),
		RequiresOrgContext: RequiresOrganizationContext(ctx),
	}

	if orgID := GetOrganizationIDFromContext(ctx); orgID != nil {
		summary.OrganizationID = orgID
	}

	if orgID := GetDetectedOrganizationIDFromContext(ctx); orgID != nil {
		summary.DetectedOrganizationID = orgID
	}

	if user := GetUserFromContext(ctx); user != nil {
		summary.UserType = &user.UserType
		if user.OrganizationID != nil {
			summary.UserOrganizationID = user.OrganizationID
		}
	}

	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil && apiKey.OrganizationID != nil {
		summary.APIKeyOrganizationID = apiKey.OrganizationID
	}

	if detectedType := GetDetectedUserTypeFromContext(ctx); detectedType != nil {
		summary.DetectedUserType = detectedType
	}

	return summary
}

// Helper functions for middleware integration

// SetDetectedUserType sets the detected user type in context
func SetDetectedUserType(ctx context.Context, userType model.UserType) context.Context {
	return context.WithValue(ctx, DetectedUserTypeKey, string(userType))
}

// SetDetectedOrganizationID sets the detected organization ID in context
func SetDetectedOrganizationID(ctx context.Context, orgID xid.ID) context.Context {
	return context.WithValue(ctx, DetectedOrganizationIDKey, orgID)
}

// SetOrganizationContext sets the organization context
func SetOrganizationContext(ctx context.Context, org *OrganizationContext) context.Context {
	ctx = context.WithValue(ctx, OrganizationContextKey, org)
	ctx = context.WithValue(ctx, OrganizationIDContextKey, org.ID)
	return ctx
}

// SetOrganizationContextHuma sets the organization context
func SetOrganizationContextHuma(ctx huma.Context, org *OrganizationContext) huma.Context {
	ctx = huma.WithValue(ctx, OrganizationContextKey, org)
	ctx = huma.WithValue(ctx, OrganizationIDContextKey, org.ID)
	return ctx
}

// SetRegistrationFlow sets the registration flow context
func SetRegistrationFlow(ctx context.Context, flow RegistrationFlowType, data map[string]interface{}) context.Context {
	ctx = context.WithValue(ctx, RegistrationFlowKey, flow)
	if data != nil {
		ctx = context.WithValue(ctx, RegistrationFlowDataKey, data)
	}
	return ctx
}
