package contexts

import (
	"context"
	"net/http"

	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// // GetOrganizationFromContext retrieves the organization from request context
// func GetOrganizationFromContext(ctx context.Context) *model.Organization {
// 	if org, ok := ctx.Value(contexts.OrganizationContextKey).(*model.Organization); ok {
// 		return org
// 	}
// 	return nil
// }

// GetDetectedUserTypeFromContext retrieves detected user type from context
func GetDetectedUserTypeFromContext(ctx context.Context) string {
	if userType, ok := ctx.Value(DetectedUserTypeKey).(string); ok {
		return userType
	}
	return ""
}

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
	if detectedType := GetDetectedUserTypeFromContext(ctx); detectedType != "" {
		return model.UserType(detectedType)
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
	if userType := GetDetectedUserTypeFromContext(ctx); userType != "" {
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
