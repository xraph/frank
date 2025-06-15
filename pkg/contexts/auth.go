package contexts

import (
	"context"
	"net/http"
	"strings"

	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// GetUserIDFromContext retrieves the user ID from request context
func GetUserIDFromContext(ctx context.Context) *xid.ID {
	if userID, ok := ctx.Value(UserIDContextKey).(xid.ID); ok {
		return &userID
	}
	return nil
}

// GetUserTypeFromContext retrieves the user type from request context
func GetUserTypeFromContext(ctx context.Context) *model.UserType {
	if userType, ok := ctx.Value(UserTypeContextKey).(model.UserType); ok {
		return &userType
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

// GetPermissionsFromContext retrieves permissions from request context
func GetPermissionsFromContext(ctx context.Context) []string {
	if permissions, ok := ctx.Value(PermissionsContextKey).([]string); ok {
		return permissions
	}
	return nil
}

// GetRolesFromContext retrieves roles from request context
func GetRolesFromContext(ctx context.Context) []model.RoleInfo {
	if roles, ok := ctx.Value(RolesContextKey).([]model.RoleInfo); ok {
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
