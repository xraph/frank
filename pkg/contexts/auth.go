package contexts

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/model"
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
	ID             xid.ID            `json:"id"`
	Email          string            `json:"email"`
	Username       string            `json:"username,omitempty"`
	FirstName      string            `json:"firstName,omitempty"`
	LastName       string            `json:"lastName,omitempty"`
	UserType       model.UserType    `json:"userType"`
	OrganizationID *xid.ID           `json:"organizationId,omitempty"`
	Active         bool              `json:"active"`
	EmailVerified  bool              `json:"emailVerified"`
	Permissions    []string          `json:"permissions,omitempty"`
	Roles          []model.RoleInfo  `json:"roles,omitempty"`
	Metadata       map[string]any    `json:"metadata,omitempty"`
	SessionID      xid.ID            `json:"sessionId,omitempty"`
	Membership     *model.Membership `json:"membership,omitempty"`
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

// AuthenticationContext holds all authentication-related information
type AuthenticationContext struct {
	User    *UserContext
	Session *SessionContext
	APIKey  *APIKeyContext
	Method  AuthMethod
}

// APIKeyContext represents the API key context
type APIKeyContext struct {
	ID             xid.ID                  `json:"id"`
	Name           string                  `json:"name"`
	Type           model.APIKeyType        `json:"type"`
	UserID         *xid.ID                 `json:"userId,omitempty"`
	OrganizationID *xid.ID                 `json:"organizationId,omitempty"`
	Permissions    []string                `json:"permissions,omitempty"`
	Scopes         []string                `json:"scopes,omitempty"`
	LastUsed       *time.Time              `json:"lastUsed,omitempty"`
	RateLimits     *model.APIKeyRateLimits `json:"rateLimits,omitempty"`
	Environment    model.Environment       `json:"environment"`

	// New fields for public/secret key support
	PublicKey string `json:"publicKey,omitempty"`
	KeyType   string `json:"keyType"` // "public", "secret", or "legacy"

	// Legacy support
	LegacyKey string `json:"legacyKey,omitempty"`

	// Additional metadata
	IPWhitelist []string               `json:"ipWhitelist,omitempty"`
	ExpiresAt   *time.Time             `json:"expiresAt,omitempty"`
	Active      bool                   `json:"active"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// OrganizationContext represents the organization context
type OrganizationContext struct {
	ID                     xid.ID         `json:"id"`
	Name                   string         `json:"name"`
	Slug                   string         `json:"slug"`
	Domain                 string         `json:"domain,omitempty"`
	Plan                   string         `json:"plan"`
	Active                 bool           `json:"active"`
	IsPlatformOrganization bool           `json:"isPlatformOrganization"`
	OrgType                model.OrgType  `json:"orgType"`
	Metadata               map[string]any `json:"metadata,omitempty"`
	Source                 string         `json:"source"`
}

// RequestContext represents request-specific context information
type RequestContext struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	IPAddress string            `json:"ipAddress"`
	UserAgent string            `json:"userAgent"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// TenantLimits represents tenant-specific limits
type TenantLimits struct {
	ExternalUsers  int   `json:"external_users"`
	EndUsers       int   `json:"end_users"`
	APIRequests    int   `json:"api_requests"`
	Storage        int64 `json:"storage"` // bytes
	EmailsPerMonth int   `json:"emails_per_month"`
	SMSPerMonth    int   `json:"sms_per_month"`
	Webhooks       int   `json:"webhooks"`
	SSO            bool  `json:"sso"`
	CustomDomains  int   `json:"custom_domains"`
}

// TrialInfo represents trial information
type TrialInfo struct {
	Active    bool       `json:"active"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	DaysLeft  int        `json:"days_left"`
	Used      bool       `json:"used"`
}

// TenantContext represents the tenant context for multi-tenancy
type TenantContext struct {
	Organization *model.Organization `json:"organization"`
	Plan         string              `json:"plan"`
	Type         model.OrgType       `json:"type"`
	Features     []string            `json:"features,omitempty"`
	Limits       *TenantLimits       `json:"limits,omitempty"`
	Settings     map[string]any      `json:"settings,omitempty"`
	Active       bool                `json:"active"`
	Trial        *TrialInfo          `json:"trial,omitempty"`
}

// GetUserFromContextSafe retrieves the user from request context
func GetUserFromContextSafe(ctx context.Context) (*UserContext, error) {
	if user, ok := ctx.Value(UserContextKey).(*UserContext); ok {
		return user, nil
	}
	return nil, errors.New(errors.CodeUnauthorized, "user not authorized")
}

// GetUserFromContext retrieves the user from request context
func GetUserFromContext(ctx context.Context) *UserContext {
	if user, ok := ctx.Value(UserContextKey).(*UserContext); ok {
		return user
	}
	return nil
}

// GetSessionFromContext retrieves the session from request context
func GetSessionFromContext(ctx context.Context) *SessionContext {
	if session, ok := ctx.Value(SessionContextKey).(*SessionContext); ok {
		return session
	}
	return nil
}

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
