package contexts

import (
	"context"
	"net/http"
)

// GetRequestIDFromContext retrieves the request ID from request context
func GetRequestIDFromContext(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDContextKey).(string); ok {
		return requestID
	}
	return ""
}

// GetRequestFromContext retrieves the request ID from request context
func GetRequestFromContext(ctx context.Context) *http.Request {
	if requestID, ok := ctx.Value(HTTPRequestContextKey).(*http.Request); ok {
		return requestID
	}
	return nil
}

// GetTenantFromContext retrieves the tenant from request context
func GetTenantFromContext(ctx context.Context) *TenantContext {
	if tenant, ok := ctx.Value(TenantContextKey).(*TenantContext); ok {
		return tenant
	}
	return nil
}

// IsAuthenticated checks if the request is authenticated
func IsAuthenticated(ctx context.Context) bool {
	return GetUserFromContext(ctx) != nil
}

// Context creation helper functions

// WithUser creates a new context with user information
func WithUser(ctx context.Context, user *UserContext) context.Context {
	ctx = context.WithValue(ctx, UserContextKey, user)
	ctx = context.WithValue(ctx, UserIDContextKey, user.ID)
	ctx = context.WithValue(ctx, UserTypeContextKey, user.UserType)

	if user.OrganizationID != nil {
		ctx = context.WithValue(ctx, OrganizationIDContextKey, *user.OrganizationID)
	}

	return ctx
}

// WithSession creates a new context with session information
func WithSession(ctx context.Context, session *SessionContext) context.Context {
	ctx = context.WithValue(ctx, SessionContextKey, session)
	ctx = context.WithValue(ctx, SessionIDContextKey, session.ID)
	return ctx
}

// WithOrganization creates a new context with organization information
func WithOrganization(ctx context.Context, org *OrganizationContext) context.Context {
	ctx = context.WithValue(ctx, OrganizationContextKey, org)
	ctx = context.WithValue(ctx, OrganizationIDContextKey, org.ID)
	return ctx
}

// WithRequestInfo creates a new context with request information
func WithRequestInfo(ctx context.Context, requestID, ipAddress, userAgent string) context.Context {
	ctx = context.WithValue(ctx, RequestIDContextKey, requestID)

	if ipAddress != "" {
		ctx = context.WithValue(ctx, IPAddressContextKey, ipAddress)
	}

	if userAgent != "" {
		ctx = context.WithValue(ctx, UserAgentContextKey, userAgent)
	}

	return ctx
}

// WithTenant creates a new context with tenant information
func WithTenant(ctx context.Context, tenant *TenantContext) context.Context {
	ctx = context.WithValue(ctx, TenantContextKey, tenant)

	if tenant.Organization != nil {
		ctx = context.WithValue(ctx, TenantIDContextKey, tenant.Organization.ID)
		ctx = context.WithValue(ctx, TenantSlugContextKey, tenant.Organization.Slug)
		ctx = context.WithValue(ctx, TenantPlanContextKey, tenant.Plan)
		ctx = context.WithValue(ctx, TenantTypeContextKey, tenant.Type)
	}

	return ctx
}

// Validation helper functions

// ValidateUserContext validates user context
func ValidateUserContext(user *UserContext) error {
	if user == nil {
		return NewContextError("user context is nil")
	}

	if user.ID.IsNil() {
		return NewContextError("user ID is required")
	}

	if user.Email == "" {
		return NewContextError("user email is required")
	}

	return nil
}

// ValidateAPIKeyContext validates API key context
func ValidateAPIKeyContext(apiKey *APIKeyContext) error {
	if apiKey == nil {
		return NewContextError("API key context is nil")
	}

	if apiKey.ID.IsNil() {
		return NewContextError("API key ID is required")
	}

	if apiKey.Type == "" {
		return NewContextError("API key type is required")
	}

	if apiKey.Environment == "" {
		return NewContextError("API key environment is required")
	}

	if apiKey.KeyType != "public" && apiKey.KeyType != "secret" && apiKey.KeyType != "legacy" {
		return NewContextError("invalid API key type")
	}

	return nil
}

// ContextError Error types for context validation
type ContextError struct {
	Message string
}

func (e ContextError) Error() string {
	return e.Message
}

func NewContextError(message string) error {
	return ContextError{Message: message}
}
