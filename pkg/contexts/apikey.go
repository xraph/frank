package contexts

import (
	"context"
	"time"

	"github.com/rs/xid"
	
)

// GetAPIKeyFromContext retrieves the API key from request context
func GetAPIKeyFromContext(ctx context.Context) *APIKeyContext {
	if apiKey, ok := ctx.Value(APIKeyContextKey).(*APIKeyContext); ok {
		return apiKey
	}
	return nil
}

// GetAPIKeyIDFromContext retrieves the API key ID from request context
func GetAPIKeyIDFromContext(ctx context.Context) *xid.ID {
	if keyID, ok := ctx.Value(APIKeyIDContextKey).(xid.ID); ok {
		return &keyID
	}
	return nil
}

// IsPublicKeyAuthenticated checks if the request is authenticated with a public key
func IsPublicKeyAuthenticated(ctx context.Context) bool {
	apiKey := GetAPIKeyFromContext(ctx)
	return apiKey != nil && apiKey.KeyType == "public"
}

// IsSecretKeyAuthenticated checks if the request is authenticated with a secret key
func IsSecretKeyAuthenticated(ctx context.Context) bool {
	apiKey := GetAPIKeyFromContext(ctx)
	return apiKey != nil && apiKey.KeyType == "secret"
}

// IsLegacyKeyAuthenticated checks if the request is authenticated with a legacy key
func IsLegacyKeyAuthenticated(ctx context.Context) bool {
	apiKey := GetAPIKeyFromContext(ctx)
	return apiKey != nil && apiKey.KeyType == "legacy"
}

// GetAPIKeyEnvironment returns the environment of the current API key
func GetAPIKeyEnvironment(ctx context.Context) model.Environment {
	apiKey := GetAPIKeyFromContext(ctx)
	if apiKey != nil {
		return apiKey.Environment
	}
	return ""
}

// IsTestEnvironment checks if the current API key is for test environment
func IsTestEnvironment(ctx context.Context) bool {
	env := GetAPIKeyEnvironment(ctx)
	return env == model.EnvironmentTest || env == model.EnvironmentDevelopment
}

// IsLiveEnvironment checks if the current API key is for live environment
func IsLiveEnvironment(ctx context.Context) bool {
	env := GetAPIKeyEnvironment(ctx)
	return env == model.EnvironmentLive || env == model.EnvironmentProduction
}

// GetAPIKeyType returns the type of the current API key
func GetAPIKeyType(ctx context.Context) model.APIKeyType {
	apiKey := GetAPIKeyFromContext(ctx)
	if apiKey != nil {
		return apiKey.Type
	}
	return ""
}

// IsServerAPIKey checks if the current API key is a server key
func IsServerAPIKey(ctx context.Context) bool {
	return GetAPIKeyType(ctx) == model.APIKeyTypeServer
}

// IsClientAPIKey checks if the current API key is a client key
func IsClientAPIKey(ctx context.Context) bool {
	return GetAPIKeyType(ctx) == model.APIKeyTypeClient
}

// IsAdminAPIKey checks if the current API key is an admin key
func IsAdminAPIKey(ctx context.Context) bool {
	return GetAPIKeyType(ctx) == model.APIKeyTypeAdmin
}

// HasAPIKeyPermission checks if the current API key has a specific permission
func HasAPIKeyPermission(ctx context.Context, permission string) bool {
	apiKey := GetAPIKeyFromContext(ctx)
	if apiKey == nil {
		return false
	}

	for _, p := range apiKey.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasAPIKeyScope checks if the current API key has a specific scope
func HasAPIKeyScope(ctx context.Context, scope string) bool {
	apiKey := GetAPIKeyFromContext(ctx)
	if apiKey == nil {
		return false
	}

	for _, s := range apiKey.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// IsAPIKeyExpired checks if the current API key is expired
func IsAPIKeyExpired(ctx context.Context) bool {
	apiKey := GetAPIKeyFromContext(ctx)
	if apiKey == nil || apiKey.ExpiresAt == nil {
		return false
	}

	return time.Now().After(*apiKey.ExpiresAt)
}

// IsAPIKeyActive checks if the current API key is active
func IsAPIKeyActive(ctx context.Context) bool {
	apiKey := GetAPIKeyFromContext(ctx)
	if apiKey == nil {
		return false
	}

	return apiKey.Active && !IsAPIKeyExpired(ctx)
}

// GetAPIKeyRateLimits returns the rate limits for the current API key
func GetAPIKeyRateLimits(ctx context.Context) *model.APIKeyRateLimits {
	apiKey := GetAPIKeyFromContext(ctx)
	if apiKey != nil {
		return apiKey.RateLimits
	}
	return nil
}

// WithAPIKey creates a new context with API key information
func WithAPIKey(ctx context.Context, apiKey *APIKeyContext) context.Context {
	ctx = context.WithValue(ctx, APIKeyContextKey, apiKey)
	ctx = context.WithValue(ctx, APIKeyIDContextKey, apiKey.ID)

	if apiKey.OrganizationID != nil {
		ctx = context.WithValue(ctx, OrganizationIDContextKey, *apiKey.OrganizationID)
	}

	if len(apiKey.Permissions) > 0 {
		ctx = context.WithValue(ctx, PermissionsContextKey, apiKey.Permissions)
	}

	return ctx
}
