package apikeys

import (
	"regexp"
	"strings"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// Validator provides API key validation functionality
type Validator interface {
	// ValidateKeyFormat validates the format of an API key
	ValidateKeyFormat(key string) error

	// Validate validates an API key against required permissions and scopes
	Validate(apiKey *ent.ApiKey, key string, requiredPermissions []string, requiredScopes []string) (*ent.ApiKey, error)

	// HasPermission checks if an API key has a specific permission
	HasPermission(apiKey *ent.ApiKey, permission string) bool

	// HasScope checks if an API key has a specific scope
	HasScope(apiKey *ent.ApiKey, scope string) bool

	// CanPerformAction checks if an API key has permission to perform an action on a resource
	CanPerformAction(apiKey *ent.ApiKey, resource, action string) bool
}

type validator struct {
	logger logging.Logger
}

// NewValidator creates a new API key validator
func NewValidator(logger logging.Logger) Validator {
	return &validator{
		logger: logger,
	}
}

// ValidateKeyFormat validates the format of an API key
func (v *validator) ValidateKeyFormat(key string) error {
	// Check if key is empty
	if key == "" {
		return errors.New(errors.CodeInvalidAPIKey, "API key cannot be empty")
	}

	// Check format (expecting "key_" prefix followed by base64 chars)
	if !regexp.MustCompile(`^key_[A-Za-z0-9_\-]+$`).MatchString(key) {
		return errors.New(errors.CodeInvalidAPIKey, "invalid API key format")
	}

	return nil
}

// Validate validates an API key against required permissions and scopes
func (v *validator) Validate(apiKey *ent.ApiKey, key string, requiredPermissions []string, requiredScopes []string) (*ent.ApiKey, error) {
	// Validate key format
	if err := v.ValidateKeyFormat(key); err != nil {
		return nil, err
	}

	// Check permissions if required
	if len(requiredPermissions) > 0 {
		hasAllPermissions := true

		for _, permission := range requiredPermissions {
			if !v.HasPermission(apiKey, permission) {
				hasAllPermissions = false
				break
			}
		}

		if !hasAllPermissions {
			return nil, errors.New(errors.CodeForbidden, "API key is missing required permissions")
		}
	}

	// Check scopes if required
	if len(requiredScopes) > 0 {
		hasAllScopes := true

		for _, scope := range requiredScopes {
			if !v.HasScope(apiKey, scope) {
				hasAllScopes = false
				break
			}
		}

		if !hasAllScopes {
			return nil, errors.New(errors.CodeForbidden, "API key is missing required scopes")
		}
	}

	return apiKey, nil
}

// HasPermission checks if an API key has a specific permission
func (v *validator) HasPermission(apiKey *ent.ApiKey, permission string) bool {
	// Check if API key has permission
	for _, p := range apiKey.Permissions {
		// Check for exact match or wildcard
		if p == permission || p == "*" {
			return true
		}

		// Check for prefix wildcard (e.g. "users:*" matches "users:read")
		if strings.HasSuffix(p, ":*") {
			prefix := strings.TrimSuffix(p, ":*")
			if strings.HasPrefix(permission, prefix+":") {
				return true
			}
		}
	}

	return false
}

// HasScope checks if an API key has a specific scope
func (v *validator) HasScope(apiKey *ent.ApiKey, scope string) bool {
	// Check if API key has scope
	for _, s := range apiKey.Scopes {
		// Check for exact match or wildcard
		if s == scope || s == "*" {
			return true
		}
	}

	return false
}

// CanPerformAction checks if an API key has permission to perform an action on a resource
func (v *validator) CanPerformAction(apiKey *ent.ApiKey, resource, action string) bool {
	// Construct the permission string (e.g. "users:read")
	permission := resource + ":" + action

	return v.HasPermission(apiKey, permission)
}
