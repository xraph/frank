package apikey

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/model"
)

// validatePermissions validates that all provided permissions exist and are applicable for API keys
func (s *service) validatePermissions(ctx context.Context, permissions []string) error {
	if len(permissions) == 0 {
		return nil // Empty permissions are valid
	}

	var invalidPermissions []string
	var nonExistentPermissions []string

	for _, permissionName := range permissions {
		if permissionName == "*" {
			continue
		}
		// Check if permission exists in the system
		permission, err := s.rbacService.GetPermissionByName(ctx, permissionName)
		if err != nil {
			if errors.IsNotFound(err) {
				nonExistentPermissions = append(nonExistentPermissions, permissionName)
				continue
			}
			return errors.Newf(errors.CodeInternalServer, "failed to validate permission %s: %v", permissionName, err)
		}

		// Check if permission is applicable for API keys
		if !s.isPermissionApplicableForAPIKey(permission) {
			invalidPermissions = append(invalidPermissions, permissionName)
		}
	}

	// Collect all validation errors
	var errorMessages []string
	if len(nonExistentPermissions) > 0 {
		errorMessages = append(errorMessages, fmt.Sprintf("permissions do not exist: %v", nonExistentPermissions))
	}
	if len(invalidPermissions) > 0 {
		errorMessages = append(errorMessages, fmt.Sprintf("permissions not applicable for API keys: %v", invalidPermissions))
	}

	if len(errorMessages) > 0 {
		return errors.New(errors.CodeInvalidInput, strings.Join(errorMessages, "; "))
	}

	return nil
}

// isPermissionApplicableForAPIKey checks if a permission can be assigned to an API key
func (s *service) isPermissionApplicableForAPIKey(permission *model.Permission) bool {
	// API keys should not have self-access permissions or user-specific permissions
	selfAccessPermissions := map[string]bool{
		"view:self":                    true,
		"update:self":                  true,
		"delete:self":                  true,
		"manage:self":                  true,
		"view:own:profile":             true,
		"update:own:profile":           true,
		"manage:own:mfa":               true,
		"manage:own:sessions":          true,
		"view:own:audit:logs":          true,
		"delete:own:account":           true,
		"export:own:data":              true,
		"view:personal:api:key":        true,
		"manage:personal:api:key":      true,
		"view:personal:session":        true,
		"manage:personal:session":      true,
		"view:personal:mfa":            true,
		"manage:personal:mfa":          true,
		"view:personal:verification":   true,
		"manage:personal:verification": true,
		"view:personal:passkey":        true,
		"manage:personal:passkey":      true,
		"view:personal:oauth":          true,
		"manage:personal:oauth":        true,
		"view:personal:activity":       true,
		"manage:personal:activity":     true,
	}

	// Check if this is a self-access permission
	if selfAccessPermissions[permission.Name] {
		return false
	}

	// Check if permission resource includes "personal" or "self"
	if strings.Contains(strings.ToLower(permission.Resource), "personal") ||
		strings.Contains(strings.ToLower(permission.Resource), "self") {
		return false
	}

	// Check applicable user types - API keys should work with all user types or specific ones
	// but not be restricted to end users only for most operations
	if len(permission.ApplicableUserTypes) == 1 &&
		permission.ApplicableUserTypes[0] == model.UserTypeEndUser {
		// Allow end-user specific permissions for auth service API keys
		return true
	}

	// Most other permissions should be applicable
	return true
}

func (s *service) validateCreateRequest(ctx context.Context, req *model.CreateAPIKeyRequest, systemMode bool) error {
	if req.Name == "" {
		return errors.New(errors.CodeBadRequest, "API key name is required")
	}

	if len(req.Name) > 255 {
		return errors.New(errors.CodeBadRequest, "API key name too long (max 255 characters)")
	}

	// Validate API key type
	if req.Type != "" {
		validTypes := []model.APIKeyType{model.APIKeyTypeServer, model.APIKeyTypeClient, model.APIKeyTypeAdmin}
		found := false
		for _, validType := range validTypes {
			if req.Type == validType {
				found = true
				break
			}
		}
		if !found {
			return errors.New(errors.CodeBadRequest, "invalid API key type: %s", req.Type)
		}
	}

	// Validate environment
	if req.Environment != "" {
		validEnvironments := []model.Environment{
			model.EnvironmentTest, model.EnvironmentLive, model.EnvironmentDevelopment,
			model.EnvironmentStaging, model.EnvironmentProduction,
		}
		found := false
		for _, validEnv := range validEnvironments {
			if req.Environment == validEnv {
				found = true
				break
			}
		}
		if !found {
			return errors.New(errors.CodeBadRequest, "invalid environment: %s", req.Environment)
		}
	}

	// Validate expiration date
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		return errors.New(errors.CodeBadRequest, "expiration date cannot be in the past")
	}

	// Validate IP whitelist
	for _, ip := range req.IPWhitelist {
		if !s.isValidIPOrCIDR(ip) {
			return errors.New(errors.CodeBadRequest, "invalid IP address or CIDR: %s", ip)
		}
	}

	// Additional validation for permissions scope
	if len(req.Permissions) > 50 {
		return errors.New(errors.CodeBadRequest, "too many permissions (max 50)")
	}

	if systemMode {
		return nil
	}

	// Validate that user has permission to create API keys
	userID, organizationID, err := s.getContextInfo(ctx)
	if err != nil {
		return err
	}

	// todo: reenable // Check if user can create API keys in this organization
	// hasPermission, err := s.rbacService.HasPermission(ctx, userID.String(), string(model.ResourceAPIKey), "write")
	// if err != nil {
	// 	return errors.Newf(errors.CodeInternalServer, "failed to check permissions: %v", err)
	// }
	// if !hasPermission {
	// 	return errors.New(errors.CodeForbidden, "insufficient permissions to create API keys")
	// }

	// Validate that the requested permissions don't exceed user's own permissions
	if err = s.validateUserCanGrantPermissions(ctx, *userID, *organizationID, req.Permissions); err != nil {
		return err
	}

	return nil
}

// validateUserCanGrantPermissions ensures user can only grant permissions they have themselves
func (s *service) validateUserCanGrantPermissions(ctx context.Context, userID, organizationID xid.ID, requestedPermissions []string) error {
	if len(requestedPermissions) == 0 {
		return nil
	}

	// Get user's effective permissions
	userPermissions, err := s.rbacService.GetUserPermissionsWithContext(ctx, userID, model.ContextOrganization, &organizationID)
	if err != nil {
		return errors.Newf(errors.CodeInternalServer, "failed to get user permissions: %v", err)
	}

	fmt.Println(userPermissions)

	// Create a map of user's permissions for quick lookup
	userPermMap := make(map[string]bool)
	for _, perm := range userPermissions {
		userPermMap[perm.Name] = true
	}

	fmt.Println(userPermMap)

	// Check if user has all requested permissions
	var missingPermissions []string
	for _, requestedPerm := range requestedPermissions {
		if !userPermMap[requestedPerm] {
			missingPermissions = append(missingPermissions, requestedPerm)
		}
	}

	if len(missingPermissions) > 0 {
		return errors.Newf(errors.CodeForbidden,
			"cannot grant permissions you don't have: %v", missingPermissions)
	}

	return nil
}

func (s *service) isValidIPOrCIDR(ipStr string) bool {
	// Try parsing as IP
	if net.ParseIP(ipStr) != nil {
		return true
	}

	// Try parsing as CIDR
	_, _, err := net.ParseCIDR(ipStr)
	return err == nil
}

func (s *service) isIPAllowed(ipStr string, whitelist []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, allowed := range whitelist {
		// Check exact IP match
		if allowedIP := net.ParseIP(allowed); allowedIP != nil {
			if ip.Equal(allowedIP) {
				return true
			}
			continue
		}

		// Check CIDR match
		if _, network, err := net.ParseCIDR(allowed); err == nil {
			if network.Contains(ip) {
				return true
			}
		}
	}

	return false
}

func (s *service) convertToAPIKeySummary(key *ent.ApiKey) model.APIKeySummary {
	return model.APIKeySummary{
		ID:              key.ID,
		Name:            key.Name,
		PublicKey:       key.PublicKey,
		Type:            key.Type,
		Environment:     key.Environment,
		Active:          key.Active,
		LastUsed:        key.LastUsed,
		ExpiresAt:       key.ExpiresAt,
		CreatedAt:       key.CreatedAt,
		SecretKeyPrefix: s.getKeyPrefix(key.SecretKey),
		PermissionCount: len(key.Permissions),
	}
}

// getKeyPrefix extracts a prefix from a secret key for display purposes
func (s *service) getKeyPrefix(secretKey string) string {
	if len(secretKey) < 16 {
		return secretKey
	}
	return secretKey[:16] + "..."
}
