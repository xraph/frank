package authz

import (
	"github.com/juicycleff/frank/pkg/data"
)

// PermissionsService represents the permission checking service
type PermissionsService struct {
	checker PermissionCheckerWithContext
}

// NewService creates a new PermissionsService
func NewService(client *data.Clients) Service {
	return &PermissionsService{
		checker: NewEnhancedPermissionChecker(client),
	}
}

// Checker returns the permission checker
func (ps *PermissionsService) Checker() PermissionCheckerWithContext {
	return ps.checker
}

// WithCustomRolePermissions allows setting custom role permissions
func (ps *PermissionsService) WithCustomRolePermissions(rolePerms RolePermissions) Service {
	ps.checker = NewEnhancedPermissionChecker(ps.checker.(*EnhancedPermissionChecker).client).
		WithCustomRolePermissions(rolePerms)
	return ps
}

func (ps *PermissionsService) PermissionChecker() PermissionCheckerWithContext {
	return ps.checker
}

// func (a *PermissionsService) RoleChecker() RoleChecker {
// 	return a.roleChecker
// }
