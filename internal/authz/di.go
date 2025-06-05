package authz

import (
	"github.com/juicycleff/frank/pkg/data"
)

// PermissionsService represents the permission checking service
type PermissionsService struct {
	checker PermissionChecker
}

// NewPermissionsService creates a new PermissionsService
func NewPermissionsService(client *data.Clients) *PermissionsService {
	return &PermissionsService{
		checker: NewPermissionChecker(client),
	}
}

// Checker returns the permission checker
func (ps *PermissionsService) Checker() PermissionChecker {
	return ps.checker
}

// WithCustomRolePermissions allows setting custom role permissions
func (ps *PermissionsService) WithCustomRolePermissions(rolePerms RolePermissions) *PermissionsService {
	ps.checker = NewPermissionChecker(ps.checker.(*DefaultPermissionChecker).client).
		WithCustomRolePermissions(rolePerms)
	return ps
}
