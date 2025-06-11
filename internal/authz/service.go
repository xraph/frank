package authz

type Service interface {
	// Checker returns the permission checker
	Checker() PermissionCheckerWithContext

	// PermissionChecker returns the permission checker
	PermissionChecker() PermissionCheckerWithContext

	// WithCustomRolePermissions allows setting custom role permissions
	WithCustomRolePermissions(rolePerms RolePermissions) Service
}
