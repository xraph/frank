package authz

import (
	"fmt"

	"github.com/juicycleff/frank/pkg/model"
)

// RolePermissions maps role names to their permissions
type RolePermissions map[model.RoleName][]Permission

// RoleInheritance defines the parent role for each role using RoleName enum
type RoleInheritance map[model.RoleName]model.RoleName

// =============================================================================
// BASE ROLE PERMISSIONS
// =============================================================================

// BaseRolePermissions defines the direct permissions for each role (before inheritance)
var BaseRolePermissions = RolePermissions{
	// =============================================================================
	// SYSTEM ROLES (INTERNAL USERS)
	// =============================================================================

	// Platform Super Admin - Full platform control
	model.RolePlatformSuperAdmin: {
		// System administration
		PermissionSystemAdmin,
		PermissionManagePlatform,
		PermissionManageSystemSettings,
		PermissionViewSystemSettings,

		// Platform management
		PermissionViewPlatformMetrics,
		PermissionManagePlatformSettings,
		PermissionViewPlatformAnalytics,

		// Global organization management
		PermissionViewAllOrganizations,
		PermissionManageAllOrganizations,
		PermissionSuspendOrganization,
		PermissionDeleteAnyOrganization,
		PermissionViewCustomerOrganizations,
		PermissionManageCustomerOrganizations,
		PermissionCreateCustomerOrganization,
		PermissionUpdateCustomerOrganization,
		PermissionDeleteCustomerOrganization,

		// Global user management
		PermissionViewAllUsers,
		PermissionManageAllUsers,
		PermissionImpersonateAnyUser,
		PermissionSuspendAnyUser,
		PermissionViewInternalUsers,
		PermissionManageInternalUsers,
		PermissionCreateInternalUser,
		PermissionUpdateInternalUser,
		PermissionDeleteInternalUser,

		// Customer management
		PermissionViewAllCustomers,
		PermissionManageCustomerBilling,
		PermissionSuspendCustomer,

		// Platform security and audit
		PermissionViewPlatformAuditLogs,
		PermissionManagePlatformSecurity,
		PermissionManageSystemRoles,
		PermissionViewSystemRoles,

		// Billing and compliance
		PermissionViewAllBilling,
		PermissionManageAllBilling,
		PermissionViewComplianceReports,

		// Role and permission management
		PermissionReadRoles,
		PermissionWriteRole,
		PermissionDeleteRole,
		PermissionManageRole,
		PermissionAssignRoles,
		PermissionRevokeRole,
		PermissionReadPermission,
		PermissionWritePermission,
		PermissionDeletePermission,
		PermissionManagePermission,
		PermissionCheckPermission,
		PermissionManageSystemPermission,

		// Global activity tracking
		PermissionReadActivityGlobal,
	},

	// Platform Admin - Platform administration with limited destructive access
	model.RolePlatformAdmin: {
		// Limited platform management
		PermissionViewPlatformMetrics,
		PermissionManagePlatformSettings,
		PermissionViewPlatformAnalytics,

		// Organization management (non-destructive)
		PermissionViewAllOrganizations,
		PermissionManageAllOrganizations,
		PermissionSuspendOrganization,
		PermissionViewCustomerOrganizations,
		PermissionManageCustomerOrganizations,
		PermissionCreateCustomerOrganization,
		PermissionUpdateCustomerOrganization,

		// User management (non-destructive)
		PermissionViewAllUsers,
		PermissionManageAllUsers,
		PermissionImpersonateAnyUser,
		PermissionSuspendAnyUser,
		PermissionViewInternalUsers,
		PermissionManageInternalUsers,
		PermissionCreateInternalUser,
		PermissionUpdateInternalUser,

		// Customer management
		PermissionViewAllCustomers,
		PermissionManageCustomerBilling,
		PermissionSuspendCustomer,

		// Security and audit
		PermissionViewPlatformAuditLogs,
		PermissionManagePlatformSecurity,
		PermissionViewSystemRoles,

		// Billing
		PermissionViewAllBilling,
		PermissionManageAllBilling,
		PermissionViewComplianceReports,

		// Role management (non-destructive)
		PermissionReadRoles,
		PermissionWriteRole,
		PermissionManageRole,
		PermissionAssignRoles,
		PermissionRevokeRole,
		PermissionReadPermission,
		PermissionWritePermission,
		PermissionManagePermission,
		PermissionCheckPermission,
	},

	// Platform Support - Support role for assisting customers
	model.RolePlatformSupport: {
		// Read-only platform access
		PermissionViewPlatformMetrics,
		PermissionViewPlatformAnalytics,
		PermissionViewSystemSettings,

		// Customer support
		PermissionViewAllOrganizations,
		PermissionViewAllUsers,
		PermissionViewAllCustomers,
		PermissionViewCustomerOrganizations,

		// Audit and monitoring
		PermissionViewPlatformAuditLogs,
		PermissionViewAllBilling,
		PermissionViewComplianceReports,

		// Basic role viewing
		PermissionReadRoles,
		PermissionViewSystemRoles,
		PermissionReadPermission,
		PermissionCheckPermission,
	},

	// =============================================================================
	// ORGANIZATION ROLES (EXTERNAL USERS)
	// =============================================================================

	// Organization Owner - Full ownership and control of organization
	model.RoleOrganizationOwner: {
		PermissionReadPermission,
		PermissionReadSSO,
		PermissionWriteSSO,

		// Organization management
		PermissionCreateOrganization,
		PermissionViewOrganization,
		PermissionUpdateOrganization,
		PermissionDeleteOrganization,
		PermissionListOrganizations,

		// Advanced organization operations
		PermissionTransferOwnership,
		PermissionDeleteAllData,
		PermissionExportData,
		PermissionManageCompliance,

		// Billing management
		PermissionViewBilling,
		PermissionManageBilling,

		// Full membership control
		PermissionViewInvitations,
		PermissionInviteMembers,
		PermissionViewMembers,
		PermissionManageMembers,
		PermissionRemoveMembers,

		// Organization settings
		PermissionManageSettings,
		PermissionManageIntegrations,
		PermissionManageSSO,

		// API and webhook management
		PermissionReadAPIKeys,
		PermissionWriteAPIKey,
		PermissionDeleteAPIKey,
		PermissionManageAPIKeys,
		PermissionReadWebhooks,
		PermissionWriteWebhook,
		PermissionDeleteWebhook,
		PermissionManageWebhooks,

		// Security and audit
		PermissionViewAuditLogs,
		PermissionReadSessions,
		PermissionDeleteSession,
		PermissionManageSession,
		PermissionReadMFA,
		PermissionWriteMFA,
		PermissionDeleteMFA,
		PermissionManageMFA,

		// Analytics and reporting
		PermissionViewAnalytics,
		PermissionExportUsers,

		// Role management within organization
		PermissionReadRoles,
		PermissionWriteRole,
		PermissionDeleteRole,
		PermissionManageRole,
		PermissionAssignRoles,
		PermissionRevokeRole,

		// User management within organization
		PermissionCreateUser,
		PermissionReadUser,
		PermissionUpdateUser,
		PermissionDeleteUser,
		PermissionListUsers,
		PermissionManageUsers,
		PermissionImpersonateUser,
		PermissionResetPassword,
		PermissionManageUserSession,
		PermissionManageUserMFA,
	},

	// Organization Admin - Administrative access without destructive permissions
	model.RoleOrganizationAdmin: {
		// Basic organization management (no deletion)
		PermissionViewOrganization,
		PermissionUpdateOrganization,

		// Membership management
		PermissionInviteMembers,
		PermissionViewMembers,
		PermissionManageMembers,

		// Settings management
		PermissionManageSettings,
		PermissionManageIntegrations,

		// API and webhook management
		PermissionReadAPIKeys,
		PermissionWriteAPIKey,
		PermissionManageAPIKeys,
		PermissionReadWebhooks,
		PermissionWriteWebhook,
		PermissionManageWebhooks,

		// Security management
		PermissionViewAuditLogs,
		PermissionReadSessions,
		PermissionDeleteSession,
		PermissionManageSession,
		PermissionReadMFA,
		PermissionManageMFA,

		// Analytics
		PermissionViewAnalytics,

		// Role management (limited)
		PermissionReadRoles,
		PermissionAssignRoles,
		PermissionRevokeRole,

		// User management (limited)
		PermissionCreateUser,
		PermissionReadUser,
		PermissionUpdateUser,
		PermissionListUsers,
		PermissionManageUsers,
		PermissionResetPassword,
		PermissionManageUserSession,
		PermissionManageUserMFA,
	},

	// Organization Member - Standard member access
	model.RoleOrganizationMember: {
		// Basic organization access
		PermissionViewOrganization,
		PermissionViewMembers,

		// Limited settings view
		PermissionViewAnalytics,

		// Basic user operations
		PermissionReadUser,
		PermissionListUsers,

		// Basic role viewing
		PermissionReadRoles,
	},

	// Organization Viewer - Read-only access
	model.RoleOrganizationViewer: {
		// Read-only organization access
		PermissionViewOrganization,
		PermissionViewMembers,

		// Basic role viewing
		PermissionReadRoles,
	},

	// =============================================================================
	// APPLICATION ROLES (END USERS)
	// =============================================================================

	// End User Admin - Administrative access for end user management
	model.RoleEndUserAdmin: {
		// Full end user management
		PermissionViewEndUsers,
		PermissionListEndUsers,
		PermissionCreateEndUser,
		PermissionUpdateEndUser,
		PermissionDeleteEndUser,
		PermissionBlockEndUser,
		PermissionManageEndUserSessions,
		PermissionViewEndUserAnalytics,

		// Auth service configuration
		PermissionManageAuthService,
		PermissionConfigureAuthService,
		PermissionViewAuthMetrics,
		PermissionViewAuthServiceAnalytics,
		PermissionManageAuthProvider,
		PermissionManageAuthTemplate,
		PermissionManageAuthDomain,
		PermissionManageAuthServiceDomain,
		PermissionViewAuthLogs,

		// Email template management
		PermissionReadEmailTemplate,
		PermissionWriteEmailTemplate,
		PermissionDeleteEmailTemplate,
		PermissionManageEmailTemplate,

		// Session management for end users
		PermissionReadSessions,
		PermissionDeleteSession,
		PermissionManageSession,

		// Activity management
		PermissionReadActivity,
		PermissionWriteActivity,
		PermissionDeleteActivity,
		PermissionManageActivity,
	},

	// End User - Standard end user access
	model.RoleEndUser: {
		// Basic auth service interaction
		PermissionViewAuthMetrics,
		PermissionViewAuthLogs,

		// Basic activity access
		PermissionReadActivity,

		// Basic template viewing
		PermissionReadEmailTemplate,
	},

	// End User Readonly - Read-only access for end users
	model.RoleEndUserReadonly: {
		// Very limited read access
		PermissionViewAuthLogs,
		PermissionReadActivity,
	},
}

// =============================================================================
// ROLE INHERITANCE MAPPING
// =============================================================================

// DefaultRoleInheritance defines the parent role for each role
var DefaultRoleInheritance = RoleInheritance{
	// System role inheritance
	model.RolePlatformAdmin:   model.RolePlatformSupport,
	model.RolePlatformSupport: "", // No parent, base role

	// Organization role inheritance
	model.RoleOrganizationAdmin:  model.RoleOrganizationMember,
	model.RoleOrganizationMember: model.RoleOrganizationViewer,
	model.RoleOrganizationViewer: "", // No parent, base role

	// Application role inheritance
	model.RoleEndUserAdmin:    model.RoleEndUser,
	model.RoleEndUser:         model.RoleEndUserReadonly,
	model.RoleEndUserReadonly: "", // No parent, base role

	// Top-level roles have no parents
	model.RolePlatformSuperAdmin: "", // No parent, top-level role
	model.RoleOrganizationOwner:  "", // No parent, top-level role
}

// =============================================================================
// SELF-ACCESS PERMISSIONS (AUTOMATICALLY GRANTED TO ALL USERS)
// =============================================================================

// SelfAccessPermissions are automatically granted to all authenticated users
var SelfAccessPermissions = []Permission{
	PermissionViewSelf,
	PermissionUpdateSelf,
	PermissionManageSelf,
	PermissionViewOwnProfile,
	PermissionUpdateOwnProfile,
	PermissionManageOwnMFA,
	PermissionManageOwnSessions,
	PermissionManageOwnAPIKeys,
	PermissionViewOwnAuditLogs,
	PermissionDeleteOwnAccount,
	PermissionExportOwnData,
	PermissionReadPersonalAPIKeys,
	PermissionManagePersonalAPIKeys,
	PermissionReadPersonalSessions,
	PermissionManagePersonalSessions,
	PermissionViewPersonalMFA,
	PermissionManagePersonalMFA,
	PermissionViewPersonalVerifications,
	PermissionManagePersonalVerifications,
	PermissionViewPersonalPasskey,
	PermissionManagePersonalPasskey,
	PermissionViewPersonalOAuth,
	PermissionManagePersonalOAuth,
	PermissionViewPersonalActivity,
	PermissionManagePersonalActivity,
}

// =============================================================================
// INHERITANCE LOGIC
// =============================================================================

// getInheritedPermissions recursively gets all permissions for a role including inherited permissions
func getInheritedPermissions(role model.RoleName, inheritance RoleInheritance, basePerms RolePermissions) []Permission {
	// Start with self-access permissions that all users get
	allPermissions := make([]Permission, len(SelfAccessPermissions))
	copy(allPermissions, SelfAccessPermissions)

	// Get direct permissions for this role
	if directPermissions, exists := basePerms[role]; exists {
		allPermissions = append(allPermissions, directPermissions...)
	}

	// Check if this role inherits from another role
	parentRole, hasParent := inheritance[role]
	if hasParent && parentRole != "" {
		// Get parent permissions recursively
		parentPermissions := getInheritedPermissions(parentRole, inheritance, basePerms)
		allPermissions = append(allPermissions, parentPermissions...)
	}

	// Return unique permissions
	return uniquePermissions(allPermissions)
}

// uniquePermissions removes duplicate permissions from a slice
func uniquePermissions(permissions []Permission) []Permission {
	seen := make(map[Permission]struct{})
	unique := make([]Permission, 0, len(permissions))

	for _, perm := range permissions {
		if _, exists := seen[perm]; !exists {
			seen[perm] = struct{}{}
			unique = append(unique, perm)
		}
	}

	return unique
}

// =============================================================================
// PUBLIC API
// =============================================================================

// GetAllRolePermissions builds the complete role permissions map with inheritance
func GetAllRolePermissions() RolePermissions {
	result := make(RolePermissions)

	// Process each role to build its complete permission set
	for role := range BaseRolePermissions {
		result[role] = getInheritedPermissions(role, DefaultRoleInheritance, BaseRolePermissions)
	}

	// Also process roles that might not have base permissions but have inheritance
	for role := range DefaultRoleInheritance {
		if _, exists := result[role]; !exists {
			result[role] = getInheritedPermissions(role, DefaultRoleInheritance, BaseRolePermissions)
		}
	}

	return result
}

// DefaultRolePermissions defines the complete permissions for each role with inheritance
var DefaultRolePermissions = GetAllRolePermissions()

// GetPermissionsForRole returns all permissions assigned to a specific role
func GetPermissionsForRole(role model.RoleName) []Permission {
	return DefaultRolePermissions[role]
}

// HasRolePermission checks if a specific role has a specific permission
func HasRolePermission(role model.RoleName, permission Permission) bool {
	permissions := DefaultRolePermissions[role]
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// GetRoleHierarchy returns all roles in the inheritance chain for a given role
func GetRoleHierarchy(role model.RoleName) []model.RoleName {
	var hierarchy []model.RoleName
	current := role
	visited := make(map[model.RoleName]bool)

	for {
		// Prevent infinite loops
		if visited[current] {
			break
		}
		visited[current] = true
		hierarchy = append(hierarchy, current)

		// Get parent role
		parent, hasParent := DefaultRoleInheritance[current]
		if !hasParent || parent == "" {
			break
		}
		current = parent
	}

	return hierarchy
}

// GetChildRoles returns all roles that inherit from the given role
func GetChildRoles(role model.RoleName) []model.RoleName {
	var children []model.RoleName
	for childRole, parentRole := range DefaultRoleInheritance {
		if parentRole == role {
			children = append(children, childRole)
		}
	}
	return children
}

// IsRoleHigherThan checks if role1 has higher privileges than role2 based on inheritance
func IsRoleHigherThan(role1, role2 model.RoleName) bool {
	hierarchy2 := GetRoleHierarchy(role2)
	for _, ancestorRole := range hierarchy2 {
		if ancestorRole == role1 {
			return true
		}
	}
	return false
}

// CreateCustomRolePermissions creates a new role permissions map with custom settings
func CreateCustomRolePermissions(customizations map[model.RoleName][]Permission) RolePermissions {
	// Start with the default permissions
	customRolePermissions := make(RolePermissions)

	// Copy default permissions
	for role, perms := range DefaultRolePermissions {
		permissionsCopy := make([]Permission, len(perms))
		copy(permissionsCopy, perms)
		customRolePermissions[role] = permissionsCopy
	}

	// Apply customizations
	for role, perms := range customizations {
		customRolePermissions[role] = perms
	}

	return customRolePermissions
}

// AddPermissionsToRole adds permissions to a role while maintaining inheritance
func AddPermissionsToRole(role model.RoleName, additionalPermissions []Permission) []Permission {
	existingPermissions := GetPermissionsForRole(role)
	combinedPermissions := append(existingPermissions, additionalPermissions...)
	return uniquePermissions(combinedPermissions)
}

// RemovePermissionsFromRole removes permissions from a role (affects only direct permissions)
func RemovePermissionsFromRole(role model.RoleName, permissionsToRemove []Permission) []Permission {
	existingPermissions := GetPermissionsForRole(role)
	removeMap := make(map[Permission]bool)

	for _, perm := range permissionsToRemove {
		removeMap[perm] = true
	}

	var filteredPermissions []Permission
	for _, perm := range existingPermissions {
		if !removeMap[perm] {
			filteredPermissions = append(filteredPermissions, perm)
		}
	}

	return filteredPermissions
}

// ValidateRolePermissions validates that a role's permissions are consistent with its hierarchy
func ValidateRolePermissions(role model.RoleName, permissions []Permission) (bool, []string) {
	var issues []string

	// Check if role exists
	if _, exists := model.RoleDefinitions[role]; !exists {
		issues = append(issues, "Role does not exist")
		return false, issues
	}

	// Check for dangerous permissions in lower-privilege roles
	hierarchy := GetRoleHierarchy(role)
	roleMetadata, _ := role.GetMetadata()

	fmt.Println(roleMetadata.Category)
	fmt.Println(hierarchy)

	for _, perm := range permissions {
		// Check if permission is valid
		if !IsValidPermission(perm.String()) {
			issues = append(issues, "Invalid permission: "+perm.String())
			continue
		}

		// Check user type compatibility (would need access to permission metadata)
		// This would require access to the AllPermissions map from permissions.go
	}

	// Check inheritance consistency
	parentRole, hasParent := DefaultRoleInheritance[role]
	if hasParent && parentRole != "" {
		parentPermissions := GetPermissionsForRole(parentRole)
		parentPermMap := make(map[Permission]bool)
		for _, perm := range parentPermissions {
			parentPermMap[perm] = true
		}

		// Child role should have at least all parent permissions
		for _, perm := range parentPermissions {
			found := false
			for _, childPerm := range permissions {
				if childPerm == perm {
					found = true
					break
				}
			}
			if !found {
				issues = append(issues, "Missing inherited permission: "+perm.String())
			}
		}
	}

	return len(issues) == 0, issues
}

// GetRolePermissionSummary returns a summary of permissions for a role
type RolePermissionSummary struct {
	Role              model.RoleName   `json:"role"`
	DirectPermissions []Permission     `json:"direct_permissions"`
	InheritedFrom     []model.RoleName `json:"inherited_from"`
	TotalPermissions  int              `json:"total_permissions"`
	HighRiskCount     int              `json:"high_risk_count"`
}

// GetRolePermissionSummary returns a detailed summary of a role's permissions
func GetRolePermissionSummary(role model.RoleName) *RolePermissionSummary {
	directPermissions := BaseRolePermissions[role]
	if directPermissions == nil {
		directPermissions = []Permission{}
	}

	hierarchy := GetRoleHierarchy(role)
	totalPermissions := GetPermissionsForRole(role)

	// Count high-risk permissions (would need access to permission metadata)
	highRiskCount := 0
	// for _, perm := range totalPermissions {
	//     if IsDangerousPermission(perm) {
	//         highRiskCount++
	//     }
	// }

	return &RolePermissionSummary{
		Role:              role,
		DirectPermissions: directPermissions,
		InheritedFrom:     hierarchy[1:], // Exclude self
		TotalPermissions:  len(totalPermissions),
		HighRiskCount:     highRiskCount,
	}
}

// =============================================================================
// ROLE PERMISSION HELPERS
// =============================================================================

// GetRolesWithPermission returns all roles that have a specific permission
func GetRolesWithPermission(permission Permission) []model.RoleName {
	var rolesWithPermission []model.RoleName

	for role, permissions := range DefaultRolePermissions {
		for _, perm := range permissions {
			if perm == permission {
				rolesWithPermission = append(rolesWithPermission, role)
				break
			}
		}
	}

	return rolesWithPermission
}

// GetMinimumRoleForPermission returns the lowest-privilege role that has a specific permission
func GetMinimumRoleForPermission(permission Permission, category model.RoleCategory) *model.RoleName {
	rolesWithPermission := GetRolesWithPermission(permission)

	var minRole *model.RoleName
	minPriority := 999

	for _, role := range rolesWithPermission {
		metadata, exists := role.GetMetadata()
		if !exists || metadata.Category != category {
			continue
		}

		if metadata.Priority < minPriority {
			minPriority = metadata.Priority
			minRole = &role
		}
	}

	return minRole
}

// GetPermissionDifference returns permissions in role1 but not in role2
func GetPermissionDifference(role1, role2 model.RoleName) []Permission {
	perms1 := GetPermissionsForRole(role1)
	perms2 := GetPermissionsForRole(role2)

	perms2Map := make(map[Permission]bool)
	for _, perm := range perms2 {
		perms2Map[perm] = true
	}

	var difference []Permission
	for _, perm := range perms1 {
		if !perms2Map[perm] {
			difference = append(difference, perm)
		}
	}

	return difference
}

// GetCommonPermissions returns permissions that both roles have
func GetCommonPermissions(role1, role2 model.RoleName) []Permission {
	perms1 := GetPermissionsForRole(role1)
	perms2 := GetPermissionsForRole(role2)

	perms2Map := make(map[Permission]bool)
	for _, perm := range perms2 {
		perms2Map[perm] = true
	}

	var common []Permission
	for _, perm := range perms1 {
		if perms2Map[perm] {
			common = append(common, perm)
		}
	}

	return common
}
