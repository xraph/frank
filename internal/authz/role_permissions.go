package authz

// RoleType represents the built-in role types in the system
type RoleType string

const (
	RoleSystemAdmin RoleType = "system_admin"
	RoleOwner       RoleType = "owner"
	RoleAdmin       RoleType = "admin"
	RoleMember      RoleType = "member"
	RoleViewer      RoleType = "viewer"
	RoleGuest       RoleType = "guest"
)

// RolePermissions maps roles to their permissions
type RolePermissions map[RoleType][]Permission

// RoleInheritance defines the parent role for each role
type RoleInheritance map[RoleType]RoleType

// DefaultRoleInheritance defines the inheritance hierarchy for roles
var DefaultRoleInheritance = RoleInheritance{
	RoleOwner:  RoleAdmin,  // Owner inherits from Admin
	RoleAdmin:  RoleMember, // Admin inherits from Member
	RoleMember: RoleViewer, // Member inherits from Viewer
	RoleViewer: RoleGuest,  // Viewer inherits from Guest
}

// BaseRolePermissions defines the base permissions for each role (without inheritance)
var BaseRolePermissions = RolePermissions{
	RoleSystemAdmin: {
		// System administrators have all permissions
		PermissionSystemAdmin,
		PermissionManageSystemSettings, PermissionViewSystemSettings,
		PermissionManageAllOrganizations, PermissionViewAllOrganizations,
		PermissionManageAllUsers, PermissionViewAllUsers,
		PermissionManageSystemRoles, PermissionViewSystemRoles,
		PermissionManageSystemPermissions, PermissionManagePermissions,
		PermissionManageSystemEmailTemplates,
	},
	RoleOwner: {
		// Owner-specific permissions (those not in Admin)
		PermissionDeleteOrganization,
		PermissionRemoveMembers,
		PermissionDeleteUser, // Can delete users in their org
	},
	RoleAdmin: {
		// Admin-specific permissions (those not in Member)
		PermissionUpdateOrganization,
		PermissionInviteMembers,
		PermissionRemoveMembers,
		PermissionManageMembers,
		PermissionUpdateUser, PermissionCreateUser,
		PermissionManageAPIKeys, PermissionDeleteAPIKey,
		PermissionManageSessions, PermissionDeleteSession,
		PermissionManageWebhooks, PermissionDeleteWebhook,
		PermissionManageWebhookEvents, PermissionDeleteWebhookEvent,
		PermissionManageEmailTemplates, PermissionDeleteEmailTemplate,
		PermissionManageRoles, PermissionDeleteRole, PermissionAssignRoles,
		PermissionManageMFA, PermissionDeleteMFA,
		PermissionManageVerifications, PermissionDeleteVerification,
	},
	RoleMember: {
		// Member-specific permissions (those not in Viewer)
		PermissionCreateAPIKey, PermissionUpdateAPIKey,
		PermissionCreateWebhook, PermissionUpdateWebhook,
		PermissionCreateWebhookEvent,
		PermissionCreateEmailTemplate, PermissionUpdateEmailTemplate,
		PermissionCreateRole, PermissionUpdateRole,
		PermissionCreateMFA, PermissionUpdateMFA,
		PermissionCreateVerification, PermissionUpdateVerification,
	},
	RoleViewer: {
		// Viewer-specific permissions (those not in Guest)
		PermissionViewOrganization, PermissionViewMembers,
		PermissionViewUser, PermissionListUsers,
		PermissionViewAPIKeys, PermissionListAPIKeys,
		PermissionViewSessions, PermissionListSessions,
		PermissionViewWebhooks, PermissionListWebhooks,
		PermissionViewWebhookEvents, PermissionListWebhookEvents,
		PermissionViewEmailTemplates, PermissionListEmailTemplates,
		PermissionViewRoles, PermissionListRoles,
		PermissionViewPermissions, PermissionListPermissions,
		PermissionViewMFA, PermissionListMFA,
		PermissionViewVerifications, PermissionListVerifications,
	},
	RoleGuest: {
		// Base permissions for all authenticated users
		PermissionViewSelf, PermissionUpdateSelf, PermissionManageSelf,
		PermissionViewPersonalAPIKeys, PermissionManagePersonalAPIKeys,
		PermissionViewPersonalSessions, PermissionManagePersonalSessions,
		PermissionViewPersonalMFA, PermissionManagePersonalMFA,
		PermissionViewPersonalVerifications, PermissionManagePersonalVerifications,
	},
}

// getInheritedPermissions recursively gets all permissions for a role including inherited permissions
func getInheritedPermissions(role RoleType, inheritance RoleInheritance, basePerms RolePermissions) []Permission {
	// Get direct permissions for this role
	directPermissions := basePerms[role]

	// Check if this role inherits from another role
	parentRole, hasParent := inheritance[role]
	if !hasParent {
		// No parent, just return direct permissions
		return directPermissions
	}

	// Get parent permissions recursively
	parentPermissions := getInheritedPermissions(parentRole, inheritance, basePerms)

	// Combine permissions
	allPermissions := make([]Permission, 0, len(directPermissions)+len(parentPermissions))
	allPermissions = append(allPermissions, parentPermissions...)
	allPermissions = append(allPermissions, directPermissions...)

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

// GetAllRolePermissions builds the complete role permissions map with inheritance
func GetAllRolePermissions() RolePermissions {
	result := make(RolePermissions)

	// Process each role to build its complete permission set
	for role := range BaseRolePermissions {
		result[role] = getInheritedPermissions(role, DefaultRoleInheritance, BaseRolePermissions)
	}

	return result
}

// DefaultRolePermissions defines the complete permissions for each role with inheritance
var DefaultRolePermissions = GetAllRolePermissions()

// GetPermissionsForRole returns all permissions assigned to a specific role
func GetPermissionsForRole(role RoleType) []Permission {
	return DefaultRolePermissions[role]
}

// HasRolePermission checks if a specific role has a specific permission
func HasRolePermission(role RoleType, permission Permission) bool {
	permissions := DefaultRolePermissions[role]
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// CreateCustomRolePermissions creates a new role permissions map with custom settings
func CreateCustomRolePermissions(customizations map[RoleType][]Permission) RolePermissions {
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
