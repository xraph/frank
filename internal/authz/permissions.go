package authz

import (
	"strings"

	"github.com/xraph/frank/pkg/model"
)

// ================================
// PERMISSION ACTIONS
// ================================

type PermissionAction string

const (
	ActionWrite      PermissionAction = "write"
	ActionRead       PermissionAction = "read"
	ActionUpdate     PermissionAction = "update"
	ActionDelete     PermissionAction = "delete"
	ActionList       PermissionAction = "list"
	ActionView       PermissionAction = "view"
	ActionManage     PermissionAction = "manage"
	ActionAdmin      PermissionAction = "admin"
	ActionAssign     PermissionAction = "assign"
	ActionRevoke     PermissionAction = "revoke"
	ActionInvite     PermissionAction = "invite"
	ActionRemove     PermissionAction = "remove"
	ActionExecute    PermissionAction = "execute"
	ActionExport     PermissionAction = "export"
	ActionImport     PermissionAction = "import"
	ActionTransfer   PermissionAction = "transfer"
	ActionSuspend    PermissionAction = "suspend"
	ActionActivate   PermissionAction = "activate"
	ActionDeactivate PermissionAction = "deactivate"
)

// ================================
// ENHANCED PERMISSION DEFINITIONS
// ================================

// PermissionDefinition provides complete metadata for a permission
type PermissionDefinition struct {
	Name            string                   `json:"name"`
	DisplayName     string                   `json:"display_name"`
	Description     string                   `json:"description"`
	Resource        model.ResourceType       `json:"resource"`
	Action          PermissionAction         `json:"action"`
	Category        model.PermissionCategory `json:"category"`
	Group           model.PermissionGroup    `json:"group"`
	RiskLevel       int                      `json:"risk_level"`       // 1-5, 5 being highest risk
	Dangerous       bool                     `json:"dangerous"`        // Requires special handling
	System          bool                     `json:"system"`           // System-managed permission
	UserTypes       []model.UserType         `json:"user_types"`       // Applicable user types
	RequiredContext []model.ContextType      `json:"required_context"` // Required contexts
	Dependencies    []Permission             `json:"dependencies"`     // Permission dependencies
	ConflictsWith   []Permission             `json:"conflicts_with"`   // Conflicting permissions
	Tags            []string                 `json:"tags"`             // Additional metadata tags
}

// ================================
// COMPREHENSIVE PERMISSION CATALOG
// ================================

var AllPermissions = map[Permission]PermissionDefinition{
	// ================================
	// ORGANIZATION MANAGEMENT
	// ================================
	PermissionCreateOrganization: {
		Name:            string(PermissionCreateOrganization),
		DisplayName:     "Create Organization",
		Description:     "Create new organizations in the system",
		Resource:        model.ResourceSystem,
		Action:          ActionWrite,
		Category:        model.PermissionCategoryOrganization,
		Group:           model.GroupOrganizationManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Tags:            []string{"creation", "organization"},
	},
	PermissionViewOrganization: {
		Name:            string(PermissionViewOrganization),
		DisplayName:     "View Organization",
		Description:     "View organization details, settings, and metadata",
		Resource:        model.ResourceOrganization,
		Action:          ActionView,
		Category:        model.PermissionCategoryOrganization,
		Group:           model.GroupOrganizationManagement,
		RiskLevel:       1,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"read", "organization"},
	},
	PermissionUpdateOrganization: {
		Name:            string(PermissionUpdateOrganization),
		DisplayName:     "Update Organization",
		Description:     "Update organization details, settings, and configuration",
		Resource:        model.ResourceOrganization,
		Action:          ActionUpdate,
		Category:        model.PermissionCategoryOrganization,
		Group:           model.GroupOrganizationManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewOrganization},
		Tags:            []string{"modification", "organization"},
	},
	PermissionDeleteOrganization: {
		Name:            string(PermissionDeleteOrganization),
		DisplayName:     "Delete Organization",
		Description:     "Permanently delete organizations and all associated data",
		Resource:        model.ResourceOrganization,
		Action:          ActionDelete,
		Category:        model.PermissionCategoryOrganization,
		Group:           model.GroupOrganizationManagement,
		RiskLevel:       5,
		Dangerous:       true,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewOrganization, PermissionUpdateOrganization},
		Tags:            []string{"destructive", "organization", "permanent"},
	},
	PermissionListOrganizations: {
		Name:            string(PermissionListOrganizations),
		DisplayName:     "List Organizations",
		Description:     "List organizations the user has access to",
		Resource:        model.ResourceSystem,
		Action:          ActionList,
		Category:        model.PermissionCategoryOrganization,
		Group:           model.GroupOrganizationManagement,
		RiskLevel:       1,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Tags:            []string{"enumeration", "organization"},
	},

	// ================================
	// MEMBERSHIP MANAGEMENT
	// ================================
	PermissionInviteMembers: {
		Name:            string(PermissionInviteMembers),
		DisplayName:     "Invite Members",
		Description:     "Invite new members to join the organization",
		Resource:        model.ResourceOrganization,
		Action:          ActionInvite,
		Category:        model.PermissionCategoryMembership,
		Group:           model.GroupMembershipManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewMembers},
		Tags:            []string{"invitation", "membership"},
	},
	PermissionViewMembers: {
		Name:            string(PermissionViewMembers),
		DisplayName:     "View Members",
		Description:     "View organization members, their roles, and membership details",
		Resource:        model.ResourceOrganization,
		Action:          ActionView,
		Category:        model.PermissionCategoryMembership,
		Group:           model.GroupMembershipManagement,
		RiskLevel:       1,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"read", "membership"},
	},
	PermissionManageMembers: {
		Name:            string(PermissionManageMembers),
		DisplayName:     "Manage Members",
		Description:     "Update member roles, permissions, and membership settings",
		Resource:        model.ResourceOrganization,
		Action:          ActionManage,
		Category:        model.PermissionCategoryMembership,
		Group:           model.GroupMembershipManagement,
		RiskLevel:       3,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewMembers},
		Tags:            []string{"modification", "membership", "roles"},
	},
	PermissionRemoveMembers: {
		Name:            string(PermissionRemoveMembers),
		DisplayName:     "Remove Members",
		Description:     "Remove members from the organization",
		Resource:        model.ResourceOrganization,
		Action:          ActionRemove,
		Category:        model.PermissionCategoryMembership,
		Group:           model.GroupMembershipManagement,
		RiskLevel:       4,
		Dangerous:       true,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewMembers, PermissionManageMembers},
		Tags:            []string{"removal", "membership", "destructive"},
	},

	// ================================
	// USER MANAGEMENT
	// ================================
	PermissionCreateUser: {
		Name:            string(PermissionCreateUser),
		DisplayName:     "Create User",
		Description:     "Create new user accounts in the organization",
		Resource:        model.ResourceUser,
		Action:          ActionWrite,
		Category:        model.PermissionCategoryUserManagement,
		Group:           model.GroupUserManagement,
		RiskLevel:       3,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"creation", "user"},
	},
	PermissionReadUser: {
		Name:            string(PermissionReadUser),
		DisplayName:     "Read User",
		Description:     "View user profiles, details, and account information",
		Resource:        model.ResourceUser,
		Action:          ActionRead,
		Category:        model.PermissionCategoryUserManagement,
		Group:           model.GroupUserManagement,
		RiskLevel:       1,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"read", "user"},
	},
	PermissionUpdateUser: {
		Name:            string(PermissionUpdateUser),
		DisplayName:     "Update User",
		Description:     "Update user profiles, settings, and account details",
		Resource:        model.ResourceUser,
		Action:          ActionUpdate,
		Category:        model.PermissionCategoryUserManagement,
		Group:           model.GroupUserManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionReadUser},
		Tags:            []string{"modification", "user"},
	},
	PermissionDeleteUser: {
		Name:            string(PermissionDeleteUser),
		DisplayName:     "Delete User",
		Description:     "Permanently delete user accounts and associated data",
		Resource:        model.ResourceUser,
		Action:          ActionDelete,
		Category:        model.PermissionCategoryUserManagement,
		Group:           model.GroupUserManagement,
		RiskLevel:       4,
		Dangerous:       true,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionReadUser, PermissionUpdateUser},
		Tags:            []string{"destructive", "user", "permanent"},
	},
	PermissionListUsers: {
		Name:            string(PermissionListUsers),
		DisplayName:     "List Users",
		Description:     "List and search users in the organization",
		Resource:        model.ResourceUser,
		Action:          ActionList,
		Category:        model.PermissionCategoryUserManagement,
		Group:           model.GroupUserManagement,
		RiskLevel:       1,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"enumeration", "user"},
	},

	// ================================
	// SELF-ACCESS PERMISSIONS
	// ================================
	PermissionViewSelf: {
		Name:            string(PermissionViewSelf),
		DisplayName:     "View Own Profile",
		Description:     "View own user profile, settings, and account information",
		Resource:        model.ResourceUser,
		Action:          ActionView,
		Category:        model.PermissionCategorySelfAccess,
		Group:           model.GroupSelfAccess,
		RiskLevel:       1,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal, model.UserTypeEndUser},
		RequiredContext: []model.ContextType{model.ContextSelf},
		Tags:            []string{"self", "profile", "basic"},
	},
	PermissionUpdateSelf: {
		Name:            string(PermissionUpdateSelf),
		DisplayName:     "Update Own Profile",
		Description:     "Update own user profile, settings, and preferences",
		Resource:        model.ResourceUser,
		Action:          ActionUpdate,
		Category:        model.PermissionCategorySelfAccess,
		Group:           model.GroupSelfAccess,
		RiskLevel:       1,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal, model.UserTypeEndUser},
		RequiredContext: []model.ContextType{model.ContextSelf},
		Dependencies:    []Permission{PermissionViewSelf},
		Tags:            []string{"self", "profile", "modification"},
	},
	PermissionDeleteSelf: {
		Name:            string(PermissionDeleteSelf),
		DisplayName:     "Delete Own Account",
		Description:     "Delete own user account and associated data",
		Resource:        model.ResourceUser,
		Action:          ActionDelete,
		Category:        model.PermissionCategorySelfAccess,
		Group:           model.GroupSelfAccess,
		RiskLevel:       3,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal, model.UserTypeEndUser},
		RequiredContext: []model.ContextType{model.ContextSelf},
		Dependencies:    []Permission{PermissionViewSelf, PermissionUpdateSelf},
		Tags:            []string{"self", "destructive", "account"},
	},

	// ================================
	// API KEY MANAGEMENT
	// ================================
	PermissionReadAPIKeys: {
		Name:            string(PermissionReadAPIKeys),
		DisplayName:     "View API Keys",
		Description:     "View organization API keys and their metadata",
		Resource:        model.ResourceAPIKey,
		Action:          ActionView,
		Category:        model.PermissionCategoryAPIManagement,
		Group:           model.GroupAPIManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"api", "keys", "integration"},
	},
	PermissionWriteAPIKey: {
		Name:            string(PermissionWriteAPIKey),
		DisplayName:     "Write API Key",
		Description:     "Create new and update API keys for organization integration",
		Resource:        model.ResourceAPIKey,
		Action:          ActionWrite,
		Category:        model.PermissionCategoryAPIManagement,
		Group:           model.GroupAPIManagement,
		RiskLevel:       3,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionReadAPIKeys},
		Tags:            []string{"api", "keys", "creation"},
	},
	PermissionDeleteAPIKey: {
		Name:            string(PermissionDeleteAPIKey),
		DisplayName:     "Delete API Key",
		Description:     "Delete organization API keys",
		Resource:        model.ResourceAPIKey,
		Action:          ActionDelete,
		Category:        model.PermissionCategoryAPIManagement,
		Group:           model.GroupAPIManagement,
		RiskLevel:       3,
		Dangerous:       true,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionReadAPIKeys},
		Tags:            []string{"api", "keys", "destructive"},
	},
	PermissionReadPersonalAPIKeys: {
		Name:            string(PermissionReadPersonalAPIKeys),
		DisplayName:     "View Personal API Keys",
		Description:     "View own personal API keys",
		Resource:        model.ResourceAPIKey,
		Action:          ActionView,
		Category:        model.PermissionCategorySelfAccess,
		Group:           model.GroupSelfAccess,
		RiskLevel:       1,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal, model.UserTypeEndUser},
		RequiredContext: []model.ContextType{model.ContextSelf},
		Tags:            []string{"self", "api", "keys"},
	},
	PermissionManagePersonalAPIKeys: {
		Name:            string(PermissionManagePersonalAPIKeys),
		DisplayName:     "Manage Personal API Keys",
		Description:     "Create, update, and delete own personal API keys",
		Resource:        model.ResourceAPIKey,
		Action:          ActionManage,
		Category:        model.PermissionCategorySelfAccess,
		Group:           model.GroupSelfAccess,
		RiskLevel:       2,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal, model.UserTypeEndUser},
		RequiredContext: []model.ContextType{model.ContextSelf},
		Dependencies:    []Permission{PermissionReadPersonalAPIKeys},
		Tags:            []string{"self", "api", "keys", "management"},
	},

	// ================================
	// RBAC PERMISSIONS
	// ================================
	PermissionReadRoles: {
		Name:            string(PermissionReadRoles),
		DisplayName:     "View Roles",
		Description:     "View roles and their permissions in the organization",
		Resource:        model.ResourceRole,
		Action:          ActionView,
		Category:        model.PermissionCategoryRBAC,
		Group:           model.GroupRBACManagement,
		RiskLevel:       1,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"rbac", "roles"},
	},
	PermissionWriteRole: {
		Name:            string(PermissionWriteRole),
		DisplayName:     "Write Role",
		Description:     "Create new roles and define their permissions and also update them",
		Resource:        model.ResourceRole,
		Action:          ActionWrite,
		Category:        model.PermissionCategoryRBAC,
		Group:           model.GroupRBACManagement,
		RiskLevel:       3,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionReadRoles},
		Tags:            []string{"rbac", "roles", "write"},
	},
	PermissionDeleteRole: {
		Name:            string(PermissionDeleteRole),
		DisplayName:     "Delete Role",
		Description:     "Delete roles from the organization",
		Resource:        model.ResourceRole,
		Action:          ActionDelete,
		Category:        model.PermissionCategoryRBAC,
		Group:           model.GroupRBACManagement,
		RiskLevel:       4,
		Dangerous:       true,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionReadRoles, PermissionWriteRole},
		Tags:            []string{"rbac", "roles", "destructive"},
	},
	PermissionAssignRoles: {
		Name:            string(PermissionAssignRoles),
		DisplayName:     "Assign Roles",
		Description:     "Assign and revoke roles to/from users",
		Resource:        model.ResourceRole,
		Action:          ActionAssign,
		Category:        model.PermissionCategoryRBAC,
		Group:           model.GroupRBACManagement,
		RiskLevel:       3,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionReadRoles, PermissionReadUser},
		Tags:            []string{"rbac", "roles", "assignment"},
	},

	// ================================
	// SYSTEM ADMIN PERMISSIONS
	// ================================
	PermissionSystemAdmin: {
		Name:            string(PermissionSystemAdmin),
		DisplayName:     "System Administrator",
		Description:     "Full system administrative access with all privileges",
		Resource:        model.ResourceSystem,
		Action:          ActionAdmin,
		Category:        model.PermissionCategorySystem,
		Group:           model.GroupSystemAdministration,
		RiskLevel:       5,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Tags:            []string{"system", "admin", "super", "dangerous"},
	},
	PermissionManageSystemSettings: {
		Name:            string(PermissionManageSystemSettings),
		DisplayName:     "Manage System Settings",
		Description:     "Manage global system configuration and settings",
		Resource:        model.ResourceSystem,
		Action:          ActionManage,
		Category:        model.PermissionCategorySystem,
		Group:           model.GroupSystemAdministration,
		RiskLevel:       4,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Tags:            []string{"system", "settings", "configuration"},
	},
	PermissionViewAllOrganizations: {
		Name:            string(PermissionViewAllOrganizations),
		DisplayName:     "View All Organizations",
		Description:     "View all organizations across the entire platform",
		Resource:        model.ResourceSystem,
		Action:          ActionView,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Tags:            []string{"platform", "organizations", "global"},
	},
	PermissionManageAllOrganizations: {
		Name:            string(PermissionManageAllOrganizations),
		DisplayName:     "Manage All Organizations",
		Description:     "Manage all organizations across the entire platform",
		Resource:        model.ResourceSystem,
		Action:          ActionManage,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       4,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewAllOrganizations},
		Tags:            []string{"platform", "organizations", "global", "management"},
	},
	PermissionViewAllUsers: {
		Name:            string(PermissionViewAllUsers),
		DisplayName:     "View All Users",
		Description:     "View all users across the entire platform",
		Resource:        model.ResourceSystem,
		Action:          ActionView,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Tags:            []string{"platform", "users", "global"},
	},
	PermissionManageAllUsers: {
		Name:            string(PermissionManageAllUsers),
		DisplayName:     "Manage All Users",
		Description:     "Manage all users across the entire platform",
		Resource:        model.ResourceSystem,
		Action:          ActionManage,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       4,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewAllUsers},
		Tags:            []string{"platform", "users", "global", "management"},
	},

	// ================================
	// SESSION MANAGEMENT
	// ================================
	PermissionReadSessions: {
		Name:            string(PermissionReadSessions),
		DisplayName:     "View Sessions",
		Description:     "View active user sessions in the organization",
		Resource:        model.ResourceSession,
		Action:          ActionView,
		Category:        model.PermissionCategorySecurity,
		Group:           model.GroupSecurityManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"security", "sessions"},
	},
	PermissionDeleteSession: {
		Name:            string(PermissionDeleteSession),
		DisplayName:     "Delete Session",
		Description:     "Terminate user sessions in the organization",
		Resource:        model.ResourceSession,
		Action:          ActionDelete,
		Category:        model.PermissionCategorySecurity,
		Group:           model.GroupSecurityManagement,
		RiskLevel:       3,
		Dangerous:       true,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionReadSessions},
		Tags:            []string{"security", "sessions", "termination"},
	},
	PermissionReadPersonalSessions: {
		Name:            string(PermissionReadPersonalSessions),
		DisplayName:     "View Personal Sessions",
		Description:     "View own active sessions",
		Resource:        model.ResourceSession,
		Action:          ActionView,
		Category:        model.PermissionCategorySelfAccess,
		Group:           model.GroupSelfAccess,
		RiskLevel:       1,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal, model.UserTypeEndUser},
		RequiredContext: []model.ContextType{model.ContextSelf},
		Tags:            []string{"self", "sessions"},
	},
	PermissionManagePersonalSessions: {
		Name:            string(PermissionManagePersonalSessions),
		DisplayName:     "Manage Personal Sessions",
		Description:     "Manage and terminate own active sessions",
		Resource:        model.ResourceSession,
		Action:          ActionManage,
		Category:        model.PermissionCategorySelfAccess,
		Group:           model.GroupSelfAccess,
		RiskLevel:       2,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal, model.UserTypeEndUser},
		RequiredContext: []model.ContextType{model.ContextSelf},
		Dependencies:    []Permission{PermissionReadPersonalSessions},
		Tags:            []string{"self", "sessions", "management"},
	},

	// ================================
	// MFA PERMISSIONS
	// ================================
	PermissionReadMFA: {
		Name:            string(PermissionReadMFA),
		DisplayName:     "View MFA",
		Description:     "View MFA settings and status for organization users",
		Resource:        model.ResourceMFA,
		Action:          ActionView,
		Category:        model.PermissionCategorySecurity,
		Group:           model.GroupSecurityManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"security", "mfa", "authentication"},
	},
	PermissionManageMFA: {
		Name:            string(PermissionManageMFA),
		DisplayName:     "Manage MFA",
		Description:     "Manage MFA settings and requirements for organization users",
		Resource:        model.ResourceMFA,
		Action:          ActionManage,
		Category:        model.PermissionCategorySecurity,
		Group:           model.GroupSecurityManagement,
		RiskLevel:       3,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionReadMFA},
		Tags:            []string{"security", "mfa", "authentication", "policy"},
	},
	PermissionViewPersonalMFA: {
		Name:            string(PermissionViewPersonalMFA),
		DisplayName:     "View Personal MFA",
		Description:     "View own MFA settings and enrolled devices",
		Resource:        model.ResourceMFA,
		Action:          ActionView,
		Category:        model.PermissionCategorySelfAccess,
		Group:           model.GroupSelfAccess,
		RiskLevel:       1,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal, model.UserTypeEndUser},
		RequiredContext: []model.ContextType{model.ContextSelf},
		Tags:            []string{"self", "mfa", "authentication"},
	},
	PermissionManagePersonalMFA: {
		Name:            string(PermissionManagePersonalMFA),
		DisplayName:     "Manage Personal MFA",
		Description:     "Manage own MFA settings and enrolled devices",
		Resource:        model.ResourceMFA,
		Action:          ActionManage,
		Category:        model.PermissionCategorySelfAccess,
		Group:           model.GroupSelfAccess,
		RiskLevel:       2,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal, model.UserTypeExternal, model.UserTypeEndUser},
		RequiredContext: []model.ContextType{model.ContextSelf},
		Dependencies:    []Permission{PermissionViewPersonalMFA},
		Tags:            []string{"self", "mfa", "authentication", "devices"},
	},

	// ================================
	// WEBHOOK PERMISSIONS
	// ================================
	PermissionReadWebhooks: {
		Name:            string(PermissionReadWebhooks),
		DisplayName:     "View Webhooks",
		Description:     "View organization webhooks and their configurations",
		Resource:        model.ResourceWebhook,
		Action:          ActionView,
		Category:        model.PermissionCategoryIntegration,
		Group:           model.GroupIntegrationManagement,
		RiskLevel:       1,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"integration", "webhooks"},
	},
	PermissionWriteWebhook: {
		Name:            string(PermissionWriteWebhook),
		DisplayName:     "Create Webhook",
		Description:     "Create new webhooks for organization integrations",
		Resource:        model.ResourceWebhook,
		Action:          ActionWrite,
		Category:        model.PermissionCategoryIntegration,
		Group:           model.GroupIntegrationManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionReadWebhooks},
		Tags:            []string{"integration", "webhooks", "creation"},
	},
	PermissionDeleteWebhook: {
		Name:            string(PermissionDeleteWebhook),
		DisplayName:     "Delete Webhook",
		Description:     "Delete organization webhooks",
		Resource:        model.ResourceWebhook,
		Action:          ActionDelete,
		Category:        model.PermissionCategoryIntegration,
		Group:           model.GroupIntegrationManagement,
		RiskLevel:       3,
		Dangerous:       true,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionReadWebhooks},
		Tags:            []string{"integration", "webhooks", "destructive"},
	},

	// ================================
	// AUDIT PERMISSIONS
	// ================================
	PermissionViewAuditLogs: {
		Name:            string(PermissionViewAuditLogs),
		DisplayName:     "View Audit Logs",
		Description:     "View organization audit logs and security events",
		Resource:        model.ResourceAudit,
		Action:          ActionView,
		Category:        model.PermissionCategorySecurity,
		Group:           model.GroupSecurityManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"security", "audit", "logs", "compliance"},
	},

	// ================================
	// END USER MANAGEMENT PERMISSIONS
	// ================================
	PermissionViewEndUsers: {
		Name:            string(PermissionViewEndUsers),
		DisplayName:     "View End Users",
		Description:     "View end users of the auth service",
		Resource:        model.ResourceEndUser,
		Action:          ActionView,
		Category:        model.PermissionCategoryUserManagement,
		Group:           model.GroupUserManagement,
		RiskLevel:       1,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Tags:            []string{"end_users", "auth_service"},
	},
	PermissionListEndUsers: {
		Name:            string(PermissionListEndUsers),
		DisplayName:     "List End Users",
		Description:     "List and search end users of the auth service",
		Resource:        model.ResourceEndUser,
		Action:          ActionList,
		Category:        model.PermissionCategoryUserManagement,
		Group:           model.GroupUserManagement,
		RiskLevel:       1,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewEndUsers},
		Tags:            []string{"end_users", "auth_service", "enumeration"},
	},
	PermissionCreateEndUser: {
		Name:            string(PermissionCreateEndUser),
		DisplayName:     "Create End User",
		Description:     "Create new end users in the auth service",
		Resource:        model.ResourceEndUser,
		Action:          ActionWrite,
		Category:        model.PermissionCategoryUserManagement,
		Group:           model.GroupUserManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewEndUsers},
		Tags:            []string{"end_users", "auth_service", "creation"},
	},
	PermissionUpdateEndUser: {
		Name:            string(PermissionUpdateEndUser),
		DisplayName:     "Update End User",
		Description:     "Update end user profiles and settings",
		Resource:        model.ResourceEndUser,
		Action:          ActionUpdate,
		Category:        model.PermissionCategoryUserManagement,
		Group:           model.GroupUserManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewEndUsers},
		Tags:            []string{"end_users", "auth_service", "modification"},
	},
	PermissionDeleteEndUser: {
		Name:            string(PermissionDeleteEndUser),
		DisplayName:     "Delete End User",
		Description:     "Delete end users from the auth service",
		Resource:        model.ResourceEndUser,
		Action:          ActionDelete,
		Category:        model.PermissionCategoryUserManagement,
		Group:           model.GroupUserManagement,
		RiskLevel:       4,
		Dangerous:       true,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewEndUsers, PermissionUpdateEndUser},
		Tags:            []string{"end_users", "auth_service", "destructive"},
	},
	PermissionBlockEndUser: {
		Name:            string(PermissionBlockEndUser),
		DisplayName:     "Block End User",
		Description:     "Block or suspend end users from accessing the auth service",
		Resource:        model.ResourceEndUser,
		Action:          ActionSuspend,
		Category:        model.PermissionCategorySecurity,
		Group:           model.GroupSecurityManagement,
		RiskLevel:       3,
		Dangerous:       true,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewEndUsers, PermissionUpdateEndUser},
		Tags:            []string{"end_users", "auth_service", "security", "blocking"},
	},
	PermissionManageEndUserSessions: {
		Name:            string(PermissionManageEndUserSessions),
		DisplayName:     "Manage End User Sessions",
		Description:     "Manage active sessions for end users",
		Resource:        model.ResourceSession,
		Action:          ActionManage,
		Category:        model.PermissionCategorySecurity,
		Group:           model.GroupSecurityManagement,
		RiskLevel:       3,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewEndUsers, PermissionReadSessions},
		Tags:            []string{"end_users", "sessions", "security"},
	},
	PermissionViewEndUserAnalytics: {
		Name:            string(PermissionViewEndUserAnalytics),
		DisplayName:     "View End User Analytics",
		Description:     "View analytics and metrics for end users",
		Resource:        model.ResourceAnalytics,
		Action:          ActionView,
		Category:        model.PermissionCategoryAnalytics,
		Group:           model.GroupAnalyticsAccess,
		RiskLevel:       1,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewEndUsers},
		Tags:            []string{"end_users", "analytics", "metrics"},
	},

	// ================================
	// AUTH SERVICE CONFIGURATION PERMISSIONS
	// ================================
	PermissionConfigureAuthService: {
		Name:            string(PermissionConfigureAuthService),
		DisplayName:     "Configure Auth Service",
		Description:     "Configure and manage auth service settings",
		Resource:        model.ResourceApplication,
		Action:          ActionManage,
		Category:        model.PermissionCategorySystem,
		Group:           model.GroupSystemAdministration,
		RiskLevel:       3,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewOrganization},
		Tags:            []string{"auth_service", "configuration"},
	},
	PermissionViewAuthServiceAnalytics: {
		Name:            string(PermissionViewAuthServiceAnalytics),
		DisplayName:     "View Auth Service Analytics",
		Description:     "View analytics and metrics for the auth service",
		Resource:        model.ResourceAnalytics,
		Action:          ActionView,
		Category:        model.PermissionCategoryAnalytics,
		Group:           model.GroupAnalyticsAccess,
		RiskLevel:       1,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionViewOrganization},
		Tags:            []string{"auth_service", "analytics", "metrics"},
	},
	PermissionManageAuthServiceDomain: {
		Name:            string(PermissionManageAuthServiceDomain),
		DisplayName:     "Manage Auth Service Domain",
		Description:     "Manage custom domains for the auth service",
		Resource:        model.ResourceApplication,
		Action:          ActionManage,
		Category:        model.PermissionCategoryIntegration,
		Group:           model.GroupIntegrationManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          false,
		UserTypes:       []model.UserType{model.UserTypeExternal},
		RequiredContext: []model.ContextType{model.ContextOrganization},
		Dependencies:    []Permission{PermissionConfigureAuthService},
		Tags:            []string{"auth_service", "domain", "dns"},
	},

	// ================================
	// INTERNAL USER MANAGEMENT PERMISSIONS
	// ================================
	PermissionViewInternalUsers: {
		Name:            string(PermissionViewInternalUsers),
		DisplayName:     "View Internal Users",
		Description:     "View internal platform staff users",
		Resource:        model.ResourceUser,
		Action:          ActionView,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Tags:            []string{"internal_users", "platform", "staff"},
	},
	PermissionCreateInternalUser: {
		Name:            string(PermissionCreateInternalUser),
		DisplayName:     "Create Internal User",
		Description:     "Create new internal platform staff users",
		Resource:        model.ResourceUser,
		Action:          ActionWrite,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       4,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewInternalUsers},
		Tags:            []string{"internal_users", "platform", "staff", "creation"},
	},
	PermissionUpdateInternalUser: {
		Name:            string(PermissionUpdateInternalUser),
		DisplayName:     "Update Internal User",
		Description:     "Update internal platform staff user details",
		Resource:        model.ResourceUser,
		Action:          ActionUpdate,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       3,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewInternalUsers},
		Tags:            []string{"internal_users", "platform", "staff", "modification"},
	},
	PermissionDeleteInternalUser: {
		Name:            string(PermissionDeleteInternalUser),
		DisplayName:     "Delete Internal User",
		Description:     "Delete internal platform staff users",
		Resource:        model.ResourceUser,
		Action:          ActionDelete,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       5,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewInternalUsers, PermissionUpdateInternalUser},
		Tags:            []string{"internal_users", "platform", "staff", "destructive"},
	},
	PermissionManageInternalUsers: {
		Name:            string(PermissionManageInternalUsers),
		DisplayName:     "Manage Internal Users",
		Description:     "Full management access for internal platform staff users",
		Resource:        model.ResourceUser,
		Action:          ActionManage,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       4,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewInternalUsers, PermissionCreateInternalUser, PermissionUpdateInternalUser},
		Tags:            []string{"internal_users", "platform", "staff", "management"},
	},

	// ================================
	// CUSTOMER ORGANIZATION MANAGEMENT PERMISSIONS
	// ================================
	PermissionViewCustomerOrganizations: {
		Name:            string(PermissionViewCustomerOrganizations),
		DisplayName:     "View Customer Organizations",
		Description:     "View customer organizations across the platform",
		Resource:        model.ResourceOrganization,
		Action:          ActionView,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewAllOrganizations},
		Tags:            []string{"customer_organizations", "platform"},
	},
	PermissionCreateCustomerOrganization: {
		Name:            string(PermissionCreateCustomerOrganization),
		DisplayName:     "Create Customer Organization",
		Description:     "Create new customer organizations on the platform",
		Resource:        model.ResourceOrganization,
		Action:          ActionWrite,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       3,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewCustomerOrganizations},
		Tags:            []string{"customer_organizations", "platform", "creation"},
	},
	PermissionUpdateCustomerOrganization: {
		Name:            string(PermissionUpdateCustomerOrganization),
		DisplayName:     "Update Customer Organization",
		Description:     "Update customer organization details and settings",
		Resource:        model.ResourceOrganization,
		Action:          ActionUpdate,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       3,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewCustomerOrganizations},
		Tags:            []string{"customer_organizations", "platform", "modification"},
	},
	PermissionDeleteCustomerOrganization: {
		Name:            string(PermissionDeleteCustomerOrganization),
		DisplayName:     "Delete Customer Organization",
		Description:     "Delete customer organizations from the platform",
		Resource:        model.ResourceOrganization,
		Action:          ActionDelete,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       5,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewCustomerOrganizations, PermissionUpdateCustomerOrganization},
		Tags:            []string{"customer_organizations", "platform", "destructive"},
	},
	PermissionManageCustomerOrganizations: {
		Name:            string(PermissionManageCustomerOrganizations),
		DisplayName:     "Manage Customer Organizations",
		Description:     "Full management access for customer organizations",
		Resource:        model.ResourceOrganization,
		Action:          ActionManage,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       4,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewCustomerOrganizations, PermissionCreateCustomerOrganization, PermissionUpdateCustomerOrganization},
		Tags:            []string{"customer_organizations", "platform", "management"},
	},

	// ================================
	// ENHANCED PLATFORM PERMISSIONS
	// ================================
	PermissionManagePlatform: {
		Name:            string(PermissionManagePlatform),
		DisplayName:     "Manage Platform",
		Description:     "Full platform management access",
		Resource:        model.ResourceSystem,
		Action:          ActionManage,
		Category:        model.PermissionCategorySystem,
		Group:           model.GroupSystemAdministration,
		RiskLevel:       5,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionSystemAdmin},
		Tags:            []string{"platform", "management", "super"},
	},
	PermissionViewPlatformMetrics: {
		Name:            string(PermissionViewPlatformMetrics),
		DisplayName:     "View Platform Metrics",
		Description:     "View platform-wide metrics and analytics",
		Resource:        model.ResourceAnalytics,
		Action:          ActionView,
		Category:        model.PermissionCategoryAnalytics,
		Group:           model.GroupAnalyticsAccess,
		RiskLevel:       2,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Tags:            []string{"platform", "metrics", "analytics"},
	},
	PermissionViewAllCustomers: {
		Name:            string(PermissionViewAllCustomers),
		DisplayName:     "View All Customers",
		Description:     "View all customer data across the platform",
		Resource:        model.ResourceSystem,
		Action:          ActionView,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       2,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewAllOrganizations},
		Tags:            []string{"customers", "platform", "global"},
	},
	PermissionManageCustomerBilling: {
		Name:            string(PermissionManageCustomerBilling),
		DisplayName:     "Manage Customer Billing",
		Description:     "Manage billing for customer organizations",
		Resource:        model.ResourceBilling,
		Action:          ActionManage,
		Category:        model.PermissionCategoryBilling,
		Group:           model.GroupBillingManagement,
		RiskLevel:       4,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewAllCustomers},
		Tags:            []string{"billing", "customers", "financial"},
	},
	PermissionSuspendCustomer: {
		Name:            string(PermissionSuspendCustomer),
		DisplayName:     "Suspend Customer",
		Description:     "Suspend customer organizations and their services",
		Resource:        model.ResourceOrganization,
		Action:          ActionSuspend,
		Category:        model.PermissionCategoryPlatformManagement,
		Group:           model.GroupPlatformManagement,
		RiskLevel:       4,
		Dangerous:       true,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewAllCustomers, PermissionManageCustomerOrganizations},
		Tags:            []string{"suspension", "customers", "enforcement"},
	},
	PermissionViewPlatformAnalytics: {
		Name:            string(PermissionViewPlatformAnalytics),
		DisplayName:     "View Platform Analytics",
		Description:     "View comprehensive platform analytics and reporting",
		Resource:        model.ResourceAnalytics,
		Action:          ActionView,
		Category:        model.PermissionCategoryAnalytics,
		Group:           model.GroupAnalyticsAccess,
		RiskLevel:       2,
		Dangerous:       false,
		System:          true,
		UserTypes:       []model.UserType{model.UserTypeInternal},
		RequiredContext: []model.ContextType{model.ContextPlatform},
		Dependencies:    []Permission{PermissionViewPlatformMetrics},
		Tags:            []string{"platform", "analytics", "reporting"},
	},
}

// ================================
// PERMISSION UTILITY FUNCTIONS
// ================================

// Ismodel.UserTypeAllowed checks if a user type is allowed for a permission
func IsUserTypeAllowed(permission Permission, userType model.UserType) bool {
	def, exists := AllPermissions[permission]
	if !exists {
		return false
	}

	for _, allowedType := range def.UserTypes {
		if allowedType == userType {
			return true
		}
	}
	return false
}

// IsDangerousPermission checks if a permission is considered dangerous
func IsDangerousPermission(permission Permission) bool {
	def, exists := AllPermissions[permission]
	if !exists {
		return false
	}
	return def.Dangerous || def.RiskLevel >= 4
}

// GetPermissionRiskLevel returns the risk level of a permission
func GetPermissionRiskLevel(permission Permission) int {
	def, exists := AllPermissions[permission]
	if !exists {
		return 1
	}
	return def.RiskLevel
}

// GetPermissionsByCategory returns all permissions in a category
func GetPermissionsByCategory(category model.PermissionCategory) []Permission {
	var permissions []Permission
	for name, def := range AllPermissions {
		if def.Category == category {
			permissions = append(permissions, name)
		}
	}
	return permissions
}

// GetPermissionsByGroup returns all permissions in a group
func GetPermissionsByGroup(group model.PermissionGroup) []Permission {
	var permissions []Permission
	for name, def := range AllPermissions {
		if def.Group == group {
			permissions = append(permissions, name)
		}
	}
	return permissions
}

// GetPermissionsForUserType returns all permissions applicable to a user type
func GetPermissionsForUserType(userType model.UserType) []Permission {
	var permissions []Permission
	for name, def := range AllPermissions {
		for _, ut := range def.UserTypes {
			if ut == userType {
				permissions = append(permissions, name)
				break
			}
		}
	}
	return permissions
}

// GetSystemPermissions returns all system-managed permissions
func GetSystemPermissions() []Permission {
	var permissions []Permission
	for name, def := range AllPermissions {
		if def.System {
			permissions = append(permissions, name)
		}
	}
	return permissions
}

// GetDangerousPermissions returns all dangerous permissions
func GetDangerousPermissions() []Permission {
	var permissions []Permission
	for name, def := range AllPermissions {
		if def.Dangerous {
			permissions = append(permissions, name)
		}
	}
	return permissions
}

// PermissionRequiresContext checks if permission requires a specific context
func PermissionRequiresContext(permission Permission, context model.ContextType) bool {
	def, exists := AllPermissions[permission]
	if !exists {
		return false
	}

	for _, reqContext := range def.RequiredContext {
		if reqContext == context {
			return true
		}
	}
	return false
}

// GetPermissionDependencies returns the dependencies for a permission
func GetPermissionDependencies(permission Permission) []Permission {
	def, exists := AllPermissions[permission]
	if !exists {
		return nil
	}
	return def.Dependencies
}

// ValidatePermissionDependencies checks if all dependencies are satisfied
func ValidatePermissionDependencies(userPermissions []Permission, targetPermission Permission) bool {
	dependencies := GetPermissionDependencies(targetPermission)
	if len(dependencies) == 0 {
		return true
	}

	userPermMap := make(map[Permission]bool)
	for _, perm := range userPermissions {
		userPermMap[perm] = true
	}

	for _, dep := range dependencies {
		if !userPermMap[dep] {
			return false
		}
	}
	return true
}

// SearchPermissions searches permissions by name, description, or tags
func SearchPermissions(query string) []Permission {
	query = strings.ToLower(query)
	var results []Permission

	for name, def := range AllPermissions {
		// Search in name
		if strings.Contains(strings.ToLower(def.Name), query) {
			results = append(results, name)
			continue
		}

		// Search in display name
		if strings.Contains(strings.ToLower(def.DisplayName), query) {
			results = append(results, name)
			continue
		}

		// Search in description
		if strings.Contains(strings.ToLower(def.Description), query) {
			results = append(results, name)
			continue
		}

		// Search in tags
		for _, tag := range def.Tags {
			if strings.Contains(strings.ToLower(tag), query) {
				results = append(results, name)
				break
			}
		}
	}

	return results
}

// GetPermissionMetadata returns complete metadata for a permission
func GetPermissionMetadata(permission Permission) (*PermissionDefinition, bool) {
	def, exists := AllPermissions[permission]
	if !exists {
		return nil, false
	}
	return &def, true
}

// ================================
// PERMISSION VALIDATION
// ================================

// ValidatePermissionName checks if a permission name is valid
func ValidatePermissionName(name string) bool {
	if name == "" {
		return false
	}

	// Check if it follows the pattern: action:resource
	parts := strings.Split(name, ":")
	if len(parts) < 2 {
		return false
	}

	// Check for valid characters
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-:"
	for _, char := range name {
		if !strings.ContainsRune(validChars, char) {
			return false
		}
	}

	return true
}

// ================================
// PERMISSION INHERITANCE SYSTEM
// ================================

// PermissionInheritanceEngine handles permission inheritance and validation
type PermissionInheritanceEngine struct {
	permissionDefinitions map[Permission]PermissionDefinition
	roleInheritance       map[string][]string // role name -> parent role names
}

// NewPermissionInheritanceEngine creates a new inheritance engine
func NewPermissionInheritanceEngine() *PermissionInheritanceEngine {
	return &PermissionInheritanceEngine{
		permissionDefinitions: AllPermissions,
		roleInheritance:       make(map[string][]string),
	}
}

// SetRoleInheritance sets up role inheritance relationships
func (pie *PermissionInheritanceEngine) SetRoleInheritance(childRole string, parentRoles []string) {
	pie.roleInheritance[childRole] = parentRoles
}

// GetInheritedPermissions returns all permissions for a role including inherited ones
func (pie *PermissionInheritanceEngine) GetInheritedPermissions(rolePermissions []Permission, roleName string) []Permission {
	inheritedPerms := make(map[Permission]bool)

	// Add direct permissions
	for _, perm := range rolePermissions {
		inheritedPerms[perm] = true

		// Add dependency permissions
		deps := pie.getPermissionDependenciesRecursive(perm, make(map[Permission]bool))
		for dep := range deps {
			inheritedPerms[dep] = true
		}
	}

	// Add permissions from parent roles
	if parentRoles, exists := pie.roleInheritance[roleName]; exists {
		for _, parentRole := range parentRoles {
			parentPerms := pie.GetInheritedPermissions(rolePermissions, parentRole)
			for _, perm := range parentPerms {
				inheritedPerms[perm] = true
			}
			// This would need to be called with parent role permissions
			// parentPerms := getParentRolePermissions(parentRole)
			// parentInherited := pie.GetInheritedPermissions(parentPerms, parentRole)
			// for _, perm := range parentInherited {
			//     inheritedPerms[perm] = true
			// }
		}
	}

	// Convert back to slice
	result := make([]Permission, 0, len(inheritedPerms))
	for perm := range inheritedPerms {
		result = append(result, perm)
	}

	return result
}

// getPermissionDependenciesRecursive gets all dependencies recursively
func (pie *PermissionInheritanceEngine) getPermissionDependenciesRecursive(permission Permission, visited map[Permission]bool) map[Permission]bool {
	if visited[permission] {
		return visited // Prevent circular dependencies
	}

	visited[permission] = true

	def, exists := pie.permissionDefinitions[permission]
	if !exists {
		return visited
	}

	for _, dep := range def.Dependencies {
		pie.getPermissionDependenciesRecursive(dep, visited)
	}

	return visited
}

// ValidatePermissionSet validates that all dependencies are satisfied in a permission set
func (pie *PermissionInheritanceEngine) ValidatePermissionSet(permissions []Permission) (bool, []Permission) {
	permissionMap := make(map[Permission]bool)
	for _, perm := range permissions {
		permissionMap[perm] = true
	}

	var missingDeps []Permission

	for _, perm := range permissions {
		def, exists := pie.permissionDefinitions[perm]
		if !exists {
			continue
		}

		for _, dep := range def.Dependencies {
			if !permissionMap[dep] {
				missingDeps = append(missingDeps, dep)
			}
		}
	}

	return len(missingDeps) == 0, missingDeps
}

// GetPermissionHierarchy returns the hierarchy tree for a permission
func (pie *PermissionInheritanceEngine) GetPermissionHierarchy(permission Permission) *PermissionHierarchyNode {
	def, exists := pie.permissionDefinitions[permission]
	if !exists {
		return nil
	}

	node := &PermissionHierarchyNode{
		Permission: permission,
		Definition: def,
		Children:   make([]*PermissionHierarchyNode, 0),
		Parents:    make([]*PermissionHierarchyNode, 0),
	}

	// Build dependency tree (parents)
	for _, dep := range def.Dependencies {
		parentNode := pie.GetPermissionHierarchy(dep)
		if parentNode != nil {
			node.Parents = append(node.Parents, parentNode)
		}
	}

	// Find dependents (children)
	for otherPerm, otherDef := range pie.permissionDefinitions {
		for _, otherDep := range otherDef.Dependencies {
			if otherDep == permission {
				childNode := &PermissionHierarchyNode{
					Permission: otherPerm,
					Definition: otherDef,
				}
				node.Children = append(node.Children, childNode)
			}
		}
	}

	return node
}

// PermissionHierarchyNode represents a node in the permission hierarchy
type PermissionHierarchyNode struct {
	Permission Permission                 `json:"permission"`
	Definition PermissionDefinition       `json:"definition"`
	Children   []*PermissionHierarchyNode `json:"children,omitempty"`
	Parents    []*PermissionHierarchyNode `json:"parents,omitempty"`
}

// PermissionTemplates define common permission groupings
var PermissionTemplates = map[string][]Permission{
	"basic_self_access": {
		PermissionViewSelf,
		PermissionUpdateSelf,
		PermissionReadPersonalAPIKeys,
		PermissionManagePersonalAPIKeys,
		PermissionReadPersonalSessions,
		PermissionManagePersonalSessions,
		PermissionViewPersonalMFA,
		PermissionManagePersonalMFA,
	},
	"organization_viewer": {
		PermissionViewOrganization,
		PermissionViewMembers,
	},
	"organization_basic_management": {
		PermissionViewOrganization,
		PermissionUpdateOrganization,
		PermissionViewMembers,
		PermissionInviteMembers,
		PermissionManageMembers,
	},
	"user_management": {
		PermissionCreateUser,
		PermissionReadUser,
		PermissionUpdateUser,
		PermissionListUsers,
	},
	"end_user_management": {
		PermissionViewEndUsers,
		PermissionListEndUsers,
		PermissionCreateEndUser,
		PermissionUpdateEndUser,
		PermissionViewEndUserAnalytics,
	},
	"security_management": {
		PermissionReadSessions,
		PermissionReadMFA,
		PermissionViewAuditLogs,
	},
	"api_management": {
		PermissionReadAPIKeys,
		PermissionWriteAPIKey,
	},
	"webhook_management": {
		PermissionReadWebhooks,
		PermissionWriteWebhook,
	},
	"platform_read_access": {
		PermissionViewAllOrganizations,
		PermissionViewAllUsers,
		PermissionViewAllCustomers,
		PermissionViewPlatformMetrics,
	},
	"platform_management": {
		PermissionManageAllOrganizations,
		PermissionManageAllUsers,
		PermissionManageCustomerOrganizations,
		PermissionManageInternalUsers,
	},
}

// GetPermissionsFromTemplate returns permissions for a given template
func GetPermissionsFromTemplate(templateName string) []Permission {
	return PermissionTemplates[templateName]
}

// CombinePermissionTemplates combines multiple permission templates
func CombinePermissionTemplates(templateNames ...string) []Permission {
	seen := make(map[Permission]bool)
	var result []Permission

	for _, templateName := range templateNames {
		for _, perm := range PermissionTemplates[templateName] {
			if !seen[perm] {
				seen[perm] = true
				result = append(result, perm)
			}
		}
	}

	return result
}

// ExpandPermissionsWithDependencies expands a permission list to include all dependencies
func ExpandPermissionsWithDependencies(permissions []Permission) []Permission {
	engine := NewPermissionInheritanceEngine()
	expanded := make(map[Permission]bool)

	for _, perm := range permissions {
		expanded[perm] = true
		deps := engine.getPermissionDependenciesRecursive(perm, make(map[Permission]bool))
		for dep := range deps {
			expanded[dep] = true
		}
	}

	result := make([]Permission, 0, len(expanded))
	for perm := range expanded {
		result = append(result, perm)
	}

	return result
}

// PermissionRequiresOrganizationContext checks if permission requires organization context
func PermissionRequiresOrganizationContext(permission Permission) bool {
	def, exists := AllPermissions[permission]
	if !exists {
		return false
	}

	for _, context := range def.RequiredContext {
		if context == "organization" {
			return true
		}
	}
	return false
}
