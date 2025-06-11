package authz

// Organization Management Permissions
const (
	// Organization CRUD Permissions
	PermissionCreateOrganization Permission = "create:organization"
	PermissionViewOrganization   Permission = "view:organization"
	PermissionUpdateOrganization Permission = "update:organization"
	PermissionDeleteOrganization Permission = "delete:organization"
	PermissionListOrganizations  Permission = "list:organizations"

	// Organization membership management
	// PermissionViewOrganizationMembers   Permission = "view:organization:members"
	// PermissionAddOrganizationMember     Permission = "add:organization:member"
	// PermissionUpdateOrganizationMember  Permission = "update:organization:member"
	// PermissionRemoveOrganizationMember  Permission = "remove:organization:member"
	// PermissionManageOrganizationInvites Permission = "manage:organization:invites"

	// Membership Management Permissions
	PermissionViewInvitations Permission = "view:invitations"
	PermissionInviteMembers   Permission = "invite:members"
	PermissionViewMembers     Permission = "view:members"
	PermissionManageMembers   Permission = "manage:members"
	PermissionRemoveMembers   Permission = "remove:members"

	// Organization Settings Permissions
	PermissionManageSettings     Permission = "manage:organization_settings"
	PermissionViewBilling        Permission = "view:billing"
	PermissionManageBilling      Permission = "manage:billing"
	PermissionManageIntegrations Permission = "manage:integrations"
	PermissionManageSSO          Permission = "manage:sso"
	PermissionViewAuditLogs      Permission = "view:audit_logs"
	PermissionManageAPIKeys      Permission = "manage:api_keys"
	PermissionManageWebhooks     Permission = "manage:webhooks"

	// Advanced Organization Permissions
	PermissionTransferOwnership Permission = "transfer:ownership"
	PermissionDeleteAllData     Permission = "delete:all_data"
	PermissionExportData        Permission = "export:data"
	PermissionManageCompliance  Permission = "manage:compliance"

	PermissionViewAnalytics Permission = "view:analytics"
	PermissionExportUsers   Permission = "export:users"
)

// User Management Permissions (for external users)
const (
	PermissionCreateUser         Permission = "create:user"
	PermissionViewUser           Permission = "view:user"
	PermissionUpdateUser         Permission = "update:user"
	PermissionDeleteUser         Permission = "delete:user"
	PermissionListUsers          Permission = "list:users"
	PermissionManageUserMFA      Permission = "manage:user_mfa"
	PermissionImpersonateUser    Permission = "impersonate:user"
	PermissionResetPassword      Permission = "reset:password"
	PermissionManageUserSessions Permission = "manage:user_sessions"
	PermissionManageUsers        Permission = "manage:users"
)

// User management permissions
const (
	// User self-management permissions
	PermissionViewSelf   Permission = "view:self"
	PermissionUpdateSelf Permission = "update:self"
	PermissionDeleteSelf Permission = "delete:self"
	PermissionManageSelf Permission = "manage:self"
)

// Auth Service Permissions (for end users)
const (
	PermissionManageAuthService   Permission = "manage:auth_service"
	PermissionViewAuthMetrics     Permission = "view:auth_metrics"
	PermissionManageAuthProviders Permission = "manage:auth_providers"
	PermissionManageAuthTemplates Permission = "manage:auth_templates"
	PermissionManageAuthDomains   Permission = "manage:auth_domains"
	PermissionViewAuthLogs        Permission = "view:auth_logs"
)

// Permission Groups for easier management
var OrganizationPermissionGroups = map[string][]Permission{
	"organization_admin": {
		PermissionViewOrganization,
		PermissionUpdateOrganization,
		PermissionManageSettings,
		PermissionInviteMembers,
		PermissionViewMembers,
		PermissionManageMembers,
		PermissionManageAPIKeys,
		PermissionManageWebhooks,
		PermissionViewAuditLogs,
	},
	"organization_owner": {
		// Includes all admin permissions plus destructive ones
		PermissionViewOrganization,
		PermissionUpdateOrganization,
		PermissionDeleteOrganization,
		PermissionManageSettings,
		PermissionManageBilling,
		PermissionManageIntegrations,
		PermissionManageSSO,
		PermissionInviteMembers,
		PermissionViewMembers,
		PermissionManageMembers,
		PermissionRemoveMembers,
		PermissionManageAPIKeys,
		PermissionManageWebhooks,
		PermissionViewAuditLogs,
		PermissionTransferOwnership,
		PermissionDeleteAllData,
		PermissionExportData,
		PermissionManageCompliance,
	},
	"member": {
		PermissionViewOrganization,
		PermissionViewMembers,
	},
	"billing_manager": {
		PermissionViewOrganization,
		PermissionManageBilling,
		PermissionViewMembers,
	},
	"developer": {
		PermissionViewOrganization,
		PermissionManageAPIKeys,
		PermissionManageWebhooks,
		PermissionViewMembers,
		PermissionManageAuthService,
		PermissionViewAuthMetrics,
		PermissionManageAuthProviders,
	},
}

// Platform Admin Permissions (for internal users)
const (
	// Platform administration (internal users only)
	// Platform Management
	PermissionManagePlatform         Permission = "manage:platform"
	PermissionViewPlatformMetrics    Permission = "view:platform_metrics"
	PermissionManagePlatformSettings Permission = "manage:platform_settings"
	PermissionViewAllCustomers       Permission = "view:all:customers"
	PermissionManageCustomerBilling  Permission = "manage:customer:billing"
	PermissionSuspendCustomer        Permission = "suspend:customer"
	PermissionViewPlatformAnalytics  Permission = "view:platform:analytics"

	// Global Organization Management
	PermissionViewAllOrganizations   Permission = "view:all_organizations"
	PermissionManageAllOrganizations Permission = "manage:all_organizations"
	PermissionSuspendOrganization    Permission = "suspend:organization"
	PermissionDeleteAnyOrganization  Permission = "delete:any_organization"

	// Global User Management
	PermissionViewAllUsers       Permission = "view:all_users"
	PermissionManageAllUsers     Permission = "manage:all_users"
	PermissionImpersonateAnyUser Permission = "impersonate:any_user"
	PermissionSuspendAnyUser     Permission = "suspend:any_user"

	// Platform Security
	PermissionViewPlatformAuditLogs  Permission = "view:platform_audit_logs"
	PermissionManagePlatformSecurity Permission = "manage:platform_security"
	PermissionManageSystemRoles      Permission = "manage:system_roles"

	// Billing and Compliance
	PermissionViewAllBilling        Permission = "view:all_billing"
	PermissionManageAllBilling      Permission = "manage:all_billing"
	PermissionViewComplianceReports Permission = "view:compliance_reports"
	// PermissionManageCompliance      Permission = "manage:platform_compliance"
)

// Self-Access Permissions (permissions users have on their own resources)
const (
	PermissionViewOwnProfile    Permission = "view:own_profile"
	PermissionUpdateOwnProfile  Permission = "update:own_profile"
	PermissionManageOwnMFA      Permission = "manage:own_mfa"
	PermissionManageOwnSessions Permission = "manage:own_sessions"
	PermissionManageOwnAPIKeys  Permission = "manage:own_api_keys"
	PermissionViewOwnAuditLogs  Permission = "view:own_audit_logs"
	PermissionDeleteOwnAccount  Permission = "delete:own_account"
	PermissionExportOwnData     Permission = "export:own_data"
)

// Permission Definitions with metadata
type PermissionDefinition struct {
	Name            string       `json:"name"`
	DisplayName     string       `json:"display_name"`
	Description     string       `json:"description"`
	Resource        ResourceType `json:"resource"`
	Action          string       `json:"action"`
	Category        string       `json:"category"`
	RiskLevel       int          `json:"risk_level"`
	Dangerous       bool         `json:"dangerous"`
	UserTypes       []string     `json:"user_types"`
	RequiredContext []string     `json:"required_context"`
}

// All permission definitions
var AllPermissions = map[Permission]PermissionDefinition{
	// Organization Management
	PermissionCreateOrganization: {
		Name:            string(PermissionCreateOrganization),
		DisplayName:     "Create Organization",
		Description:     "Create new organizations",
		Resource:        ResourceSystem,
		Action:          "create",
		Category:        "organization",
		RiskLevel:       2,
		Dangerous:       false,
		UserTypes:       []string{"internal", "external"},
		RequiredContext: []string{"system"},
	},
	PermissionViewOrganization: {
		Name:            string(PermissionViewOrganization),
		DisplayName:     "View Organization",
		Description:     "View organization details and settings",
		Resource:        ResourceOrganization,
		Action:          "view",
		Category:        "organization",
		RiskLevel:       1,
		Dangerous:       false,
		UserTypes:       []string{"internal", "external"},
		RequiredContext: []string{"organization"},
	},
	PermissionUpdateOrganization: {
		Name:            string(PermissionUpdateOrganization),
		DisplayName:     "Update Organization",
		Description:     "Update organization details and settings",
		Resource:        ResourceOrganization,
		Action:          "update",
		Category:        "organization",
		RiskLevel:       2,
		Dangerous:       false,
		UserTypes:       []string{"internal", "external"},
		RequiredContext: []string{"organization"},
	},
	PermissionDeleteOrganization: {
		Name:            string(PermissionDeleteOrganization),
		DisplayName:     "Delete Organization",
		Description:     "Delete organizations",
		Resource:        ResourceOrganization,
		Action:          "delete",
		Category:        "organization",
		RiskLevel:       5,
		Dangerous:       true,
		UserTypes:       []string{"internal", "external"},
		RequiredContext: []string{"organization"},
	},
	PermissionListOrganizations: {
		Name:            string(PermissionListOrganizations),
		DisplayName:     "List Organizations",
		Description:     "List organizations user has access to",
		Resource:        ResourceSystem,
		Action:          "list",
		Category:        "organization",
		RiskLevel:       1,
		Dangerous:       false,
		UserTypes:       []string{"internal", "external"},
		RequiredContext: []string{"system"},
	},

	// Membership Management
	PermissionInviteMembers: {
		Name:            string(PermissionInviteMembers),
		DisplayName:     "Invite Members",
		Description:     "Invite new members to the organization",
		Resource:        ResourceOrganization,
		Action:          "invite",
		Category:        "membership",
		RiskLevel:       2,
		Dangerous:       false,
		UserTypes:       []string{"external"},
		RequiredContext: []string{"organization"},
	},
	PermissionViewMembers: {
		Name:            string(PermissionViewMembers),
		DisplayName:     "View Members",
		Description:     "View organization members and their details",
		Resource:        ResourceOrganization,
		Action:          "view",
		Category:        "membership",
		RiskLevel:       1,
		Dangerous:       false,
		UserTypes:       []string{"external"},
		RequiredContext: []string{"organization"},
	},
	PermissionManageMembers: {
		Name:            string(PermissionManageMembers),
		DisplayName:     "Manage Members",
		Description:     "Manage organization members (update roles, remove members)",
		Resource:        ResourceOrganization,
		Action:          "manage",
		Category:        "membership",
		RiskLevel:       3,
		Dangerous:       false,
		UserTypes:       []string{"external"},
		RequiredContext: []string{"organization"},
	},

	// Self-Access Permissions
	PermissionViewOwnProfile: {
		Name:            string(PermissionViewOwnProfile),
		DisplayName:     "View Own Profile",
		Description:     "View own user profile and settings",
		Resource:        ResourceUser,
		Action:          "view",
		Category:        "self",
		RiskLevel:       1,
		Dangerous:       false,
		UserTypes:       []string{"internal", "external", "end_user"},
		RequiredContext: []string{"self"},
	},
	PermissionUpdateOwnProfile: {
		Name:            string(PermissionUpdateOwnProfile),
		DisplayName:     "Update Own Profile",
		Description:     "Update own user profile and settings",
		Resource:        ResourceUser,
		Action:          "update",
		Category:        "self",
		RiskLevel:       1,
		Dangerous:       false,
		UserTypes:       []string{"internal", "external", "end_user"},
		RequiredContext: []string{"self"},
	},
	PermissionManageOwnMFA: {
		Name:            string(PermissionManageOwnMFA),
		DisplayName:     "Manage Own MFA",
		Description:     "Manage own multi-factor authentication settings",
		Resource:        ResourceUser,
		Action:          "manage",
		Category:        "security",
		RiskLevel:       2,
		Dangerous:       false,
		UserTypes:       []string{"internal", "external", "end_user"},
		RequiredContext: []string{"self"},
	},
	PermissionManageOwnSessions: {
		Name:            string(PermissionManageOwnSessions),
		DisplayName:     "Manage Own Sessions",
		Description:     "Manage own active sessions",
		Resource:        ResourceUser,
		Action:          "manage",
		Category:        "security",
		RiskLevel:       2,
		Dangerous:       false,
		UserTypes:       []string{"internal", "external", "end_user"},
		RequiredContext: []string{"self"},
	},
}

// Helper functions for permission checking

// IsUserTypeAllowed checks if a user type is allowed for a permission
func IsUserTypeAllowed(permission Permission, userType string) bool {
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
func GetPermissionsByCategory(category string) []Permission {
	var permissions []Permission
	for name, def := range AllPermissions {
		if def.Category == category {
			permissions = append(permissions, name)
		}
	}
	return permissions
}

// GetPermissionsForUserType returns all permissions applicable to a user type
func GetPermissionsForUserType(userType Permission) []Permission {
	var permissions []Permission
	for name, def := range AllPermissions {
		for _, ut := range def.UserTypes {
			if ut == userType.String() {
				permissions = append(permissions, name)
				break
			}
		}
	}
	return permissions
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
