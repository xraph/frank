package authz

// Organization Management Permissions
const (
	// Organization CRUD Permissions
	PermissionCreateOrganization = "create:organization"
	PermissionViewOrganization   = "view:organization"
	PermissionUpdateOrganization = "update:organization"
	PermissionDeleteOrganization = "delete:organization"
	PermissionListOrganizations  = "list:organizations"

	// Membership Management Permissions
	PermissionInviteMembers = "invite:members"
	PermissionViewMembers   = "view:members"
	PermissionManageMembers = "manage:members"
	PermissionRemoveMembers = "remove:members"

	// Organization Settings Permissions
	PermissionManageSettings     = "manage:organization_settings"
	PermissionManageBilling      = "manage:billing"
	PermissionManageIntegrations = "manage:integrations"
	PermissionManageSSO          = "manage:sso"
	PermissionViewAuditLogs      = "view:audit_logs"
	PermissionManageAPIKeys      = "manage:api_keys"
	PermissionManageWebhooks     = "manage:webhooks"

	// Advanced Organization Permissions
	PermissionTransferOwnership = "transfer:ownership"
	PermissionDeleteAllData     = "delete:all_data"
	PermissionExportData        = "export:data"
	PermissionManageCompliance  = "manage:compliance"
)

// User Management Permissions (for external users)
const (
	PermissionCreateUser         = "create:user"
	PermissionViewUser           = "view:user"
	PermissionUpdateUser         = "update:user"
	PermissionDeleteUser         = "delete:user"
	PermissionListUsers          = "list:users"
	PermissionManageUserMFA      = "manage:user_mfa"
	PermissionImpersonateUser    = "impersonate:user"
	PermissionResetPassword      = "reset:password"
	PermissionManageUserSessions = "manage:user_sessions"
)

// Auth Service Permissions (for end users)
const (
	PermissionManageAuthService   = "manage:auth_service"
	PermissionViewAuthMetrics     = "view:auth_metrics"
	PermissionManageAuthProviders = "manage:auth_providers"
	PermissionManageAuthTemplates = "manage:auth_templates"
	PermissionManageAuthDomains   = "manage:auth_domains"
	PermissionViewAuthLogs        = "view:auth_logs"
)

// Permission Groups for easier management
var OrganizationPermissionGroups = map[string][]string{
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
	// Platform Management
	PermissionManagePlatform         = "manage:platform"
	PermissionViewPlatformMetrics    = "view:platform_metrics"
	PermissionManagePlatformSettings = "manage:platform_settings"

	// Global Organization Management
	PermissionViewAllOrganizations   = "view:all_organizations"
	PermissionManageAllOrganizations = "manage:all_organizations"
	PermissionSuspendOrganization    = "suspend:organization"
	PermissionDeleteAnyOrganization  = "delete:any_organization"

	// Global User Management
	PermissionViewAllUsers       = "view:all_users"
	PermissionManageAllUsers     = "manage:all_users"
	PermissionImpersonateAnyUser = "impersonate:any_user"
	PermissionSuspendAnyUser     = "suspend:any_user"

	// Platform Security
	PermissionViewPlatformAuditLogs  = "view:platform_audit_logs"
	PermissionManagePlatformSecurity = "manage:platform_security"
	PermissionManageSystemRoles      = "manage:system_roles"

	// Billing and Compliance
	PermissionViewAllBilling        = "view:all_billing"
	PermissionManageAllBilling      = "manage:all_billing"
	PermissionViewComplianceReports = "view:compliance_reports"
	PermissionManageCompliance      = "manage:platform_compliance"
)

// Self-Access Permissions (permissions users have on their own resources)
const (
	PermissionViewOwnProfile    = "view:own_profile"
	PermissionUpdateOwnProfile  = "update:own_profile"
	PermissionManageOwnMFA      = "manage:own_mfa"
	PermissionManageOwnSessions = "manage:own_sessions"
	PermissionManageOwnAPIKeys  = "manage:own_api_keys"
	PermissionViewOwnAuditLogs  = "view:own_audit_logs"
	PermissionDeleteOwnAccount  = "delete:own_account"
	PermissionExportOwnData     = "export:own_data"
)

// Resource Types for context-aware permissions
const (
	ResourceSystem       = "system"
	ResourceOrganization = "organization"
	ResourceUser         = "user"
	ResourceApplication  = "application"
	ResourceAPIKey       = "api_key"
	ResourceWebhook      = "webhook"
	ResourceAuditLog     = "audit_log"
	ResourceBilling      = "billing"
)

// Permission Definitions with metadata
type PermissionDefinition struct {
	Name            string   `json:"name"`
	DisplayName     string   `json:"display_name"`
	Description     string   `json:"description"`
	Resource        string   `json:"resource"`
	Action          string   `json:"action"`
	Category        string   `json:"category"`
	RiskLevel       int      `json:"risk_level"`
	Dangerous       bool     `json:"dangerous"`
	UserTypes       []string `json:"user_types"`
	RequiredContext []string `json:"required_context"`
}

// All permission definitions
var AllPermissions = map[string]PermissionDefinition{
	// Organization Management
	PermissionCreateOrganization: {
		Name:            PermissionCreateOrganization,
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
		Name:            PermissionViewOrganization,
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
		Name:            PermissionUpdateOrganization,
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
		Name:            PermissionDeleteOrganization,
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
		Name:            PermissionListOrganizations,
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
		Name:            PermissionInviteMembers,
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
		Name:            PermissionViewMembers,
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
		Name:            PermissionManageMembers,
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
		Name:            PermissionViewOwnProfile,
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
		Name:            PermissionUpdateOwnProfile,
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
		Name:            PermissionManageOwnMFA,
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
		Name:            PermissionManageOwnSessions,
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
func IsUserTypeAllowed(permission string, userType string) bool {
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
func IsDangerousPermission(permission string) bool {
	def, exists := AllPermissions[permission]
	if !exists {
		return false
	}
	return def.Dangerous || def.RiskLevel >= 4
}

// GetPermissionRiskLevel returns the risk level of a permission
func GetPermissionRiskLevel(permission string) int {
	def, exists := AllPermissions[permission]
	if !exists {
		return 1
	}
	return def.RiskLevel
}

// GetPermissionsByCategory returns all permissions in a category
func GetPermissionsByCategory(category string) []string {
	var permissions []string
	for name, def := range AllPermissions {
		if def.Category == category {
			permissions = append(permissions, name)
		}
	}
	return permissions
}

// GetPermissionsForUserType returns all permissions applicable to a user type
func GetPermissionsForUserType(userType string) []string {
	var permissions []string
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

// PermissionRequiresOrganizationContext checks if permission requires organization context
func PermissionRequiresOrganizationContext(permission string) bool {
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
