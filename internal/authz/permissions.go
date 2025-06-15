package authz

import (
	"context"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// Permission represents a single, atomic permission
type Permission string

// API Key permissions
const (
	PermissionReadAPIKey           Permission = "read:api:key"
	PermissionWriteAPIKey          Permission = "write:api:key"
	PermissionDeleteAPIKey         Permission = "delete:api:key"
	PermissionViewPersonalAPIKey   Permission = "view:personal:api:key"
	PermissionManagePersonalAPIKey Permission = "manage:personal:api:key"
	// PermissionManageAPIKeys         Permission = "manage:api:keys"
)

// SSO permissions
const (
	PermissionReadSSO  Permission = "read:sso"
	PermissionWriteSSO Permission = "write:sso"
)

// Session management permissions
const (
	PermissionReadSessions          Permission = "read:session"
	PermissionDeleteSession         Permission = "delete:session"
	PermissionManageSession         Permission = "manage:session"
	PermissionViewPersonalSession   Permission = "view:personal:session"
	PermissionManagePersonalSession Permission = "manage:personal:session"
)

// Multi-Factor Authentication permissions
const (
	PermissionReadMFA           Permission = "read:mfa"
	PermissionWriteMFA          Permission = "write:mfa"
	PermissionDeleteMFA         Permission = "delete:mfa"
	PermissionManageMFA         Permission = "manage:mfa"
	PermissionViewPersonalMFA   Permission = "view:personal:mfa"
	PermissionManagePersonalMFA Permission = "manage:personal:mfa"
)

// Verification permissions
const (
	PermissionReadVerification            Permission = "view:verification"
	PermissionWriteVerification           Permission = "write:verification"
	PermissionDeleteVerification          Permission = "delete:verification"
	PermissionManageVerifications         Permission = "manage:verification"
	PermissionViewPersonalVerifications   Permission = "view:personal:verification"
	PermissionManagePersonalVerifications Permission = "manage:personal:verification"
)

// Webhook permissions
const (
	PermissionReadWebhook   Permission = "read:webhook"
	PermissionWriteWebhook  Permission = "write:webhook"
	PermissionDeleteWebhook Permission = "delete:webhook"
	// PermissionManageWebhooks Permission = "manage:webhooks"

	// Webhook events
	PermissionReadWebhookEvents  Permission = "read:webhook:events"
	PermissionWriteWebhookEvent  Permission = "write:webhook:event"
	PermissionDeleteWebhookEvent Permission = "delete:webhook:event"
	PermissionManageWebhookEvent Permission = "manage:webhook:event"
)

// Email template permissions
const (
	PermissionReadEmailTemplate         Permission = "read:email:template"
	PermissionWriteEmailTemplate        Permission = "write:email:template"
	PermissionDeleteEmailTemplate       Permission = "delete:email:template"
	PermissionManageEmailTemplate       Permission = "manage:email:template"
	PermissionManageSystemEmailTemplate Permission = "manage:system:email:template"
)

// Oauth permissions
const (
	PermissionReadOAuth           Permission = "read:oauth"
	PermissionWriteOAuth          Permission = "write:oauth"
	PermissionManageOAuth         Permission = "manage:oauth"
	PermissionViewPersonalOAuth   Permission = "view:personal:oauth"
	PermissionManagePersonalOAuth Permission = "manage:personal:oauth"
)

// Passkey permissions
const (
	PermissionReadPasskey           Permission = "read:passkey"
	PermissionWritePasskey          Permission = "write:passkey"
	PermissionManagePasskey         Permission = "manage:passkey"
	PermissionViewPersonalPasskey   Permission = "view:personal:passkey"
	PermissionManagePersonalPasskey Permission = "manage:personal:passkey"
)

// Passkey permissions
const (
	PermissionReadActivity           Permission = "read:activity"
	PermissionWriteActivity          Permission = "write:activity"
	PermissionDeleteActivity         Permission = "delete:activity"
	PermissionManageActivity         Permission = "manage:activity"
	PermissionViewPersonalActivity   Permission = "view:personal:activity"
	PermissionManagePersonalActivity Permission = "manage:personal:activity"
)

// Role and Permission management
const (
	PermissionReadRole   Permission = "read:role"
	PermissionWriteRole  Permission = "write:role"
	PermissionDeleteRole Permission = "delete:role"
	PermissionManageRole Permission = "manage:roles"
	PermissionAssignRole Permission = "assign:roles"
	PermissionRevokeRole Permission = "revoke:roles"

	PermissionReadPermission         Permission = "read:permission"
	PermissionWritePermission        Permission = "write:permission"
	PermissionDeletePermission       Permission = "delete:permission"
	PermissionManagePermission       Permission = "manage:permission"
	PermissionCheckPermission        Permission = "check:permission"
	PermissionManageSystemPermission Permission = "manage:system:permission"
)

// System admin permissions
const (
	PermissionSystemAdmin          Permission = "system:admin"
	PermissionManageSystemSettings Permission = "manage:system:settings"
	PermissionViewSystemSettings   Permission = "view:system:settings"
	// PermissionManageAllOrganizations Permission = "manage:all:organizations"
	// PermissionViewAllOrganizations   Permission = "view:all:organizations"
	// PermissionManageAllUsers         Permission = "manage:all:users"
	// PermissionViewAllUsers           Permission = "view:all:users"
	// PermissionManageSystemRoles      Permission = "manage:system:roles"
	PermissionViewSystemRoles Permission = "view:system:roles"
)

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
	PermissionCreateUser        Permission = "create:user"
	PermissionReadUser          Permission = "read:user"
	PermissionUpdateUser        Permission = "update:user"
	PermissionDeleteUser        Permission = "delete:user"
	PermissionListUsers         Permission = "list:users"
	PermissionManageUserMFA     Permission = "manage:user_mfa"
	PermissionImpersonateUser   Permission = "impersonate:user"
	PermissionResetPassword     Permission = "reset:password"
	PermissionManageUserSession Permission = "manage:user_session"
	PermissionManageUsers       Permission = "manage:users"
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
	PermissionManageAuthService  Permission = "manage:auth_service"
	PermissionViewAuthMetrics    Permission = "view:auth_metrics"
	PermissionManageAuthProvider Permission = "manage:auth_provider"
	PermissionManageAuthTemplate Permission = "manage:auth_template"
	PermissionManageAuthDomain   Permission = "manage:auth_domain"
	PermissionViewAuthLogs       Permission = "view:auth_logs"
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
		PermissionManageAuthProvider,
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
	PermissionReadActivityGlobal     Permission = "read:activity:global"

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

func (p Permission) String() string {
	return string(p)
}

// ErrNoPermission is returned when a user doesn't have the required permission
var ErrNoPermission = errors.New(errors.CodeForbidden, "permission denied")

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

// PermissionChecker defines the interface for checking permissions
type PermissionChecker interface {
	// HasPermissionString checks if the current user has the specified permission for the given resource
	HasPermissionString(ctx context.Context, permission Permission, resourceType ResourceType, resourceID string) (bool, error)

	// HasPermission checks if the current user has the specified permission for the given resource
	HasPermission(ctx context.Context, permission Permission, resourceType ResourceType, resourceID xid.ID) (bool, error)

	// HasPermissionWithUserID checks if the specified user has the specified permission for the given resource
	HasPermissionWithUserID(ctx context.Context, permission Permission, resourceType ResourceType, resourceID xid.ID, userID xid.ID) (bool, error)

	// HasPermissions checks if the current user has all the specified permissions for the given resource
	HasPermissions(ctx context.Context, permissions []Permission, resourceType ResourceType, resourceID xid.ID) (bool, error)

	// HasAnyPermission checks if the current user has any of the specified permissions for the given resource
	HasAnyPermission(ctx context.Context, permissions []Permission, resourceType ResourceType, resourceID xid.ID) (bool, error)

	// HasAnyPermissionWithUserID checks if the specified user has any of the specified permissions for the given resource
	HasAnyPermissionWithUserID(ctx context.Context, permissions []Permission, resourceType ResourceType, resourceID xid.ID, userID xid.ID) (bool, error)
}

// PermissionCheckerWithContext defines the interface for checking permissions
type PermissionCheckerWithContext interface {
	PermissionChecker

	// IsInternalUser checks if user is internal platform staff
	IsInternalUser(ctx context.Context, userID xid.ID) (bool, error)

	// IsPlatformAdmin checks if user is platform administrator
	IsPlatformAdmin(ctx context.Context, userID xid.ID) (bool, error)

	// IsExternalUser checks if user is external customer organization member
	IsExternalUser(ctx context.Context, userID xid.ID) (bool, error)

	// GetUserType returns the user's type
	GetUserType(ctx context.Context, userID xid.ID) (model.UserType, error)

	// CanAccessCustomerData checks if user can access customer organization data
	CanAccessCustomerData(ctx context.Context, userID xid.ID, customerOrgID xid.ID) (bool, error)
	// HasPermissionForUserType checks permissions with user type context
	HasPermissionForUserType(ctx context.Context, permission Permission, resourceType ResourceType, resourceID xid.ID, userID xid.ID) (bool, error)

	// CheckContextualPermission Context-aware permission checking
	CheckContextualPermission(ctx context.Context, permission Permission, resourceType ResourceType, resourceID xid.ID) (bool, error)
}

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
