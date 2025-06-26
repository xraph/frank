package authz

import (
	"context"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// Permission represents a single, atomic permission
type Permission string

// =============================================================================
// SELF-MANAGEMENT PERMISSIONS
// =============================================================================
// Permissions users have on their own resources and profile
const (
	PermissionViewSelf          Permission = "view:self"
	PermissionUpdateSelf        Permission = "update:self"
	PermissionDeleteSelf        Permission = "delete:self"
	PermissionManageSelf        Permission = "manage:self"
	PermissionViewOwnProfile    Permission = "view:own:profile"
	PermissionUpdateOwnProfile  Permission = "update:own:profile"
	PermissionManageOwnMFA      Permission = "manage:own:mfa"
	PermissionManageOwnSessions Permission = "manage:own:sessions"
	PermissionManageOwnAPIKeys  Permission = "manage:own:api:keys"
	PermissionViewOwnAuditLogs  Permission = "view:own:audit:logs"
	PermissionDeleteOwnAccount  Permission = "delete:own:account"
	PermissionExportOwnData     Permission = "export:own:data"
)

// =============================================================================
// API KEY PERMISSIONS
// =============================================================================
const (
	PermissionReadAPIKeys           Permission = "read:api:key"
	PermissionWriteAPIKey           Permission = "write:api:key"
	PermissionDeleteAPIKey          Permission = "delete:api:key"
	PermissionReadPersonalAPIKeys   Permission = "view:personal:api:key"
	PermissionManagePersonalAPIKeys Permission = "manage:personal:api:key"
	PermissionManageAPIKeys         Permission = "manage:api:keys"
)

// =============================================================================
// SESSION MANAGEMENT PERMISSIONS
// =============================================================================
const (
	PermissionReadSessions           Permission = "read:session"
	PermissionDeleteSession          Permission = "delete:session"
	PermissionManageSession          Permission = "manage:session"
	PermissionReadPersonalSessions   Permission = "view:personal:session"
	PermissionManagePersonalSessions Permission = "manage:personal:session"
	PermissionManageUserSession      Permission = "manage:user:session"
)

// =============================================================================
// MULTI-FACTOR AUTHENTICATION PERMISSIONS
// =============================================================================
const (
	PermissionReadMFA           Permission = "read:mfa"
	PermissionWriteMFA          Permission = "write:mfa"
	PermissionDeleteMFA         Permission = "delete:mfa"
	PermissionManageMFA         Permission = "manage:mfa"
	PermissionViewPersonalMFA   Permission = "view:personal:mfa"
	PermissionManagePersonalMFA Permission = "manage:personal:mfa"
	PermissionManageUserMFA     Permission = "manage:user:mfa"
)

// =============================================================================
// VERIFICATION PERMISSIONS
// =============================================================================
const (
	PermissionReadVerification            Permission = "view:verification"
	PermissionWriteVerification           Permission = "write:verification"
	PermissionDeleteVerification          Permission = "delete:verification"
	PermissionManageVerifications         Permission = "manage:verification"
	PermissionViewPersonalVerifications   Permission = "view:personal:verification"
	PermissionManagePersonalVerifications Permission = "manage:personal:verification"
)

// =============================================================================
// PASSKEY PERMISSIONS
// =============================================================================
const (
	PermissionReadPasskey           Permission = "read:passkey"
	PermissionWritePasskey          Permission = "write:passkey"
	PermissionManagePasskey         Permission = "manage:passkey"
	PermissionViewPersonalPasskey   Permission = "view:personal:passkey"
	PermissionManagePersonalPasskey Permission = "manage:personal:passkey"
)

// =============================================================================
// OAUTH PERMISSIONS
// =============================================================================
const (
	PermissionReadOAuth           Permission = "read:oauth"
	PermissionWriteOAuth          Permission = "write:oauth"
	PermissionManageOAuth         Permission = "manage:oauth"
	PermissionViewPersonalOAuth   Permission = "view:personal:oauth"
	PermissionManagePersonalOAuth Permission = "manage:personal:oauth"
)

// =============================================================================
// SSO PERMISSIONS
// =============================================================================
const (
	PermissionReadSSO   Permission = "read:sso"
	PermissionWriteSSO  Permission = "write:sso"
	PermissionManageSSO Permission = "manage:sso"
)

// =============================================================================
// WEBHOOK PERMISSIONS
// =============================================================================
const (
	PermissionReadWebhooks   Permission = "read:webhook"
	PermissionWriteWebhook   Permission = "write:webhook"
	PermissionDeleteWebhook  Permission = "delete:webhook"
	PermissionManageWebhooks Permission = "manage:webhooks"

	// Webhook events
	PermissionReadWebhookEvents  Permission = "read:webhook:events"
	PermissionWriteWebhookEvent  Permission = "write:webhook:event"
	PermissionDeleteWebhookEvent Permission = "delete:webhook:event"
	PermissionManageWebhookEvent Permission = "manage:webhook:event"
)

// =============================================================================
// EMAIL TEMPLATE PERMISSIONS
// =============================================================================
const (
	PermissionReadEmailTemplate         Permission = "read:email:template"
	PermissionWriteEmailTemplate        Permission = "write:email:template"
	PermissionDeleteEmailTemplate       Permission = "delete:email:template"
	PermissionManageEmailTemplate       Permission = "manage:email:template"
	PermissionManageSystemEmailTemplate Permission = "manage:system:email:template"
)

// =============================================================================
// ACTIVITY PERMISSIONS
// =============================================================================
const (
	PermissionReadActivity           Permission = "read:activity"
	PermissionWriteActivity          Permission = "write:activity"
	PermissionDeleteActivity         Permission = "delete:activity"
	PermissionManageActivity         Permission = "manage:activity"
	PermissionViewPersonalActivity   Permission = "view:personal:activity"
	PermissionManagePersonalActivity Permission = "manage:personal:activity"
	PermissionReadActivityGlobal     Permission = "read:activity:global"
)

// =============================================================================
// ROLE AND PERMISSION MANAGEMENT
// =============================================================================
const (
	PermissionReadRoles         Permission = "read:role"
	PermissionWriteRole         Permission = "write:role"
	PermissionDeleteRole        Permission = "delete:role"
	PermissionManageRole        Permission = "manage:roles"
	PermissionAssignRoles       Permission = "assign:roles"
	PermissionRevokeRole        Permission = "revoke:roles"
	PermissionViewSystemRoles   Permission = "view:system:roles"
	PermissionManageSystemRoles Permission = "manage:system:roles"

	PermissionReadPermission         Permission = "read:permission"
	PermissionWritePermission        Permission = "write:permission"
	PermissionDeletePermission       Permission = "delete:permission"
	PermissionManagePermission       Permission = "manage:permission"
	PermissionCheckPermission        Permission = "check:permission"
	PermissionManageSystemPermission Permission = "manage:system:permission"
)

// =============================================================================
// USER MANAGEMENT PERMISSIONS
// =============================================================================
const (
	// General user management
	PermissionCreateUser      Permission = "create:user"
	PermissionReadUser        Permission = "read:user"
	PermissionUpdateUser      Permission = "update:user"
	PermissionDeleteUser      Permission = "delete:user"
	PermissionListUsers       Permission = "list:users"
	PermissionManageUsers     Permission = "manage:users"
	PermissionImpersonateUser Permission = "impersonate:user"
	PermissionResetPassword   Permission = "reset:password"

	// Internal user management (platform staff)
	PermissionViewInternalUsers   Permission = "view:internal:users"
	PermissionManageInternalUsers Permission = "manage:internal:users"
	PermissionCreateInternalUser  Permission = "create:internal:user"
	PermissionUpdateInternalUser  Permission = "update:internal:user"
	PermissionDeleteInternalUser  Permission = "delete:internal:user"

	// End user management (auth service users)
	PermissionViewEndUsers          Permission = "view:end:users"
	PermissionListEndUsers          Permission = "list:end:users"
	PermissionCreateEndUser         Permission = "create:end:user"
	PermissionUpdateEndUser         Permission = "update:end:user"
	PermissionDeleteEndUser         Permission = "delete:end:user"
	PermissionBlockEndUser          Permission = "block:end:user"
	PermissionManageEndUserSessions Permission = "manage:end:user:sessions"
	PermissionViewEndUserAnalytics  Permission = "view:end:user:analytics"
)

// =============================================================================
// ORGANIZATION MANAGEMENT PERMISSIONS
// =============================================================================
const (
	// Organization CRUD operations
	PermissionCreateOrganization Permission = "create:organization"
	PermissionViewOrganization   Permission = "view:organization"
	PermissionUpdateOrganization Permission = "update:organization"
	PermissionDeleteOrganization Permission = "delete:organization"
	PermissionListOrganizations  Permission = "list:organizations"

	// Organization membership management
	PermissionViewInvitations Permission = "view:invitations"
	PermissionInviteMembers   Permission = "invite:members"
	PermissionViewMembers     Permission = "view:members"
	PermissionManageMembers   Permission = "manage:members"
	PermissionRemoveMembers   Permission = "remove:members"

	// Organization settings and configuration
	PermissionManageSettings     Permission = "manage:organization:settings"
	PermissionViewBilling        Permission = "view:billing"
	PermissionManageBilling      Permission = "manage:billing"
	PermissionManageIntegrations Permission = "manage:integrations"
	PermissionViewAuditLogs      Permission = "view:audit:logs"

	// Advanced organization operations
	PermissionTransferOwnership Permission = "transfer:ownership"
	PermissionDeleteAllData     Permission = "delete:all:data"
	PermissionExportData        Permission = "export:data"
	PermissionManageCompliance  Permission = "manage:compliance"
	PermissionViewAnalytics     Permission = "view:analytics"
	PermissionExportUsers       Permission = "export:users"

	// Customer organization management (for platform admins)
	PermissionViewCustomerOrganizations   Permission = "view:customer:organizations"
	PermissionManageCustomerOrganizations Permission = "manage:customer:organizations"
	PermissionCreateCustomerOrganization  Permission = "create:customer:organization"
	PermissionUpdateCustomerOrganization  Permission = "update:customer:organization"
	PermissionDeleteCustomerOrganization  Permission = "delete:customer:organization"
)

// =============================================================================
// AUTH SERVICE PERMISSIONS
// =============================================================================
const (
	// Auth service management (for customer organizations)
	PermissionManageAuthService        Permission = "manage:auth:service"
	PermissionConfigureAuthService     Permission = "configure:auth:service"
	PermissionViewAuthMetrics          Permission = "view:auth:metrics"
	PermissionViewAuthServiceAnalytics Permission = "view:auth:service:analytics"
	PermissionManageAuthProvider       Permission = "manage:auth:provider"
	PermissionManageAuthTemplate       Permission = "manage:auth:template"
	PermissionManageAuthDomain         Permission = "manage:auth:domain"
	PermissionManageAuthServiceDomain  Permission = "manage:auth:service:domain"
	PermissionViewAuthLogs             Permission = "view:auth:logs"
)

// =============================================================================
// SYSTEM ADMINISTRATION PERMISSIONS
// =============================================================================
const (
	PermissionSystemAdmin          Permission = "system:admin"
	PermissionManageSystemSettings Permission = "manage:system:settings"
	PermissionViewSystemSettings   Permission = "view:system:settings"
)

// =============================================================================
// PLATFORM ADMINISTRATION PERMISSIONS (Internal Users Only)
// =============================================================================
const (
	// Platform management
	PermissionManagePlatform         Permission = "manage:platform"
	PermissionViewPlatformMetrics    Permission = "view:platform:metrics"
	PermissionManagePlatformSettings Permission = "manage:platform:settings"
	PermissionViewPlatformAnalytics  Permission = "view:platform:analytics"

	// Global organization management
	PermissionViewAllOrganizations   Permission = "view:all:organizations"
	PermissionManageAllOrganizations Permission = "manage:all:organizations"
	PermissionSuspendOrganization    Permission = "suspend:organization"
	PermissionDeleteAnyOrganization  Permission = "delete:any:organization"

	// Global user management
	PermissionViewAllUsers       Permission = "view:all:users"
	PermissionManageAllUsers     Permission = "manage:all:users"
	PermissionImpersonateAnyUser Permission = "impersonate:any:user"
	PermissionSuspendAnyUser     Permission = "suspend:any:user"

	// Customer management
	PermissionViewAllCustomers      Permission = "view:all:customers"
	PermissionManageCustomerBilling Permission = "manage:customer:billing"
	PermissionSuspendCustomer       Permission = "suspend:customer"

	// Platform security and audit
	PermissionViewPlatformAuditLogs  Permission = "view:platform:audit:logs"
	PermissionManagePlatformSecurity Permission = "manage:platform:security"

	// Billing and compliance
	PermissionViewAllBilling        Permission = "view:all:billing"
	PermissionManageAllBilling      Permission = "manage:all:billing"
	PermissionViewComplianceReports Permission = "view:compliance:reports"
)

// =============================================================================
// PERMISSION GROUPS FOR ROLE MANAGEMENT
// =============================================================================

// OrganizationPermissionGroups defines common permission sets for organization roles
var OrganizationPermissionGroups = map[string][]Permission{
	"organization_owner": {
		// Full organization control
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
		PermissionViewAnalytics,
		PermissionExportUsers,
	},
	"organization_admin": {
		// Administrative control without destructive operations
		PermissionViewOrganization,
		PermissionUpdateOrganization,
		PermissionManageSettings,
		PermissionInviteMembers,
		PermissionViewMembers,
		PermissionManageMembers,
		PermissionManageAPIKeys,
		PermissionManageWebhooks,
		PermissionViewAuditLogs,
		PermissionViewAnalytics,
	},
	"billing_manager": {
		// Billing and financial management
		PermissionViewOrganization,
		PermissionManageBilling,
		PermissionViewMembers,
		PermissionViewAnalytics,
	},
	"developer": {
		// Technical integration management
		PermissionViewOrganization,
		PermissionManageAPIKeys,
		PermissionManageWebhooks,
		PermissionViewMembers,
		PermissionManageAuthService,
		PermissionConfigureAuthService,
		PermissionViewAuthMetrics,
		PermissionManageAuthProvider,
		PermissionViewAuthServiceAnalytics,
	},
	"member": {
		// Basic organization access
		PermissionViewOrganization,
		PermissionViewMembers,
	},
	"auth_service_admin": {
		// Auth service management for customer organizations
		PermissionViewOrganization,
		PermissionManageAuthService,
		PermissionConfigureAuthService,
		PermissionViewEndUsers,
		PermissionListEndUsers,
		PermissionCreateEndUser,
		PermissionUpdateEndUser,
		PermissionDeleteEndUser,
		PermissionBlockEndUser,
		PermissionManageEndUserSessions,
		PermissionViewEndUserAnalytics,
		PermissionViewAuthServiceAnalytics,
		PermissionManageAuthProvider,
		PermissionManageAuthServiceDomain,
	},
}

// PlatformPermissionGroups defines permission sets for platform roles (internal users)
var PlatformPermissionGroups = map[string][]Permission{
	"platform_admin": {
		// Full platform control
		PermissionSystemAdmin,
		PermissionManagePlatform,
		PermissionViewPlatformMetrics,
		PermissionManagePlatformSettings,
		PermissionViewPlatformAnalytics,
		PermissionViewAllOrganizations,
		PermissionManageAllOrganizations,
		PermissionSuspendOrganization,
		PermissionDeleteAnyOrganization,
		PermissionViewAllUsers,
		PermissionManageAllUsers,
		PermissionImpersonateAnyUser,
		PermissionSuspendAnyUser,
		PermissionViewAllCustomers,
		PermissionManageCustomerBilling,
		PermissionSuspendCustomer,
		PermissionViewPlatformAuditLogs,
		PermissionManagePlatformSecurity,
		PermissionManageSystemRoles,
		PermissionViewAllBilling,
		PermissionManageAllBilling,
		PermissionViewComplianceReports,
		PermissionManageInternalUsers,
		PermissionManageCustomerOrganizations,
	},
	"platform_support": {
		// Support and monitoring
		PermissionViewPlatformMetrics,
		PermissionViewAllOrganizations,
		PermissionViewAllUsers,
		PermissionViewAllCustomers,
		PermissionViewPlatformAuditLogs,
		PermissionViewAllBilling,
		PermissionViewComplianceReports,
	},
	"platform_developer": {
		// Technical platform management
		PermissionViewPlatformMetrics,
		PermissionManagePlatformSettings,
		PermissionViewAllOrganizations,
		PermissionViewSystemSettings,
		PermissionManageSystemEmailTemplate,
	},
}

func (p Permission) String() string {
	return string(p)
}

// ErrNoPermission is returned when a user doesn't have the required permission
var ErrNoPermission = errors.New(errors.CodeForbidden, "permission denied")

// PermissionChecker defines the interface for checking permissions
type PermissionChecker interface {
	// HasPermissionString checks if the current user has the specified permission for the given resource
	HasPermissionString(ctx context.Context, permission Permission, resourceType model.ResourceType, resourceID string) (bool, error)

	// HasPermission checks if the current user has the specified permission for the given resource
	HasPermission(ctx context.Context, permission Permission, resourceType model.ResourceType, resourceID xid.ID) (bool, error)

	// HasPermissionWithUserID checks if the specified user has the specified permission for the given resource
	HasPermissionWithUserID(ctx context.Context, permission Permission, resourceType model.ResourceType, resourceID xid.ID, userID xid.ID) (bool, error)

	// HasPermissions checks if the current user has all the specified permissions for the given resource
	HasPermissions(ctx context.Context, permissions []Permission, resourceType model.ResourceType, resourceID xid.ID) (bool, error)

	// HasAnyPermission checks if the current user has any of the specified permissions for the given resource
	HasAnyPermission(ctx context.Context, permissions []Permission, resourceType model.ResourceType, resourceID xid.ID) (bool, error)

	// HasAnyPermissionWithUserID checks if the specified user has any of the specified permissions for the given resource
	HasAnyPermissionWithUserID(ctx context.Context, permissions []Permission, resourceType model.ResourceType, resourceID xid.ID, userID xid.ID) (bool, error)
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
	HasPermissionForUserType(ctx context.Context, permission Permission, resourceType model.ResourceType, resourceID xid.ID, userID xid.ID) (bool, error)

	// CheckContextualPermission Context-aware permission checking
	CheckContextualPermission(ctx context.Context, permission Permission, resourceType model.ResourceType, resourceID xid.ID) (bool, error)
}

// =============================================================================
// PERMISSION VALIDATION HELPERS
// =============================================================================

// GetAllPermissions returns all defined permissions
func GetAllPermissions() []Permission {
	return []Permission{
		// Self-management permissions
		PermissionViewSelf,
		PermissionUpdateSelf,
		PermissionDeleteSelf,
		PermissionManageSelf,
		PermissionViewOwnProfile,
		PermissionUpdateOwnProfile,
		PermissionManageOwnMFA,
		PermissionManageOwnSessions,
		PermissionManageOwnAPIKeys,
		PermissionViewOwnAuditLogs,
		PermissionDeleteOwnAccount,
		PermissionExportOwnData,

		// API Key permissions
		PermissionReadAPIKeys,
		PermissionWriteAPIKey,
		PermissionDeleteAPIKey,
		PermissionReadPersonalAPIKeys,
		PermissionManagePersonalAPIKeys,
		PermissionManageAPIKeys,

		// Session management permissions
		PermissionReadSessions,
		PermissionDeleteSession,
		PermissionManageSession,
		PermissionReadPersonalSessions,
		PermissionManagePersonalSessions,
		PermissionManageUserSession,

		// MFA permissions
		PermissionReadMFA,
		PermissionWriteMFA,
		PermissionDeleteMFA,
		PermissionManageMFA,
		PermissionViewPersonalMFA,
		PermissionManagePersonalMFA,
		PermissionManageUserMFA,

		// Verification permissions
		PermissionReadVerification,
		PermissionWriteVerification,
		PermissionDeleteVerification,
		PermissionManageVerifications,
		PermissionViewPersonalVerifications,
		PermissionManagePersonalVerifications,

		// Passkey permissions
		PermissionReadPasskey,
		PermissionWritePasskey,
		PermissionManagePasskey,
		PermissionViewPersonalPasskey,
		PermissionManagePersonalPasskey,

		// OAuth permissions
		PermissionReadOAuth,
		PermissionWriteOAuth,
		PermissionManageOAuth,
		PermissionViewPersonalOAuth,
		PermissionManagePersonalOAuth,

		// SSO permissions
		PermissionReadSSO,
		PermissionWriteSSO,
		PermissionManageSSO,

		// Webhook permissions
		PermissionReadWebhooks,
		PermissionWriteWebhook,
		PermissionDeleteWebhook,
		PermissionManageWebhooks,
		PermissionReadWebhookEvents,
		PermissionWriteWebhookEvent,
		PermissionDeleteWebhookEvent,
		PermissionManageWebhookEvent,

		// Email template permissions
		PermissionReadEmailTemplate,
		PermissionWriteEmailTemplate,
		PermissionDeleteEmailTemplate,
		PermissionManageEmailTemplate,
		PermissionManageSystemEmailTemplate,

		// Activity permissions
		PermissionReadActivity,
		PermissionWriteActivity,
		PermissionDeleteActivity,
		PermissionManageActivity,
		PermissionViewPersonalActivity,
		PermissionManagePersonalActivity,
		PermissionReadActivityGlobal,

		// Role and permission management
		PermissionReadRoles,
		PermissionWriteRole,
		PermissionDeleteRole,
		PermissionManageRole,
		PermissionAssignRoles,
		PermissionRevokeRole,
		PermissionViewSystemRoles,
		PermissionManageSystemRoles,
		PermissionReadPermission,
		PermissionWritePermission,
		PermissionDeletePermission,
		PermissionManagePermission,
		PermissionCheckPermission,
		PermissionManageSystemPermission,

		// User management permissions
		PermissionCreateUser,
		PermissionReadUser,
		PermissionUpdateUser,
		PermissionDeleteUser,
		PermissionListUsers,
		PermissionManageUsers,
		PermissionImpersonateUser,
		PermissionResetPassword,
		PermissionViewInternalUsers,
		PermissionManageInternalUsers,
		PermissionCreateInternalUser,
		PermissionUpdateInternalUser,
		PermissionDeleteInternalUser,
		PermissionViewEndUsers,
		PermissionListEndUsers,
		PermissionCreateEndUser,
		PermissionUpdateEndUser,
		PermissionDeleteEndUser,
		PermissionBlockEndUser,
		PermissionManageEndUserSessions,
		PermissionViewEndUserAnalytics,

		// Organization management permissions
		PermissionCreateOrganization,
		PermissionViewOrganization,
		PermissionUpdateOrganization,
		PermissionDeleteOrganization,
		PermissionListOrganizations,
		PermissionViewInvitations,
		PermissionInviteMembers,
		PermissionViewMembers,
		PermissionManageMembers,
		PermissionRemoveMembers,
		PermissionManageSettings,
		PermissionViewBilling,
		PermissionManageBilling,
		PermissionManageIntegrations,
		PermissionViewAuditLogs,
		PermissionTransferOwnership,
		PermissionDeleteAllData,
		PermissionExportData,
		PermissionManageCompliance,
		PermissionViewAnalytics,
		PermissionExportUsers,
		PermissionViewCustomerOrganizations,
		PermissionManageCustomerOrganizations,
		PermissionCreateCustomerOrganization,
		PermissionUpdateCustomerOrganization,
		PermissionDeleteCustomerOrganization,

		// Auth service permissions
		PermissionManageAuthService,
		PermissionConfigureAuthService,
		PermissionViewAuthMetrics,
		PermissionViewAuthServiceAnalytics,
		PermissionManageAuthProvider,
		PermissionManageAuthTemplate,
		PermissionManageAuthDomain,
		PermissionManageAuthServiceDomain,
		PermissionViewAuthLogs,

		// System administration permissions
		PermissionSystemAdmin,
		PermissionManageSystemSettings,
		PermissionViewSystemSettings,

		// Platform administration permissions
		PermissionManagePlatform,
		PermissionViewPlatformMetrics,
		PermissionManagePlatformSettings,
		PermissionViewPlatformAnalytics,
		PermissionViewAllOrganizations,
		PermissionManageAllOrganizations,
		PermissionSuspendOrganization,
		PermissionDeleteAnyOrganization,
		PermissionViewAllUsers,
		PermissionManageAllUsers,
		PermissionImpersonateAnyUser,
		PermissionSuspendAnyUser,
		PermissionViewAllCustomers,
		PermissionManageCustomerBilling,
		PermissionSuspendCustomer,
		PermissionViewPlatformAuditLogs,
		PermissionManagePlatformSecurity,
		PermissionViewAllBilling,
		PermissionManageAllBilling,
		PermissionViewComplianceReports,
	}
}

// IsValidPermission checks if a permission string is valid
func IsValidPermission(permission string) bool {
	allPerms := GetAllPermissions()
	for _, p := range allPerms {
		if p.String() == permission {
			return true
		}
	}
	return false
}
