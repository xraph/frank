package authz

import (
	"context"

	entUser "github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

// Permission represents a single, atomic permission
type Permission string

// API Key permissions
const (
	PermissionViewAPIKeys  Permission = "view:api:keys"
	PermissionListAPIKeys  Permission = "list:api:keys"
	PermissionCreateAPIKey Permission = "create:api:key"
	PermissionUpdateAPIKey Permission = "update:api:key"
	PermissionDeleteAPIKey Permission = "delete:api:key"
	// PermissionManageAPIKeys         Permission = "manage:api:keys"
	PermissionViewPersonalAPIKeys   Permission = "view:personal:api:keys"
	PermissionManagePersonalAPIKeys Permission = "manage:personal:api:keys"
)

// Session management permissions
const (
	PermissionViewSessions           Permission = "view:sessions"
	PermissionListSessions           Permission = "list:sessions"
	PermissionDeleteSession          Permission = "delete:session"
	PermissionManageSessions         Permission = "manage:sessions"
	PermissionViewPersonalSessions   Permission = "view:personal:sessions"
	PermissionManagePersonalSessions Permission = "manage:personal:sessions"
)

// Multi-Factor Authentication permissions
const (
	PermissionViewMFA           Permission = "view:mfa"
	PermissionListMFA           Permission = "list:mfa"
	PermissionCreateMFA         Permission = "create:mfa"
	PermissionUpdateMFA         Permission = "update:mfa"
	PermissionDeleteMFA         Permission = "delete:mfa"
	PermissionManageMFA         Permission = "manage:mfa"
	PermissionViewPersonalMFA   Permission = "view:personal:mfa"
	PermissionManagePersonalMFA Permission = "manage:personal:mfa"
)

// Verification permissions
const (
	PermissionViewVerifications           Permission = "view:verifications"
	PermissionListVerifications           Permission = "list:verifications"
	PermissionCreateVerification          Permission = "create:verification"
	PermissionUpdateVerification          Permission = "update:verification"
	PermissionDeleteVerification          Permission = "delete:verification"
	PermissionManageVerifications         Permission = "manage:verifications"
	PermissionViewPersonalVerifications   Permission = "view:personal:verifications"
	PermissionManagePersonalVerifications Permission = "manage:personal:verifications"
)

// Webhook permissions
const (
	PermissionViewWebhooks  Permission = "view:webhooks"
	PermissionListWebhooks  Permission = "list:webhooks"
	PermissionCreateWebhook Permission = "create:webhook"
	PermissionUpdateWebhook Permission = "update:webhook"
	PermissionDeleteWebhook Permission = "delete:webhook"
	// PermissionManageWebhooks Permission = "manage:webhooks"

	// Webhook events
	PermissionViewWebhookEvents   Permission = "view:webhook:events"
	PermissionListWebhookEvents   Permission = "list:webhook:events"
	PermissionCreateWebhookEvent  Permission = "create:webhook:event"
	PermissionDeleteWebhookEvent  Permission = "delete:webhook:event"
	PermissionManageWebhookEvents Permission = "manage:webhook:events"
)

// Email template permissions
const (
	PermissionViewEmailTemplates         Permission = "view:email:templates"
	PermissionListEmailTemplates         Permission = "list:email:templates"
	PermissionCreateEmailTemplate        Permission = "create:email:template"
	PermissionUpdateEmailTemplate        Permission = "update:email:template"
	PermissionDeleteEmailTemplate        Permission = "delete:email:template"
	PermissionManageEmailTemplates       Permission = "manage:email:templates"
	PermissionManageSystemEmailTemplates Permission = "manage:system:email:templates"
)

// Role and Permission management
const (
	PermissionViewRoles   Permission = "view:roles"
	PermissionListRoles   Permission = "list:roles"
	PermissionCreateRole  Permission = "create:role"
	PermissionUpdateRole  Permission = "update:role"
	PermissionDeleteRole  Permission = "delete:role"
	PermissionManageRoles Permission = "manage:roles"
	PermissionAssignRoles Permission = "assign:roles"

	PermissionViewPermissions         Permission = "view:permissions"
	PermissionListPermissions         Permission = "list:permissions"
	PermissionCreatePermission        Permission = "create:permission"
	PermissionUpdatePermission        Permission = "update:permission"
	PermissionDeletePermission        Permission = "delete:permission"
	PermissionManagePermissions       Permission = "manage:permissions"
	PermissionManageSystemPermissions Permission = "manage:system:permissions"
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

func (p Permission) String() string {
	return string(p)
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
	GetUserType(ctx context.Context, userID xid.ID) (entUser.UserType, error)

	// CanAccessCustomerData checks if user can access customer organization data
	CanAccessCustomerData(ctx context.Context, userID xid.ID, customerOrgID xid.ID) (bool, error)
	// HasPermissionForUserType checks permissions with user type context
	HasPermissionForUserType(ctx context.Context, permission Permission, resourceType ResourceType, resourceID xid.ID, userID xid.ID) (bool, error)

	// CheckContextualPermission Context-aware permission checking
	CheckContextualPermission(ctx context.Context, permission Permission, resourceType ResourceType, resourceID xid.ID) (bool, error)
}

// ErrNoPermission is returned when a user doesn't have the required permission
var ErrNoPermission = errors.New(errors.CodeForbidden, "permission denied")
