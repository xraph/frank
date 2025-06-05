package authz

import (
	"context"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

// Permission represents a single, atomic permission
type Permission string

// Organization permissions
const (
	// Organization viewing and management
	PermissionViewOrganization   Permission = "view:organization"
	PermissionListOrganizations  Permission = "list:organizations"
	PermissionCreateOrganization Permission = "create:organization"
	PermissionUpdateOrganization Permission = "update:organization"
	PermissionDeleteOrganization Permission = "delete:organization"

	// Organization membership management
	PermissionViewOrganizationMembers   Permission = "view:organization:members"
	PermissionAddOrganizationMember     Permission = "add:organization:member"
	PermissionUpdateOrganizationMember  Permission = "update:organization:member"
	PermissionRemoveOrganizationMember  Permission = "remove:organization:member"
	PermissionManageOrganizationInvites Permission = "manage:organization:invites"
)

// User management permissions
const (
	PermissionViewUser   Permission = "view:user"
	PermissionListUsers  Permission = "list:users"
	PermissionCreateUser Permission = "create:user"
	PermissionUpdateUser Permission = "update:user"
	PermissionDeleteUser Permission = "delete:user"

	// User self-management permissions
	PermissionViewSelf   Permission = "view:self"
	PermissionUpdateSelf Permission = "update:self"
	PermissionDeleteSelf Permission = "delete:self"
	PermissionManageSelf Permission = "manage:self"
)

// API Key permissions
const (
	PermissionViewAPIKeys           Permission = "view:api:keys"
	PermissionListAPIKeys           Permission = "list:api:keys"
	PermissionCreateAPIKey          Permission = "create:api:key"
	PermissionUpdateAPIKey          Permission = "update:api:key"
	PermissionDeleteAPIKey          Permission = "delete:api:key"
	PermissionManageAPIKeys         Permission = "manage:api:keys"
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
	PermissionViewWebhooks   Permission = "view:webhooks"
	PermissionListWebhooks   Permission = "list:webhooks"
	PermissionCreateWebhook  Permission = "create:webhook"
	PermissionUpdateWebhook  Permission = "update:webhook"
	PermissionDeleteWebhook  Permission = "delete:webhook"
	PermissionManageWebhooks Permission = "manage:webhooks"

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
	PermissionSystemAdmin            Permission = "system:admin"
	PermissionManageSystemSettings   Permission = "manage:system:settings"
	PermissionViewSystemSettings     Permission = "view:system:settings"
	PermissionManageAllOrganizations Permission = "manage:all:organizations"
	PermissionViewAllOrganizations   Permission = "view:all:organizations"
	PermissionManageAllUsers         Permission = "manage:all:users"
	PermissionViewAllUsers           Permission = "view:all:users"
	PermissionManageSystemRoles      Permission = "manage:system:roles"
	PermissionViewSystemRoles        Permission = "view:system:roles"
)

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

// ErrNoPermission is returned when a user doesn't have the required permission
var ErrNoPermission = errors.New(errors.CodeForbidden, "permission denied")
