package authz

import (
	"context"
	"fmt"

	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/model"
)

// ResourcePermissionChecker provides permission checking for specific resources
type ResourcePermissionChecker struct {
	checker      PermissionChecker
	resourceType model.ResourceType
	resourceID   string
}

// NewResourcePermissionChecker creates a new resource-scoped permission checker
func NewResourcePermissionChecker(checker PermissionChecker, resourceType model.ResourceType, resourceID string) *ResourcePermissionChecker {
	return &ResourcePermissionChecker{
		checker:      checker,
		resourceType: resourceType,
		resourceID:   resourceID,
	}
}

// HasPermissionString checks if the current user has the specified permission for this resource
func (rpc *ResourcePermissionChecker) HasPermissionString(ctx context.Context, permission Permission) (bool, error) {
	return rpc.checker.HasPermissionString(ctx, permission, rpc.resourceType, rpc.resourceID)
}

// HasPermission checks if the current user has the specified permission for this resource
func (rpc *ResourcePermissionChecker) HasPermission(ctx context.Context, permission Permission) (bool, error) {
	xxid, err := xid.FromString(rpc.resourceID)
	if err != nil {
		// If it's not a valid XID, use string-based checking
		return rpc.HasPermissionString(ctx, permission)
	}

	return rpc.checker.HasPermission(ctx, permission, rpc.resourceType, xxid)
}

// HasPermissions checks if the current user has all the specified permissions for this resource
func (rpc *ResourcePermissionChecker) HasPermissions(ctx context.Context, permissions []Permission) (bool, error) {
	xxid, err := xid.FromString(rpc.resourceID)
	if err != nil {
		// If it's not a valid XID, check each permission individually
		for _, permission := range permissions {
			has, err := rpc.HasPermissionString(ctx, permission)
			if err != nil {
				return false, err
			}
			if !has {
				return false, nil
			}
		}
		return true, nil
	}

	return rpc.checker.HasPermissions(ctx, permissions, rpc.resourceType, xxid)
}

// HasAnyPermission checks if the current user has any of the specified permissions for this resource
func (rpc *ResourcePermissionChecker) HasAnyPermission(ctx context.Context, permissions []Permission) (bool, error) {
	xxid, err := xid.FromString(rpc.resourceID)
	if err != nil {
		// If it's not a valid XID, check each permission individually
		for _, permission := range permissions {
			has, err := rpc.HasPermissionString(ctx, permission)
			if err != nil {
				return false, err
			}
			if has {
				return true, nil
			}
		}
		return false, nil
	}

	return rpc.checker.HasAnyPermission(ctx, permissions, rpc.resourceType, xxid)
}

// RequirePermission checks if the user has the required permission and returns an error if not
func (rpc *ResourcePermissionChecker) RequirePermission(ctx context.Context, permission Permission) error {
	hasPermission, err := rpc.HasPermission(ctx, permission)
	if err != nil {
		return err
	}
	if !hasPermission {
		return fmt.Errorf("%w: missing permission %s for %s %s",
			ErrNoPermission, permission, rpc.resourceType, rpc.resourceID)
	}
	return nil
}

// RequirePermissions checks if the user has all required permissions and returns an error if not
func (rpc *ResourcePermissionChecker) RequirePermissions(ctx context.Context, permissions []Permission) error {
	hasPermissions, err := rpc.HasPermissions(ctx, permissions)
	if err != nil {
		return err
	}
	if !hasPermissions {
		return fmt.Errorf("%w: missing one or more permissions %v for %s %s",
			ErrNoPermission, permissions, rpc.resourceType, rpc.resourceID)
	}
	return nil
}

// RequireAnyPermission checks if the user has any of the required permissions and returns an error if not
func (rpc *ResourcePermissionChecker) RequireAnyPermission(ctx context.Context, permissions []Permission) error {
	hasAnyPermission, err := rpc.HasAnyPermission(ctx, permissions)
	if err != nil {
		return err
	}
	if !hasAnyPermission {
		return fmt.Errorf("%w: missing all permissions %v for %s %s",
			ErrNoPermission, permissions, rpc.resourceType, rpc.resourceID)
	}
	return nil
}

// CanView checks if the user can view this resource
func (rpc *ResourcePermissionChecker) CanView(ctx context.Context) (bool, error) {
	viewPermissions := []Permission{
		PermissionViewSelf, // For self-access
	}

	// Add resource-specific view permissions
	switch rpc.resourceType {
	case model.ResourceOrganization:
		viewPermissions = append(viewPermissions, PermissionViewOrganization)
	case model.ResourceUser:
		viewPermissions = append(viewPermissions, PermissionReadUser)
	case model.ResourceAPIKey:
		viewPermissions = append(viewPermissions, PermissionReadAPIKeys, PermissionReadPersonalAPIKeys)
	case model.ResourceSession:
		viewPermissions = append(viewPermissions, PermissionReadSessions, PermissionReadPersonalSessions)
	case model.ResourceMFA:
		viewPermissions = append(viewPermissions, PermissionReadMFA, PermissionViewPersonalMFA)
	case model.ResourceVerification:
		viewPermissions = append(viewPermissions, PermissionReadVerification, PermissionViewPersonalVerifications)
	case model.ResourceWebhook:
		viewPermissions = append(viewPermissions, PermissionReadWebhooks)
	case model.ResourceWebhookEvent:
		viewPermissions = append(viewPermissions, PermissionReadWebhookEvents)
	case model.ResourceEmailTemplate:
		viewPermissions = append(viewPermissions, PermissionReadEmailTemplate)
	case model.ResourceRole:
		viewPermissions = append(viewPermissions, PermissionReadRoles)
	case model.ResourcePermission:
		viewPermissions = append(viewPermissions, PermissionReadPermission)
	}

	return rpc.HasAnyPermission(ctx, viewPermissions)
}

// CanEdit checks if the user can edit this resource
func (rpc *ResourcePermissionChecker) CanEdit(ctx context.Context) (bool, error) {
	editPermissions := []Permission{
		PermissionUpdateSelf, // For self-access
	}

	// Add resource-specific edit permissions
	switch rpc.resourceType {
	case model.ResourceOrganization:
		editPermissions = append(editPermissions, PermissionUpdateOrganization)
	case model.ResourceUser:
		editPermissions = append(editPermissions, PermissionUpdateUser)
	case model.ResourceAPIKey:
		editPermissions = append(editPermissions, PermissionWriteAPIKey, PermissionManagePersonalAPIKeys)
	case model.ResourceMFA:
		editPermissions = append(editPermissions, PermissionWriteMFA, PermissionManagePersonalMFA)
	case model.ResourceVerification:
		editPermissions = append(editPermissions, PermissionWriteVerification, PermissionManagePersonalVerifications)
	case model.ResourceWebhook:
		editPermissions = append(editPermissions, PermissionWriteWebhook)
	case model.ResourceEmailTemplate:
		editPermissions = append(editPermissions, PermissionWriteEmailTemplate)
	case model.ResourceRole:
		editPermissions = append(editPermissions, PermissionWriteRole)
	case model.ResourcePermission:
		editPermissions = append(editPermissions, PermissionWritePermission)
	}

	return rpc.HasAnyPermission(ctx, editPermissions)
}

// CanDelete checks if the user can delete this resource
func (rpc *ResourcePermissionChecker) CanDelete(ctx context.Context) (bool, error) {
	deletePermissions := []Permission{
		PermissionDeleteSelf, // For self-access
	}

	// Add resource-specific delete permissions
	switch rpc.resourceType {
	case model.ResourceOrganization:
		deletePermissions = append(deletePermissions, PermissionDeleteOrganization)
	case model.ResourceUser:
		deletePermissions = append(deletePermissions, PermissionDeleteUser)
	case model.ResourceAPIKey:
		deletePermissions = append(deletePermissions, PermissionDeleteAPIKey, PermissionManagePersonalAPIKeys)
	case model.ResourceSession:
		deletePermissions = append(deletePermissions, PermissionDeleteSession, PermissionManagePersonalSessions)
	case model.ResourceMFA:
		deletePermissions = append(deletePermissions, PermissionDeleteMFA, PermissionManagePersonalMFA)
	case model.ResourceVerification:
		deletePermissions = append(deletePermissions, PermissionDeleteVerification, PermissionManagePersonalVerifications)
	case model.ResourceWebhook:
		deletePermissions = append(deletePermissions, PermissionDeleteWebhook)
	case model.ResourceWebhookEvent:
		deletePermissions = append(deletePermissions, PermissionDeleteWebhookEvent)
	case model.ResourceEmailTemplate:
		deletePermissions = append(deletePermissions, PermissionDeleteEmailTemplate)
	case model.ResourceRole:
		deletePermissions = append(deletePermissions, PermissionDeleteRole)
	case model.ResourcePermission:
		deletePermissions = append(deletePermissions, PermissionDeletePermission)
	}

	return rpc.HasAnyPermission(ctx, deletePermissions)
}
