package authz

import (
	"context"
	"fmt"

	"github.com/rs/xid"
)

// ResourcePermissionChecker provides permission checking for specific resources
type ResourcePermissionChecker struct {
	checker      PermissionChecker
	resourceType ResourceType
	resourceID   string
}

// NewResourcePermissionChecker creates a new resource-scoped permission checker
func NewResourcePermissionChecker(checker PermissionChecker, resourceType ResourceType, resourceID string) *ResourcePermissionChecker {
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
	case ResourceOrganization:
		viewPermissions = append(viewPermissions, PermissionViewOrganization)
	case ResourceUser:
		viewPermissions = append(viewPermissions, PermissionReadUser)
	case ResourceAPIKey:
		viewPermissions = append(viewPermissions, PermissionReadAPIKey, PermissionViewPersonalAPIKey)
	case ResourceSession:
		viewPermissions = append(viewPermissions, PermissionReadSessions, PermissionViewPersonalSession)
	case ResourceMFA:
		viewPermissions = append(viewPermissions, PermissionReadMFA, PermissionViewPersonalMFA)
	case ResourceVerification:
		viewPermissions = append(viewPermissions, PermissionReadVerification, PermissionViewPersonalVerifications)
	case ResourceWebhook:
		viewPermissions = append(viewPermissions, PermissionReadWebhook)
	case ResourceWebhookEvent:
		viewPermissions = append(viewPermissions, PermissionReadWebhookEvents)
	case ResourceEmailTemplate:
		viewPermissions = append(viewPermissions, PermissionReadEmailTemplate)
	case ResourceRole:
		viewPermissions = append(viewPermissions, PermissionReadRole)
	case ResourcePermission:
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
	case ResourceOrganization:
		editPermissions = append(editPermissions, PermissionUpdateOrganization)
	case ResourceUser:
		editPermissions = append(editPermissions, PermissionUpdateUser)
	case ResourceAPIKey:
		editPermissions = append(editPermissions, PermissionWriteAPIKey, PermissionManagePersonalAPIKey)
	case ResourceMFA:
		editPermissions = append(editPermissions, PermissionWriteMFA, PermissionManagePersonalMFA)
	case ResourceVerification:
		editPermissions = append(editPermissions, PermissionWriteVerification, PermissionManagePersonalVerifications)
	case ResourceWebhook:
		editPermissions = append(editPermissions, PermissionWriteWebhook)
	case ResourceEmailTemplate:
		editPermissions = append(editPermissions, PermissionWriteEmailTemplate)
	case ResourceRole:
		editPermissions = append(editPermissions, PermissionWriteRole)
	case ResourcePermission:
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
	case ResourceOrganization:
		deletePermissions = append(deletePermissions, PermissionDeleteOrganization)
	case ResourceUser:
		deletePermissions = append(deletePermissions, PermissionDeleteUser)
	case ResourceAPIKey:
		deletePermissions = append(deletePermissions, PermissionDeleteAPIKey, PermissionManagePersonalAPIKey)
	case ResourceSession:
		deletePermissions = append(deletePermissions, PermissionDeleteSession, PermissionManagePersonalSession)
	case ResourceMFA:
		deletePermissions = append(deletePermissions, PermissionDeleteMFA, PermissionManagePersonalMFA)
	case ResourceVerification:
		deletePermissions = append(deletePermissions, PermissionDeleteVerification, PermissionManagePersonalVerifications)
	case ResourceWebhook:
		deletePermissions = append(deletePermissions, PermissionDeleteWebhook)
	case ResourceWebhookEvent:
		deletePermissions = append(deletePermissions, PermissionDeleteWebhookEvent)
	case ResourceEmailTemplate:
		deletePermissions = append(deletePermissions, PermissionDeleteEmailTemplate)
	case ResourceRole:
		deletePermissions = append(deletePermissions, PermissionDeleteRole)
	case ResourcePermission:
		deletePermissions = append(deletePermissions, PermissionDeletePermission)
	}

	return rpc.HasAnyPermission(ctx, deletePermissions)
}
