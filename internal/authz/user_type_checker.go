package authz

import (
	"context"

	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/contexts"
	"github.com/xraph/frank/pkg/data"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/model"
)

// UserTypeChecker defines interface for checking user types
type UserTypeChecker interface {
	// IsInternalUser checks if user is internal platform staff
	IsInternalUser(ctx context.Context, userID xid.ID) (bool, error)

	// IsPlatformAdmin checks if user is platform administrator
	IsPlatformAdmin(ctx context.Context, userID xid.ID) (bool, error)

	// IsExternalUser checks if user is external customer organization member
	IsExternalUser(ctx context.Context, userID xid.ID) (bool, error)

	// GetUserType returns the user's type
	GetUserType(ctx context.Context, userID xid.ID) (UserType, error)

	// CanAccessCustomerData checks if user can access customer organization data
	CanAccessCustomerData(ctx context.Context, userID xid.ID, customerOrgID xid.ID) (bool, error)
}

// Enhanced permission checker that includes user type checking
type EnhancedPermissionChecker struct {
	*DefaultPermissionChecker
	userMgmt *UserManagementService
}

// NewEnhancedPermissionChecker creates a permission checker with user type support
func NewEnhancedPermissionChecker(client *data.Clients) *EnhancedPermissionChecker {
	return &EnhancedPermissionChecker{
		DefaultPermissionChecker: NewPermissionChecker(client),
		userMgmt:                 NewUserManagementService(client),
	}
}

// WithCustomRolePermissions allows setting custom role permissions
func (epc *EnhancedPermissionChecker) WithCustomRolePermissions(rolePerms RolePermissions) *EnhancedPermissionChecker {
	epc.rolePerms = rolePerms
	return epc
}

// IsInternalUser checks if user is internal platform staff
func (epc *EnhancedPermissionChecker) IsInternalUser(ctx context.Context, userID xid.ID) (bool, error) {
	return epc.userMgmt.IsInternalUser(ctx, userID)
}

// IsPlatformAdmin checks if user is platform administrator
func (epc *EnhancedPermissionChecker) IsPlatformAdmin(ctx context.Context, userID xid.ID) (bool, error) {
	return epc.userMgmt.IsPlatformAdmin(ctx, userID)
}

// IsExternalUser checks if user is external customer organization member
func (epc *EnhancedPermissionChecker) IsExternalUser(ctx context.Context, userID xid.ID) (bool, error) {
	userType, err := epc.GetUserType(ctx, userID)
	if err != nil {
		return false, err
	}
	return userType == model.UserTypeExternal, nil
}

// GetUserType returns the user's type
func (epc *EnhancedPermissionChecker) GetUserType(ctx context.Context, userID xid.ID) (model.UserType, error) {
	userCtx, err := epc.userMgmt.GetUserContext(ctx, userID)
	if err != nil {
		return "", err
	}
	return userCtx.UserType, nil
}

// CanAccessCustomerData checks if user can access customer organization data
func (epc *EnhancedPermissionChecker) CanAccessCustomerData(ctx context.Context, userID xid.ID, customerOrgID xid.ID) (bool, error) {
	// Platform admins can access all customer data
	isPlatformAdmin, err := epc.IsPlatformAdmin(ctx, userID)
	if err != nil {
		return false, err
	}
	if isPlatformAdmin {
		return true, nil
	}

	// Internal users with appropriate permissions can access customer data
	isInternal, err := epc.IsInternalUser(ctx, userID)
	if err != nil {
		return false, err
	}
	if isInternal {
		return epc.HasPermission(ctx, PermissionViewAllCustomers, model.ResourceOrganization, customerOrgID)
	}

	// External users can only access their own organization's data
	return epc.IsOrganizationMember(ctx, userID, customerOrgID)
}

// HasPermissionForUserType checks permissions with user type context
func (epc *EnhancedPermissionChecker) HasPermissionForUserType(ctx context.Context, permission Permission, resourceType model.ResourceType, resourceID xid.ID, userID xid.ID) (bool, error) {
	userType, err := epc.GetUserType(ctx, userID)
	if err != nil {
		return false, err
	}

	// Platform-specific permissions only for internal users
	platformPermissions := []Permission{
		PermissionManagePlatform,
		PermissionViewAllCustomers,
		PermissionManageCustomerBilling,
		PermissionSuspendCustomer,
		PermissionViewPlatformAnalytics,
		PermissionManageInternalUsers,
		PermissionManageCustomerOrganizations,
	}

	for _, platPerm := range platformPermissions {
		if permission == platPerm && userType != model.UserTypeInternal {
			return false, errors.New(errors.CodeForbidden, "permission requires internal user")
		}
	}

	// End user management permissions only for external users in customer orgs
	endUserPermissions := []Permission{
		PermissionViewEndUsers,
		PermissionCreateEndUser,
		PermissionUpdateEndUser,
		PermissionDeleteEndUser,
		PermissionBlockEndUser,
		PermissionManageEndUserSessions,
		PermissionConfigureAuthService,
	}

	for _, euPerm := range endUserPermissions {
		if permission == euPerm && userType != model.UserTypeExternal {
			return false, errors.New(errors.CodeForbidden, "permission requires external customer user")
		}
	}

	// Use standard permission checking
	return epc.HasPermissionWithUserID(ctx, permission, resourceType, resourceID, userID)
}

// CheckContextualPermission Context-aware permission checking
func (epc *EnhancedPermissionChecker) CheckContextualPermission(ctx context.Context, permission Permission, resourceType model.ResourceType, resourceID xid.ID) (bool, error) {
	// Get current user
	userId := contexts.GetUserIDFromContext(ctx)
	if userId == nil {
		return false, errors.New(errors.CodeForbidden, "user not found in context")
	}

	return epc.HasPermissionForUserType(ctx, permission, resourceType, resourceID, *userId)
}
