package authz

import (
	"context"

	entUser "github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

// Additional permissions for user type management
const (
	// Platform administration (internal users only)
	PermissionManagePlatform        Permission = "manage:platform"
	PermissionViewAllCustomers      Permission = "view:all:customers"
	PermissionManageCustomerBilling Permission = "manage:customer:billing"
	PermissionSuspendCustomer       Permission = "suspend:customer"
	PermissionViewPlatformAnalytics Permission = "view:platform:analytics"

	// End user management (customer organizations managing their auth service users)
	PermissionViewEndUsers          Permission = "view:end:users"
	PermissionListEndUsers          Permission = "list:end:users"
	PermissionCreateEndUser         Permission = "create:end:user"
	PermissionUpdateEndUser         Permission = "update:end:user"
	PermissionDeleteEndUser         Permission = "delete:end:user"
	PermissionBlockEndUser          Permission = "block:end:user"
	PermissionManageEndUserSessions Permission = "manage:end:user:sessions"
	PermissionViewEndUserAnalytics  Permission = "view:end:user:analytics"

	// Auth service configuration (customer organizations)
	PermissionConfigureAuthService     Permission = "configure:auth:service"
	PermissionManageAuthProviders      Permission = "manage:auth:providers"
	PermissionViewAuthServiceAnalytics Permission = "view:auth:service:analytics"
	PermissionManageAuthServiceDomain  Permission = "manage:auth:service:domain"

	// Internal user management
	PermissionManageInternalUsers Permission = "manage:internal:users"
	PermissionViewInternalUsers   Permission = "view:internal:users"
	PermissionCreateInternalUser  Permission = "create:internal:user"
	PermissionUpdateInternalUser  Permission = "update:internal:user"
	PermissionDeleteInternalUser  Permission = "delete:internal:user"

	// Customer organization management
	PermissionManageCustomerOrganizations Permission = "manage:customer:organizations"
	PermissionViewCustomerOrganizations   Permission = "view:customer:organizations"
	PermissionCreateCustomerOrganization  Permission = "create:customer:organization"
	PermissionUpdateCustomerOrganization  Permission = "update:customer:organization"
	PermissionDeleteCustomerOrganization  Permission = "delete:customer:organization"
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
	return userType == entUser.UserTypeExternal, nil
}

// GetUserType returns the user's type
func (epc *EnhancedPermissionChecker) GetUserType(ctx context.Context, userID xid.ID) (entUser.UserType, error) {
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
		return epc.HasPermission(ctx, PermissionViewAllCustomers, ResourceOrganization, customerOrgID)
	}

	// External users can only access their own organization's data
	return epc.IsOrganizationMember(ctx, userID, customerOrgID)
}

// HasPermissionForUserType checks permissions with user type context
func (epc *EnhancedPermissionChecker) HasPermissionForUserType(ctx context.Context, permission Permission, resourceType ResourceType, resourceID xid.ID, userID xid.ID) (bool, error) {
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
		if permission == platPerm && userType != entUser.UserTypeInternal {
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
		if permission == euPerm && userType != entUser.UserTypeExternal {
			return false, errors.New(errors.CodeForbidden, "permission requires external customer user")
		}
	}

	// Use standard permission checking
	return epc.HasPermissionWithUserID(ctx, permission, resourceType, resourceID, userID)
}

// CheckContextualPermission Context-aware permission checking
func (epc *EnhancedPermissionChecker) CheckContextualPermission(ctx context.Context, permission Permission, resourceType ResourceType, resourceID xid.ID) (bool, error) {
	// Get current user
	userId, err := middleware.GetUserIDFromContext(ctx)
	if err != nil {
		return false, err
	}

	return epc.HasPermissionForUserType(ctx, permission, resourceType, resourceID, userId)
}
