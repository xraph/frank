package authz

import (
	"context"

	"github.com/juicycleff/frank/ent"
	entMembership "github.com/juicycleff/frank/ent/membership"
	entOrganization "github.com/juicycleff/frank/ent/organization"
	entRole "github.com/juicycleff/frank/ent/role"
	entUser "github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

// DefaultPermissionChecker is the default implementation of PermissionChecker
type DefaultPermissionChecker struct {
	client    *data.Clients
	rolePerms RolePermissions
}

// NewPermissionChecker creates a new DefaultPermissionChecker
func NewPermissionChecker(client *data.Clients) *DefaultPermissionChecker {
	return &DefaultPermissionChecker{
		client:    client,
		rolePerms: DefaultRolePermissions,
	}
}

// WithCustomRolePermissions allows setting custom role permissions
func (pc *DefaultPermissionChecker) WithCustomRolePermissions(rolePerms RolePermissions) *DefaultPermissionChecker {
	pc.rolePerms = rolePerms
	return pc
}

// HasPermission checks if the current user has the specified permission
func (pc *DefaultPermissionChecker) HasPermission(ctx context.Context, permission Permission, resourceType ResourceType, resourceID xid.ID) (bool, error) {
	return pc.HasPermissions(ctx, []Permission{permission}, resourceType, resourceID)
}

// HasPermissionString checks if the current user has the specified permission
func (pc *DefaultPermissionChecker) HasPermissionString(ctx context.Context, permission Permission, resourceType ResourceType, resourceID string) (bool, error) {
	return pc.HasPermissionsString(ctx, []Permission{permission}, resourceType, resourceID)
}

// HasPermissionWithUserID checks if the specified user has the specified permission
func (pc *DefaultPermissionChecker) HasPermissionWithUserID(ctx context.Context, permission Permission, resourceType ResourceType, resourceID xid.ID, userID xid.ID) (bool, error) {
	return pc.HasPermissionsWithUserID(ctx, []Permission{permission}, resourceType, resourceID, userID)
}

// HasPermissions checks if the current user has all the specified permissions
func (pc *DefaultPermissionChecker) HasPermissions(ctx context.Context, permissions []Permission, resourceType ResourceType, resourceID xid.ID) (bool, error) {
	// Get user from context
	userId, err := GetUserIDFromContext(ctx)
	if err != nil {
		return false, err
	}
	return pc.HasPermissionsWithUserID(ctx, permissions, resourceType, resourceID, userId)
}

// HasPermissionsString checks if the current user has all the specified permissions
func (pc *DefaultPermissionChecker) HasPermissionsString(ctx context.Context, permissions []Permission, resourceType ResourceType, resourceID string) (bool, error) {
	// Get user from context
	userId, err := GetUserIDFromContext(ctx)
	if err != nil {
		return false, err
	}

	var xxid xid.ID
	if resourceID != "" {
		xxid, err = xid.FromString(resourceID)
		if err != nil {
			// If it's not a valid XID, it might be a slug or identifier
			return pc.HasPermissionsWithUserIDString(ctx, permissions, resourceType, resourceID, userId)
		}
	}

	return pc.HasPermissionsWithUserID(ctx, permissions, resourceType, xxid, userId)
}

// HasPermissionsWithUserID checks if the specified user has all the specified permissions
func (pc *DefaultPermissionChecker) HasPermissionsWithUserID(ctx context.Context, permissions []Permission, resourceType ResourceType, resourceID xid.ID, userID xid.ID) (bool, error) {
	// Get user roles for the resource
	roles, err := pc.getUserRoles(ctx, userID, resourceType, resourceID)
	if err != nil {
		return false, err
	}

	if len(roles) == 0 {
		return false, nil
	}

	// Check permissions for all roles
	for _, role := range roles {
		if pc.roleHasAllPermissions(role, permissions) {
			return true, nil
		}
	}

	return false, nil
}

// HasPermissionsWithUserIDString handles string-based resource IDs (like slugs)
func (pc *DefaultPermissionChecker) HasPermissionsWithUserIDString(ctx context.Context, permissions []Permission, resourceType ResourceType, resourceID string, userID xid.ID) (bool, error) {
	// Get user roles for the resource using string identifier
	roles, err := pc.getUserRolesString(ctx, userID, resourceType, resourceID)
	if err != nil {
		return false, err
	}

	if len(roles) == 0 {
		return false, nil
	}

	// Check permissions for all roles
	for _, role := range roles {
		if pc.roleHasAllPermissions(role, permissions) {
			return true, nil
		}
	}

	return false, nil
}

// HasAnyPermission checks if the current user has any of the specified permissions
func (pc *DefaultPermissionChecker) HasAnyPermission(ctx context.Context, permissions []Permission, resourceType ResourceType, resourceID xid.ID) (bool, error) {
	// Get user from context
	userId, ok := middleware.GetUserID(ctx)
	if !ok {
		return false, errors.New(errors.CodeResourceNotFound, "logged in user resource not found")
	}
	return pc.HasAnyPermissionWithUserID(ctx, permissions, resourceType, resourceID, userId)
}

// HasAnyPermissionWithUserID checks if the specified user has any of the specified permissions
func (pc *DefaultPermissionChecker) HasAnyPermissionWithUserID(ctx context.Context, permissions []Permission, resourceType ResourceType, resourceID xid.ID, userID xid.ID) (bool, error) {
	// Get user roles for the resource
	roles, err := pc.getUserRoles(ctx, userID, resourceType, resourceID)
	if err != nil {
		return false, err
	}

	if len(roles) == 0 {
		return false, nil
	}

	// Check if any role has any of the required permissions
	for _, role := range roles {
		if pc.roleHasAnyPermission(role, permissions) {
			return true, nil
		}
	}

	return false, nil
}

// getUserRoles gets the user's roles for a specific resource
func (pc *DefaultPermissionChecker) getUserRoles(ctx context.Context, userID xid.ID, resourceType ResourceType, resourceID xid.ID) ([]RoleType, error) {
	switch resourceType {
	case ResourceGlobal:
		// For global resources, check if user is system admin
		return pc.getUserSystemRoles(ctx, userID)

	case ResourceOrganization:
		// Get user's role in this organization through membership
		return pc.getUserOrganizationRoles(ctx, userID, resourceID)

	case ResourceUser:
		// For user resources, check if it's the same user (self-access) or organization admin
		if resourceID == userID {
			// User accessing their own resource gets guest role + any org roles
			roles := []RoleType{RoleGuest}
			orgRoles, _ := pc.getUserPrimaryOrganizationRoles(ctx, userID)
			roles = append(roles, orgRoles...)
			return roles, nil
		}
		// For accessing other users, need organization-level permissions
		return pc.getUserOrganizationRolesForUser(ctx, userID, resourceID)

	default:
		// For other resources, determine organization and check roles there
		return pc.getUserRolesForResource(ctx, userID, resourceType, resourceID)
	}
}

// getUserRolesString gets the user's roles for a string-based resource identifier
func (pc *DefaultPermissionChecker) getUserRolesString(ctx context.Context, userID xid.ID, resourceType ResourceType, resourceID string) ([]RoleType, error) {
	switch resourceType {
	case ResourceOrganization:
		// Handle organization by slug
		return pc.getUserOrganizationRolesBySlug(ctx, userID, resourceID)
	default:
		// Try to convert to XID and use regular method
		xxid, err := xid.FromString(resourceID)
		if err != nil {
			return nil, errors.New(errors.CodeInvalidInput, "invalid resource ID format")
		}
		return pc.getUserRoles(ctx, userID, resourceType, xxid)
	}
}

// getUserSystemRoles checks if user has system-level roles
func (pc *DefaultPermissionChecker) getUserSystemRoles(ctx context.Context, userID xid.ID) ([]RoleType, error) {
	// Check if user has any system roles (direct user-role relationship)
	roles, err := pc.client.DB.Role.Query().
		Where(
			entRole.HasSystemUsersWith(entUser.IDEQ(userID)),
			entRole.OrganizationIDIsNil(), // System roles have no organization
			entRole.System(true),
		).
		All(ctx)

	if err != nil {
		return nil, err
	}

	var roleTypes []RoleType
	for _, role := range roles {
		// Map role names to RoleType constants
		if roleType := mapRoleNameToType(role.Name); roleType != "" {
			roleTypes = append(roleTypes, roleType)
		}
	}

	return roleTypes, nil
}

// getUserOrganizationRoles gets user's roles in a specific organization through membership
func (pc *DefaultPermissionChecker) getUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]RoleType, error) {
	// Get user's active membership in this organization
	membership, err := pc.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
		).
		WithRole().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return []RoleType{}, nil
		}
		return nil, err
	}

	var roleTypes []RoleType
	if membership.Edges.Role != nil {
		if roleType := mapRoleNameToType(membership.Edges.Role.Name); roleType != "" {
			roleTypes = append(roleTypes, roleType)
		}
	}

	// Always include guest role for active organization members
	if len(roleTypes) > 0 {
		roleTypes = append(roleTypes, RoleGuest)
	}

	return roleTypes, nil
}

// getUserOrganizationRolesBySlug gets user's roles in an organization by slug
func (pc *DefaultPermissionChecker) getUserOrganizationRolesBySlug(ctx context.Context, userID xid.ID, orgSlug string) ([]RoleType, error) {
	// Get user's active membership in this organization by slug
	membership, err := pc.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.HasOrganizationWith(entOrganization.Slug(orgSlug)),
			entMembership.StatusEQ("active"),
		).
		WithRole().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return []RoleType{}, nil
		}
		return nil, err
	}

	var roleTypes []RoleType
	if membership.Edges.Role != nil {
		if roleType := mapRoleNameToType(membership.Edges.Role.Name); roleType != "" {
			roleTypes = append(roleTypes, roleType)
		}
	}

	// Always include guest role for active organization members
	if len(roleTypes) > 0 {
		roleTypes = append(roleTypes, RoleGuest)
	}

	return roleTypes, nil
}

// getUserPrimaryOrganizationRoles gets user's roles in their primary organization
func (pc *DefaultPermissionChecker) getUserPrimaryOrganizationRoles(ctx context.Context, userID xid.ID) ([]RoleType, error) {
	user, err := pc.client.DB.User.Get(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user.PrimaryOrganizationID.IsNil() {
		return []RoleType{}, nil
	}

	return pc.getUserOrganizationRoles(ctx, userID, user.PrimaryOrganizationID)
}

// getUserOrganizationRolesForUser gets user's roles when accessing another user's resource
func (pc *DefaultPermissionChecker) getUserOrganizationRolesForUser(ctx context.Context, userID xid.ID, targetUserID xid.ID) ([]RoleType, error) {
	// Get target user's primary organization
	targetUser, err := pc.client.DB.User.Get(ctx, targetUserID)
	if err != nil {
		return nil, err
	}

	if targetUser.PrimaryOrganizationID.IsNil() {
		return []RoleType{}, nil
	}

	// Check if requesting user has roles in the target user's organization
	return pc.getUserOrganizationRoles(ctx, userID, targetUser.PrimaryOrganizationID)
}

// getUserRolesForResource gets user roles for other resource types by determining their organization
func (pc *DefaultPermissionChecker) getUserRolesForResource(ctx context.Context, userID xid.ID, resourceType ResourceType, resourceID xid.ID) ([]RoleType, error) {
	// Determine the organization for this resource
	checker := NewResourceOwnershipChecker(pc.client)
	orgID, err := checker.GetResourceOrganization(ctx, resourceType, resourceID)
	if err != nil {
		// If resource is not org-scoped, check system roles
		return pc.getUserSystemRoles(ctx, userID)
	}

	// Get user's roles in the resource's organization
	return pc.getUserOrganizationRoles(ctx, userID, orgID)
}

// roleHasAllPermissions checks if a role has all the specified permissions
func (pc *DefaultPermissionChecker) roleHasAllPermissions(role RoleType, permissions []Permission) bool {
	rolePermissions, exists := pc.rolePerms[role]
	if !exists {
		return false
	}

	permissionSet := make(map[Permission]bool)
	for _, p := range rolePermissions {
		permissionSet[p] = true
	}

	for _, p := range permissions {
		if !permissionSet[p] {
			return false
		}
	}

	return true
}

// roleHasAnyPermission checks if a role has any of the specified permissions
func (pc *DefaultPermissionChecker) roleHasAnyPermission(role RoleType, permissions []Permission) bool {
	rolePermissions, exists := pc.rolePerms[role]
	if !exists {
		return false
	}

	permissionSet := make(map[Permission]bool)
	for _, p := range rolePermissions {
		permissionSet[p] = true
	}

	for _, p := range permissions {
		if permissionSet[p] {
			return true
		}
	}

	return false
}

// mapRoleNameToType maps database role names to RoleType constants
func mapRoleNameToType(roleName string) RoleType {
	switch roleName {
	case "system_admin":
		return RoleSystemAdmin
	case "owner":
		return RoleOwner
	case "admin":
		return RoleAdmin
	case "member":
		return RoleMember
	case "viewer":
		return RoleViewer
	case "guest":
		return RoleGuest
	default:
		return ""
	}
}

// Helper functions for membership management

// IsOrganizationMember checks if a user is an active member of an organization
func (pc *DefaultPermissionChecker) IsOrganizationMember(ctx context.Context, userID xid.ID, orgID xid.ID) (bool, error) {
	count, err := pc.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
		).
		Count(ctx)

	return count > 0, err
}

// GetUserOrganizations returns all organizations a user is a member of
func (pc *DefaultPermissionChecker) GetUserOrganizations(ctx context.Context, userID xid.ID) ([]*ent.Organization, error) {
	memberships, err := pc.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.StatusEQ("active"),
		).
		WithOrganization().
		All(ctx)

	if err != nil {
		return nil, err
	}

	orgs := make([]*ent.Organization, 0, len(memberships))
	for _, membership := range memberships {
		if membership.Edges.Organization != nil {
			orgs = append(orgs, membership.Edges.Organization)
		}
	}

	return orgs, nil
}

// GetOrganizationMembers returns all active members of an organization
func (pc *DefaultPermissionChecker) GetOrganizationMembers(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error) {
	return pc.client.DB.Membership.Query().
		Where(
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
		).
		WithUser().
		WithRole().
		All(ctx)
}
