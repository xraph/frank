package authz

import (
	"context"
	"strings"

	"github.com/juicycleff/frank/ent"
	entMembership "github.com/juicycleff/frank/ent/membership"
	entOrganization "github.com/juicycleff/frank/ent/organization"
	entRole "github.com/juicycleff/frank/ent/role"
	entUser "github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/pkg/contexts"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
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
func (pc *DefaultPermissionChecker) HasPermission(ctx context.Context, permission Permission, resourceType model.ResourceType, resourceID xid.ID) (bool, error) {
	return pc.HasPermissions(ctx, []Permission{permission}, resourceType, resourceID)
}

// HasPermissionString checks if the current user has the specified permission
func (pc *DefaultPermissionChecker) HasPermissionString(ctx context.Context, permission Permission, resourceType model.ResourceType, resourceID string) (bool, error) {
	return pc.HasPermissionsString(ctx, []Permission{permission}, resourceType, resourceID)
}

// HasPermissionWithUserID checks if the specified user has the specified permission
func (pc *DefaultPermissionChecker) HasPermissionWithUserID(ctx context.Context, permission Permission, resourceType model.ResourceType, resourceID xid.ID, userID xid.ID) (bool, error) {
	return pc.HasPermissionsWithUserID(ctx, []Permission{permission}, resourceType, resourceID, userID)
}

// HasPermissions checks if the current user has all the specified permissions
func (pc *DefaultPermissionChecker) HasPermissions(ctx context.Context, permissions []Permission, resourceType model.ResourceType, resourceID xid.ID) (bool, error) {
	// Get user from context
	userId, err := GetUserIDFromContext(ctx)
	if err != nil {
		return false, err
	}
	return pc.HasPermissionsWithUserID(ctx, permissions, resourceType, resourceID, userId)
}

// HasPermissionsString checks if the current user has all the specified permissions
func (pc *DefaultPermissionChecker) HasPermissionsString(ctx context.Context, permissions []Permission, resourceType model.ResourceType, resourceID string) (bool, error) {
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
func (pc *DefaultPermissionChecker) HasPermissionsWithUserID(ctx context.Context, permissions []Permission, resourceType model.ResourceType, resourceID xid.ID, userID xid.ID) (bool, error) {
	// Check for self-access permissions first
	if pc.isSelfAccessScenario(resourceType, resourceID, userID) && pc.hasSelfAccessPermissions(permissions) {
		return true, nil
	}

	// Get user roles for the resource
	roles, err := pc.getUserRoles(ctx, userID, resourceType, resourceID)
	if err != nil {
		return false, err
	}

	if len(roles) == 0 {
		return false, nil
	}

	// Check permissions for all roles (user has permission if ANY role grants it)
	for _, role := range roles {
		if pc.roleHasAllPermissions(role, permissions) {
			return true, nil
		}
	}

	return false, nil
}

// HasPermissionsWithUserIDString handles string-based resource IDs (like slugs)
func (pc *DefaultPermissionChecker) HasPermissionsWithUserIDString(ctx context.Context, permissions []Permission, resourceType model.ResourceType, resourceID string, userID xid.ID) (bool, error) {
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
func (pc *DefaultPermissionChecker) HasAnyPermission(ctx context.Context, permissions []Permission, resourceType model.ResourceType, resourceID xid.ID) (bool, error) {
	// Get user from context
	userId := contexts.GetUserIDFromContext(ctx)
	if userId == nil {
		return false, errors.New(errors.CodeResourceNotFound, "logged in user resource not found")
	}
	return pc.HasAnyPermissionWithUserID(ctx, permissions, resourceType, resourceID, *userId)
}

// HasAnyPermissionWithUserID checks if the specified user has any of the specified permissions
func (pc *DefaultPermissionChecker) HasAnyPermissionWithUserID(ctx context.Context, permissions []Permission, resourceType model.ResourceType, resourceID xid.ID, userID xid.ID) (bool, error) {
	// Check for self-access permissions first
	if pc.isSelfAccessScenario(resourceType, resourceID, userID) && pc.hasAnySelfAccessPermissions(permissions) {
		return true, nil
	}

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

// =============================================================================
// SELF-ACCESS PERMISSION HELPERS
// =============================================================================

// isSelfAccessScenario checks if the user is accessing their own resource
func (pc *DefaultPermissionChecker) isSelfAccessScenario(resourceType model.ResourceType, resourceID xid.ID, userID xid.ID) bool {
	switch resourceType {
	case model.ResourceUser:
		return resourceID == userID
	case model.ResourceSession, model.ResourceAPIKey, model.ResourceMFA:
		// These would need additional logic to check if the resource belongs to the user
		// For now, we'll handle this in the main permission checking logic
		return false
	default:
		return false
	}
}

// hasSelfAccessPermissions checks if all requested permissions are self-access permissions
func (pc *DefaultPermissionChecker) hasSelfAccessPermissions(permissions []Permission) bool {
	selfAccessMap := make(map[Permission]bool)
	for _, perm := range SelfAccessPermissions {
		selfAccessMap[perm] = true
	}

	for _, perm := range permissions {
		if !selfAccessMap[perm] {
			return false
		}
	}
	return true
}

// hasAnySelfAccessPermissions checks if any requested permission is a self-access permission
func (pc *DefaultPermissionChecker) hasAnySelfAccessPermissions(permissions []Permission) bool {
	selfAccessMap := make(map[Permission]bool)
	for _, perm := range SelfAccessPermissions {
		selfAccessMap[perm] = true
	}

	for _, perm := range permissions {
		if selfAccessMap[perm] {
			return true
		}
	}
	return false
}

// =============================================================================
// ROLE RESOLUTION METHODS
// =============================================================================

// getUserRoles gets the user's roles for a specific resource
func (pc *DefaultPermissionChecker) getUserRoles(ctx context.Context, userID xid.ID, resourceType model.ResourceType, resourceID xid.ID) ([]model.RoleName, error) {
	switch resourceType {
	case model.ResourceSystem, model.ResourceGlobal:
		// For system/global resources, check system roles
		return pc.getUserSystemRoles(ctx, userID)

	case model.ResourceOrganization:
		// Get user's role in this organization through membership
		return pc.getUserOrganizationRoles(ctx, userID, resourceID)

	case model.ResourceUser:
		// For user resources, check if it's the same user (self-access) or organization admin
		if resourceID == userID {
			// User accessing their own resource - no additional roles needed as self-access is handled separately
			return []model.RoleName{}, nil
		}
		// For accessing other users, need organization-level permissions
		return pc.getUserOrganizationRolesForUser(ctx, userID, resourceID)

	default:
		// For other resources, determine organization and check roles there
		return pc.getUserRolesForResource(ctx, userID, resourceType, resourceID)
	}
}

// getUserRolesString gets the user's roles for a string-based resource identifier
func (pc *DefaultPermissionChecker) getUserRolesString(ctx context.Context, userID xid.ID, resourceType model.ResourceType, resourceID string) ([]model.RoleName, error) {
	switch resourceType {
	case model.ResourceOrganization:
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
func (pc *DefaultPermissionChecker) getUserSystemRoles(ctx context.Context, userID xid.ID) ([]model.RoleName, error) {
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

	var roleTypes []model.RoleName
	for _, role := range roles {
		// Map role names to model.RoleName constants
		if roleType := mapStringToRoleName(role.Name); roleType != "" {
			roleTypes = append(roleTypes, roleType)
		}
	}

	return roleTypes, nil
}

// getUserOrganizationRoles gets user's roles in a specific organization through membership
func (pc *DefaultPermissionChecker) getUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]model.RoleName, error) {
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
			return []model.RoleName{}, nil
		}
		return nil, err
	}

	var roleTypes []model.RoleName
	if membership.Edges.Role != nil {
		if roleType := mapStringToRoleName(membership.Edges.Role.Name); roleType != "" {
			roleTypes = append(roleTypes, roleType)
		}
	}

	return roleTypes, nil
}

// getUserOrganizationRolesBySlug gets user's roles in an organization by slug
func (pc *DefaultPermissionChecker) getUserOrganizationRolesBySlug(ctx context.Context, userID xid.ID, orgSlug string) ([]model.RoleName, error) {
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
			return []model.RoleName{}, nil
		}
		return nil, err
	}

	var roleTypes []model.RoleName
	if membership.Edges.Role != nil {
		if roleType := mapStringToRoleName(membership.Edges.Role.Name); roleType != "" {
			roleTypes = append(roleTypes, roleType)
		}
	}

	return roleTypes, nil
}

// getUserPrimaryOrganizationRoles gets user's roles in their primary organization
func (pc *DefaultPermissionChecker) getUserPrimaryOrganizationRoles(ctx context.Context, userID xid.ID) ([]model.RoleName, error) {
	user, err := pc.client.DB.User.Get(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user.PrimaryOrganizationID.IsNil() {
		return []model.RoleName{}, nil
	}

	return pc.getUserOrganizationRoles(ctx, userID, user.PrimaryOrganizationID)
}

// getUserOrganizationRolesForUser gets user's roles when accessing another user's resource
func (pc *DefaultPermissionChecker) getUserOrganizationRolesForUser(ctx context.Context, userID xid.ID, targetUserID xid.ID) ([]model.RoleName, error) {
	// Get target user's primary organization
	targetUser, err := pc.client.DB.User.Get(ctx, targetUserID)
	if err != nil {
		return nil, err
	}

	if targetUser.PrimaryOrganizationID.IsNil() {
		return []model.RoleName{}, nil
	}

	// Check if requesting user has roles in the target user's organization
	return pc.getUserOrganizationRoles(ctx, userID, targetUser.PrimaryOrganizationID)
}

// getUserRolesForResource gets user roles for other resource types by determining their organization
func (pc *DefaultPermissionChecker) getUserRolesForResource(ctx context.Context, userID xid.ID, resourceType model.ResourceType, resourceID xid.ID) ([]model.RoleName, error) {
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

// =============================================================================
// ROLE PERMISSION CHECKING
// =============================================================================

// roleHasAllPermissions checks if a role has all the specified permissions using inheritance
func (pc *DefaultPermissionChecker) roleHasAllPermissions(role model.RoleName, permissions []Permission) bool {
	// Use the inherited permissions which include permissions from parent roles
	rolePermissions := GetPermissionsForRole(role)

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

// roleHasAnyPermission checks if a role has any of the specified permissions using inheritance
func (pc *DefaultPermissionChecker) roleHasAnyPermission(role model.RoleName, permissions []Permission) bool {
	// Use the inherited permissions which include permissions from parent roles
	rolePermissions := GetPermissionsForRole(role)

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

// =============================================================================
// ROLE NAME MAPPING
// =============================================================================

// mapStringToRoleName maps a string role name to model.RoleName enum
func mapStringToRoleName(roleName string) model.RoleName {
	// Normalize the role name
	normalized := strings.ToLower(strings.TrimSpace(roleName))

	switch normalized {
	// System Roles
	case "platform_super_admin", "platformsuperadmin", "super_admin":
		return model.RolePlatformSuperAdmin
	case "platform_admin", "platformadmin":
		return model.RolePlatformAdmin
	case "platform_support", "platformsupport", "support":
		return model.RolePlatformSupport

	// Organization Roles
	case "organization_owner", "organizationowner", "owner":
		return model.RoleOrganizationOwner
	case "organization_admin", "organizationadmin", "admin":
		return model.RoleOrganizationAdmin
	case "organization_member", "organizationmember", "member":
		return model.RoleOrganizationMember
	case "organization_viewer", "organizationviewer", "viewer":
		return model.RoleOrganizationViewer

	// Application Roles
	case "end_user_admin", "enduseradmin", "user_admin":
		return model.RoleEndUserAdmin
	case "end_user", "enduser", "user":
		return model.RoleEndUser
	case "end_user_readonly", "enduserreadonly", "readonly":
		return model.RoleEndUserReadonly

	default:
		return ""
	}
}

// =============================================================================
// MEMBERSHIP HELPER FUNCTIONS
// =============================================================================

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

// GetOrganizationMembers returns all active members of an organization with their roles
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

// GetUserRole returns the user's role in a specific organization
func (pc *DefaultPermissionChecker) GetUserRole(ctx context.Context, userID xid.ID, orgID xid.ID) (model.RoleName, error) {
	roles, err := pc.getUserOrganizationRoles(ctx, userID, orgID)
	if err != nil {
		return "", err
	}

	if len(roles) == 0 {
		return "", errors.New(errors.CodeResourceNotFound, "user is not a member of this organization")
	}

	// Return the first (and typically only) role
	return roles[0], nil
}

// HasSystemRole checks if a user has any system-level role
func (pc *DefaultPermissionChecker) HasSystemRole(ctx context.Context, userID xid.ID) (bool, error) {
	roles, err := pc.getUserSystemRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	return len(roles) > 0, nil
}

// IsSystemAdmin checks if a user has system admin privileges
func (pc *DefaultPermissionChecker) IsSystemAdmin(ctx context.Context, userID xid.ID) (bool, error) {
	roles, err := pc.getUserSystemRoles(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		// Check if any role is a system admin role
		if role == model.RolePlatformSuperAdmin || role == model.RolePlatformAdmin {
			return true, nil
		}
	}
	return false, nil
}

// GetUserHighestRole returns the highest privilege role a user has in an organization
func (pc *DefaultPermissionChecker) GetUserHighestRole(ctx context.Context, userID xid.ID, orgID xid.ID) (model.RoleName, error) {
	roles, err := pc.getUserOrganizationRoles(ctx, userID, orgID)
	if err != nil {
		return "", err
	}

	if len(roles) == 0 {
		return "", errors.New(errors.CodeResourceNotFound, "user has no roles in this organization")
	}

	// Find the highest priority role
	var highestRole model.RoleName
	highestPriority := -1

	for _, role := range roles {
		priority := role.GetPriority()
		if priority > highestPriority {
			highestPriority = priority
			highestRole = role
		}
	}

	return highestRole, nil
}
