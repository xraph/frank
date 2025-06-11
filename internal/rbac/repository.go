package rbac

import (
	"context"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/permission"
	"github.com/juicycleff/frank/ent/predicate"
	"github.com/juicycleff/frank/ent/role"
	entRole "github.com/juicycleff/frank/ent/role"
	"github.com/juicycleff/frank/ent/user"
	entUserRole "github.com/juicycleff/frank/ent/userrole"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

var (
	ErrRoleNotFound       = errors.New(errors.CodeNotFound, "role not found")
	ErrPermissionNotFound = errors.New(errors.CodeNotFound, "permission not found")
	ErrUserNotFound       = errors.New(errors.CodeNotFound, "user not found")
	ErrRoleConflict       = errors.New(errors.CodeConflict, "role with this name already exists")
	ErrPermissionConflict = errors.New(errors.CodeConflict, "permission already exists")
)

// Repository provides access to RBAC storage
type Repository interface {
	// Basic Role operations
	CreateRole(ctx context.Context, roleCreate *ent.RoleCreate) (*ent.Role, error)
	GetRoleByID(ctx context.Context, id xid.ID) (*ent.Role, error)
	GetRoleByName(ctx context.Context, name string, orgId xid.ID) (*ent.Role, error)
	ListRoles(ctx context.Context, input ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)
	UpdateRole(ctx context.Context, roleUpdate *ent.RoleUpdateOne) (*ent.Role, error)
	DeleteRole(ctx context.Context, id xid.ID) error

	// Enhanced Role operations (from RoleService)
	CreateRoleAdvanced(ctx context.Context, req CreateRoleRequest) (*ent.Role, error)
	UpdateRoleAdvanced(ctx context.Context, roleID xid.ID, updates map[string]interface{}) (*ent.Role, error)
	GetRolesByType(ctx context.Context, roleType entRole.RoleType, orgID *xid.ID) ([]*ent.Role, error)

	// Role Assignment Methods (from RoleService)
	AssignSystemRole(ctx context.Context, userID xid.ID, roleName string) error
	AssignOrganizationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error
	AssignApplicationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error
	RemoveUserRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType entUserRole.ContextType, contextID *xid.ID) error

	// Role Query Methods (from RoleService)
	GetUserSystemRoles(ctx context.Context, userID xid.ID) ([]*ent.Role, error)
	GetUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error)
	GetUserApplicationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error)
	GetAllUserRoles(ctx context.Context, userID xid.ID) ([]*ent.UserRole, error)

	// Role Checking Methods (Enhanced from RoleService)
	HasRole(ctx context.Context, userID xid.ID, roleName string, contextType entUserRole.ContextType, contextID *xid.ID) (bool, error)
	HasAnyRole(ctx context.Context, userID xid.ID, roleNames []string, contextType entUserRole.ContextType, contextID *xid.ID) (bool, error)

	// Role-permission operations
	AddPermissionToRole(ctx context.Context, roleID, permissionID xid.ID) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID xid.ID) error
	GetRolePermissions(ctx context.Context, roleID xid.ID) ([]*ent.Permission, error)

	// Permission operations
	CreatePermission(ctx context.Context, permissionCreate *ent.PermissionCreate) (*ent.Permission, error)
	GetPermissionByID(ctx context.Context, id xid.ID) (*ent.Permission, error)
	GetPermissionByName(ctx context.Context, name string) (*ent.Permission, error)
	ListPermissions(ctx context.Context, input ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	UpdatePermission(ctx context.Context, permissionUpdate *ent.PermissionUpdateOne) (*ent.Permission, error)
	DeletePermission(ctx context.Context, id xid.ID) error

	// Legacy User role operations (kept for backward compatibility)
	GetUserRoles(ctx context.Context, userID xid.ID) ([]*ent.Role, error)
	GetUserPermissions(ctx context.Context, userID xid.ID) ([]*ent.Permission, error)

	// Client returns the database client
	Client() *ent.Client
}

type repository struct {
	client      *ent.Client
	roleService *RoleService
}

// NewRepository creates a new RBAC repository with RoleService integration
func NewRepository(dataClients *data.Clients) Repository {
	return &repository{
		client:      dataClients.DB,
		roleService: NewRoleService(dataClients),
	}
}

// ================================
// BASIC ROLE OPERATIONS
// ================================

// CreateRole creates a new role
func (r *repository) CreateRole(ctx context.Context, roleCreate *ent.RoleCreate) (*ent.Role, error) {
	// Get values from mutation
	name, _ := roleCreate.Mutation().Name()
	organizationID, organizationIDExists := roleCreate.Mutation().OrganizationID()

	// Check if role with the same name already exists in the organization
	if organizationIDExists && !organizationID.IsNil() {
		exists, err := r.client.Role.
			Query().
			Where(
				role.Name(name),
				role.OrganizationIDEQ(organizationID),
			).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check role existence")
		}

		if exists {
			return nil, ErrRoleConflict
		}
	} else {
		// Check for global role (no organization)
		exists, err := r.client.Role.
			Query().
			Where(
				role.Name(name),
				role.OrganizationIDIsNil(),
			).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check role existence")
		}

		if exists {
			return nil, ErrRoleConflict
		}
	}

	// Execute create
	role, err := roleCreate.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrRoleConflict
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create role")
	}

	return role, nil
}

// GetRoleByID retrieves a role by ID
func (r *repository) GetRoleByID(ctx context.Context, id xid.ID) (*ent.Role, error) {
	role, err := r.client.Role.
		Query().
		Where(role.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrRoleNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get role")
	}

	return role, nil
}

// GetRoleByName retrieves a role by name and organization
func (r *repository) GetRoleByName(ctx context.Context, name string, orgId xid.ID) (*ent.Role, error) {
	query := r.client.Role.
		Query().
		Where(role.Name(name))

	if !orgId.IsNil() {
		query = query.Where(role.OrganizationIDEQ(orgId))
	} else {
		query = query.Where(role.OrganizationIDIsNil())
	}

	role, err := query.Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrRoleNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get role by name")
	}

	return role, nil
}

// ListRoles retrieves roles with pagination
func (r *repository) ListRoles(ctx context.Context, input ListRolesParams) (*model.PaginatedOutput[*ent.Role], error) {
	// Build query predicates
	var predicates []predicate.Role

	if input.OrgID.IsSet {
		predicates = append(predicates, role.OrganizationIDEQ(input.OrgID.Value))
	}

	if input.Search != "" {
		predicates = append(predicates,
			role.Or(
				role.NameContainsFold(input.Search),
				role.DescriptionContainsFold(input.Search),
			),
		)
	}

	if input.RoleType.IsSet {
		predicates = append(predicates,
			role.Or(
				role.RoleTypeEQ(input.RoleType.Value),
			),
		)
	}

	// Create query with predicates
	query := r.client.Role.Query()
	if len(predicates) > 0 {
		query = query.Where(role.And(predicates...))
	}

	// Apply ordering
	for _, o := range model.GetOrdering(input.PaginationParams) {
		if o.Desc {
			query = query.Order(ent.Desc(o.Field))
			continue
		}
		query = query.Order(ent.Asc(o.Field))
	}

	return model.WithPaginationAndOptions[*ent.Role, *ent.RoleQuery](ctx, query, input.PaginationParams)
}

// UpdateRole updates a role
func (r *repository) UpdateRole(ctx context.Context, roleUpdate *ent.RoleUpdateOne) (*ent.Role, error) {
	// Get the role ID from the update mutation
	roleID, _ := roleUpdate.Mutation().ID()

	// Check if role exists
	existingRole, err := r.GetRoleByID(ctx, roleID)
	if err != nil {
		return nil, err
	}

	// Check for name uniqueness if changing the name
	if name, exists := roleUpdate.Mutation().Name(); exists {
		if name != existingRole.Name {
			var nameExists bool
			if !existingRole.OrganizationID.IsNil() {
				// Check within organization
				nameExists, err = r.client.Role.
					Query().
					Where(
						role.Name(name),
						role.OrganizationIDEQ(existingRole.OrganizationID),
						role.IDNEQ(roleID),
					).
					Exist(ctx)
			} else {
				// Check global roles
				nameExists, err = r.client.Role.
					Query().
					Where(
						role.Name(name),
						role.OrganizationIDIsNil(),
						role.IDNEQ(roleID),
					).
					Exist(ctx)
			}

			if err != nil {
				return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check role name uniqueness")
			}

			if nameExists {
				return nil, ErrRoleConflict
			}
		}
	}

	// Execute update
	updatedRole, err := roleUpdate.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrRoleNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update role")
	}

	return updatedRole, nil
}

// DeleteRole deletes a role
func (r *repository) DeleteRole(ctx context.Context, id xid.ID) error {
	// Check if role exists
	_, err := r.GetRoleByID(ctx, id)
	if err != nil {
		return err
	}

	// Delete role
	err = r.client.Role.
		DeleteOneID(id).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return ErrRoleNotFound
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete role")
	}

	return nil
}

// ================================
// ENHANCED ROLE OPERATIONS (RoleService Integration)
// ================================

// CreateRoleAdvanced creates a new role using RoleService functionality
func (r *repository) CreateRoleAdvanced(ctx context.Context, req CreateRoleRequest) (*ent.Role, error) {
	return r.roleService.CreateRole(ctx, req)
}

// UpdateRoleAdvanced updates a role using RoleService functionality
func (r *repository) UpdateRoleAdvanced(ctx context.Context, roleID xid.ID, updates map[string]interface{}) (*ent.Role, error) {
	return r.roleService.UpdateRole(ctx, roleID, updates)
}

// GetRolesByType returns roles of a specific type
func (r *repository) GetRolesByType(ctx context.Context, roleType entRole.RoleType, orgID *xid.ID) ([]*ent.Role, error) {
	return r.roleService.GetRolesByType(ctx, roleType, orgID)
}

// ================================
// ROLE ASSIGNMENT METHODS (RoleService Integration)
// ================================

// AssignSystemRole assigns a system-level role to a user
func (r *repository) AssignSystemRole(ctx context.Context, userID xid.ID, roleName string) error {
	return r.roleService.AssignSystemRole(ctx, userID, roleName)
}

// AssignOrganizationRole assigns an organization-scoped role to a user
func (r *repository) AssignOrganizationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	return r.roleService.AssignOrganizationRole(ctx, userID, orgID, roleName)
}

// AssignApplicationRole assigns an application-scoped role to an end user
func (r *repository) AssignApplicationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	return r.roleService.AssignApplicationRole(ctx, userID, orgID, roleName)
}

// RemoveUserRole removes a role assignment
func (r *repository) RemoveUserRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType entUserRole.ContextType, contextID *xid.ID) error {
	return r.roleService.RemoveUserRole(ctx, userID, roleID, contextType, contextID)
}

// ================================
// ROLE QUERY METHODS (RoleService Integration)
// ================================

// GetUserSystemRoles returns all system roles for a user
func (r *repository) GetUserSystemRoles(ctx context.Context, userID xid.ID) ([]*ent.Role, error) {
	return r.roleService.GetUserSystemRoles(ctx, userID)
}

// GetUserOrganizationRoles returns all organization roles for a user
func (r *repository) GetUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error) {
	return r.roleService.GetUserOrganizationRoles(ctx, userID, orgID)
}

// GetUserApplicationRoles returns all application roles for a user
func (r *repository) GetUserApplicationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error) {
	return r.roleService.GetUserApplicationRoles(ctx, userID, orgID)
}

// GetAllUserRoles returns all roles for a user across all contexts
func (r *repository) GetAllUserRoles(ctx context.Context, userID xid.ID) ([]*ent.UserRole, error) {
	return r.roleService.GetAllUserRoles(ctx, userID)
}

// ================================
// ROLE CHECKING METHODS (RoleService Integration)
// ================================

// HasRole checks if a user has a specific role in a given context
func (r *repository) HasRole(ctx context.Context, userID xid.ID, roleName string, contextType entUserRole.ContextType, contextID *xid.ID) (bool, error) {
	return r.roleService.HasRole(ctx, userID, roleName, contextType, contextID)
}

// HasAnyRole checks if a user has any of the specified roles in a context
func (r *repository) HasAnyRole(ctx context.Context, userID xid.ID, roleNames []string, contextType entUserRole.ContextType, contextID *xid.ID) (bool, error) {
	return r.roleService.HasAnyRole(ctx, userID, roleNames, contextType, contextID)
}

// ================================
// ROLE-PERMISSION OPERATIONS
// ================================

// AddPermissionToRole adds a permission to a role
func (r *repository) AddPermissionToRole(ctx context.Context, roleID, permissionID xid.ID) error {
	// Check if role exists
	_, err := r.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}

	// Check if permission exists
	_, err = r.GetPermissionByID(ctx, permissionID)
	if err != nil {
		return err
	}

	// Check if permission is already assigned to role
	exists, err := r.client.Role.
		Query().
		Where(
			role.ID(roleID),
			role.HasPermissionsWith(permission.ID(permissionID)),
		).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to check permission assignment")
	}

	if exists {
		// Permission already assigned, no need to do anything
		return nil
	}

	// Add permission to role
	err = r.client.Role.
		UpdateOneID(roleID).
		AddPermissionIDs(permissionID).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to add permission to role")
	}

	return nil
}

// RemovePermissionFromRole removes a permission from a role
func (r *repository) RemovePermissionFromRole(ctx context.Context, roleID, permissionID xid.ID) error {
	// Check if role exists
	_, err := r.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}

	// Check if permission exists
	_, err = r.GetPermissionByID(ctx, permissionID)
	if err != nil {
		return err
	}

	// Remove permission from role
	err = r.client.Role.
		UpdateOneID(roleID).
		RemovePermissionIDs(permissionID).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to remove permission from role")
	}

	return nil
}

// GetRolePermissions retrieves permissions assigned to a role
func (r *repository) GetRolePermissions(ctx context.Context, roleID xid.ID) ([]*ent.Permission, error) {
	// Check if role exists
	_, err := r.GetRoleByID(ctx, roleID)
	if err != nil {
		return nil, err
	}

	// Get permissions
	permissions, err := r.client.Role.
		Query().
		Where(role.ID(roleID)).
		QueryPermissions().
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get role permissions")
	}

	return permissions, nil
}

// ================================
// PERMISSION OPERATIONS
// ================================

// CreatePermission creates a new permission
func (r *repository) CreatePermission(ctx context.Context, permissionCreate *ent.PermissionCreate) (*ent.Permission, error) {
	// Get values from mutation
	resource, _ := permissionCreate.Mutation().Resource()
	action, _ := permissionCreate.Mutation().Action()
	name, _ := permissionCreate.Mutation().Name()

	// Check for unique resource:action combination
	exists, err := r.client.Permission.
		Query().
		Where(
			permission.Resource(resource),
			permission.Action(action),
		).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check permission existence")
	}

	if exists {
		return nil, ErrPermissionConflict
	}

	// Check for unique name
	if name != "" {
		exists, err = r.client.Permission.
			Query().
			Where(permission.Name(name)).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check permission name uniqueness")
		}

		if exists {
			return nil, ErrPermissionConflict
		}
	}

	// Execute create
	permission, err := permissionCreate.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrPermissionConflict
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create permission")
	}

	return permission, nil
}

// GetPermissionByID retrieves a permission by ID
func (r *repository) GetPermissionByID(ctx context.Context, id xid.ID) (*ent.Permission, error) {
	permission, err := r.client.Permission.
		Query().
		Where(permission.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrPermissionNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get permission")
	}

	return permission, nil
}

// GetPermissionByName retrieves a permission by name
func (r *repository) GetPermissionByName(ctx context.Context, name string) (*ent.Permission, error) {
	permission, err := r.client.Permission.
		Query().
		Where(permission.Name(name)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrPermissionNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get permission by name")
	}

	return permission, nil
}

// ListPermissions retrieves permissions with pagination
func (r *repository) ListPermissions(ctx context.Context, input ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error) {
	// Build query predicates
	var predicates []predicate.Permission

	if input.Resource != "" {
		predicates = append(predicates, permission.Resource(input.Resource))
	}

	if input.Action != "" {
		predicates = append(predicates, permission.Action(input.Action))
	}

	if input.Search != "" {
		predicates = append(predicates,
			permission.Or(
				permission.NameContainsFold(input.Search),
				permission.DescriptionContainsFold(input.Search),
				permission.ResourceContainsFold(input.Search),
				permission.ActionContainsFold(input.Search),
			),
		)
	}

	// Create query with predicates
	query := r.client.Permission.Query()
	if len(predicates) > 0 {
		query = query.Where(permission.And(predicates...))
	}

	// Apply ordering
	for _, o := range model.GetOrdering(input.PaginationParams) {
		if o.Desc {
			query = query.Order(ent.Desc(o.Field))
			continue
		}
		query = query.Order(ent.Asc(o.Field))
	}

	return model.WithPaginationAndOptions[*ent.Permission, *ent.PermissionQuery](ctx, query, input.PaginationParams)
}

// UpdatePermission updates a permission
func (r *repository) UpdatePermission(ctx context.Context, permissionUpdate *ent.PermissionUpdateOne) (*ent.Permission, error) {
	// Get the permission ID from the update mutation
	permissionID, _ := permissionUpdate.Mutation().ID()

	// Check if permission exists
	existingPermission, err := r.GetPermissionByID(ctx, permissionID)
	if err != nil {
		return nil, err
	}

	// Check for name uniqueness if changing the name
	if name, exists := permissionUpdate.Mutation().Name(); exists {
		if name != existingPermission.Name {
			nameExists, err := r.client.Permission.
				Query().
				Where(
					permission.Name(name),
					permission.IDNEQ(permissionID),
				).
				Exist(ctx)

			if err != nil {
				return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check permission name uniqueness")
			}

			if nameExists {
				return nil, ErrPermissionConflict
			}
		}
	}

	// Execute update
	updatedPermission, err := permissionUpdate.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrPermissionNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update permission")
	}

	return updatedPermission, nil
}

// DeletePermission deletes a permission
func (r *repository) DeletePermission(ctx context.Context, id xid.ID) error {
	// Check if permission exists
	_, err := r.GetPermissionByID(ctx, id)
	if err != nil {
		return err
	}

	// Delete permission
	err = r.client.Permission.
		DeleteOneID(id).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return ErrPermissionNotFound
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete permission")
	}

	return nil
}

// ================================
// LEGACY USER ROLE OPERATIONS (Backward Compatibility)
// ================================

// GetUserRoles retrieves roles assigned to a user (legacy method)
func (r *repository) GetUserRoles(ctx context.Context, userID xid.ID) ([]*ent.Role, error) {
	// Check if user exists
	exists, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check user existence")
	}

	if !exists {
		return nil, ErrUserNotFound
	}

	// Get user's roles
	roles, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		QuerySystemRoles().
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get user roles")
	}

	return roles, nil
}

// GetUserPermissions retrieves all permissions a user has through their roles (legacy method)
func (r *repository) GetUserPermissions(ctx context.Context, userID xid.ID) ([]*ent.Permission, error) {
	// Check if user exists
	exists, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check user existence")
	}

	if !exists {
		return nil, ErrUserNotFound
	}

	// Get user's permissions through their roles
	permissions, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		QuerySystemRoles().
		QueryPermissions().
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get user permissions")
	}

	return permissions, nil
}

// Client returns the database client
func (r *repository) Client() *ent.Client {
	return r.client
}
