package rbac

import (
	"context"

	"github.com/google/uuid"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/permission"
	"github.com/juicycleff/frank/ent/predicate"
	"github.com/juicycleff/frank/ent/role"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/pkg/errors"
)

// Repository provides access to RBAC storage
type Repository interface {
	// Role operations
	CreateRole(ctx context.Context, input RepositoryCreateRoleInput) (*ent.Role, error)
	GetRoleByID(ctx context.Context, id string) (*ent.Role, error)
	GetRoleByName(ctx context.Context, name, organizationID string) (*ent.Role, error)
	ListRoles(ctx context.Context, input RepositoryListRolesInput) ([]*ent.Role, int, error)
	UpdateRole(ctx context.Context, id string, input RepositoryUpdateRoleInput) (*ent.Role, error)
	DeleteRole(ctx context.Context, id string) error

	// Role-permission operations
	AddPermissionToRole(ctx context.Context, roleID, permissionID string) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID string) error
	GetRolePermissions(ctx context.Context, roleID string) ([]*ent.Permission, error)

	// Permission operations
	CreatePermission(ctx context.Context, input RepositoryCreatePermissionInput) (*ent.Permission, error)
	GetPermissionByID(ctx context.Context, id string) (*ent.Permission, error)
	GetPermissionByName(ctx context.Context, name string) (*ent.Permission, error)
	ListPermissions(ctx context.Context, input RepositoryListPermissionsInput) ([]*ent.Permission, int, error)
	UpdatePermission(ctx context.Context, id string, input RepositoryUpdatePermissionInput) (*ent.Permission, error)
	DeletePermission(ctx context.Context, id string) error

	// User role operations
	GetUserRoles(ctx context.Context, userID string) ([]*ent.Role, error)
	GetUserPermissions(ctx context.Context, userID string) ([]*ent.Permission, error)
	HasRole(ctx context.Context, userID, roleName string, organizationID string) (bool, error)
}

// RepositoryCreateRoleInput represents input for creating a role
type RepositoryCreateRoleInput struct {
	Name           string
	Description    string
	OrganizationID string
	IsDefault      bool
	System         bool
}

// RepositoryUpdateRoleInput represents input for updating a role
type RepositoryUpdateRoleInput struct {
	Name        *string
	Description *string
	IsDefault   *bool
}

// RepositoryListRolesInput represents input for listing roles
type RepositoryListRolesInput struct {
	Offset         int
	Limit          int
	OrganizationID string
	Search         string
}

// RepositoryCreatePermissionInput represents input for creating a permission
type RepositoryCreatePermissionInput struct {
	Name        string
	Description string
	Resource    string
	Action      string
	Conditions  string
	System      bool
}

// RepositoryUpdatePermissionInput represents input for updating a permission
type RepositoryUpdatePermissionInput struct {
	Name        *string
	Description *string
	Conditions  *string
}

// RepositoryListPermissionsInput represents input for listing permissions
type RepositoryListPermissionsInput struct {
	Offset   int
	Limit    int
	Resource string
	Action   string
	Search   string
}

type repository struct {
	client *ent.Client
}

// NewRepository creates a new RBAC repository
func NewRepository(client *ent.Client) Repository {
	return &repository{
		client: client,
	}
}

// CreateRole creates a new role
func (r *repository) CreateRole(ctx context.Context, input RepositoryCreateRoleInput) (*ent.Role, error) {
	// Generate UUID
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(errors.CodeInternalServer, err, "failed to generate uuid")
	}

	// Check if role with the same name already exists in the organization
	if input.OrganizationID != "" {
		exists, err := r.client.Role.
			Query().
			Where(
				role.Name(input.Name),
				role.OrganizationIDEQ(input.OrganizationID),
			).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check role existence")
		}

		if exists {
			return nil, errors.New(errors.CodeConflict, "role with this name already exists in the organization")
		}
	} else {
		// Check for global role (no organization)
		exists, err := r.client.Role.
			Query().
			Where(
				role.Name(input.Name),
				role.OrganizationIDIsNil(),
			).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check role existence")
		}

		if exists {
			return nil, errors.New(errors.CodeConflict, "global role with this name already exists")
		}
	}

	// Create role builder
	create := r.client.Role.
		Create().
		SetID(id.String()).
		SetName(input.Name).
		SetIsDefault(input.IsDefault).
		SetSystem(input.System)

	// Set optional fields
	if input.Description != "" {
		create = create.SetDescription(input.Description)
	}

	if input.OrganizationID != "" {
		create = create.SetOrganizationID(input.OrganizationID)
	}

	// Execute create
	role, err := create.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create role")
	}

	return role, nil
}

// GetRoleByID retrieves a role by ID
func (r *repository) GetRoleByID(ctx context.Context, id string) (*ent.Role, error) {
	role, err := r.client.Role.
		Query().
		Where(role.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "role not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get role")
	}

	return role, nil
}

// GetRoleByName retrieves a role by name and organization
func (r *repository) GetRoleByName(ctx context.Context, name, organizationID string) (*ent.Role, error) {
	query := r.client.Role.
		Query().
		Where(role.Name(name))

	if organizationID != "" {
		query = query.Where(role.OrganizationIDEQ(organizationID))
	} else {
		query = query.Where(role.OrganizationIDIsNil())
	}

	role, err := query.Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "role not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get role by name")
	}

	return role, nil
}

// ListRoles retrieves roles with pagination
func (r *repository) ListRoles(ctx context.Context, input RepositoryListRolesInput) ([]*ent.Role, int, error) {
	// Build query predicates
	var predicates []predicate.Role

	if input.OrganizationID != "" {
		predicates = append(predicates, role.OrganizationIDEQ(input.OrganizationID))
	}

	if input.Search != "" {
		predicates = append(predicates,
			role.Or(
				role.NameContainsFold(input.Search),
				role.DescriptionContainsFold(input.Search),
			),
		)
	}

	// Create query with predicates
	query := r.client.Role.Query()
	if len(predicates) > 0 {
		query = query.Where(role.And(predicates...))
	}

	// Count total results
	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to count roles")
	}

	// Apply pagination
	roles, err := query.
		Limit(input.Limit).
		Offset(input.Offset).
		Order(ent.Asc(role.FieldName)).
		All(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to list roles")
	}

	return roles, total, nil
}

// UpdateRole updates a role
func (r *repository) UpdateRole(ctx context.Context, id string, input RepositoryUpdateRoleInput) (*ent.Role, error) {
	// Get role to check existence
	existingRole, err := r.GetRoleByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Build update query
	update := r.client.Role.
		UpdateOneID(id)

	// Apply updates
	if input.Name != nil {
		// Check for name uniqueness if changing the name
		if *input.Name != existingRole.Name {
			var exists bool
			if existingRole.OrganizationID != "" {
				// Check within organization
				exists, err = r.client.Role.
					Query().
					Where(
						role.Name(*input.Name),
						role.OrganizationIDEQ(existingRole.OrganizationID),
						role.IDNEQ(id),
					).
					Exist(ctx)
			} else {
				// Check global roles
				exists, err = r.client.Role.
					Query().
					Where(
						role.Name(*input.Name),
						role.OrganizationIDIsNil(),
						role.IDNEQ(id),
					).
					Exist(ctx)
			}

			if err != nil {
				return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check role name uniqueness")
			}

			if exists {
				return nil, errors.New(errors.CodeConflict, "role with this name already exists")
			}
		}

		update = update.SetName(*input.Name)
	}

	if input.Description != nil {
		update = update.SetDescription(*input.Description)
	}

	if input.IsDefault != nil {
		update = update.SetIsDefault(*input.IsDefault)
	}

	// Execute update
	updatedRole, err := update.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to update role")
	}

	return updatedRole, nil
}

// DeleteRole deletes a role
func (r *repository) DeleteRole(ctx context.Context, id string) error {
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
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete role")
	}

	return nil
}

// AddPermissionToRole adds a permission to a role
func (r *repository) AddPermissionToRole(ctx context.Context, roleID, permissionID string) error {
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
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check permission assignment")
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
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to add permission to role")
	}

	return nil
}

// RemovePermissionFromRole removes a permission from a role
func (r *repository) RemovePermissionFromRole(ctx context.Context, roleID, permissionID string) error {
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
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to remove permission from role")
	}

	return nil
}

// GetRolePermissions retrieves permissions assigned to a role
func (r *repository) GetRolePermissions(ctx context.Context, roleID string) ([]*ent.Permission, error) {
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
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get role permissions")
	}

	return permissions, nil
}

// CreatePermission creates a new permission
func (r *repository) CreatePermission(ctx context.Context, input RepositoryCreatePermissionInput) (*ent.Permission, error) {
	// Generate UUID
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(errors.CodeInternalServer, err, "failed to generate uuid")
	}

	// Check for unique resource:action combination
	exists, err := r.client.Permission.
		Query().
		Where(
			permission.Resource(input.Resource),
			permission.Action(input.Action),
		).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check permission existence")
	}

	if exists {
		return nil, errors.New(errors.CodeConflict, "permission for this resource and action already exists")
	}

	// Check for unique name
	if input.Name != "" {
		exists, err = r.client.Permission.
			Query().
			Where(permission.Name(input.Name)).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check permission name uniqueness")
		}

		if exists {
			return nil, errors.New(errors.CodeConflict, "permission with this name already exists")
		}
	}

	// Create permission
	create := r.client.Permission.
		Create().
		SetID(id.String()).
		SetName(input.Name).
		SetResource(input.Resource).
		SetAction(input.Action).
		SetSystem(input.System)

	// Set optional fields
	if input.Description != "" {
		create = create.SetDescription(input.Description)
	}

	if input.Conditions != "" {
		create = create.SetConditions(input.Conditions)
	}

	// Execute create
	permission, err := create.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create permission")
	}

	return permission, nil
}

// GetPermissionByID retrieves a permission by ID
func (r *repository) GetPermissionByID(ctx context.Context, id string) (*ent.Permission, error) {
	permission, err := r.client.Permission.
		Query().
		Where(permission.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get permission")
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
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get permission by name")
	}

	return permission, nil
}

// ListPermissions retrieves permissions with pagination
func (r *repository) ListPermissions(ctx context.Context, input RepositoryListPermissionsInput) ([]*ent.Permission, int, error) {
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

	// Count total results
	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to count permissions")
	}

	// Apply pagination
	permissions, err := query.
		Limit(input.Limit).
		Offset(input.Offset).
		Order(ent.Asc(permission.FieldResource), ent.Asc(permission.FieldAction)).
		All(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to list permissions")
	}

	return permissions, total, nil
}

// UpdatePermission updates a permission
func (r *repository) UpdatePermission(ctx context.Context, id string, input RepositoryUpdatePermissionInput) (*ent.Permission, error) {
	// Get permission to check existence
	existingPermission, err := r.GetPermissionByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Build update query
	update := r.client.Permission.
		UpdateOneID(id)

	// Apply updates
	if input.Name != nil {
		// Check for name uniqueness if changing the name
		if *input.Name != existingPermission.Name {
			exists, err := r.client.Permission.
				Query().
				Where(
					permission.Name(*input.Name),
					permission.IDNEQ(id),
				).
				Exist(ctx)

			if err != nil {
				return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check permission name uniqueness")
			}

			if exists {
				return nil, errors.New(errors.CodeConflict, "permission with this name already exists")
			}
		}

		update = update.SetName(*input.Name)
	}

	if input.Description != nil {
		update = update.SetDescription(*input.Description)
	}

	if input.Conditions != nil {
		update = update.SetConditions(*input.Conditions)
	}

	// Execute update
	updatedPermission, err := update.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to update permission")
	}

	return updatedPermission, nil
}

// DeletePermission deletes a permission
func (r *repository) DeletePermission(ctx context.Context, id string) error {
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
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete permission")
	}

	return nil
}

// GetUserRoles retrieves roles assigned to a user
func (r *repository) GetUserRoles(ctx context.Context, userID string) ([]*ent.Role, error) {
	// Check if user exists
	exists, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !exists {
		return nil, errors.New(errors.CodeNotFound, "user not found")
	}

	// Get user's roles
	roles, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		QueryRoles().
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get user roles")
	}

	return roles, nil
}

// GetUserPermissions retrieves all permissions a user has through their roles
func (r *repository) GetUserPermissions(ctx context.Context, userID string) ([]*ent.Permission, error) {
	// Check if user exists
	exists, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !exists {
		return nil, errors.New(errors.CodeNotFound, "user not found")
	}

	// Get user's permissions through their roles
	permissions, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		QueryRoles().
		QueryPermissions().
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get user permissions")
	}

	return permissions, nil
}

// HasRole checks if a user has a specific role
func (r *repository) HasRole(ctx context.Context, userID, roleName string, organizationID string) (bool, error) {
	// Build query to check if user has the role
	query := r.client.User.
		Query().
		Where(
			user.ID(userID),
			user.HasRolesWith(role.Name(roleName)),
		)

	// Add organization constraint if provided
	if organizationID != "" {
		query = query.Where(
			user.HasRolesWith(role.OrganizationIDEQ(organizationID)),
		)
	}

	// Execute query
	return query.Exist(ctx)
}
