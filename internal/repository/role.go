package repository

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/membership"
	"github.com/juicycleff/frank/ent/permission"
	"github.com/juicycleff/frank/ent/role"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/ent/userrole"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// RoleRepository defines the interface for role data access
type RoleRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateRoleInput) (*ent.Role, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Role, error)
	GetByName(ctx context.Context, name string, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) (*ent.Role, error)
	Update(ctx context.Context, id xid.ID, input UpdateRoleInput) (*ent.Role, error)
	Delete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)
	ListByOrganization(ctx context.Context, organizationID xid.ID, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)
	ListByApplication(ctx context.Context, applicationID xid.ID, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)
	Search(ctx context.Context, query string, params SearchRolesParams) (*model.PaginatedOutput[*ent.Role], error)

	// Role type specific operations
	GetSystemRoles(ctx context.Context, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)
	GetOrganizationRoles(ctx context.Context, organizationID xid.ID, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)
	GetApplicationRoles(ctx context.Context, applicationID xid.ID, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error)

	// Default role operations
	GetDefaultRoles(ctx context.Context, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) ([]*ent.Role, error)
	SetAsDefault(ctx context.Context, id xid.ID) error
	UnsetAsDefault(ctx context.Context, id xid.ID) error

	// Permission operations
	AddPermission(ctx context.Context, roleID, permissionID xid.ID) error
	RemovePermission(ctx context.Context, roleID, permissionID xid.ID) error
	GetPermissions(ctx context.Context, roleID xid.ID) ([]*ent.Permission, error)
	HasPermission(ctx context.Context, roleID, permissionID xid.ID) (bool, error)
	GetRolesWithPermission(ctx context.Context, permissionID xid.ID) ([]*ent.Role, error)

	// Role hierarchy operations
	GetChildren(ctx context.Context, roleID xid.ID) ([]*ent.Role, error)
	GetParent(ctx context.Context, roleID xid.ID) (*ent.Role, error)
	GetAncestors(ctx context.Context, roleID xid.ID) ([]*ent.Role, error)
	GetDescendants(ctx context.Context, roleID xid.ID) ([]*ent.Role, error)
	SetParent(ctx context.Context, roleID, parentID xid.ID) error
	RemoveParent(ctx context.Context, roleID xid.ID) error

	// User assignment operations
	GetUsersWithRole(ctx context.Context, roleID xid.ID) ([]*ent.User, error)
	GetUserCount(ctx context.Context, roleID xid.ID) (int, error)

	// Role validation and checks
	CanDelete(ctx context.Context, roleID xid.ID) (bool, error)
	IsInUse(ctx context.Context, roleID xid.ID) (bool, error)
	ExistsByName(ctx context.Context, name string, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) (bool, error)

	// Bulk operations
	BulkCreate(ctx context.Context, inputs []CreateRoleInput) ([]*ent.Role, error)
	BulkDelete(ctx context.Context, ids []xid.ID) error
}

// CreateRoleInput represents input for creating a role
type CreateRoleInput struct {
	Name                string        `json:"name"`
	DisplayName         *string       `json:"display_name,omitempty"`
	Description         *string       `json:"description,omitempty"`
	RoleType            role.RoleType `json:"role_type"`
	OrganizationID      *xid.ID       `json:"organization_id,omitempty"`
	ApplicationID       *xid.ID       `json:"application_id,omitempty"`
	System              bool          `json:"system"`
	IsDefault           bool          `json:"is_default"`
	Priority            int           `json:"priority"`
	Color               *string       `json:"color,omitempty"`
	ApplicableUserTypes []string      `json:"applicable_user_types,omitempty"`
	CreatedBy           *string       `json:"created_by,omitempty"`
	ParentID            *xid.ID       `json:"parent_id,omitempty"`
}

// UpdateRoleInput represents input for updating a role
type UpdateRoleInput struct {
	Name                *string  `json:"name,omitempty"`
	DisplayName         *string  `json:"display_name,omitempty"`
	Description         *string  `json:"description,omitempty"`
	IsDefault           *bool    `json:"is_default,omitempty"`
	Priority            *int     `json:"priority,omitempty"`
	Color               *string  `json:"color,omitempty"`
	ApplicableUserTypes []string `json:"applicable_user_types,omitempty"`
	Active              *bool    `json:"active,omitempty"`
	ParentID            *xid.ID  `json:"parent_id,omitempty"`
}

// ListRolesParams represents parameters for listing roles
type ListRolesParams struct {
	model.PaginationParams
	RoleType           *role.RoleType `json:"role_type,omitempty"`
	OrganizationID     *xid.ID        `json:"organization_id,omitempty"`
	ApplicationID      *xid.ID        `json:"application_id,omitempty"`
	System             *bool          `json:"system,omitempty"`
	IsDefault          *bool          `json:"is_default,omitempty"`
	Active             *bool          `json:"active,omitempty"`
	CreatedBy          *string        `json:"created_by,omitempty"`
	ParentID           *xid.ID        `json:"parent_id,omitempty"`
	ApplicableUserType *string        `json:"applicable_user_type,omitempty"`
	Search             *string        `json:"search,omitempty"`
	IncludeChildren    bool           `json:"include_children,omitempty"`
}

// SearchRolesParams represents parameters for searching roles
type SearchRolesParams struct {
	model.PaginationParams
	RoleType       *role.RoleType `json:"role_type,omitempty"`
	OrganizationID *xid.ID        `json:"organization_id,omitempty"`
	ApplicationID  *xid.ID        `json:"application_id,omitempty"`
	ExactMatch     bool           `json:"exact_match"`

	RoleTypes       []role.RoleType
	OrganizationIDs []xid.ID
	ApplicationIDs  []xid.ID
	UserTypes       []string
	IncludeSystem   *bool
	IncludeDefault  *bool
	ExcludeInactive *bool
	HasPermissions  *bool
	HasUsers        *bool
}

// roleRepository implements RoleRepository
type roleRepository struct {
	client *ent.Client
	logger logging.Logger
}

// NewRoleRepository creates a new role repository
func NewRoleRepository(client *ent.Client, logger logging.Logger) RoleRepository {
	return &roleRepository{
		client: client,
		logger: logger,
	}
}

// Create creates a new role
func (r *roleRepository) Create(ctx context.Context, input CreateRoleInput) (*ent.Role, error) {
	create := r.client.Role.Create().
		SetName(input.Name).
		SetRoleType(input.RoleType).
		SetSystem(input.System).
		SetIsDefault(input.IsDefault).
		SetPriority(input.Priority).
		SetApplicableUserTypes(input.ApplicableUserTypes)

	// Set optional fields
	if input.DisplayName != nil {
		create.SetDisplayName(*input.DisplayName)
	}
	if input.Description != nil {
		create.SetDescription(*input.Description)
	}
	if input.OrganizationID != nil {
		create.SetOrganizationID(*input.OrganizationID)
	}
	if input.ApplicationID != nil {
		create.SetApplicationID(*input.ApplicationID)
	}
	if input.Color != nil {
		create.SetColor(*input.Color)
	}
	if input.CreatedBy != nil {
		create.SetCreatedBy(*input.CreatedBy)
	}
	if input.ParentID != nil {
		create.SetParentID(*input.ParentID)
	}

	role, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "Role with this name already exists in the specified context")
		}
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	return role, nil
}

// GetByID retrieves a role by ID
func (r *roleRepository) GetByID(ctx context.Context, id xid.ID) (*ent.Role, error) {
	role, err := r.client.Role.Query().
		Where(role.ID(id)).
		WithPermissions().
		WithParent().
		WithChildren().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Role not found")
		}
		return nil, fmt.Errorf("failed to get role by ID: %w", err)
	}
	return role, nil
}

// GetByName retrieves a role by name within a specific context
func (r *roleRepository) GetByName(ctx context.Context, name string, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) (*ent.Role, error) {
	query := r.client.Role.Query().
		Where(
			role.Name(name),
			role.RoleTypeEQ(roleType),
		)

	if organizationID != nil {
		query = query.Where(role.OrganizationID(*organizationID))
	}
	if applicationID != nil {
		query = query.Where(role.ApplicationID(*applicationID))
	}

	role, err := query.WithPermissions().
		WithParent().
		WithChildren().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Role not found")
		}
		return nil, fmt.Errorf("failed to get role by name: %w", err)
	}
	return role, nil
}

// Update updates a role
func (r *roleRepository) Update(ctx context.Context, id xid.ID, input UpdateRoleInput) (*ent.Role, error) {
	update := r.client.Role.UpdateOneID(id)

	if input.Name != nil {
		update.SetName(*input.Name)
	}
	if input.DisplayName != nil {
		update.SetDisplayName(*input.DisplayName)
	}
	if input.Description != nil {
		update.SetDescription(*input.Description)
	}
	if input.IsDefault != nil {
		update.SetIsDefault(*input.IsDefault)
	}
	if input.Priority != nil {
		update.SetPriority(*input.Priority)
	}
	if input.Color != nil {
		update.SetColor(*input.Color)
	}
	if input.ApplicableUserTypes != nil {
		update.SetApplicableUserTypes(input.ApplicableUserTypes)
	}
	if input.Active != nil {
		update.SetActive(*input.Active)
	}
	if input.ParentID != nil {
		update.SetParentID(*input.ParentID)
	}

	role, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Role not found")
		}
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "Role with this name already exists in the specified context")
		}
		return nil, fmt.Errorf("failed to update role: %w", err)
	}
	return role, nil
}

// Delete deletes a role
func (r *roleRepository) Delete(ctx context.Context, id xid.ID) error {
	// Check if role can be deleted
	canDelete, err := r.CanDelete(ctx, id)
	if err != nil {
		return err
	}
	if !canDelete {
		return errors.New(errors.CodeConflict, "Role cannot be deleted as it is currently in use")
	}

	err = r.client.Role.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Role not found")
		}
		return fmt.Errorf("failed to delete role: %w", err)
	}
	return nil
}

// List retrieves roles with pagination and filtering
func (r *roleRepository) List(ctx context.Context, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error) {
	query := r.client.Role.Query().
		WithPermissions().
		WithParent()

	// Apply filters
	if params.RoleType != nil {
		query = query.Where(role.RoleTypeEQ(*params.RoleType))
	}
	if params.OrganizationID != nil {
		query = query.Where(role.OrganizationID(*params.OrganizationID))
	}
	if params.ApplicationID != nil {
		query = query.Where(role.ApplicationID(*params.ApplicationID))
	}
	if params.System != nil {
		query = query.Where(role.System(*params.System))
	}
	if params.IsDefault != nil {
		query = query.Where(role.IsDefault(*params.IsDefault))
	}
	if params.Active != nil {
		query = query.Where(role.Active(*params.Active))
	}
	if params.CreatedBy != nil {
		query = query.Where(role.CreatedBy(*params.CreatedBy))
	}
	if params.ParentID != nil {
		query = query.Where(role.ParentID(*params.ParentID))
	}
	if params.ApplicableUserType != nil {
		query = query.Where(func(s *sql.Selector) {
			s.Where(sqljson.ValueContains(role.FieldApplicableUserTypes, *params.ApplicableUserType))
		})
	}

	// Apply pagination
	return model.WithPaginationAndOptions[*ent.Role, *ent.RoleQuery](ctx, query, params.PaginationParams)
}

// ListByOrganization retrieves roles for a specific organization
func (r *roleRepository) ListByOrganization(ctx context.Context, organizationID xid.ID, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error) {
	params.OrganizationID = &organizationID
	return r.List(ctx, params)
}

// ListByApplication retrieves roles for a specific application
func (r *roleRepository) ListByApplication(ctx context.Context, applicationID xid.ID, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error) {
	params.ApplicationID = &applicationID
	return r.List(ctx, params)
}

// Search searches for roles
func (r *roleRepository) Search(ctx context.Context, query string, params SearchRolesParams) (*model.PaginatedOutput[*ent.Role], error) {
	q := r.client.Role.Query().
		WithPermissions().
		WithParent()

	// Apply filters
	if params.RoleType != nil {
		q = q.Where(role.RoleTypeEQ(*params.RoleType))
	}
	if params.OrganizationID != nil {
		q = q.Where(role.OrganizationID(*params.OrganizationID))
	}
	if params.ApplicationID != nil {
		q = q.Where(role.ApplicationID(*params.ApplicationID))
	}

	// Apply search conditions
	if params.ExactMatch {
		q = q.Where(role.Or(
			role.Name(query),
			role.DisplayName(query),
		))
	} else {
		q = q.Where(role.Or(
			role.NameContains(query),
			role.DisplayNameContains(query),
			role.DescriptionContains(query),
		))
	}

	return model.WithPaginationAndOptions[*ent.Role, *ent.RoleQuery](ctx, q, params.PaginationParams)
}

// Role type specific operations

func (r *roleRepository) GetSystemRoles(ctx context.Context, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error) {
	roleType := role.RoleTypeSystem
	params.RoleType = &roleType
	return r.List(ctx, params)
}

func (r *roleRepository) GetOrganizationRoles(ctx context.Context, organizationID xid.ID, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error) {
	roleType := role.RoleTypeOrganization
	params.RoleType = &roleType
	params.OrganizationID = &organizationID
	return r.List(ctx, params)
}

func (r *roleRepository) GetApplicationRoles(ctx context.Context, applicationID xid.ID, params ListRolesParams) (*model.PaginatedOutput[*ent.Role], error) {
	roleType := role.RoleTypeApplication
	params.RoleType = &roleType
	params.ApplicationID = &applicationID
	return r.List(ctx, params)
}

// Default role operations

func (r *roleRepository) GetDefaultRoles(ctx context.Context, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) ([]*ent.Role, error) {
	query := r.client.Role.Query().
		Where(
			role.RoleTypeEQ(roleType),
			role.IsDefault(true),
			role.Active(true),
		)

	if organizationID != nil {
		query = query.Where(role.OrganizationID(*organizationID))
	}
	if applicationID != nil {
		query = query.Where(role.ApplicationID(*applicationID))
	}

	roles, err := query.WithPermissions().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get default roles: %w", err)
	}
	return roles, nil
}

func (r *roleRepository) SetAsDefault(ctx context.Context, id xid.ID) error {
	err := r.client.Role.UpdateOneID(id).
		SetIsDefault(true).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Role not found")
		}
		return fmt.Errorf("failed to set role as default: %w", err)
	}
	return nil
}

func (r *roleRepository) UnsetAsDefault(ctx context.Context, id xid.ID) error {
	err := r.client.Role.UpdateOneID(id).
		SetIsDefault(false).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Role not found")
		}
		return fmt.Errorf("failed to unset role as default: %w", err)
	}
	return nil
}

// Permission operations

func (r *roleRepository) AddPermission(ctx context.Context, roleID, permissionID xid.ID) error {
	err := r.client.Role.UpdateOneID(roleID).
		AddPermissionIDs(permissionID).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Role or permission not found")
		}
		return fmt.Errorf("failed to add permission to role: %w", err)
	}
	return nil
}

func (r *roleRepository) RemovePermission(ctx context.Context, roleID, permissionID xid.ID) error {
	err := r.client.Role.UpdateOneID(roleID).
		RemovePermissionIDs(permissionID).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Role or permission not found")
		}
		return fmt.Errorf("failed to remove permission from role: %w", err)
	}
	return nil
}

func (r *roleRepository) GetPermissions(ctx context.Context, roleID xid.ID) ([]*ent.Permission, error) {
	role, err := r.client.Role.Query().
		Where(role.ID(roleID)).
		WithPermissions().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Role not found")
		}
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}
	return role.Edges.Permissions, nil
}

func (r *roleRepository) HasPermission(ctx context.Context, roleID, permissionID xid.ID) (bool, error) {
	permissions, err := r.GetPermissions(ctx, roleID)
	if err != nil {
		return false, err
	}

	for _, perm := range permissions {
		if perm.ID == permissionID {
			return true, nil
		}
	}
	return false, nil
}

func (r *roleRepository) GetRolesWithPermission(ctx context.Context, permissionID xid.ID) ([]*ent.Role, error) {
	roles, err := r.client.Role.Query().
		Where(role.HasPermissionsWith(permission.ID(permissionID))).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles with permission: %w", err)
	}
	return roles, nil
}

// Role hierarchy operations

func (r *roleRepository) GetChildren(ctx context.Context, roleID xid.ID) ([]*ent.Role, error) {
	roles, err := r.client.Role.Query().
		Where(role.ParentID(roleID)).
		WithPermissions().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get child roles: %w", err)
	}
	return roles, nil
}

func (r *roleRepository) GetParent(ctx context.Context, roleID xid.ID) (*ent.Role, error) {
	role, err := r.client.Role.Query().
		Where(role.ID(roleID)).
		WithParent().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Role not found")
		}
		return nil, fmt.Errorf("failed to get parent role: %w", err)
	}
	return role.Edges.Parent, nil
}

func (r *roleRepository) GetAncestors(ctx context.Context, roleID xid.ID) ([]*ent.Role, error) {
	var ancestors []*ent.Role
	currentID := roleID

	for {
		parent, err := r.GetParent(ctx, currentID)
		if err != nil {
			if errors.IsNotFound(err) {
				break
			}
			return nil, err
		}
		if parent == nil {
			break
		}
		ancestors = append(ancestors, parent)
		currentID = parent.ID
	}

	return ancestors, nil
}

func (r *roleRepository) GetDescendants(ctx context.Context, roleID xid.ID) ([]*ent.Role, error) {
	var descendants []*ent.Role

	// Get immediate children
	children, err := r.GetChildren(ctx, roleID)
	if err != nil {
		return nil, err
	}

	// Recursively get descendants of each child
	for _, child := range children {
		descendants = append(descendants, child)
		childDescendants, err := r.GetDescendants(ctx, child.ID)
		if err != nil {
			return nil, err
		}
		descendants = append(descendants, childDescendants...)
	}

	return descendants, nil
}

func (r *roleRepository) SetParent(ctx context.Context, roleID, parentID xid.ID) error {
	// Check for circular reference
	descendants, err := r.GetDescendants(ctx, roleID)
	if err != nil {
		return err
	}
	for _, desc := range descendants {
		if desc.ID == parentID {
			return errors.New(errors.CodeBadRequest, "Cannot set parent: would create circular reference")
		}
	}

	err = r.client.Role.UpdateOneID(roleID).
		SetParentID(parentID).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Role not found")
		}
		return fmt.Errorf("failed to set parent role: %w", err)
	}
	return nil
}

func (r *roleRepository) RemoveParent(ctx context.Context, roleID xid.ID) error {
	err := r.client.Role.UpdateOneID(roleID).
		ClearParentID().
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Role not found")
		}
		return fmt.Errorf("failed to remove parent role: %w", err)
	}
	return nil
}

// User assignment operations

func (r *roleRepository) GetUsersWithRole(ctx context.Context, roleID xid.ID) ([]*ent.User, error) {
	// Get users through UserRole assignments
	users, err := r.client.User.Query().
		Where(user.HasUserRolesWith(userrole.RoleID(roleID))).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get users with role: %w", err)
	}
	return users, nil
}

func (r *roleRepository) GetUserCount(ctx context.Context, roleID xid.ID) (int, error) {
	count, err := r.client.User.Query().
		Where(user.HasUserRolesWith(userrole.RoleID(roleID))).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get user count for role: %w", err)
	}
	return count, nil
}

// Role validation and checks

func (r *roleRepository) CanDelete(ctx context.Context, roleID xid.ID) (bool, error) {
	// Check if role is system role
	role, err := r.GetByID(ctx, roleID)
	if err != nil {
		return false, err
	}
	if role.System {
		return false, nil
	}

	// Check if role is in use
	inUse, err := r.IsInUse(ctx, roleID)
	if err != nil {
		return false, err
	}
	return !inUse, nil
}

func (r *roleRepository) IsInUse(ctx context.Context, roleID xid.ID) (bool, error) {
	// Check if any users have this role
	userCount, err := r.GetUserCount(ctx, roleID)
	if err != nil {
		return false, err
	}
	if userCount > 0 {
		return true, nil
	}

	// Check if any memberships use this role
	membershipCount, err := r.client.Membership.Query().
		Where(membership.RoleID(roleID)).
		Count(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check membership usage: %w", err)
	}
	if membershipCount > 0 {
		return true, nil
	}

	// Check if any child roles exist
	children, err := r.GetChildren(ctx, roleID)
	if err != nil {
		return false, err
	}
	return len(children) > 0, nil
}

func (r *roleRepository) ExistsByName(ctx context.Context, name string, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) (bool, error) {
	query := r.client.Role.Query().
		Where(
			role.Name(name),
			role.RoleTypeEQ(roleType),
		)

	if organizationID != nil {
		query = query.Where(role.OrganizationID(*organizationID))
	}
	if applicationID != nil {
		query = query.Where(role.ApplicationID(*applicationID))
	}

	exists, err := query.Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check if role exists by name: %w", err)
	}
	return exists, nil
}

// Bulk operations

func (r *roleRepository) BulkCreate(ctx context.Context, inputs []CreateRoleInput) ([]*ent.Role, error) {
	creates := make([]*ent.RoleCreate, len(inputs))
	for i, input := range inputs {
		create := r.client.Role.Create().
			SetName(input.Name).
			SetRoleType(input.RoleType).
			SetSystem(input.System).
			SetIsDefault(input.IsDefault).
			SetPriority(input.Priority).
			SetApplicableUserTypes(input.ApplicableUserTypes)

		// Set optional fields
		if input.DisplayName != nil {
			create.SetDisplayName(*input.DisplayName)
		}
		if input.Description != nil {
			create.SetDescription(*input.Description)
		}
		if input.OrganizationID != nil {
			create.SetOrganizationID(*input.OrganizationID)
		}
		if input.ApplicationID != nil {
			create.SetApplicationID(*input.ApplicationID)
		}
		if input.Color != nil {
			create.SetColor(*input.Color)
		}
		if input.CreatedBy != nil {
			create.SetCreatedBy(*input.CreatedBy)
		}
		if input.ParentID != nil {
			create.SetParentID(*input.ParentID)
		}

		creates[i] = create
	}

	roles, err := r.client.Role.CreateBulk(creates...).Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to bulk create roles: %w", err)
	}
	return roles, nil
}

func (r *roleRepository) BulkDelete(ctx context.Context, ids []xid.ID) error {
	// Check if all roles can be deleted
	for _, id := range ids {
		canDelete, err := r.CanDelete(ctx, id)
		if err != nil {
			return err
		}
		if !canDelete {
			return errors.New(errors.CodeConflict, fmt.Sprintf("Role %s cannot be deleted as it is currently in use", id))
		}
	}

	// Delete all roles
	_, err := r.client.Role.Delete().
		Where(role.IDIn(ids...)).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to bulk delete roles: %w", err)
	}
	return nil
}
