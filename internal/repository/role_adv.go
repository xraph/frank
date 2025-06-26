package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/permission"
	"github.com/juicycleff/frank/ent/predicate"
	"github.com/juicycleff/frank/ent/role"
	entRole "github.com/juicycleff/frank/ent/role"
	"github.com/juicycleff/frank/ent/user"
	entUserRole "github.com/juicycleff/frank/ent/userrole"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

var (
	ErrRoleNotFound       = errors.New(errors.CodeNotFound, "role not found")
	ErrPermissionNotFound = errors.New(errors.CodeNotFound, "permission not found")
	ErrUserNotFound       = errors.New(errors.CodeNotFound, "user not found")
	ErrRoleConflict       = errors.New(errors.CodeConflict, "role with this name already exists")
	ErrPermissionConflict = errors.New(errors.CodeConflict, "permission already exists")
)

// CreateRoleRequest represents the request structure for RoleService
type CreateRoleRequest struct {
	Name                string           `json:"name"`
	DisplayName         string           `json:"display_name"`
	Description         string           `json:"description"`
	RoleType            model.RoleType   `json:"role_type"` // system, organization, application
	OrganizationID      *xid.ID          `json:"organization_id,omitempty"`
	ApplicationID       *xid.ID          `json:"application_id,omitempty"`
	ApplicableUserTypes []model.UserType `json:"applicable_user_types"`
	Permissions         []string         `json:"permissions"`
	Priority            int              `json:"priority"`
	Color               string           `json:"color,omitempty"`
	CreatedBy           string           `json:"created_by,omitempty"`
}

// ================================
// BASIC ROLE OPERATIONS
// ================================

// CreateRole creates a new role
func (r *roleRepository) CreateRole(ctx context.Context, roleCreate *ent.RoleCreate) (*ent.Role, error) {
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
func (r *roleRepository) GetRoleByID(ctx context.Context, id xid.ID) (*ent.Role, error) {
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
func (r *roleRepository) GetRoleByName(ctx context.Context, name string, orgId xid.ID) (*ent.Role, error) {
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
func (r *roleRepository) ListRoles(ctx context.Context, input ListRolesParams) (*model.PaginatedOutput[*ent.Role], error) {
	// Build query predicates
	var predicates []predicate.Role

	if input.OrganizationID != nil {
		predicates = append(predicates, role.OrganizationIDEQ(*input.OrganizationID))
	}

	if input.Search != "" {
		predicates = append(predicates,
			role.Or(
				role.NameContainsFold(input.Search),
				role.DescriptionContainsFold(input.Search),
			),
		)
	}

	if input.RoleType != nil {
		predicates = append(predicates,
			role.Or(
				role.RoleTypeEQ(*input.RoleType),
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
func (r *roleRepository) UpdateRole(ctx context.Context, roleUpdate *ent.RoleUpdateOne) (*ent.Role, error) {
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
func (r *roleRepository) DeleteRole(ctx context.Context, id xid.ID) error {
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
func (r *roleRepository) CreateRoleAdvanced(ctx context.Context, req CreateRoleRequest) (*ent.Role, error) {
	// Check if role already exists in the same context
	query := r.client.Role.Query().
		Where(
			entRole.Name(req.Name),
			entRole.RoleTypeEQ(req.RoleType),
		)

	if req.OrganizationID != nil {
		query = query.Where(entRole.OrganizationID(*req.OrganizationID))
	} else {
		query = query.Where(entRole.OrganizationIDIsNil())
	}

	if req.ApplicationID != nil {
		query = query.Where(entRole.ApplicationID(*req.ApplicationID))
	}

	exists, err := query.Exist(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New(errors.CodeConflict, "role with this name already exists in this context")
	}

	// Create role
	roleBuilder := r.client.Role.Create().
		SetName(req.Name).
		SetDescription(req.Description).
		SetRoleType(req.RoleType).
		SetPriority(req.Priority).
		SetApplicableUserTypes(req.ApplicableUserTypes).
		SetActive(true)

	if req.DisplayName != "" {
		roleBuilder.SetDisplayName(req.DisplayName)
	}
	if req.OrganizationID != nil {
		roleBuilder.SetOrganizationID(*req.OrganizationID)
	}
	if req.ApplicationID != nil {
		roleBuilder.SetApplicationID(*req.ApplicationID)
	}
	if req.Color != "" {
		roleBuilder.SetColor(req.Color)
	}
	if req.CreatedBy != "" {
		roleBuilder.SetCreatedBy(req.CreatedBy)
	}

	role, err := roleBuilder.Save(ctx)
	if err != nil {
		return nil, err
	}

	// Assign permissions if provided
	if len(req.Permissions) > 0 {
		// Note: You'll need to implement PermissionService
		// or handle permission assignments directly here
		for _, permName := range req.Permissions {
			fmt.Println("permission name:", permName)
			// TODO: Implement permission assignment
			// err = permissionService.AssignPermissionToRole(ctx, role.ID, permName)
			// if err != nil {
			//     // Log error but continue
			// }
		}
	}

	return role, nil
}

// UpdateRoleAdvanced updates a role using RoleService functionality
func (r *roleRepository) UpdateRoleAdvanced(ctx context.Context, roleID xid.ID, updates map[string]interface{}) (*ent.Role, error) {
	role, err := r.client.Role.Get(ctx, roleID)
	if err != nil {
		return nil, err
	}

	updateBuilder := role.Update()

	for field, value := range updates {
		switch field {
		case "display_name":
			if v, ok := value.(string); ok {
				updateBuilder.SetDisplayName(v)
			}
		case "description":
			if v, ok := value.(string); ok {
				updateBuilder.SetDescription(v)
			}
		case "priority":
			if v, ok := value.(int); ok {
				updateBuilder.SetPriority(v)
			}
		case "color":
			if v, ok := value.(string); ok {
				updateBuilder.SetColor(v)
			}
		case "active":
			if v, ok := value.(bool); ok {
				updateBuilder.SetActive(v)
			}
		case "is_default":
			if v, ok := value.(bool); ok {
				updateBuilder.SetIsDefault(v)
			}
		case "name":
			if v, ok := value.(string); ok {
				updateBuilder.SetName(v)
			}
		}
	}

	return updateBuilder.Save(ctx)
}

// GetRolesByType returns roles of a specific type
func (r *roleRepository) GetRolesByType(ctx context.Context, roleType model.RoleType, orgID *xid.ID) ([]*ent.Role, error) {
	query := r.client.Role.Query().
		Where(
			entRole.RoleTypeEQ(roleType),
			entRole.Active(true),
		)

	if orgID != nil {
		query = query.Where(entRole.OrganizationID(*orgID))
	} else if roleType == "system" {
		query = query.Where(entRole.OrganizationIDIsNil())
	}

	return query.WithPermissions().All(ctx)
}

// ================================
// ROLE ASSIGNMENT METHODS (RoleService Integration)
// ================================

// AssignSystemRole assigns a system-level role to a user
func (r *roleRepository) AssignSystemRole(ctx context.Context, userID xid.ID, roleName string) error {
	// Get system role
	role, err := r.client.Role.Query().
		Where(
			entRole.Name(roleName),
			entRole.RoleTypeEQ("system"),
			entRole.OrganizationIDIsNil(),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeResourceNotFound, "system role not found")
		}
		return err
	}

	// Check if assignment already exists
	exists, err := r.client.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.RoleID(role.ID),
			entUserRole.ContextTypeEQ(model.ContextPlatform),
			entUserRole.Active(true),
		).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil // Already assigned
	}

	// Create role assignment
	_, err = r.client.UserRole.Create().
		SetUserID(userID).
		SetRoleID(role.ID).
		SetContextType(model.ContextPlatform).
		SetActive(true).
		SetAssignedAt(time.Now()).
		Save(ctx)

	return err
}

// AssignOrganizationRole assigns an organization-scoped role to a user
func (r *roleRepository) AssignOrganizationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	// Get organization role
	role, err := r.client.Role.Query().
		Where(
			entRole.Name(roleName),
			entRole.RoleTypeEQ("organization"),
			entRole.OrganizationID(orgID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeResourceNotFound, "organization role not found")
		}
		return err
	}

	// Check if assignment already exists
	exists, err := r.client.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.RoleID(role.ID),
			entUserRole.ContextTypeEQ(model.ContextOrganization),
			entUserRole.ContextID(orgID),
			entUserRole.Active(true),
		).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil // Already assigned
	}

	// Create role assignment
	_, err = r.client.UserRole.Create().
		SetUserID(userID).
		SetRoleID(role.ID).
		SetContextType(model.ContextOrganization).
		SetContextID(orgID).
		SetActive(true).
		SetAssignedAt(time.Now()).
		Save(ctx)

	return err
}

// AssignApplicationRole assigns an application-scoped role to an end user
func (r *roleRepository) AssignApplicationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	// Get application role
	role, err := r.client.Role.Query().
		Where(
			entRole.Name(roleName),
			entRole.RoleTypeEQ(model.RoleTypeApplication),
			entRole.OrganizationID(orgID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeResourceNotFound, "application role not found")
		}
		return err
	}

	// Check if assignment already exists
	exists, err := r.client.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.RoleID(role.ID),
			entUserRole.ContextTypeEQ(model.ContextApplication),
			entUserRole.ContextID(orgID),
			entUserRole.Active(true),
		).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil // Already assigned
	}

	// Create role assignment
	_, err = r.client.UserRole.Create().
		SetUserID(userID).
		SetRoleID(role.ID).
		SetContextType(model.ContextApplication).
		SetContextID(orgID).
		SetActive(true).
		SetAssignedAt(time.Now()).
		Save(ctx)

	return err
}

// RemoveUserRole removes a role assignment
func (r *roleRepository) RemoveUserRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType model.ContextType, contextID *xid.ID) error {
	query := r.client.UserRole.Update().
		Where(
			entUserRole.UserID(userID),
			entUserRole.RoleID(roleID),
			entUserRole.ContextTypeEQ(contextType),
		)

	if contextID != nil {
		query = query.Where(entUserRole.ContextID(*contextID))
	} else {
		query = query.Where(entUserRole.ContextIDIsNil())
	}

	_, err := query.SetActive(false).Save(ctx)
	return err
}

// ================================
// ROLE QUERY METHODS (RoleService Integration)
// ================================

// GetUserSystemRoles returns all system roles for a user
func (r *roleRepository) GetUserSystemRoles(ctx context.Context, userID xid.ID) ([]*ent.Role, error) {
	userRoles, err := r.client.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.ContextTypeEQ(model.ContextPlatform),
			entUserRole.Active(true),
		).
		WithRole().
		All(ctx)
	if err != nil {
		return nil, err
	}

	roles := make([]*ent.Role, 0, len(userRoles))
	for _, ur := range userRoles {
		if ur.Edges.Role != nil {
			roles = append(roles, ur.Edges.Role)
		}
	}

	return roles, nil
}

// GetUserOrganizationRoles returns all organization roles for a user
func (r *roleRepository) GetUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error) {
	userRoles, err := r.client.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.ContextTypeEQ(model.ContextOrganization),
			entUserRole.ContextID(orgID),
			entUserRole.Active(true),
		).
		WithRole().
		All(ctx)
	if err != nil {
		return nil, err
	}

	roles := make([]*ent.Role, 0, len(userRoles))
	for _, ur := range userRoles {
		if ur.Edges.Role != nil {
			roles = append(roles, ur.Edges.Role)
		}
	}

	return roles, nil
}

// GetUserApplicationRoles returns all application roles for a user
func (r *roleRepository) GetUserApplicationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error) {
	userRoles, err := r.client.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.ContextTypeEQ(model.ContextApplication),
			entUserRole.ContextID(orgID),
			entUserRole.Active(true),
		).
		WithRole().
		All(ctx)
	if err != nil {
		return nil, err
	}

	roles := make([]*ent.Role, 0, len(userRoles))
	for _, ur := range userRoles {
		if ur.Edges.Role != nil {
			roles = append(roles, ur.Edges.Role)
		}
	}

	return roles, nil
}

// GetAllUserRoles returns all roles for a user across all contexts
func (r *roleRepository) GetAllUserRoles(ctx context.Context, userID xid.ID) ([]*ent.UserRole, error) {
	return r.client.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.Active(true),
		).
		WithRole().
		WithOrganizationContext().
		All(ctx)
}

// ================================
// ROLE CHECKING METHODS (RoleService Integration)
// ================================

// HasRole checks if a user has a specific role in a given context
func (r *roleRepository) HasRole(ctx context.Context, userID xid.ID, roleName string, contextType model.ContextType, contextID *xid.ID) (bool, error) {
	query := r.client.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.ContextTypeEQ(contextType),
			entUserRole.Active(true),
			entUserRole.HasRoleWith(entRole.Name(roleName)),
		)

	if contextID != nil {
		query = query.Where(entUserRole.ContextID(*contextID))
	} else {
		query = query.Where(entUserRole.ContextIDIsNil())
	}

	count, err := query.Count(ctx)
	return count > 0, err
}

// HasAnyRole checks if a user has any of the specified roles in a context
func (r *roleRepository) HasAnyRole(ctx context.Context, userID xid.ID, roleNames []string, contextType model.ContextType, contextID *xid.ID) (bool, error) {
	for _, roleName := range roleNames {
		hasRole, err := r.HasRole(ctx, userID, roleName, contextType, contextID)
		if err != nil {
			return false, err
		}
		if hasRole {
			return true, nil
		}
	}
	return false, nil
}

// ================================
// ROLE-PERMISSION OPERATIONS
// ================================

// AddPermissionToRole adds a permission to a role
func (r *roleRepository) AddPermissionToRole(ctx context.Context, roleID, permissionID xid.ID) error {
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
func (r *roleRepository) RemovePermissionFromRole(ctx context.Context, roleID, permissionID xid.ID) error {
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
func (r *roleRepository) GetRolePermissions(ctx context.Context, roleID xid.ID) ([]*ent.Permission, error) {
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
func (r *roleRepository) CreatePermission(ctx context.Context, permissionCreate *ent.PermissionCreate) (*ent.Permission, error) {
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
func (r *roleRepository) GetPermissionByID(ctx context.Context, id xid.ID) (*ent.Permission, error) {
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
func (r *roleRepository) GetPermissionByName(ctx context.Context, name string) (*ent.Permission, error) {
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
func (r *roleRepository) ListPermissions(ctx context.Context, input ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error) {
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
func (r *roleRepository) UpdatePermission(ctx context.Context, permissionUpdate *ent.PermissionUpdateOne) (*ent.Permission, error) {
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
func (r *roleRepository) DeletePermission(ctx context.Context, id xid.ID) error {
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
func (r *roleRepository) GetUserRoles(ctx context.Context, userID xid.ID) ([]*ent.Role, error) {
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
func (r *roleRepository) GetUserPermissions(ctx context.Context, userID xid.ID) ([]*ent.Permission, error) {
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
func (r *roleRepository) Client() *ent.Client {
	return r.client
}
