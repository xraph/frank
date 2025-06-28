package repository

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/permission"
	"github.com/xraph/frank/ent/permissiondependency"
	"github.com/xraph/frank/ent/predicate"
	"github.com/xraph/frank/ent/role"
	"github.com/xraph/frank/ent/user"
	"github.com/xraph/frank/ent/userpermission"
	"github.com/xraph/frank/ent/userrole"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// PermissionRepository defines the interface for permission data access
type PermissionRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreatePermissionInput) (*ent.Permission, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Permission, error)
	GetByName(ctx context.Context, name string) (*ent.Permission, error)
	GetByResourceAndAction(ctx context.Context, resource, action string) (*ent.Permission, error)
	Update(ctx context.Context, id xid.ID, input UpdatePermissionInput) (*ent.Permission, error)
	Delete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	Search(ctx context.Context, query string, params SearchPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)

	// Category and grouping operations
	GetByCategory(ctx context.Context, category model.PermissionCategory, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	GetByGroup(ctx context.Context, group model.PermissionGroup, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	GetByResource(ctx context.Context, resource string, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	GetSystemPermissions(ctx context.Context, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	GetDangerousPermissions(ctx context.Context, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)

	// Role operations
	GetRolesWithPermission(ctx context.Context, permissionID xid.ID) ([]*ent.Role, error)
	GetPermissionsByRole(ctx context.Context, roleID xid.ID) ([]*ent.Permission, error)

	// User operations
	GetUsersWithPermission(ctx context.Context, permissionID xid.ID) ([]*ent.User, error)
	GetUserPermissions(ctx context.Context, userID xid.ID, contextType model.ContextType, contextID *xid.ID) ([]*ent.Permission, error)
	GetEffectiveUserPermissions(ctx context.Context, userID xid.ID, contextType model.ContextType, contextID *xid.ID) ([]*ent.Permission, error)

	// Permission dependencies
	GetDependencies(ctx context.Context, permissionID xid.ID) ([]*ent.Permission, error)
	GetDependents(ctx context.Context, permissionID xid.ID) ([]*ent.Permission, error)
	AddDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID, dependencyType permissiondependency.DependencyType) error
	RemoveDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID) error

	// Permission validation and checks
	CanDelete(ctx context.Context, permissionID xid.ID) (bool, error)
	IsInUse(ctx context.Context, permissionID xid.ID) (bool, error)
	ExistsByName(ctx context.Context, name string) (bool, error)
	ExistsByResourceAndAction(ctx context.Context, resource, action string) (bool, error)

	// Bulk operations
	BulkCreate(ctx context.Context, inputs []CreatePermissionInput) ([]*ent.Permission, error)
	BulkDelete(ctx context.Context, ids []xid.ID) error

	// Permission analysis
	GetPermissionStats(ctx context.Context) (*PermissionStats, error)
	GetMostUsedPermissions(ctx context.Context, limit int) ([]*PermissionUsage, error)
	GetUnusedPermissions(ctx context.Context) ([]*ent.Permission, error)

	// ================================
	// PERMISSION OPERATIONS (Enhanced from rbac2)
	// ================================
	CreatePermission(ctx context.Context, permissionCreate *ent.PermissionCreate) (*ent.Permission, error)
	GetPermissionByID(ctx context.Context, id xid.ID) (*ent.Permission, error)
	GetPermissionByName(ctx context.Context, name string) (*ent.Permission, error)
	GetPermissionByResourceAndAction(ctx context.Context, resource, action string) (*ent.Permission, error)
	ListPermissions(ctx context.Context, input ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error)
	UpdatePermission(ctx context.Context, permissionUpdate *ent.PermissionUpdateOne) (*ent.Permission, error)
	DeletePermission(ctx context.Context, id xid.ID) error

	Client() *ent.Client
}

// CreatePermissionInput represents input for creating a permission
type CreatePermissionInput struct {
	Name                string                   `json:"name"`
	DisplayName         string                   `json:"display_name,omitempty"`
	Description         string                   `json:"description"`
	Resource            string                   `json:"resource"`
	Action              string                   `json:"action"`
	Category            model.PermissionCategory `json:"category"`
	ApplicableUserTypes []model.UserType         `json:"applicable_user_types,omitempty"`
	ApplicableContexts  []model.ContextType      `json:"applicable_contexts,omitempty"`
	Conditions          *string                  `json:"conditions,omitempty"`
	System              bool                     `json:"system"`
	Dangerous           bool                     `json:"dangerous"`
	RiskLevel           int                      `json:"risk_level"`
	PermissionGroup     model.PermissionGroup    `json:"permission_group,omitempty"`
	CreatedBy           *string                  `json:"created_by,omitempty"`
}

// UpdatePermissionInput represents input for updating a permission
type UpdatePermissionInput struct {
	DisplayName         *string                `json:"display_name,omitempty"`
	Description         *string                `json:"description,omitempty"`
	ApplicableUserTypes []model.UserType       `json:"applicable_user_types,omitempty"`
	ApplicableContexts  []model.ContextType    `json:"applicable_contexts,omitempty"`
	Conditions          *string                `json:"conditions,omitempty"`
	Dangerous           *bool                  `json:"dangerous,omitempty"`
	RiskLevel           *int                   `json:"risk_level,omitempty"`
	PermissionGroup     *model.PermissionGroup `json:"permission_group,omitempty"`
	Active              *bool                  `json:"active,omitempty"`
}

// ListPermissionsParams represents parameters for listing permissions
type ListPermissionsParams struct {
	model.PaginationParams
	Category           *model.PermissionCategory `json:"category,omitempty"`
	Resource           string                    `json:"resource,omitempty"`
	Action             string                    `json:"action,omitempty"`
	System             *bool                     `json:"system,omitempty"`
	Dangerous          *bool                     `json:"dangerous,omitempty"`
	RiskLevel          *int                      `json:"risk_level,omitempty"`
	PermissionGroup    model.PermissionGroup     `json:"permission_group,omitempty"`
	Active             *bool                     `json:"active,omitempty"`
	CreatedBy          string                    `json:"created_by,omitempty"`
	ApplicableUserType model.UserType            `json:"applicable_user_type,omitempty"`
	ApplicableContext  model.ContextType         `json:"applicable_context,omitempty"`
	IncludeRoles       *bool                     `json:"include_roles,omitempty"`
	Search             string                    `json:"search,omitempty"`
}

// SearchPermissionsParams represents parameters for searching permissions
type SearchPermissionsParams struct {
	model.PaginationParams
	Resource         *string `json:"resource,omitempty"`
	ExactMatch       bool    `json:"exact_match"`
	Categories       []model.PermissionCategory
	Resources        []string
	Actions          []string
	RiskLevels       []int
	UserTypes        []model.UserType
	Contexts         []model.ContextType
	IncludeSystem    bool
	IncludeDangerous bool
	ExcludeInactive  *bool
}

// PermissionStats represents permission statistics
type PermissionStats struct {
	TotalPermissions     int                              `json:"total_permissions"`
	SystemPermissions    int                              `json:"system_permissions"`
	CustomPermissions    int                              `json:"custom_permissions"`
	DangerousPermissions int                              `json:"dangerous_permissions"`
	CategoryBreakdown    map[model.PermissionCategory]int `json:"category_breakdown"`
	ResourceBreakdown    map[string]int                   `json:"resource_breakdown"`
	RiskLevelBreakdown   map[int]int                      `json:"risk_level_breakdown"`
	UnusedPermissions    int                              `json:"unused_permissions"`
}

// PermissionUsage represents permission usage statistics
type PermissionUsage struct {
	Permission *ent.Permission `json:"permission"`
	UsageCount int             `json:"usage_count"`
	RoleCount  int             `json:"role_count"`
	UserCount  int             `json:"user_count"`
}

// permissionRepository implements PermissionRepository
type permissionRepository struct {
	client *ent.Client
	logger logging.Logger
}

// NewPermissionRepository creates a new permission repository
func NewPermissionRepository(client *ent.Client, logger logging.Logger) PermissionRepository {
	return &permissionRepository{
		client: client,
		logger: logger,
	}
}

// Create creates a new permission
func (r *permissionRepository) Create(ctx context.Context, input CreatePermissionInput) (*ent.Permission, error) {
	create := r.client.Permission.Create().
		SetName(input.Name).
		SetDescription(input.Description).
		SetResource(input.Resource).
		SetAction(input.Action).
		SetCategory(input.Category).
		SetApplicableUserTypes(input.ApplicableUserTypes).
		SetApplicableContexts(input.ApplicableContexts).
		SetSystem(input.System).
		SetDangerous(input.Dangerous).
		SetRiskLevel(input.RiskLevel).
		SetDisplayName(input.DisplayName)

	// Set optional fields
	if input.Conditions != nil {
		create.SetConditions(*input.Conditions)
	}
	if input.PermissionGroup != "" {
		create.SetPermissionGroup(input.PermissionGroup)
	}
	if input.CreatedBy != nil {
		create.SetCreatedBy(*input.CreatedBy)
	}

	permission, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "Permission with this name or resource/action combination already exists")
		}
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	return permission, nil
}

// GetByID retrieves a permission by ID
func (r *permissionRepository) GetByID(ctx context.Context, id xid.ID) (*ent.Permission, error) {
	permission, err := r.client.Permission.Query().
		Where(permission.ID(id)).
		WithRoles().
		WithUserAssignments().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Permission not found")
		}
		return nil, fmt.Errorf("failed to get permission by ID: %w", err)
	}
	return permission, nil
}

// GetByName retrieves a permission by name
func (r *permissionRepository) GetByName(ctx context.Context, name string) (*ent.Permission, error) {
	permission, err := r.client.Permission.Query().
		Where(permission.Name(name)).
		WithRoles().
		WithUserAssignments().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Permission not found")
		}
		return nil, fmt.Errorf("failed to get permission by name: %w", err)
	}
	return permission, nil
}

// GetByResourceAndAction retrieves a permission by resource and action
func (r *permissionRepository) GetByResourceAndAction(ctx context.Context, resource, action string) (*ent.Permission, error) {
	permission, err := r.client.Permission.Query().
		Where(
			permission.Resource(resource),
			permission.Action(action),
		).
		WithRoles().
		WithUserAssignments().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Permission not found")
		}
		return nil, fmt.Errorf("failed to get permission by resource and action: %w", err)
	}
	return permission, nil
}

// Update updates a permission
func (r *permissionRepository) Update(ctx context.Context, id xid.ID, input UpdatePermissionInput) (*ent.Permission, error) {
	update := r.client.Permission.UpdateOneID(id)

	if input.DisplayName != nil {
		update.SetDisplayName(*input.DisplayName)
	}
	if input.Description != nil {
		update.SetDescription(*input.Description)
	}
	if input.ApplicableUserTypes != nil {
		update.SetApplicableUserTypes(input.ApplicableUserTypes)
	}
	if input.ApplicableContexts != nil {
		update.SetApplicableContexts(input.ApplicableContexts)
	}
	if input.Conditions != nil {
		update.SetConditions(*input.Conditions)
	}
	if input.Dangerous != nil {
		update.SetDangerous(*input.Dangerous)
	}
	if input.RiskLevel != nil {
		update.SetRiskLevel(*input.RiskLevel)
	}
	if input.PermissionGroup != nil {
		update.SetPermissionGroup(*input.PermissionGroup)
	}
	if input.Active != nil {
		update.SetActive(*input.Active)
	}

	permission, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Permission not found")
		}
		return nil, fmt.Errorf("failed to update permission: %w", err)
	}
	return permission, nil
}

// Delete deletes a permission
func (r *permissionRepository) Delete(ctx context.Context, id xid.ID) error {
	// Check if permission can be deleted
	canDelete, err := r.CanDelete(ctx, id)
	if err != nil {
		return err
	}
	if !canDelete {
		return errors.New(errors.CodeConflict, "Permission cannot be deleted as it is currently in use")
	}

	err = r.client.Permission.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Permission not found")
		}
		return fmt.Errorf("failed to delete permission: %w", err)
	}
	return nil
}

// List retrieves permissions with pagination and filtering
func (r *permissionRepository) List(ctx context.Context, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error) {
	query := r.client.Permission.Query()

	// Apply filters
	if params.Category != nil {
		query = query.Where(permission.CategoryEQ(*params.Category))
	}
	if params.Resource != "" {
		query = query.Where(permission.Resource(params.Resource))
	}
	if params.Action != "" {
		query = query.Where(permission.Action(params.Action))
	}
	if params.System != nil {
		query = query.Where(permission.System(*params.System))
	}
	if params.Dangerous != nil {
		query = query.Where(permission.Dangerous(*params.Dangerous))
	}
	if params.RiskLevel != nil {
		query = query.Where(permission.RiskLevel(*params.RiskLevel))
	}
	if params.PermissionGroup != "" {
		query = query.Where(permission.PermissionGroup(params.PermissionGroup))
	}
	if params.Active != nil {
		query = query.Where(permission.Active(*params.Active))
	}
	if params.CreatedBy != "" {
		query = query.Where(permission.CreatedBy(params.CreatedBy))
	}
	if params.ApplicableUserType != "" {
		query = query.Where(func(s *sql.Selector) {
			s.Where(sqljson.ValueContains(permission.FieldApplicableUserTypes, params.ApplicableUserType))
		})
	}
	if params.ApplicableContext != "" {
		query = query.Where(func(s *sql.Selector) {
			s.Where(sqljson.ValueContains(permission.FieldApplicableContexts, params.ApplicableContext))
		})
	}

	// Apply pagination
	return model.WithPaginationAndOptions[*ent.Permission, *ent.PermissionQuery](ctx, query, params.PaginationParams)
}

// Search searches for permissions
func (r *permissionRepository) Search(ctx context.Context, query string, params SearchPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error) {
	q := r.client.Permission.Query()

	// Apply filters
	if params.Categories != nil {
		q = q.Where(permission.CategoryIn(params.Categories...))
	}
	if params.Resource != nil {
		q = q.Where(permission.Resource(*params.Resource))
	}

	// Apply search conditions
	if params.ExactMatch {
		q = q.Where(permission.Or(
			permission.Name(query),
			permission.DisplayName(query),
			permission.Resource(query),
			permission.Action(query),
		))
	} else {
		q = q.Where(permission.Or(
			permission.NameContains(query),
			permission.DisplayNameContains(query),
			permission.DescriptionContains(query),
			permission.ResourceContains(query),
			permission.ActionContains(query),
		))
	}

	return model.WithPaginationAndOptions[*ent.Permission, *ent.PermissionQuery](ctx, q, params.PaginationParams)
}

// Category and grouping operations

func (r *permissionRepository) GetByCategory(ctx context.Context, category model.PermissionCategory, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error) {
	params.Category = &category
	return r.List(ctx, params)
}

func (r *permissionRepository) GetByGroup(ctx context.Context, group model.PermissionGroup, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error) {
	params.PermissionGroup = group
	return r.List(ctx, params)
}

func (r *permissionRepository) GetByResource(ctx context.Context, resource string, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error) {
	params.Resource = resource
	return r.List(ctx, params)
}

func (r *permissionRepository) GetSystemPermissions(ctx context.Context, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error) {
	system := true
	params.System = &system
	return r.List(ctx, params)
}

func (r *permissionRepository) GetDangerousPermissions(ctx context.Context, params ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error) {
	dangerous := true
	params.Dangerous = &dangerous
	return r.List(ctx, params)
}

// Role operations

func (r *permissionRepository) GetRolesWithPermission(ctx context.Context, permissionID xid.ID) ([]*ent.Role, error) {
	permission, err := r.client.Permission.Query().
		Where(permission.ID(permissionID)).
		WithRoles().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Permission not found")
		}
		return nil, fmt.Errorf("failed to get roles with permission: %w", err)
	}
	return permission.Edges.Roles, nil
}

func (r *permissionRepository) GetPermissionsByRole(ctx context.Context, roleID xid.ID) ([]*ent.Permission, error) {
	permissions, err := r.client.Permission.Query().
		Where(permission.HasRolesWith(role.ID(roleID))).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions by role: %w", err)
	}
	return permissions, nil
}

// User operations

func (r *permissionRepository) GetUsersWithPermission(ctx context.Context, permissionID xid.ID) ([]*ent.User, error) {
	// Get users through direct permission assignments
	users, err := r.client.User.Query().
		Where(user.HasUserPermissionsWith(userpermission.PermissionID(permissionID))).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get users with permission: %w", err)
	}
	return users, nil
}

func (r *permissionRepository) GetUserPermissions(ctx context.Context, userID xid.ID, contextType model.ContextType, contextID *xid.ID) ([]*ent.Permission, error) {
	userPermsQuery := []predicate.UserPermission{userpermission.UserID(userID)}
	if contextID != nil {
		userPermsQuery = append(userPermsQuery, userpermission.ContextTypeEQ(contextType))
	}

	if contextID != nil {
		userPermsQuery = append(userPermsQuery, userpermission.ContextIDEQ(*contextID))
	}

	query := r.client.Permission.Query().
		Where(permission.HasUserAssignmentsWith(userPermsQuery...))
	permissions, err := query.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	return permissions, nil
}

func (r *permissionRepository) GetEffectiveUserPermissions(ctx context.Context, userID xid.ID, contextType model.ContextType, contextID *xid.ID) ([]*ent.Permission, error) {
	// Get direct permissions
	directPermissions, err := r.GetUserPermissions(ctx, userID, contextType, contextID)
	if err != nil {
		return nil, err
	}

	// Get permissions from roles
	var rolePermissions []*ent.Permission

	// Query user roles with the same context
	roleQuery := r.client.UserRole.Query().Where(userrole.UserID(userID))
	if contextType != "" {
		roleQuery = roleQuery.Where(userrole.ContextTypeEQ(contextType))
	}

	if contextID != nil {
		roleQuery = roleQuery.Where(userrole.ContextID(*contextID))
	}

	// userRoles, err := r.client.UserRole.Query().
	// 	Where(func(q *ent.UserRoleQuery) {
	// 		roleQuery := q.Where(userrole.UserID(userID))
	// 		if contextType != "" {
	// 			roleQuery = roleQuery.Where(userrole.ContextTypeEQ(contextType))
	// 		}
	// 		if contextID != nil {
	// 			roleQuery = roleQuery.Where(userrole.ContextID(*contextID))
	// 		}
	// 	}).
	// 	WithRole(func(q *ent.RoleQuery) {
	// 		q.WithPermissions()
	// 	}).
	// 	All(ctx)

	userRoles, err := roleQuery.
		WithRole(func(q *ent.RoleQuery) {
			q.WithPermissions()
		}).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Collect permissions from roles
	for _, userRole := range userRoles {
		if userRole.Edges.Role != nil && userRole.Edges.Role.Edges.Permissions != nil {
			rolePermissions = append(rolePermissions, userRole.Edges.Role.Edges.Permissions...)
		}
	}

	// Merge and deduplicate permissions
	permissionMap := make(map[xid.ID]*ent.Permission)

	// Add direct permissions
	for _, perm := range directPermissions {
		permissionMap[perm.ID] = perm
	}

	// Add role permissions
	for _, perm := range rolePermissions {
		permissionMap[perm.ID] = perm
	}

	// Convert back to slice
	result := make([]*ent.Permission, 0, len(permissionMap))
	for _, perm := range permissionMap {
		result = append(result, perm)
	}

	return result, nil
}

// Permission dependencies

func (r *permissionRepository) GetDependencies(ctx context.Context, permissionID xid.ID) ([]*ent.Permission, error) {
	dependencies, err := r.client.Permission.Query().
		Where(permission.HasDependentsWith(permissiondependency.RequiredPermissionID(permissionID))).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission dependencies: %w", err)
	}
	return dependencies, nil
}

func (r *permissionRepository) GetDependents(ctx context.Context, permissionID xid.ID) ([]*ent.Permission, error) {
	dependents, err := r.client.Permission.Query().
		Where(permission.HasDependenciesWith(permissiondependency.RequiredPermissionID(permissionID))).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission dependents: %w", err)
	}
	return dependents, nil
}

func (r *permissionRepository) AddDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID, dependencyType permissiondependency.DependencyType) error {
	_, err := r.client.PermissionDependency.Create().
		SetPermissionID(permissionID).
		SetRequiredPermissionID(requiredPermissionID).
		SetDependencyType(dependencyType).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return errors.New(errors.CodeConflict, "Permission dependency already exists")
		}
		return fmt.Errorf("failed to add permission dependency: %w", err)
	}
	return nil
}

func (r *permissionRepository) RemoveDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID) error {
	_, err := r.client.PermissionDependency.Delete().
		Where(
			permissiondependency.PermissionID(permissionID),
			permissiondependency.RequiredPermissionID(requiredPermissionID),
		).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to remove permission dependency: %w", err)
	}
	return nil
}

// Permission validation and checks

func (r *permissionRepository) CanDelete(ctx context.Context, permissionID xid.ID) (bool, error) {
	// Check if permission is system permission
	permission, err := r.GetByID(ctx, permissionID)
	if err != nil {
		return false, err
	}
	if permission.System {
		return false, nil
	}

	// Check if permission is in use
	inUse, err := r.IsInUse(ctx, permissionID)
	if err != nil {
		return false, err
	}
	return !inUse, nil
}

func (r *permissionRepository) IsInUse(ctx context.Context, permissionID xid.ID) (bool, error) {
	// Check if any roles have this permission
	roles, err := r.GetRolesWithPermission(ctx, permissionID)
	if err != nil {
		return false, err
	}
	if len(roles) > 0 {
		return true, nil
	}

	// Check if any users have this permission directly
	users, err := r.GetUsersWithPermission(ctx, permissionID)
	if err != nil {
		return false, err
	}
	if len(users) > 0 {
		return true, nil
	}

	// Check if any permissions depend on this permission
	dependents, err := r.GetDependents(ctx, permissionID)
	if err != nil {
		return false, err
	}
	return len(dependents) > 0, nil
}

func (r *permissionRepository) ExistsByName(ctx context.Context, name string) (bool, error) {
	exists, err := r.client.Permission.Query().
		Where(permission.Name(name)).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check if permission exists by name: %w", err)
	}
	return exists, nil
}

func (r *permissionRepository) ExistsByResourceAndAction(ctx context.Context, resource, action string) (bool, error) {
	exists, err := r.client.Permission.Query().
		Where(
			permission.Resource(resource),
			permission.Action(action),
		).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check if permission exists by resource and action: %w", err)
	}
	return exists, nil
}

// Bulk operations

func (r *permissionRepository) BulkCreate(ctx context.Context, inputs []CreatePermissionInput) ([]*ent.Permission, error) {
	creates := make([]*ent.PermissionCreate, len(inputs))
	for i, input := range inputs {
		create := r.client.Permission.Create().
			SetName(input.Name).
			SetDescription(input.Description).
			SetResource(input.Resource).
			SetAction(input.Action).
			SetCategory(input.Category).
			SetApplicableUserTypes(input.ApplicableUserTypes).
			SetApplicableContexts(input.ApplicableContexts).
			SetSystem(input.System).
			SetDangerous(input.Dangerous).
			SetRiskLevel(input.RiskLevel).
			SetDisplayName(input.DisplayName)

		// Set optional fields
		if input.Conditions != nil {
			create.SetConditions(*input.Conditions)
		}
		if input.PermissionGroup != "" {
			create.SetPermissionGroup(input.PermissionGroup)
		}
		if input.CreatedBy != nil {
			create.SetCreatedBy(*input.CreatedBy)
		}

		creates[i] = create
	}

	permissions, err := r.client.Permission.CreateBulk(creates...).Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to bulk create permissions: %w", err)
	}
	return permissions, nil
}

func (r *permissionRepository) BulkDelete(ctx context.Context, ids []xid.ID) error {
	// Check if all permissions can be deleted
	for _, id := range ids {
		canDelete, err := r.CanDelete(ctx, id)
		if err != nil {
			return err
		}
		if !canDelete {
			return errors.New(errors.CodeConflict, fmt.Sprintf("Permission %s cannot be deleted as it is currently in use", id))
		}
	}

	// Delete all permissions
	_, err := r.client.Permission.Delete().
		Where(permission.IDIn(ids...)).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to bulk delete permissions: %w", err)
	}
	return nil
}

// Permission analysis

func (r *permissionRepository) GetPermissionStats(ctx context.Context) (*PermissionStats, error) {
	// Get total count
	total, err := r.client.Permission.Query().Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get total permission count: %w", err)
	}

	// Get system permissions count
	system, err := r.client.Permission.Query().
		Where(permission.System(true)).
		Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get system permission count: %w", err)
	}

	// Get dangerous permissions count
	dangerous, err := r.client.Permission.Query().
		Where(permission.Dangerous(true)).
		Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get dangerous permission count: %w", err)
	}

	// Get unused permissions
	unused, err := r.GetUnusedPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get unused permissions: %w", err)
	}

	// Get category breakdown
	categoryBreakdown := make(map[model.PermissionCategory]int)
	for _, cat := range []model.PermissionCategory{
		model.PermissionCategoryOrganization,
		model.PermissionCategoryApplication,
		model.PermissionCategorySystem,
		model.PermissionCategoryCompliance,
	} {
		count, err := r.client.Permission.Query().
			Where(permission.CategoryEQ(cat)).
			Count(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get category breakdown: %w", err)
		}
		categoryBreakdown[cat] = count
	}

	// Get resource breakdown
	resourceBreakdown := make(map[string]int)
	resources, err := r.client.Permission.Query().
		GroupBy(permission.FieldResource).
		Aggregate(ent.Count()).
		Strings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource breakdown: %w", err)
	}
	for _, resource := range resources {
		count, err := r.client.Permission.Query().
			Where(permission.Resource(resource)).
			Count(ctx)
		if err != nil {
			continue
		}
		resourceBreakdown[resource] = count
	}

	// Get risk level breakdown
	riskLevelBreakdown := make(map[int]int)
	for level := 1; level <= 5; level++ {
		count, err := r.client.Permission.Query().
			Where(permission.RiskLevel(level)).
			Count(ctx)
		if err != nil {
			continue
		}
		riskLevelBreakdown[level] = count
	}

	return &PermissionStats{
		TotalPermissions:     total,
		SystemPermissions:    system,
		CustomPermissions:    total - system,
		DangerousPermissions: dangerous,
		CategoryBreakdown:    categoryBreakdown,
		ResourceBreakdown:    resourceBreakdown,
		RiskLevelBreakdown:   riskLevelBreakdown,
		UnusedPermissions:    len(unused),
	}, nil
}

func (r *permissionRepository) GetMostUsedPermissions(ctx context.Context, limit int) ([]*PermissionUsage, error) {
	// This is a simplified implementation
	// In a real scenario, you might want to use more complex queries
	permissions, err := r.client.Permission.Query().
		WithRoles().
		WithUserAssignments().
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get most used permissions: %w", err)
	}

	result := make([]*PermissionUsage, len(permissions))
	for i, perm := range permissions {
		roleCount := len(perm.Edges.Roles)
		userCount := len(perm.Edges.UserAssignments)

		result[i] = &PermissionUsage{
			Permission: perm,
			UsageCount: roleCount + userCount,
			RoleCount:  roleCount,
			UserCount:  userCount,
		}
	}

	return result, nil
}

func (r *permissionRepository) GetUnusedPermissions(ctx context.Context) ([]*ent.Permission, error) {
	permissions, err := r.client.Permission.Query().
		Where(
			permission.Not(permission.HasRoles()),
			permission.Not(permission.HasUserAssignments()),
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get unused permissions: %w", err)
	}
	return permissions, nil
}

func (r *permissionRepository) CreatePermission(ctx context.Context, permissionCreate *ent.PermissionCreate) (*ent.Permission, error) {
	// TODO implement me
	panic("implement me")
}

func (r *permissionRepository) GetPermissionByID(ctx context.Context, id xid.ID) (*ent.Permission, error) {
	// TODO implement me
	panic("implement me")
}

func (r *permissionRepository) GetPermissionByName(ctx context.Context, name string) (*ent.Permission, error) {
	// TODO implement me
	panic("implement me")
}

func (r *permissionRepository) GetPermissionByResourceAndAction(ctx context.Context, resource, action string) (*ent.Permission, error) {
	// TODO implement me
	panic("implement me")
}

func (r *permissionRepository) ListPermissions(ctx context.Context, input ListPermissionsParams) (*model.PaginatedOutput[*ent.Permission], error) {
	// TODO implement me
	panic("implement me")
}

func (r *permissionRepository) UpdatePermission(ctx context.Context, permissionUpdate *ent.PermissionUpdateOne) (*ent.Permission, error) {
	// TODO implement me
	panic("implement me")
}

func (r *permissionRepository) DeletePermission(ctx context.Context, id xid.ID) error {
	// TODO implement me
	panic("implement me")
}

func (r *permissionRepository) Client() *ent.Client {
	return r.client
}
