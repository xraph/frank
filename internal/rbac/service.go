package rbac

import (
	"context"

	"github.com/juicycleff/frank/ent"
	entRole "github.com/juicycleff/frank/ent/role"
	entUserRole "github.com/juicycleff/frank/ent/userrole"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// Service provides role-based access control operations
type Service interface {
	// Role Management (Updated with RoleService functionality)
	CreateRole(ctx context.Context, input CreateRoleInput) (*Role, error)
	GetRole(ctx context.Context, id xid.ID) (*ent.Role, error)
	ListRoles(ctx context.Context, params ListRolesParams) (*model.PaginatedOutput[*Role], error)
	UpdateRole(ctx context.Context, id xid.ID, input UpdateRoleBody) (*Role, error)
	DeleteRole(ctx context.Context, id xid.ID) error

	// Role Assignment Methods (New from RoleService)
	AssignSystemRole(ctx context.Context, userID xid.ID, roleName string) error
	AssignOrganizationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error
	AssignApplicationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error
	RemoveUserRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType entUserRole.ContextType, contextID *xid.ID) error

	// Role Query Methods (New from RoleService)
	GetUserSystemRoles(ctx context.Context, userID xid.ID) ([]*ent.Role, error)
	GetUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error)
	GetUserApplicationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error)
	GetAllUserRoles(ctx context.Context, userID xid.ID) ([]*ent.UserRole, error)
	GetRolesByType(ctx context.Context, roleType entRole.RoleType, orgID *xid.ID) ([]*ent.Role, error)

	// Permission Management (Legacy functionality preserved)
	AddPermissionToRole(ctx context.Context, roleID, permissionID xid.ID) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID xid.ID) error
	CreatePermission(ctx context.Context, input CreatePermissionInput) (*Permission, error)
	GetPermission(ctx context.Context, id xid.ID) (*Permission, error)
	ListPermissions(ctx context.Context, params ListPermissionsParams) (*model.PaginatedOutput[*Permission], error)
	ListRolePermissions(ctx context.Context, id xid.ID) ([]*Permission, error)
	UpdatePermission(ctx context.Context, id xid.ID, input UpdatePermissionInput) (*Permission, error)
	DeletePermission(ctx context.Context, id xid.ID) error

	// Permission/Role Checking (Updated with RoleService functionality)
	HasPermission(ctx context.Context, userID xid.ID, resource, action string) (bool, error)
	HasRole(ctx context.Context, userID xid.ID, roleName string, contextType entUserRole.ContextType, contextID *xid.ID) (bool, error)
	HasAnyRole(ctx context.Context, userID xid.ID, roleNames []string, contextType entUserRole.ContextType, contextID *xid.ID) (bool, error)
}

type service struct {
	repo     Repository
	enforcer Enforcer
	logger   logging.Logger
}

// NewService creates a new RBAC service
func NewService(repo Repository, enforcer Enforcer, logger logging.Logger) Service {
	return &service{
		repo:     repo,
		enforcer: enforcer,
		logger:   logger,
	}
}

// ================================
// ROLE MANAGEMENT
// ================================

// CreateRole creates a new role using Repository's advanced functionality
func (s *service) CreateRole(ctx context.Context, input CreateRoleInput) (*Role, error) {
	req := CreateRoleRequest{
		Name:                input.Name,
		DisplayName:         input.DisplayName,
		Description:         input.Description,
		RoleType:            input.RoleType,
		OrganizationID:      input.OrganizationID,
		ApplicationID:       input.ApplicationID,
		ApplicableUserTypes: input.ApplicableUserTypes,
		Permissions:         input.Permissions,
		Priority:            input.Priority,
		Color:               input.Color,
		CreatedBy:           input.CreatedBy,
	}

	entRole, err := s.repo.CreateRoleAdvanced(ctx, req)
	if err != nil {
		return nil, err
	}

	return convertRoleToDTO(entRole), nil
}

// GetRole retrieves a role by ID
func (s *service) GetRole(ctx context.Context, id xid.ID) (*ent.Role, error) {
	return s.repo.GetRoleByID(ctx, id)
}

// ListRoles retrieves roles with pagination, enhanced with type filtering
func (s *service) ListRoles(ctx context.Context, params ListRolesParams) (*model.PaginatedOutput[*Role], error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	// Fall back to standard listing method
	roles, err := s.repo.ListRoles(ctx, params)
	if err != nil {
		return nil, err
	}

	return &model.PaginatedOutput[*Role]{
		Data:       convertRolesToDTO(roles.Data),
		Pagination: roles.Pagination,
	}, nil
}

// UpdateRole updates a role using Repository's advanced functionality
func (s *service) UpdateRole(ctx context.Context, id xid.ID, input UpdateRoleBody) (*Role, error) {
	updates := make(map[string]interface{})

	if input.Name != nil {
		updates["name"] = *input.Name
	}
	if input.Description != nil {
		updates["description"] = *input.Description
	}
	if input.IsDefault != nil {
		updates["is_default"] = *input.IsDefault
	}
	if input.DisplayName != nil {
		updates["display_name"] = *input.DisplayName
	}
	if input.Priority != nil {
		updates["priority"] = *input.Priority
	}
	if input.Color != nil {
		updates["color"] = *input.Color
	}
	if input.Active != nil {
		updates["active"] = *input.Active
	}

	entRole, err := s.repo.UpdateRoleAdvanced(ctx, id, updates)
	if err != nil {
		return nil, err
	}

	return convertRoleToDTO(entRole), nil
}

// DeleteRole deactivates a role (soft delete)
func (s *service) DeleteRole(ctx context.Context, id xid.ID) error {
	// Get role to check if it's a system role
	role, err := s.repo.GetRoleByID(ctx, id)
	if err != nil {
		return err
	}

	if role.System {
		return errors.New(errors.CodeForbidden, "cannot delete system roles")
	}

	// Use Repository to deactivate
	_, err = s.repo.UpdateRoleAdvanced(ctx, id, map[string]interface{}{
		"active": false,
	})
	return err
}

// ================================
// ROLE ASSIGNMENT METHODS
// ================================

func (s *service) AssignSystemRole(ctx context.Context, userID xid.ID, roleName string) error {
	return s.repo.AssignSystemRole(ctx, userID, roleName)
}

func (s *service) AssignOrganizationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	return s.repo.AssignOrganizationRole(ctx, userID, orgID, roleName)
}

func (s *service) AssignApplicationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	return s.repo.AssignApplicationRole(ctx, userID, orgID, roleName)
}

func (s *service) RemoveUserRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType entUserRole.ContextType, contextID *xid.ID) error {
	return s.repo.RemoveUserRole(ctx, userID, roleID, contextType, contextID)
}

// ================================
// ROLE QUERY METHODS
// ================================

func (s *service) GetUserSystemRoles(ctx context.Context, userID xid.ID) ([]*ent.Role, error) {
	return s.repo.GetUserSystemRoles(ctx, userID)
}

func (s *service) GetUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error) {
	return s.repo.GetUserOrganizationRoles(ctx, userID, orgID)
}

func (s *service) GetUserApplicationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error) {
	return s.repo.GetUserApplicationRoles(ctx, userID, orgID)
}

func (s *service) GetAllUserRoles(ctx context.Context, userID xid.ID) ([]*ent.UserRole, error) {
	return s.repo.GetAllUserRoles(ctx, userID)
}

func (s *service) GetRolesByType(ctx context.Context, roleType entRole.RoleType, orgID *xid.ID) ([]*ent.Role, error) {
	return s.repo.GetRolesByType(ctx, roleType, orgID)
}

// ================================
// PERMISSION MANAGEMENT
// ================================

func (s *service) ListRolePermissions(ctx context.Context, id xid.ID) ([]*Permission, error) {
	entPermissions, err := s.repo.GetRolePermissions(ctx, id)
	if err != nil {
		return nil, err
	}

	return convertPermissionsToDTO(entPermissions), nil
}

func (s *service) AddPermissionToRole(ctx context.Context, roleID, permissionID xid.ID) error {
	return s.repo.AddPermissionToRole(ctx, roleID, permissionID)
}

func (s *service) RemovePermissionFromRole(ctx context.Context, roleID, permissionID xid.ID) error {
	return s.repo.RemovePermissionFromRole(ctx, roleID, permissionID)
}

func (s *service) CreatePermission(ctx context.Context, input CreatePermissionInput) (*Permission, error) {
	permissionCreate := s.repo.Client().Permission.Create().
		SetID(xid.New()).
		SetName(input.Name).
		SetResource(input.Resource).
		SetAction(input.Action).
		SetSystem(false)

	if input.Description != "" {
		permissionCreate = permissionCreate.SetDescription(input.Description)
	}

	if input.Conditions != "" {
		permissionCreate = permissionCreate.SetConditions(input.Conditions)
	}

	entPermission, err := s.repo.CreatePermission(ctx, permissionCreate)
	if err != nil {
		return nil, err
	}

	return convertPermissionToDTO(entPermission), nil
}

func (s *service) GetPermission(ctx context.Context, id xid.ID) (*Permission, error) {
	entPermission, err := s.repo.GetPermissionByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return convertPermissionToDTO(entPermission), nil
}

func (s *service) ListPermissions(ctx context.Context, params ListPermissionsParams) (*model.PaginatedOutput[*Permission], error) {
	if params.Limit <= 0 {
		params.Limit = 10
	}

	entResult, err := s.repo.ListPermissions(ctx, params)
	if err != nil {
		return nil, err
	}

	permissions := convertPermissionsToDTO(entResult.Data)

	return &model.PaginatedOutput[*Permission]{
		Data:       permissions,
		Pagination: entResult.Pagination,
	}, nil
}

func (s *service) UpdatePermission(ctx context.Context, id xid.ID, input UpdatePermissionInput) (*Permission, error) {
	permission, err := s.repo.GetPermissionByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if permission.System {
		return nil, errors.New(errors.CodeForbidden, "cannot update system permissions")
	}

	permissionUpdate := s.repo.Client().Permission.UpdateOneID(id)

	if input.Name != nil {
		permissionUpdate = permissionUpdate.SetName(*input.Name)
	}

	if input.Description != nil {
		permissionUpdate = permissionUpdate.SetDescription(*input.Description)
	}

	if input.Conditions != nil {
		permissionUpdate = permissionUpdate.SetConditions(*input.Conditions)
	}

	updatedEntPermission, err := s.repo.UpdatePermission(ctx, permissionUpdate)
	if err != nil {
		return nil, err
	}

	return convertPermissionToDTO(updatedEntPermission), nil
}

func (s *service) DeletePermission(ctx context.Context, id xid.ID) error {
	permission, err := s.repo.GetPermissionByID(ctx, id)
	if err != nil {
		return err
	}

	if permission.System {
		return errors.New(errors.CodeForbidden, "cannot delete system permissions")
	}

	return s.repo.DeletePermission(ctx, id)
}

// ================================
// PERMISSION/ROLE CHECKING
// ================================

func (s *service) HasPermission(ctx context.Context, userID xid.ID, resource, action string) (bool, error) {
	return s.enforcer.Enforce(ctx, userID.String(), resource, action)
}

// HasRole checks if a user has a role in a specific context
func (s *service) HasRole(ctx context.Context, userID xid.ID, roleName string, contextType entUserRole.ContextType, contextID *xid.ID) (bool, error) {
	return s.repo.HasRole(ctx, userID, roleName, contextType, contextID)
}

func (s *service) HasAnyRole(ctx context.Context, userID xid.ID, roleNames []string, contextType entUserRole.ContextType, contextID *xid.ID) (bool, error) {
	return s.repo.HasAnyRole(ctx, userID, roleNames, contextType, contextID)
}

// ================================
// CONVERTER FUNCTIONS
// ================================

func convertPermissionToDTO(entPermission *ent.Permission) *Permission {
	return &Permission{
		Base: model.Base{
			ID:        entPermission.ID,
			CreatedAt: entPermission.CreatedAt,
			UpdatedAt: entPermission.UpdatedAt,
		},
		Name:        entPermission.Name,
		Description: entPermission.Description,
		Resource:    entPermission.Resource,
		Action:      entPermission.Action,
		Conditions:  entPermission.Conditions,
	}
}

func convertPermissionsToDTO(entPermissions []*ent.Permission) []*Permission {
	permissions := make([]*Permission, len(entPermissions))
	for i, entPermission := range entPermissions {
		permissions[i] = convertPermissionToDTO(entPermission)
	}
	return permissions
}

func convertRoleToDTO(entRole *ent.Role) *Role {
	role := &Role{
		Base: model.Base{
			ID:        entRole.ID,
			CreatedAt: entRole.CreatedAt,
			UpdatedAt: entRole.UpdatedAt,
		},
		Name:           entRole.Name,
		Description:    entRole.Description,
		IsDefault:      entRole.IsDefault,
		OrganizationID: &entRole.OrganizationID,
		System:         entRole.System,
	}

	// Add RoleService specific fields if they exist
	if entRole.DisplayName != "" {
		role.DisplayName = entRole.DisplayName
	}
	if entRole.RoleType != "" {
		role.RoleType = entRole.RoleType
	}
	if entRole.Priority > 0 {
		role.Priority = entRole.Priority
	}
	if entRole.Color != "" {
		role.Color = entRole.Color
	}
	role.Active = entRole.Active

	return role
}

func convertRolesToDTO(entRoles []*ent.Role) []*Role {
	roles := make([]*Role, len(entRoles))
	for i, entRole := range entRoles {
		roles[i] = convertRoleToDTO(entRole)
	}
	return roles
}
