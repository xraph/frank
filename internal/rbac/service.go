package rbac

import (
	"context"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// Service provides role-based access control operations
type Service interface {
	// CreateRole creates a new role
	CreateRole(ctx context.Context, input CreateRoleInput) (*ent.Role, error)

	// GetRole retrieves a role by ID
	GetRole(ctx context.Context, id string) (*ent.Role, error)

	// ListRoles retrieves roles with pagination
	ListRoles(ctx context.Context, params ListRolesParams) ([]*ent.Role, int, error)

	// UpdateRole updates a role
	UpdateRole(ctx context.Context, id string, input UpdateRoleInput) (*ent.Role, error)

	// DeleteRole deletes a role
	DeleteRole(ctx context.Context, id string) error

	// AddPermissionToRole adds a permission to a role
	AddPermissionToRole(ctx context.Context, roleID, permissionID string) error

	// RemovePermissionFromRole removes a permission from a role
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID string) error

	// CreatePermission creates a new permission
	CreatePermission(ctx context.Context, input CreatePermissionInput) (*ent.Permission, error)

	// ListPermissions retrieves permissions with pagination
	ListPermissions(ctx context.Context, params ListPermissionsParams) ([]*ent.Permission, int, error)

	// UpdatePermission updates a permission
	UpdatePermission(ctx context.Context, id string, input UpdatePermissionInput) (*ent.Permission, error)

	// DeletePermission deletes a permission
	DeletePermission(ctx context.Context, id string) error

	// HasPermission checks if a user has a permission
	HasPermission(ctx context.Context, userID, resource, action string) (bool, error)

	// HasRole checks if a user has a role
	HasRole(ctx context.Context, userID, roleName string, organizationID string) (bool, error)
}

// CreateRoleInput represents input for creating a role
type CreateRoleInput struct {
	Name           string `json:"name" validate:"required"`
	Description    string `json:"description,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	IsDefault      bool   `json:"is_default"`
}

// AddRolePermissionInput represents the input structure for adding a permission to a role.
type AddRolePermissionInput struct {
	PermissionID string `json:"permissionId" validate:"required"`
}

// UpdateRoleInput represents input for updating a role
type UpdateRoleInput struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	IsDefault   *bool   `json:"is_default,omitempty"`
}

// CreatePermissionInput represents input for creating a permission
type CreatePermissionInput struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description,omitempty"`
	Resource    string `json:"resource" validate:"required"`
	Action      string `json:"action" validate:"required"`
	Conditions  string `json:"conditions,omitempty"`
}

// UpdatePermissionInput represents input for updating a permission
type UpdatePermissionInput struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Conditions  *string `json:"conditions,omitempty"`
}

// ListRolesParams represents pagination parameters for roles
type ListRolesParams struct {
	Offset         int    `json:"offset" query:"offset"`
	Limit          int    `json:"limit" query:"limit"`
	OrganizationID string `json:"organization_id" query:"organization_id"`
	Search         string `json:"search" query:"search"`
}

// ListPermissionsParams represents pagination parameters for permissions
type ListPermissionsParams struct {
	Offset   int    `json:"offset" query:"offset"`
	Limit    int    `json:"limit" query:"limit"`
	Resource string `json:"resource" query:"resource"`
	Action   string `json:"action" query:"action"`
	Search   string `json:"search" query:"search"`
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

// CreateRole creates a new role
func (s *service) CreateRole(ctx context.Context, input CreateRoleInput) (*ent.Role, error) {
	return s.repo.CreateRole(ctx, RepositoryCreateRoleInput{
		Name:           input.Name,
		Description:    input.Description,
		OrganizationID: input.OrganizationID,
		IsDefault:      input.IsDefault,
	})
}

// GetRole retrieves a role by ID
func (s *service) GetRole(ctx context.Context, id string) (*ent.Role, error) {
	return s.repo.GetRoleByID(ctx, id)
}

// ListRoles retrieves roles with pagination
func (s *service) ListRoles(ctx context.Context, params ListRolesParams) ([]*ent.Role, int, error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	return s.repo.ListRoles(ctx, RepositoryListRolesInput{
		Offset:         params.Offset,
		Limit:          params.Limit,
		OrganizationID: params.OrganizationID,
		Search:         params.Search,
	})
}

// UpdateRole updates a role
func (s *service) UpdateRole(ctx context.Context, id string, input UpdateRoleInput) (*ent.Role, error) {
	return s.repo.UpdateRole(ctx, id, RepositoryUpdateRoleInput{
		Name:        input.Name,
		Description: input.Description,
		IsDefault:   input.IsDefault,
	})
}

// DeleteRole deletes a role
func (s *service) DeleteRole(ctx context.Context, id string) error {
	// Get role to check if it's a system role
	role, err := s.repo.GetRoleByID(ctx, id)
	if err != nil {
		return err
	}

	if role.System {
		return errors.New(errors.CodeForbidden, "cannot delete system roles")
	}

	return s.repo.DeleteRole(ctx, id)
}

// AddPermissionToRole adds a permission to a role
func (s *service) AddPermissionToRole(ctx context.Context, roleID, permissionID string) error {
	return s.repo.AddPermissionToRole(ctx, roleID, permissionID)
}

// RemovePermissionFromRole removes a permission from a role
func (s *service) RemovePermissionFromRole(ctx context.Context, roleID, permissionID string) error {
	return s.repo.RemovePermissionFromRole(ctx, roleID, permissionID)
}

// CreatePermission creates a new permission
func (s *service) CreatePermission(ctx context.Context, input CreatePermissionInput) (*ent.Permission, error) {
	return s.repo.CreatePermission(ctx, RepositoryCreatePermissionInput{
		Name:        input.Name,
		Description: input.Description,
		Resource:    input.Resource,
		Action:      input.Action,
		Conditions:  input.Conditions,
	})
}

// ListPermissions retrieves permissions with pagination
func (s *service) ListPermissions(ctx context.Context, params ListPermissionsParams) ([]*ent.Permission, int, error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	return s.repo.ListPermissions(ctx, RepositoryListPermissionsInput{
		Offset:   params.Offset,
		Limit:    params.Limit,
		Resource: params.Resource,
		Action:   params.Action,
		Search:   params.Search,
	})
}

// UpdatePermission updates a permission
func (s *service) UpdatePermission(ctx context.Context, id string, input UpdatePermissionInput) (*ent.Permission, error) {
	// Get permission to check if it's a system permission
	permission, err := s.repo.GetPermissionByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if permission.System {
		return nil, errors.New(errors.CodeForbidden, "cannot update system permissions")
	}

	return s.repo.UpdatePermission(ctx, id, RepositoryUpdatePermissionInput{
		Name:        input.Name,
		Description: input.Description,
		Conditions:  input.Conditions,
	})
}

// DeletePermission deletes a permission
func (s *service) DeletePermission(ctx context.Context, id string) error {
	// Get permission to check if it's a system permission
	permission, err := s.repo.GetPermissionByID(ctx, id)
	if err != nil {
		return err
	}

	if permission.System {
		return errors.New(errors.CodeForbidden, "cannot delete system permissions")
	}

	return s.repo.DeletePermission(ctx, id)
}

// HasPermission checks if a user has a permission
func (s *service) HasPermission(ctx context.Context, userID, resource, action string) (bool, error) {
	return s.enforcer.Enforce(ctx, userID, resource, action)
}

// HasRole checks if a user has a role
func (s *service) HasRole(ctx context.Context, userID, roleName string, organizationID string) (bool, error) {
	return s.repo.HasRole(ctx, userID, roleName, organizationID)
}
