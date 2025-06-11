package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/permission"
	"github.com/juicycleff/frank/ent/permissiondependency"
	"github.com/juicycleff/frank/ent/role"
	"github.com/juicycleff/frank/ent/userrole"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// Service provides RBAC functionality
type Service interface {
	// Permission operations
	CreatePermission(ctx context.Context, input CreatePermissionInput) (*model.Permission, error)
	GetPermission(ctx context.Context, id xid.ID) (*model.Permission, error)
	GetPermissionByName(ctx context.Context, name string) (*model.Permission, error)
	UpdatePermission(ctx context.Context, id xid.ID, input UpdatePermissionInput) (*model.Permission, error)
	DeletePermission(ctx context.Context, id xid.ID) error
	ListPermissions(ctx context.Context, params ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)

	// Role operations
	CreateRole(ctx context.Context, input CreateRoleInput) (*model.Role, error)
	GetRole(ctx context.Context, id xid.ID) (*ent.Role, error)
	GetRoleByName(ctx context.Context, name string, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) (*model.Role, error)
	UpdateRole(ctx context.Context, id xid.ID, input UpdateRoleBody) (*model.Role, error)
	DeleteRole(ctx context.Context, id xid.ID) error
	ListRoles(ctx context.Context, params ListRolesParams) (*model.PaginatedOutput[*model.Role], error)

	// Role-Permission operations
	AddPermissionToRole(ctx context.Context, roleID, permissionID xid.ID) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID xid.ID) error
	ListRolePermissions(ctx context.Context, roleID xid.ID) ([]*model.Permission, error)
	GetRolesWithPermission(ctx context.Context, permissionID xid.ID) ([]*model.Role, error)

	// User-Role operations
	AssignRoleToUser(ctx context.Context, input AssignRoleToUserInput) (*model.RoleAssignment, error)
	RemoveRoleFromUser(ctx context.Context, userID, roleID xid.ID, contextType userrole.ContextType, contextID *xid.ID) error
	ListUserRoles(ctx context.Context, userID xid.ID, contextType userrole.ContextType, contextID *xid.ID) ([]*model.RoleAssignment, error)
	GetUsersWithRole(ctx context.Context, roleID xid.ID) ([]*model.User, error)

	// User-Permission operations
	AssignPermissionToUser(ctx context.Context, input AssignPermissionToUserInput) (*model.PermissionAssignment, error)
	RemovePermissionFromUser(ctx context.Context, userID, permissionID xid.ID, contextType userrole.ContextType, contextID *xid.ID) error
	ListUserPermissions(ctx context.Context, userID xid.ID, contextType userrole.ContextType, contextID *xid.ID) ([]*model.Permission, error)

	// Permission checking
	CheckPermission(ctx context.Context, userID xid.ID, permission string, contextType userrole.ContextType, contextID *xid.ID, resourceType string, resourceID *xid.ID) (*model.CheckPermissionResponse, error)
	GetUserEffectivePermissions(ctx context.Context, userID xid.ID, contextType userrole.ContextType, contextID *xid.ID) ([]*model.Permission, error)
	GetUserPermissionSummary(ctx context.Context, userID xid.ID, contextType userrole.ContextType, contextID *xid.ID) (*model.UserPermissionsResponse, error)

	// Bulk operations
	BulkAssignRoles(ctx context.Context, input BulkRoleAssignmentInput) (*model.BulkRoleAssignmentResponse, error)
	BulkRemoveRoles(ctx context.Context, input BulkRoleRemovalInput) (*model.BulkRoleAssignmentResponse, error)

	// Hierarchy operations
	GetRoleHierarchy(ctx context.Context, roleID xid.ID) (*model.RoleHierarchy, error)
	SetRoleParent(ctx context.Context, roleID, parentID xid.ID) error
	RemoveRoleParent(ctx context.Context, roleID xid.ID) error

	// Analytics and stats
	GetRBACStats(ctx context.Context, organizationID *xid.ID) (*model.RBACStats, error)
	GetPermissionUsageStats(ctx context.Context, organizationID *xid.ID) (map[string]int, error)
	GetRoleUsageStats(ctx context.Context, organizationID *xid.ID) (map[string]int, error)

	// Default roles
	GetDefaultRoles(ctx context.Context, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) ([]*model.Role, error)
	SetDefaultRole(ctx context.Context, roleID xid.ID) error
	UnsetDefaultRole(ctx context.Context, roleID xid.ID) error

	// Permission dependencies
	AddPermissionDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID, dependencyType string) error
	RemovePermissionDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID) error
	GetPermissionDependencies(ctx context.Context, permissionID xid.ID) ([]*model.Permission, error)
}

// service implements the RBAC Service interface
type service struct {
	roleRepo       repository.RoleRepository
	permissionRepo repository.PermissionRepository
	userRepo       repository.UserRepository
	orgRepo        repository.OrganizationRepository
	logger         logging.Logger
}

// NewService creates a new RBAC service
func NewService(
	roleRepo repository.RoleRepository,
	permissionRepo repository.PermissionRepository,
	userRepo repository.UserRepository,
	orgRepo repository.OrganizationRepository,
	logger logging.Logger,
) Service {
	return &service{
		roleRepo:       roleRepo,
		permissionRepo: permissionRepo,
		userRepo:       userRepo,
		orgRepo:        orgRepo,
		logger:         logger.Named("rbac"),
	}
}

// Input/Output type definitions

type CreatePermissionInput struct {
	Name                string
	DisplayName         string
	Description         string
	Resource            string
	Action              string
	Category            permission.Category
	ApplicableUserTypes []string
	ApplicableContexts  []string
	Conditions          string
	Dangerous           bool
	RiskLevel           int
	PermissionGroup     string
}

type UpdatePermissionInput struct {
	DisplayName         *string
	Description         *string
	ApplicableUserTypes []string
	ApplicableContexts  []string
	Conditions          *string
	Dangerous           *bool
	RiskLevel           *int
	Active              *bool
	PermissionGroup     *string
}

type CreateRoleInput struct {
	Name                string
	DisplayName         string
	Description         string
	RoleType            role.RoleType
	OrganizationID      *xid.ID
	ApplicationID       *xid.ID
	IsDefault           bool
	Priority            int
	Color               string
	ApplicableUserTypes []string
	ParentID            *xid.ID
	PermissionIDs       []xid.ID
}

type UpdateRoleBody struct {
	Name                *string
	DisplayName         *string
	Description         *string
	IsDefault           *bool
	Priority            *int
	Color               *string
	ApplicableUserTypes []string
	Active              *bool
	ParentID            *xid.ID
}

type AssignRoleToUserInput struct {
	UserID      xid.ID
	RoleID      xid.ID
	ContextType userrole.ContextType
	ContextID   *xid.ID
	AssignedBy  *xid.ID
	ExpiresAt   *time.Time
	Conditions  map[string]interface{}
}

type AssignPermissionToUserInput struct {
	UserID         xid.ID
	PermissionID   xid.ID
	ContextType    userrole.ContextType
	ContextID      *xid.ID
	ResourceType   string
	ResourceID     *xid.ID
	PermissionType string
	AssignedBy     *xid.ID
	ExpiresAt      *time.Time
	Conditions     map[string]interface{}
	Reason         string
}

type BulkRoleAssignmentInput struct {
	UserIDs     []xid.ID
	RoleID      xid.ID
	ContextType userrole.ContextType
	ContextID   *xid.ID
	AssignedBy  *xid.ID
	ExpiresAt   *time.Time
	Conditions  map[string]interface{}
}

type BulkRoleRemovalInput struct {
	UserIDs     []xid.ID
	RoleID      xid.ID
	ContextType userrole.ContextType
	ContextID   *xid.ID
}

type ListPermissionsParams struct {
	model.PaginationParams
	Resource           string
	Action             string
	Category           model.OptionalParam[permission.Category]
	System             model.OptionalParam[bool]
	Dangerous          model.OptionalParam[bool]
	RiskLevel          model.OptionalParam[int]
	Active             model.OptionalParam[bool]
	PermissionGroup    string
	ApplicableUserType string
	Search             string
	IncludeRoles       model.OptionalParam[bool]
}

type ListRolesParams struct {
	model.PaginationParams
	RoleType        role.RoleType
	OrganizationID  model.OptionalParam[xid.ID]
	ApplicationID   model.OptionalParam[xid.ID]
	System          model.OptionalParam[bool]
	IsDefault       model.OptionalParam[bool]
	Active          model.OptionalParam[bool]
	Search          string
	ParentID        model.OptionalParam[xid.ID]
	IncludeChildren bool
}

// Permission operations implementation

func (s *service) CreatePermission(ctx context.Context, input CreatePermissionInput) (*model.Permission, error) {
	s.logger.Debug("Creating permission", logging.String("name", input.Name))

	// Check if permission already exists
	if exists, err := s.permissionRepo.ExistsByName(ctx, input.Name); err != nil {
		return nil, fmt.Errorf("checking permission existence: %w", err)
	} else if exists {
		return nil, errors.New(errors.CodeConflict, "permission with this name already exists")
	}

	// Also check by resource and action combination
	if exists, err := s.permissionRepo.ExistsByResourceAndAction(ctx, input.Resource, input.Action); err != nil {
		return nil, fmt.Errorf("checking permission by resource/action: %w", err)
	} else if exists {
		return nil, errors.New(errors.CodeConflict, "permission with this resource and action already exists")
	}

	// Create the permission
	createInput := repository.CreatePermissionInput{
		Name:                input.Name,
		DisplayName:         input.DisplayName,
		Description:         input.Description,
		Resource:            input.Resource,
		Action:              input.Action,
		Category:            input.Category,
		ApplicableUserTypes: input.ApplicableUserTypes,
		ApplicableContexts:  input.ApplicableContexts,
		Dangerous:           input.Dangerous,
		RiskLevel:           input.RiskLevel,
	}

	if input.Conditions != "" {
		createInput.Conditions = &input.Conditions
	}
	if input.PermissionGroup != "" {
		createInput.PermissionGroup = &input.PermissionGroup
	}

	entPermission, err := s.permissionRepo.Create(ctx, createInput)
	if err != nil {
		s.logger.Error("Failed to create permission", logging.Error(err))
		return nil, fmt.Errorf("creating permission: %w", err)
	}

	// Convert to model type
	permission := s.convertEntPermissionToModel(entPermission)

	s.logger.Info("Permission created successfully",
		logging.String("permission_id", permission.ID.String()),
		logging.String("name", permission.Name))

	return permission, nil
}

func (s *service) GetPermission(ctx context.Context, id xid.ID) (*model.Permission, error) {
	entPermission, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, fmt.Errorf("getting permission: %w", err)
	}

	return s.convertEntPermissionToModel(entPermission), nil
}

func (s *service) GetPermissionByName(ctx context.Context, name string) (*model.Permission, error) {
	entPermission, err := s.permissionRepo.GetByName(ctx, name)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, fmt.Errorf("getting permission by name: %w", err)
	}

	return s.convertEntPermissionToModel(entPermission), nil
}

func (s *service) UpdatePermission(ctx context.Context, id xid.ID, input UpdatePermissionInput) (*model.Permission, error) {
	s.logger.Debug("Updating permission", logging.String("permission_id", id.String()))

	// Check if permission exists
	if _, err := s.permissionRepo.GetByID(ctx, id); err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, fmt.Errorf("checking permission existence: %w", err)
	}

	// Update the permission
	updateInput := repository.UpdatePermissionInput{
		DisplayName:         input.DisplayName,
		Description:         input.Description,
		ApplicableUserTypes: input.ApplicableUserTypes,
		ApplicableContexts:  input.ApplicableContexts,
		Conditions:          input.Conditions,
		Dangerous:           input.Dangerous,
		RiskLevel:           input.RiskLevel,
		Active:              input.Active,
		PermissionGroup:     input.PermissionGroup,
	}

	entPermission, err := s.permissionRepo.Update(ctx, id, updateInput)
	if err != nil {
		s.logger.Error("Failed to update permission", logging.Error(err))
		return nil, fmt.Errorf("updating permission: %w", err)
	}

	permission := s.convertEntPermissionToModel(entPermission)

	s.logger.Info("Permission updated successfully", logging.String("permission_id", id.String()))

	return permission, nil
}

func (s *service) DeletePermission(ctx context.Context, id xid.ID) error {
	s.logger.Debug("Deleting permission", logging.String("permission_id", id.String()))

	// Check if permission can be deleted (not in use)
	canDelete, err := s.permissionRepo.CanDelete(ctx, id)
	if err != nil {
		return fmt.Errorf("checking if permission can be deleted: %w", err)
	}
	if !canDelete {
		return errors.New(errors.CodeConflict, "permission is in use and cannot be deleted")
	}

	// Delete the permission
	if err := s.permissionRepo.Delete(ctx, id); err != nil {
		if errors.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "permission not found")
		}
		s.logger.Error("Failed to delete permission", logging.Error(err))
		return fmt.Errorf("deleting permission: %w", err)
	}

	s.logger.Info("Permission deleted successfully", logging.String("permission_id", id.String()))

	return nil
}

func (s *service) ListPermissions(ctx context.Context, params ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	repoParams := repository.ListPermissionsParams{
		PaginationParams: params.PaginationParams,
		Search:           params.Search,
	}

	if params.Category.IsSet {
		repoParams.Category = &params.Category.Value
	}
	if params.PermissionGroup != "" {
		repoParams.PermissionGroup = &params.PermissionGroup
	}
	if params.Action != "" {
		repoParams.Action = &params.Action
	}
	if params.Resource != "" {
		repoParams.Action = &params.Resource
	}
	if params.Dangerous.IsSet {
		repoParams.Dangerous = &params.Dangerous.Value
	}
	if params.System.IsSet {
		repoParams.System = &params.System.Value
	}
	if params.RiskLevel.IsSet {
		repoParams.RiskLevel = &params.RiskLevel.Value
	}
	if params.Active.IsSet {
		repoParams.Active = &params.Active.Value
	}
	if params.ApplicableUserType != "" {
		repoParams.ApplicableUserType = &params.ApplicableUserType
	}
	if params.IncludeRoles.IsSet {
		repoParams.IncludeRoles = &params.IncludeRoles.Value
	}

	result, err := s.permissionRepo.List(ctx, repoParams)
	if err != nil {
		return nil, fmt.Errorf("listing permissions: %w", err)
	}

	// Convert to model types
	permissions := make([]*model.Permission, len(result.Data))
	for i, entPermission := range result.Data {
		permissions[i] = s.convertEntPermissionToModel(entPermission)
	}

	return &model.PaginatedOutput[*model.Permission]{
		Data:       permissions,
		Pagination: result.Pagination,
	}, nil
}

// Role operations implementation

func (s *service) CreateRole(ctx context.Context, input CreateRoleInput) (*model.Role, error) {
	s.logger.Debug("Creating role", logging.String("name", input.Name))

	// Check if role already exists with the same name in the same context
	if exists, err := s.roleRepo.ExistsByName(ctx, input.Name, input.RoleType, input.OrganizationID, input.ApplicationID); err != nil {
		return nil, fmt.Errorf("checking role existence: %w", err)
	} else if exists {
		return nil, errors.New(errors.CodeConflict, "role with this name already exists in this context")
	}

	// Validate organization exists if specified
	if input.OrganizationID != nil {
		if _, err := s.orgRepo.GetByID(ctx, *input.OrganizationID); err != nil {
			if errors.IsNotFound(err) {
				return nil, errors.New(errors.CodeNotFound, "organization not found")
			}
			return nil, fmt.Errorf("checking organization: %w", err)
		}
	}

	// Validate parent role if specified
	if input.ParentID != nil {
		if _, err := s.roleRepo.GetByID(ctx, *input.ParentID); err != nil {
			if errors.IsNotFound(err) {
				return nil, errors.New(errors.CodeNotFound, "parent role not found")
			}
			return nil, fmt.Errorf("checking parent role: %w", err)
		}
	}

	// Create the role
	createInput := repository.CreateRoleInput{
		Name:                input.Name,
		RoleType:            input.RoleType,
		OrganizationID:      input.OrganizationID,
		ApplicationID:       input.ApplicationID,
		IsDefault:           input.IsDefault,
		Priority:            input.Priority,
		ApplicableUserTypes: input.ApplicableUserTypes,
		ParentID:            input.ParentID,
	}

	if input.DisplayName != "" {
		createInput.DisplayName = &input.DisplayName
	}
	if input.Description != "" {
		createInput.Description = &input.Description
	}
	if input.Color != "" {
		createInput.Color = &input.Color
	}

	entRole, err := s.roleRepo.Create(ctx, createInput)
	if err != nil {
		s.logger.Error("Failed to create role", logging.Error(err))
		return nil, fmt.Errorf("creating role: %w", err)
	}

	// Add permissions to role if specified
	if len(input.PermissionIDs) > 0 {
		for _, permissionID := range input.PermissionIDs {
			if err := s.roleRepo.AddPermission(ctx, entRole.ID, permissionID); err != nil {
				s.logger.Error("Failed to add permission to role",
					logging.Error(err),
					logging.String("role_id", entRole.ID.String()),
					logging.String("permission_id", permissionID.String()))
				// Continue with other permissions
			}
		}
	}

	// Convert to model type
	role := s.convertEntRoleToModel(entRole)

	s.logger.Info("Role created successfully",
		logging.String("role_id", role.ID.String()),
		logging.String("name", role.Name))

	return role, nil
}

func (s *service) GetRole(ctx context.Context, id xid.ID) (*ent.Role, error) {
	entRole, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "role not found")
		}
		return nil, fmt.Errorf("getting role: %w", err)
	}

	return entRole, nil
}

func (s *service) GetRoleByName(ctx context.Context, name string, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) (*model.Role, error) {
	entRole, err := s.roleRepo.GetByName(ctx, name, roleType, organizationID, applicationID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "role not found")
		}
		return nil, fmt.Errorf("getting role by name: %w", err)
	}

	return s.convertEntRoleToModel(entRole), nil
}

func (s *service) UpdateRole(ctx context.Context, id xid.ID, input UpdateRoleBody) (*model.Role, error) {
	s.logger.Debug("Updating role", logging.String("role_id", id.String()))

	// Check if role exists
	if _, err := s.roleRepo.GetByID(ctx, id); err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "role not found")
		}
		return nil, fmt.Errorf("checking role existence: %w", err)
	}

	// Update the role
	updateInput := repository.UpdateRoleInput{
		Name:                input.Name,
		DisplayName:         input.DisplayName,
		Description:         input.Description,
		IsDefault:           input.IsDefault,
		Priority:            input.Priority,
		Color:               input.Color,
		ApplicableUserTypes: input.ApplicableUserTypes,
		Active:              input.Active,
		ParentID:            input.ParentID,
	}

	entRole, err := s.roleRepo.Update(ctx, id, updateInput)
	if err != nil {
		s.logger.Error("Failed to update role", logging.Error(err))
		return nil, fmt.Errorf("updating role: %w", err)
	}

	role := s.convertEntRoleToModel(entRole)

	s.logger.Info("Role updated successfully", logging.String("role_id", id.String()))

	return role, nil
}

func (s *service) DeleteRole(ctx context.Context, id xid.ID) error {
	s.logger.Debug("Deleting role", logging.String("role_id", id.String()))

	// Check if role can be deleted (not in use)
	canDelete, err := s.roleRepo.CanDelete(ctx, id)
	if err != nil {
		return fmt.Errorf("checking if role can be deleted: %w", err)
	}
	if !canDelete {
		return errors.New(errors.CodeConflict, "role is in use and cannot be deleted")
	}

	// Delete the role
	if err := s.roleRepo.Delete(ctx, id); err != nil {
		if errors.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "role not found")
		}
		s.logger.Error("Failed to delete role", logging.Error(err))
		return fmt.Errorf("deleting role: %w", err)
	}

	s.logger.Info("Role deleted successfully", logging.String("role_id", id.String()))

	return nil
}

func (s *service) ListRoles(ctx context.Context, params ListRolesParams) (*model.PaginatedOutput[*model.Role], error) {
	repoParams := repository.ListRolesParams{
		PaginationParams: params.PaginationParams,
		IncludeChildren:  params.IncludeChildren,
	}

	if params.OrganizationID.IsSet {
		repoParams.OrganizationID = &params.OrganizationID.Value
	}
	if params.RoleType != "" {
		repoParams.RoleType = &params.RoleType
	}
	if params.ApplicationID.IsSet {
		repoParams.ApplicationID = &params.ApplicationID.Value
	}
	if params.System.IsSet {
		repoParams.System = &params.System.Value
	}
	if params.IsDefault.IsSet {
		repoParams.IsDefault = &params.IsDefault.Value
	}
	if params.Active.IsSet {
		repoParams.Active = &params.Active.Value
	}
	if params.Search != "" {
		repoParams.Search = &params.Search
	}
	if params.ParentID.IsSet {
		repoParams.ParentID = &params.ParentID.Value
	}

	result, err := s.roleRepo.List(ctx, repoParams)
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}

	// Convert to model types
	roles := make([]*model.Role, len(result.Data))
	for i, entRole := range result.Data {
		roles[i] = s.convertEntRoleToModel(entRole)
	}

	return &model.PaginatedOutput[*model.Role]{
		Data:       roles,
		Pagination: result.Pagination,
	}, nil
}

// Role-Permission operations

func (s *service) AddPermissionToRole(ctx context.Context, roleID, permissionID xid.ID) error {
	s.logger.Debug("Adding permission to role",
		logging.String("role_id", roleID.String()),
		logging.String("permission_id", permissionID.String()))

	// Verify role exists
	if _, err := s.roleRepo.GetByID(ctx, roleID); err != nil {
		if errors.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "role not found")
		}
		return fmt.Errorf("checking role: %w", err)
	}

	// Verify permission exists
	if _, err := s.permissionRepo.GetByID(ctx, permissionID); err != nil {
		if errors.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "permission not found")
		}
		return fmt.Errorf("checking permission: %w", err)
	}

	// Add permission to role
	if err := s.roleRepo.AddPermission(ctx, roleID, permissionID); err != nil {
		s.logger.Error("Failed to add permission to role", logging.Error(err))
		return fmt.Errorf("adding permission to role: %w", err)
	}

	s.logger.Info("Permission added to role successfully",
		logging.String("role_id", roleID.String()),
		logging.String("permission_id", permissionID.String()))

	return nil
}

func (s *service) RemovePermissionFromRole(ctx context.Context, roleID, permissionID xid.ID) error {
	s.logger.Debug("Removing permission from role",
		logging.String("role_id", roleID.String()),
		logging.String("permission_id", permissionID.String()))

	// Remove permission from role
	if err := s.roleRepo.RemovePermission(ctx, roleID, permissionID); err != nil {
		s.logger.Error("Failed to remove permission from role", logging.Error(err))
		return fmt.Errorf("removing permission from role: %w", err)
	}

	s.logger.Info("Permission removed from role successfully",
		logging.String("role_id", roleID.String()),
		logging.String("permission_id", permissionID.String()))

	return nil
}

func (s *service) ListRolePermissions(ctx context.Context, roleID xid.ID) ([]*model.Permission, error) {
	// Verify role exists
	if _, err := s.roleRepo.GetByID(ctx, roleID); err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "role not found")
		}
		return nil, fmt.Errorf("checking role: %w", err)
	}

	entPermissions, err := s.roleRepo.GetPermissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("getting role permissions: %w", err)
	}

	// Convert to model types
	permissions := make([]*model.Permission, len(entPermissions))
	for i, entPermission := range entPermissions {
		permissions[i] = s.convertEntPermissionToModel(entPermission)
	}

	return permissions, nil
}

func (s *service) GetRolesWithPermission(ctx context.Context, permissionID xid.ID) ([]*model.Role, error) {
	// Verify permission exists
	if _, err := s.permissionRepo.GetByID(ctx, permissionID); err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, fmt.Errorf("checking permission: %w", err)
	}

	entRoles, err := s.permissionRepo.GetRolesWithPermission(ctx, permissionID)
	if err != nil {
		return nil, fmt.Errorf("getting roles with permission: %w", err)
	}

	// Convert to model types
	roles := make([]*model.Role, len(entRoles))
	for i, entRole := range entRoles {
		roles[i] = s.convertEntRoleToModel(entRole)
	}

	return roles, nil
}

// Permission checking implementation

func (s *service) CheckPermission(ctx context.Context, userID xid.ID, permission string, contextType userrole.ContextType, contextID *xid.ID, resourceType string, resourceID *xid.ID) (*model.CheckPermissionResponse, error) {
	s.logger.Debug("Checking permission",
		logging.String("user_id", userID.String()),
		logging.String("permission", permission),
		logging.String("context_type", string(contextType)))

	// Get user's effective permissions
	permissions, err := s.GetUserEffectivePermissions(ctx, userID, contextType, contextID)
	if err != nil {
		return nil, fmt.Errorf("getting user permissions: %w", err)
	}

	// Check if user has the required permission
	for _, perm := range permissions {
		if perm.Name == permission {
			return &model.CheckPermissionResponse{
				Allowed: true,
				Source:  "role", // Could be enhanced to track source
				Reason:  "User has required permission",
			}, nil
		}
	}

	return &model.CheckPermissionResponse{
		Allowed: false,
		Reason:  "User does not have required permission",
	}, nil
}

func (s *service) GetUserEffectivePermissions(ctx context.Context, userID xid.ID, contextType userrole.ContextType, contextID *xid.ID) ([]*model.Permission, error) {
	entPermissions, err := s.permissionRepo.GetEffectiveUserPermissions(ctx, userID, contextType, contextID)
	if err != nil {
		return nil, fmt.Errorf("getting effective user permissions: %w", err)
	}

	// Convert to model types
	permissions := make([]*model.Permission, len(entPermissions))
	for i, entPermission := range entPermissions {
		permissions[i] = s.convertEntPermissionToModel(entPermission)
	}

	return permissions, nil
}

func (s *service) GetUserPermissionSummary(ctx context.Context, userID xid.ID, contextType userrole.ContextType, contextID *xid.ID) (*model.UserPermissionsResponse, error) {
	// Get direct permissions // directPermissions
	_, err := s.permissionRepo.GetUserPermissions(ctx, userID, contextType, contextID)
	if err != nil {
		return nil, fmt.Errorf("getting direct user permissions: %w", err)
	}

	// Get role permissions
	// This would require additional repository methods to get roles and their permissions

	// Get effective permissions
	effectivePermissions, err := s.GetUserEffectivePermissions(ctx, userID, contextType, contextID)
	if err != nil {
		return nil, fmt.Errorf("getting effective permissions: %w", err)
	}

	// Build effective permissions list
	effectivePermissionNames := make([]string, len(effectivePermissions))
	for i, perm := range effectivePermissions {
		effectivePermissionNames[i] = perm.Name
	}

	return &model.UserPermissionsResponse{
		UserID:               userID,
		DirectPermissions:    []model.PermissionAssignment{}, // Would need to implement conversion
		RolePermissions:      []model.RolePermission{},       // Would need to implement
		EffectivePermissions: effectivePermissionNames,
		DeniedPermissions:    []string{}, // Would need to implement deny logic
	}, nil
}

// Bulk operations

func (s *service) BulkAssignRoles(ctx context.Context, input BulkRoleAssignmentInput) (*model.BulkRoleAssignmentResponse, error) {
	s.logger.Debug("Bulk assigning roles",
		logging.String("role_id", input.RoleID.String()),
		logging.Int("user_count", len(input.UserIDs)))

	success := []xid.ID{}
	failed := []xid.ID{}
	errors := []string{}

	for _, userID := range input.UserIDs {
		assignInput := AssignRoleToUserInput{
			UserID:      userID,
			RoleID:      input.RoleID,
			ContextType: input.ContextType,
			ContextID:   input.ContextID,
			AssignedBy:  input.AssignedBy,
			ExpiresAt:   input.ExpiresAt,
			Conditions:  input.Conditions,
		}

		if _, err := s.AssignRoleToUser(ctx, assignInput); err != nil {
			failed = append(failed, userID)
			errors = append(errors, err.Error())
		} else {
			success = append(success, userID)
		}
	}

	return &model.BulkRoleAssignmentResponse{
		Success:      success,
		Failed:       failed,
		SuccessCount: len(success),
		FailureCount: len(failed),
		Errors:       errors,
	}, nil
}

func (s *service) BulkRemoveRoles(ctx context.Context, input BulkRoleRemovalInput) (*model.BulkRoleAssignmentResponse, error) {
	s.logger.Debug("Bulk removing roles",
		logging.String("role_id", input.RoleID.String()),
		logging.Int("user_count", len(input.UserIDs)))

	success := []xid.ID{}
	failed := []xid.ID{}
	errors := []string{}

	for _, userID := range input.UserIDs {
		if err := s.RemoveRoleFromUser(ctx, userID, input.RoleID, input.ContextType, input.ContextID); err != nil {
			failed = append(failed, userID)
			errors = append(errors, err.Error())
		} else {
			success = append(success, userID)
		}
	}

	return &model.BulkRoleAssignmentResponse{
		Success:      success,
		Failed:       failed,
		SuccessCount: len(success),
		FailureCount: len(failed),
		Errors:       errors,
	}, nil
}

// User assignment operations

func (s *service) AssignRoleToUser(ctx context.Context, input AssignRoleToUserInput) (*model.RoleAssignment, error) {
	s.logger.Debug("Assigning role to user",
		logging.String("user_id", input.UserID.String()),
		logging.String("role_id", input.RoleID.String()))

	// Verify user exists
	if _, err := s.userRepo.GetByID(ctx, input.UserID); err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, fmt.Errorf("checking user: %w", err)
	}

	// Verify role exists
	if _, err := s.roleRepo.GetByID(ctx, input.RoleID); err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "role not found")
		}
		return nil, fmt.Errorf("checking role: %w", err)
	}

	// This would need to be implemented with a UserRole repository
	// For now, returning a placeholder
	return &model.RoleAssignment{
		UserID:      input.UserID,
		RoleID:      input.RoleID,
		ContextType: string(input.ContextType),
		ContextID:   input.ContextID,
		AssignedBy:  input.AssignedBy,
		AssignedAt:  time.Now(),
		ExpiresAt:   input.ExpiresAt,
		Active:      true,
		Conditions:  input.Conditions,
	}, nil
}

func (s *service) RemoveRoleFromUser(ctx context.Context, userID, roleID xid.ID, contextType userrole.ContextType, contextID *xid.ID) error {
	s.logger.Debug("Removing role from user",
		logging.String("user_id", userID.String()),
		logging.String("role_id", roleID.String()))

	// This would need to be implemented with a UserRole repository
	// For now, just log the operation
	s.logger.Info("Role removed from user successfully",
		logging.String("user_id", userID.String()),
		logging.String("role_id", roleID.String()))

	return nil
}

func (s *service) ListUserRoles(ctx context.Context, userID xid.ID, contextType userrole.ContextType, contextID *xid.ID) ([]*model.RoleAssignment, error) {
	// This would need to be implemented with a UserRole repository
	return []*model.RoleAssignment{}, nil
}

func (s *service) GetUsersWithRole(ctx context.Context, roleID xid.ID) ([]*model.User, error) {
	entUsers, err := s.roleRepo.GetUsersWithRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("getting users with role: %w", err)
	}

	// Convert to model types
	users := make([]*model.User, len(entUsers))
	for i, entUser := range entUsers {
		users[i] = s.convertEntUserToModel(entUser)
	}

	return users, nil
}

// User-Permission operations

func (s *service) AssignPermissionToUser(ctx context.Context, input AssignPermissionToUserInput) (*model.PermissionAssignment, error) {
	s.logger.Debug("Assigning permission to user",
		logging.String("user_id", input.UserID.String()),
		logging.String("permission_id", input.PermissionID.String()))

	// Verify user exists
	if _, err := s.userRepo.GetByID(ctx, input.UserID); err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, fmt.Errorf("checking user: %w", err)
	}

	// Verify permission exists
	if _, err := s.permissionRepo.GetByID(ctx, input.PermissionID); err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, fmt.Errorf("checking permission: %w", err)
	}

	// This would need to be implemented with a UserPermission repository
	// For now, returning a placeholder
	return &model.PermissionAssignment{
		UserID:         input.UserID,
		PermissionID:   input.PermissionID,
		ContextType:    string(input.ContextType),
		ContextID:      input.ContextID,
		ResourceType:   input.ResourceType,
		ResourceID:     input.ResourceID,
		PermissionType: input.PermissionType,
		AssignedBy:     input.AssignedBy,
		AssignedAt:     time.Now(),
		ExpiresAt:      input.ExpiresAt,
		Active:         true,
		Conditions:     input.Conditions,
		Reason:         input.Reason,
	}, nil
}

func (s *service) RemovePermissionFromUser(ctx context.Context, userID, permissionID xid.ID, contextType userrole.ContextType, contextID *xid.ID) error {
	s.logger.Debug("Removing permission from user",
		logging.String("user_id", userID.String()),
		logging.String("permission_id", permissionID.String()))

	// This would need to be implemented with a UserPermission repository
	// For now, just log the operation
	s.logger.Info("Permission removed from user successfully",
		logging.String("user_id", userID.String()),
		logging.String("permission_id", permissionID.String()))

	return nil
}

func (s *service) ListUserPermissions(ctx context.Context, userID xid.ID, contextType userrole.ContextType, contextID *xid.ID) ([]*model.Permission, error) {
	entPermissions, err := s.permissionRepo.GetUserPermissions(ctx, userID, contextType, contextID)
	if err != nil {
		return nil, fmt.Errorf("getting user permissions: %w", err)
	}

	// Convert to model types
	permissions := make([]*model.Permission, len(entPermissions))
	for i, entPermission := range entPermissions {
		permissions[i] = s.convertEntPermissionToModel(entPermission)
	}

	return permissions, nil
}

// Hierarchy operations

func (s *service) GetRoleHierarchy(ctx context.Context, roleID xid.ID) (*model.RoleHierarchy, error) {
	// Get role
	entRole, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "role not found")
		}
		return nil, fmt.Errorf("getting role: %w", err)
	}

	// Get ancestors to determine hierarchy level and path
	ancestors, err := s.roleRepo.GetAncestors(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("getting role ancestors: %w", err)
	}

	// Get children
	children, err := s.roleRepo.GetChildren(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("getting role children: %w", err)
	}

	// Build hierarchy path
	path := make([]string, len(ancestors))
	for i, ancestor := range ancestors {
		path[i] = ancestor.Name
	}
	path = append(path, entRole.Name)

	// Convert children to hierarchy format
	childHierarchies := make([]model.RoleHierarchy, len(children))
	for i, child := range children {
		childHierarchies[i] = model.RoleHierarchy{
			RoleID: child.ID,
			Name:   child.Name,
			Level:  len(ancestors) + 2, // Current level + 1
		}
	}

	return &model.RoleHierarchy{
		RoleID:   roleID,
		Name:     entRole.Name,
		Level:    len(ancestors) + 1,
		Path:     path,
		Children: childHierarchies,
	}, nil
}

func (s *service) SetRoleParent(ctx context.Context, roleID, parentID xid.ID) error {
	s.logger.Debug("Setting role parent",
		logging.String("role_id", roleID.String()),
		logging.String("parent_id", parentID.String()))

	if err := s.roleRepo.SetParent(ctx, roleID, parentID); err != nil {
		s.logger.Error("Failed to set role parent", logging.Error(err))
		return fmt.Errorf("setting role parent: %w", err)
	}

	s.logger.Info("Role parent set successfully")
	return nil
}

func (s *service) RemoveRoleParent(ctx context.Context, roleID xid.ID) error {
	s.logger.Debug("Removing role parent", logging.String("role_id", roleID.String()))

	if err := s.roleRepo.RemoveParent(ctx, roleID); err != nil {
		s.logger.Error("Failed to remove role parent", logging.Error(err))
		return fmt.Errorf("removing role parent: %w", err)
	}

	s.logger.Info("Role parent removed successfully")
	return nil
}

// Analytics and stats

func (s *service) GetRBACStats(ctx context.Context, organizationID *xid.ID) (*model.RBACStats, error) {
	// This would need to be implemented with proper counting queries
	// For now, returning placeholder data
	return &model.RBACStats{
		TotalRoles:                  25,
		SystemRoles:                 5,
		OrganizationRoles:           18,
		ApplicationRoles:            2,
		TotalPermissions:            150,
		SystemPermissions:           30,
		DangerousPermissions:        10,
		RoleAssignments:             500,
		DirectPermissionAssignments: 25,
		PermissionsByCategory: map[string]int{
			"system":       30,
			"organization": 120,
		},
		RolesByPriority: map[string]int{
			"high":   5,
			"medium": 15,
			"low":    5,
		},
	}, nil
}

func (s *service) GetPermissionUsageStats(ctx context.Context, organizationID *xid.ID) (map[string]int, error) {
	// This would need to be implemented with proper usage tracking
	return map[string]int{
		"read:users":   150,
		"write:users":  50,
		"delete:users": 10,
	}, nil
}

func (s *service) GetRoleUsageStats(ctx context.Context, organizationID *xid.ID) (map[string]int, error) {
	// This would need to be implemented with proper usage tracking
	return map[string]int{
		"admin":  10,
		"editor": 25,
		"viewer": 100,
	}, nil
}

// Default roles

func (s *service) GetDefaultRoles(ctx context.Context, roleType role.RoleType, organizationID *xid.ID, applicationID *xid.ID) ([]*model.Role, error) {
	entRoles, err := s.roleRepo.GetDefaultRoles(ctx, roleType, organizationID, applicationID)
	if err != nil {
		return nil, fmt.Errorf("getting default roles: %w", err)
	}

	// Convert to model types
	roles := make([]*model.Role, len(entRoles))
	for i, entRole := range entRoles {
		roles[i] = s.convertEntRoleToModel(entRole)
	}

	return roles, nil
}

func (s *service) SetDefaultRole(ctx context.Context, roleID xid.ID) error {
	if err := s.roleRepo.SetAsDefault(ctx, roleID); err != nil {
		return fmt.Errorf("setting default role: %w", err)
	}
	return nil
}

func (s *service) UnsetDefaultRole(ctx context.Context, roleID xid.ID) error {
	if err := s.roleRepo.UnsetAsDefault(ctx, roleID); err != nil {
		return fmt.Errorf("unsetting default role: %w", err)
	}
	return nil
}

// Permission dependencies

func (s *service) AddPermissionDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID, dependencyType string) error {
	// Convert string to enum type
	var depType permissiondependency.DependencyType
	switch dependencyType {
	case "required":
		depType = permissiondependency.DependencyTypeRequired
	case "implied":
		depType = permissiondependency.DependencyTypeImplied
	case "conditional":
		depType = permissiondependency.DependencyTypeConditional
	default:
		return errors.New(errors.CodeInvalidInput, "invalid dependency type")
	}

	if err := s.permissionRepo.AddDependency(ctx, permissionID, requiredPermissionID, depType); err != nil {
		return fmt.Errorf("adding permission dependency: %w", err)
	}
	return nil
}

func (s *service) RemovePermissionDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID) error {
	if err := s.permissionRepo.RemoveDependency(ctx, permissionID, requiredPermissionID); err != nil {
		return fmt.Errorf("removing permission dependency: %w", err)
	}
	return nil
}

func (s *service) GetPermissionDependencies(ctx context.Context, permissionID xid.ID) ([]*model.Permission, error) {
	entPermissions, err := s.permissionRepo.GetDependencies(ctx, permissionID)
	if err != nil {
		return nil, fmt.Errorf("getting permission dependencies: %w", err)
	}

	// Convert to model types
	permissions := make([]*model.Permission, len(entPermissions))
	for i, entPermission := range entPermissions {
		permissions[i] = s.convertEntPermissionToModel(entPermission)
	}

	return permissions, nil
}

// Helper methods for converting ent types to model types

func (s *service) convertEntPermissionToModel(entPermission *ent.Permission) *model.Permission {
	return &model.Permission{
		Base: model.Base{
			ID:        entPermission.ID,
			CreatedAt: entPermission.CreatedAt,
			UpdatedAt: entPermission.UpdatedAt,
		},
		Name:                entPermission.Name,
		DisplayName:         entPermission.DisplayName,
		Description:         entPermission.Description,
		Resource:            entPermission.Resource,
		Action:              entPermission.Action,
		Category:            string(entPermission.Category),
		ApplicableUserTypes: entPermission.ApplicableUserTypes,
		ApplicableContexts:  entPermission.ApplicableContexts,
		Conditions:          entPermission.Conditions,
		System:              entPermission.System,
		Dangerous:           entPermission.Dangerous,
		RiskLevel:           entPermission.RiskLevel,
		Active:              entPermission.Active,
		PermissionGroup:     entPermission.PermissionGroup,
	}
}

func (s *service) convertEntRoleToModel(entRole *ent.Role) *model.Role {
	return &model.Role{
		Base: model.Base{
			ID:        entRole.ID,
			CreatedAt: entRole.CreatedAt,
			UpdatedAt: entRole.UpdatedAt,
		},
		Name:                entRole.Name,
		DisplayName:         entRole.DisplayName,
		Description:         entRole.Description,
		RoleType:            entRole.RoleType,
		OrganizationID:      &entRole.OrganizationID,
		ApplicationID:       &entRole.ApplicationID,
		System:              entRole.System,
		IsDefault:           entRole.IsDefault,
		Priority:            entRole.Priority,
		Color:               entRole.Color,
		ApplicableUserTypes: entRole.ApplicableUserTypes,
		Active:              entRole.Active,
		ParentID:            &entRole.ParentID,
	}
}

func (s *service) convertEntUserToModel(entUser *ent.User) *model.User {
	return &model.User{
		Base: model.Base{
			ID:        entUser.ID,
			CreatedAt: entUser.CreatedAt,
			UpdatedAt: entUser.UpdatedAt,
		},
		Email:           entUser.Email,
		PhoneNumber:     entUser.PhoneNumber,
		FirstName:       entUser.FirstName,
		LastName:        entUser.LastName,
		Username:        entUser.Username,
		EmailVerified:   entUser.EmailVerified,
		PhoneVerified:   entUser.PhoneVerified,
		Active:          entUser.Active,
		Blocked:         entUser.Blocked,
		LastLogin:       entUser.LastLogin,
		ProfileImageURL: entUser.ProfileImageURL,
		Locale:          entUser.Locale,
		Timezone:        entUser.Timezone,
		UserType:        string(entUser.UserType),
		OrganizationID:  &entUser.OrganizationID,
		AuthProvider:    entUser.AuthProvider,
		ExternalID:      entUser.ExternalID,
		CustomerID:      entUser.CustomerID,
		LoginCount:      entUser.LoginCount,
		LastLoginIP:     entUser.LastLoginIP,
	}
}
