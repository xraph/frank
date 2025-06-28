package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// RoleService handles role assignments and management across all user types
type RoleService interface {
	// Core role operations
	CreateRole(ctx context.Context, input model.CreateRoleRequest) (*model.Role, error)
	UpdateRole(ctx context.Context, id xid.ID, input model.UpdateRoleRequest) (*model.Role, error)
	DeleteRole(ctx context.Context, id xid.ID) error
	GetRole(ctx context.Context, id xid.ID) (*model.Role, error)
	GetRoleByName(ctx context.Context, name string, roleType model.RoleType, organizationID *xid.ID, applicationID *xid.ID) (*model.Role, error)
	ListRoles(ctx context.Context, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error)
	SearchRoles(ctx context.Context, query string, params SearchRolesParams) (*model.PaginatedOutput[*model.Role], error)

	// Role type specific operations
	GetSystemRoles(ctx context.Context, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error)
	GetOrganizationRoles(ctx context.Context, organizationID xid.ID, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error)
	GetApplicationRoles(ctx context.Context, applicationID xid.ID, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error)

	// Default role operations
	GetDefaultRoles(ctx context.Context, roleType model.RoleType, organizationID *xid.ID, applicationID *xid.ID) ([]*model.Role, error)
	SetAsDefault(ctx context.Context, id xid.ID) error
	UnsetAsDefault(ctx context.Context, id xid.ID) error
	GetDefaultRoleForUserType(ctx context.Context, userType model.UserType, roleType model.RoleType, organizationID *xid.ID) (*model.Role, error)

	// Role hierarchy operations
	GetRoleHierarchy(ctx context.Context, roleID xid.ID) (*model.RoleHierarchy, error)
	GetRoleAncestors(ctx context.Context, roleID xid.ID) ([]*model.Role, error)
	GetRoleDescendants(ctx context.Context, roleID xid.ID) ([]*model.Role, error)
	GetRoleChildren(ctx context.Context, roleID xid.ID) ([]*model.Role, error)
	GetRoleParent(ctx context.Context, roleID xid.ID) (*model.Role, error)
	SetRoleParent(ctx context.Context, roleID, parentID xid.ID) error
	RemoveRoleParent(ctx context.Context, roleID xid.ID) error
	ValidateHierarchy(ctx context.Context, roleID, parentID xid.ID) error
	GetHierarchyDepth(ctx context.Context, roleID xid.ID) (int, error)

	// Role-Permission operations
	AddPermissionToRole(ctx context.Context, roleID, permissionID xid.ID) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID xid.ID) error
	GetRolePermissions(ctx context.Context, roleID xid.ID) ([]*model.Permission, error)
	GetRoleEffectivePermissions(ctx context.Context, roleID xid.ID) ([]*model.Permission, error)
	HasPermission(ctx context.Context, roleID, permissionID xid.ID) (bool, error)
	BulkAddPermissionsToRole(ctx context.Context, roleID xid.ID, permissionIDs []xid.ID) error
	BulkRemovePermissionsFromRole(ctx context.Context, roleID xid.ID, permissionIDs []xid.ID) error
	SyncRolePermissions(ctx context.Context, roleID xid.ID, permissionIDs []xid.ID) error

	// Role assignment operations
	GetUsersWithRole(ctx context.Context, roleID xid.ID) ([]*model.User, error)
	GetUserRoleAssignments(ctx context.Context, roleID xid.ID) ([]*model.RoleAssignment, error)
	GetRoleAssignmentCount(ctx context.Context, roleID xid.ID) (int, error)
	GetActiveRoleAssignments(ctx context.Context, roleID xid.ID) ([]*model.RoleAssignment, error)
	GetExpiredRoleAssignments(ctx context.Context, roleID xid.ID) ([]*model.RoleAssignment, error)

	// Role validation
	ValidateRoleName(ctx context.Context, name string, roleType model.RoleType, organizationID *xid.ID) error
	CanDeleteRole(ctx context.Context, roleID xid.ID) (bool, string, error)
	IsRoleInUse(ctx context.Context, roleID xid.ID) (bool, error)
	ValidateRolePermissions(ctx context.Context, roleID xid.ID, permissionIDs []xid.ID) error
	ValidateUserTypeCompatibility(ctx context.Context, roleID xid.ID, userType model.UserType) error

	// Role templates and cloning
	CreateRoleFromTemplate(ctx context.Context, templateName string, input CreateRoleFromTemplateInput) (*model.Role, error)
	CloneRole(ctx context.Context, sourceID xid.ID, input CloneRoleInput) (*model.Role, error)
	GetRoleTemplates(ctx context.Context, roleType model.RoleType) ([]RoleTemplate, error)

	// Role analysis and reporting
	GetRoleStats(ctx context.Context, organizationID *xid.ID) (*RoleStats, error)
	GetRoleUsageStats(ctx context.Context, roleID xid.ID) (*RoleUsageStats, error)
	GetMostUsedRoles(ctx context.Context, limit int, organizationID *xid.ID) ([]*RoleUsage, error)
	GetUnusedRoles(ctx context.Context, organizationID *xid.ID) ([]*model.Role, error)
	GetOverprivilegedRoles(ctx context.Context, organizationID *xid.ID) ([]*model.Role, error)
	GetUnderprivilegedRoles(ctx context.Context, organizationID *xid.ID) ([]*model.Role, error)
	GetRolePermissionMatrix(ctx context.Context, roleIDs []xid.ID) (*RolePermissionMatrix, error)

	// Bulk operations
	BulkCreateRoles(ctx context.Context, inputs []model.CreateRoleRequest) ([]*model.Role, []error)
	BulkUpdateRoles(ctx context.Context, updates []BulkRoleUpdate) ([]*model.Role, []error)
	BulkDeleteRoles(ctx context.Context, roleIDs []xid.ID) ([]xid.ID, []error)
	BulkActivateRoles(ctx context.Context, roleIDs []xid.ID) error
	BulkDeactivateRoles(ctx context.Context, roleIDs []xid.ID) error

	// Role comparison
	CompareRoles(ctx context.Context, role1ID, role2ID xid.ID) (*RoleComparison, error)
	FindSimilarRoles(ctx context.Context, roleID xid.ID, threshold float64) ([]*model.Role, error)
	MergeRoles(ctx context.Context, sourceRoleIDs []xid.ID, targetRoleID xid.ID) error

	// Role export/import
	ExportRoles(ctx context.Context, filter RoleExportFilter) (*RoleExport, error)
	ImportRoles(ctx context.Context, data *RoleImport) (*RoleImportResult, error)
	ValidateRoleImport(ctx context.Context, data *RoleImport) (*RoleImportValidation, error)

	AssignSystemRole(ctx context.Context, userID xid.ID, roleName string) error
	AssignOrganizationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error
	AssignApplicationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error
	RemoveUserRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType model.ContextType, contextID *xid.ID) error
	GetUserSystemRoles(ctx context.Context, userID xid.ID) ([]*ent.Role, error)
	GetUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error)
	GetUserApplicationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error)
	GetAllUserRoles(ctx context.Context, userID xid.ID) ([]*ent.UserRole, error)
	GetRolesByType(ctx context.Context, roleType model.RoleType, orgID *xid.ID) ([]*ent.Role, error)
	HasRole(ctx context.Context, userID xid.ID, roleName string, contextType model.ContextType, contextID *xid.ID) (bool, error)
	HasAnyRole(ctx context.Context, userID xid.ID, roleNames []string, contextType model.ContextType, contextID *xid.ID) (bool, error)
}

// roleService implements the RoleService interface
type roleService struct {
	roleRepo       repository.RoleRepository
	permissionRepo repository.PermissionRepository
	userRepo       repository.UserRepository
	orgRepo        repository.OrganizationRepository
	logger         logging.Logger
}

// NewRoleService creates a new role service
func NewRoleService(
	repo repository.Repository,
	logger logging.Logger,
) RoleService {
	return &roleService{
		roleRepo:       repo.Role(),
		permissionRepo: repo.Permission(),
		userRepo:       repo.User(),
		orgRepo:        repo.Organization(),
		logger:         logger.Named("role"),
	}
}

// ================================
// ROLE ASSIGNMENT METHODS
// ================================

// Core role operations

func (s *roleService) CreateRole(ctx context.Context, input model.CreateRoleRequest) (*model.Role, error) {
	s.logger.Debug("Creating role", logging.String("name", input.Name))

	// Validate role name
	if err := s.ValidateRoleName(ctx, input.Name, input.RoleType, input.OrganizationID); err != nil {
		return nil, fmt.Errorf("invalid role name: %w", err)
	}

	// Check if role already exists
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
		if err := s.ValidateHierarchy(ctx, xid.NilID(), *input.ParentID); err != nil {
			return nil, fmt.Errorf("invalid parent role: %w", err)
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
		if err := s.BulkAddPermissionsToRole(ctx, entRole.ID, input.PermissionIDs); err != nil {
			s.logger.Error("Failed to add permissions to role", logging.Error(err))
			// Don't fail the role creation, just log the error
		}
	}

	role := s.convertEntRoleToModel(entRole)

	s.logger.Info("Role created successfully",
		logging.String("role_id", role.ID.String()),
		logging.String("name", role.Name))

	return role, nil
}

func (s *roleService) UpdateRole(ctx context.Context, id xid.ID, input model.UpdateRoleRequest) (*model.Role, error) {
	s.logger.Debug("Updating role", logging.String("role_id", id.String()))

	// Check if role exists
	existing, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "role not found")
		}
		return nil, fmt.Errorf("checking role existence: %w", err)
	}

	// Check if role is system-managed
	if existing.System {
		return nil, errors.New(errors.CodeForbidden, "cannot modify system-managed role")
	}

	// Validate parent role if being updated
	if input.ParentID != nil {
		if err := s.ValidateHierarchy(ctx, id, *input.ParentID); err != nil {
			return nil, fmt.Errorf("invalid parent role: %w", err)
		}
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

func (s *roleService) DeleteRole(ctx context.Context, id xid.ID) error {
	s.logger.Debug("Deleting role", logging.String("role_id", id.String()))

	// Check if role can be deleted
	canDelete, reason, err := s.CanDeleteRole(ctx, id)
	if err != nil {
		return fmt.Errorf("checking if role can be deleted: %w", err)
	}
	if !canDelete {
		return errors.New(errors.CodeConflict, reason)
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

func (s *roleService) GetRole(ctx context.Context, id xid.ID) (*model.Role, error) {
	entRole, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "role not found")
		}
		return nil, fmt.Errorf("getting role: %w", err)
	}

	return s.convertEntRoleToModel(entRole), nil
}

func (s *roleService) GetRoleByName(ctx context.Context, name string, roleType model.RoleType, organizationID *xid.ID, applicationID *xid.ID) (*model.Role, error) {
	entRole, err := s.roleRepo.GetByName(ctx, name, roleType, organizationID, applicationID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "role not found")
		}
		return nil, fmt.Errorf("getting role by name: %w", err)
	}

	return s.convertEntRoleToModel(entRole), nil
}

func (s *roleService) ListRoles(ctx context.Context, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error) {
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
		repoParams.Search = params.Search
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

func (s *roleService) SearchRoles(ctx context.Context, query string, params SearchRolesParams) (*model.PaginatedOutput[*model.Role], error) {
	searchParams := repository.SearchRolesParams{
		PaginationParams: params.PaginationParams,
		RoleTypes:        params.RoleTypes,
		OrganizationIDs:  params.OrganizationIDs,
		ApplicationIDs:   params.ApplicationIDs,
		UserTypes:        params.UserTypes,
		// IncludeSystem:    params.IncludeSystem,
		// IncludeDefault:   params.IncludeDefault,
		// ExcludeInactive:  params.ExcludeInactive,
		// HasPermissions:   params.HasPermissions,
		// HasUsers:         params.HasUsers,
	}

	result, err := s.roleRepo.Search(ctx, query, searchParams)
	if err != nil {
		return nil, fmt.Errorf("searching roles: %w", err)
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

// Role type specific operations

func (s *roleService) GetSystemRoles(ctx context.Context, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error) {
	result, err := s.roleRepo.GetSystemRoles(ctx, repository.ListRolesParams{
		PaginationParams: params.PaginationParams,
		IncludeChildren:  params.IncludeChildren,
	})
	if err != nil {
		return nil, fmt.Errorf("getting system roles: %w", err)
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

func (s *roleService) GetOrganizationRoles(ctx context.Context, organizationID xid.ID, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error) {
	result, err := s.roleRepo.GetOrganizationRoles(ctx, organizationID, repository.ListRolesParams{
		PaginationParams: params.PaginationParams,
		IncludeChildren:  params.IncludeChildren,
	})
	if err != nil {
		return nil, fmt.Errorf("getting organization roles: %w", err)
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

func (s *roleService) GetApplicationRoles(ctx context.Context, applicationID xid.ID, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error) {
	result, err := s.roleRepo.GetApplicationRoles(ctx, applicationID, repository.ListRolesParams{
		PaginationParams: params.PaginationParams,
		IncludeChildren:  params.IncludeChildren,
	})
	if err != nil {
		return nil, fmt.Errorf("getting application roles: %w", err)
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

// Default role operations

func (s *roleService) GetDefaultRoles(ctx context.Context, roleType model.RoleType, organizationID *xid.ID, applicationID *xid.ID) ([]*model.Role, error) {
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

func (s *roleService) SetAsDefault(ctx context.Context, id xid.ID) error {
	s.logger.Debug("Setting role as default", logging.String("role_id", id.String()))

	if err := s.roleRepo.SetAsDefault(ctx, id); err != nil {
		s.logger.Error("Failed to set role as default", logging.Error(err))
		return fmt.Errorf("setting role as default: %w", err)
	}

	s.logger.Info("Role set as default successfully", logging.String("role_id", id.String()))
	return nil
}

func (s *roleService) UnsetAsDefault(ctx context.Context, id xid.ID) error {
	s.logger.Debug("Unsetting role as default", logging.String("role_id", id.String()))

	if err := s.roleRepo.UnsetAsDefault(ctx, id); err != nil {
		s.logger.Error("Failed to unset role as default", logging.Error(err))
		return fmt.Errorf("unsetting role as default: %w", err)
	}

	s.logger.Info("Role unset as default successfully", logging.String("role_id", id.String()))
	return nil
}

func (s *roleService) GetDefaultRoleForUserType(ctx context.Context, userType model.UserType, roleType model.RoleType, organizationID *xid.ID) (*model.Role, error) {
	defaultRoles, err := s.GetDefaultRoles(ctx, roleType, organizationID, nil)
	if err != nil {
		return nil, fmt.Errorf("getting default roles: %w", err)
	}

	// Find role applicable to the user type
	for _, role := range defaultRoles {
		for _, applicableType := range role.ApplicableUserTypes {
			if applicableType == userType {
				return role, nil
			}
		}
	}

	return nil, errors.New(errors.CodeNotFound, "no default role found for user type")
}

// Role hierarchy operations

func (s *roleService) GetRoleHierarchy(ctx context.Context, roleID xid.ID) (*model.RoleHierarchy, error) {
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
			Level:  len(ancestors) + 2,
		}
	}

	// Get parent summary if exists
	var parentSummary *model.RoleSummary
	if !entRole.ParentID.IsNil() {
		parent, err := s.roleRepo.GetByID(ctx, entRole.ParentID)
		if err == nil {
			parentSummary = &model.RoleSummary{
				ID:          parent.ID,
				Name:        parent.Name,
				DisplayName: parent.DisplayName,
				RoleType:    parent.RoleType,
				Active:      parent.Active,
			}
		}
	}

	return &model.RoleHierarchy{
		RoleID:   roleID,
		Name:     entRole.Name,
		Level:    len(ancestors) + 1,
		Path:     path,
		Children: childHierarchies,
		Parent:   parentSummary,
	}, nil
}

func (s *roleService) GetRoleAncestors(ctx context.Context, roleID xid.ID) ([]*model.Role, error) {
	entRoles, err := s.roleRepo.GetAncestors(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("getting role ancestors: %w", err)
	}

	// Convert to model types
	roles := make([]*model.Role, len(entRoles))
	for i, entRole := range entRoles {
		roles[i] = s.convertEntRoleToModel(entRole)
	}

	return roles, nil
}

func (s *roleService) GetRoleDescendants(ctx context.Context, roleID xid.ID) ([]*model.Role, error) {
	entRoles, err := s.roleRepo.GetDescendants(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("getting role descendants: %w", err)
	}

	// Convert to model types
	roles := make([]*model.Role, len(entRoles))
	for i, entRole := range entRoles {
		roles[i] = s.convertEntRoleToModel(entRole)
	}

	return roles, nil
}

func (s *roleService) GetRoleChildren(ctx context.Context, roleID xid.ID) ([]*model.Role, error) {
	entRoles, err := s.roleRepo.GetChildren(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("getting role children: %w", err)
	}

	// Convert to model types
	roles := make([]*model.Role, len(entRoles))
	for i, entRole := range entRoles {
		roles[i] = s.convertEntRoleToModel(entRole)
	}

	return roles, nil
}

func (s *roleService) GetRoleParent(ctx context.Context, roleID xid.ID) (*model.Role, error) {
	entRole, err := s.roleRepo.GetParent(ctx, roleID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "parent role not found")
		}
		return nil, fmt.Errorf("getting role parent: %w", err)
	}

	return s.convertEntRoleToModel(entRole), nil
}

func (s *roleService) SetRoleParent(ctx context.Context, roleID, parentID xid.ID) error {
	s.logger.Debug("Setting role parent",
		logging.String("role_id", roleID.String()),
		logging.String("parent_id", parentID.String()))

	// Validate hierarchy
	if err := s.ValidateHierarchy(ctx, roleID, parentID); err != nil {
		return fmt.Errorf("invalid hierarchy: %w", err)
	}

	if err := s.roleRepo.SetParent(ctx, roleID, parentID); err != nil {
		s.logger.Error("Failed to set role parent", logging.Error(err))
		return fmt.Errorf("setting role parent: %w", err)
	}

	s.logger.Info("Role parent set successfully")
	return nil
}

func (s *roleService) RemoveRoleParent(ctx context.Context, roleID xid.ID) error {
	s.logger.Debug("Removing role parent", logging.String("role_id", roleID.String()))

	if err := s.roleRepo.RemoveParent(ctx, roleID); err != nil {
		s.logger.Error("Failed to remove role parent", logging.Error(err))
		return fmt.Errorf("removing role parent: %w", err)
	}

	s.logger.Info("Role parent removed successfully")
	return nil
}

func (s *roleService) ValidateHierarchy(ctx context.Context, roleID, parentID xid.ID) error {
	// Prevent self-parenting
	if roleID == parentID {
		return errors.New(errors.CodeInvalidInput, "role cannot be its own parent")
	}

	// Check if parent exists
	if _, err := s.roleRepo.GetByID(ctx, parentID); err != nil {
		if errors.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "parent role not found")
		}
		return fmt.Errorf("checking parent role: %w", err)
	}

	// Prevent circular references
	if roleID != xid.NilID() {
		ancestors, err := s.roleRepo.GetAncestors(ctx, parentID)
		if err != nil {
			return fmt.Errorf("getting parent ancestors: %w", err)
		}

		for _, ancestor := range ancestors {
			if ancestor.ID == roleID {
				return errors.New(errors.CodeConflict, "circular reference detected in role hierarchy")
			}
		}
	}

	return nil
}

func (s *roleService) GetHierarchyDepth(ctx context.Context, roleID xid.ID) (int, error) {
	ancestors, err := s.roleRepo.GetAncestors(ctx, roleID)
	if err != nil {
		return 0, fmt.Errorf("getting role ancestors: %w", err)
	}

	return len(ancestors), nil
}

// Role-Permission operations

func (s *roleService) AddPermissionToRole(ctx context.Context, roleID, permissionID xid.ID) error {
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

	s.logger.Info("Permission added to role successfully")
	return nil
}

func (s *roleService) RemovePermissionFromRole(ctx context.Context, roleID, permissionID xid.ID) error {
	s.logger.Debug("Removing permission from role",
		logging.String("role_id", roleID.String()),
		logging.String("permission_id", permissionID.String()))

	if err := s.roleRepo.RemovePermission(ctx, roleID, permissionID); err != nil {
		s.logger.Error("Failed to remove permission from role", logging.Error(err))
		return fmt.Errorf("removing permission from role: %w", err)
	}

	s.logger.Info("Permission removed from role successfully")
	return nil
}

func (s *roleService) GetRolePermissions(ctx context.Context, roleID xid.ID) ([]*model.Permission, error) {
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

func (s *roleService) GetRoleEffectivePermissions(ctx context.Context, roleID xid.ID) ([]*model.Permission, error) {
	// Get direct permissions
	directPermissions, err := s.GetRolePermissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("getting direct permissions: %w", err)
	}

	// Get inherited permissions from ancestors
	ancestors, err := s.GetRoleAncestors(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("getting ancestors: %w", err)
	}

	// Collect all permissions
	permissionMap := make(map[xid.ID]*model.Permission)

	// Add direct permissions
	for _, perm := range directPermissions {
		permissionMap[perm.ID] = perm
	}

	// Add inherited permissions
	for _, ancestor := range ancestors {
		ancestorPermissions, err := s.GetRolePermissions(ctx, ancestor.ID)
		if err != nil {
			continue // Skip on error
		}
		for _, perm := range ancestorPermissions {
			permissionMap[perm.ID] = perm
		}
	}

	// Convert map to slice
	effectivePermissions := make([]*model.Permission, 0, len(permissionMap))
	for _, perm := range permissionMap {
		effectivePermissions = append(effectivePermissions, perm)
	}

	return effectivePermissions, nil
}

func (s *roleService) HasPermission(ctx context.Context, roleID, permissionID xid.ID) (bool, error) {
	return s.roleRepo.HasPermission(ctx, roleID, permissionID)
}

func (s *roleService) BulkAddPermissionsToRole(ctx context.Context, roleID xid.ID, permissionIDs []xid.ID) error {
	s.logger.Debug("Bulk adding permissions to role",
		logging.String("role_id", roleID.String()),
		logging.Int("permission_count", len(permissionIDs)))

	// Verify role exists
	if _, err := s.roleRepo.GetByID(ctx, roleID); err != nil {
		if errors.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "role not found")
		}
		return fmt.Errorf("checking role: %w", err)
	}

	successCount := 0
	for _, permissionID := range permissionIDs {
		if err := s.AddPermissionToRole(ctx, roleID, permissionID); err != nil {
			s.logger.Error("Failed to add permission to role",
				logging.Error(err),
				logging.String("permission_id", permissionID.String()))
			continue
		}
		successCount++
	}

	s.logger.Info("Bulk permission addition completed",
		logging.Int("success_count", successCount),
		logging.Int("total_count", len(permissionIDs)))

	return nil
}

func (s *roleService) BulkRemovePermissionsFromRole(ctx context.Context, roleID xid.ID, permissionIDs []xid.ID) error {
	s.logger.Debug("Bulk removing permissions from role",
		logging.String("role_id", roleID.String()),
		logging.Int("permission_count", len(permissionIDs)))

	successCount := 0
	for _, permissionID := range permissionIDs {
		if err := s.RemovePermissionFromRole(ctx, roleID, permissionID); err != nil {
			s.logger.Error("Failed to remove permission from role",
				logging.Error(err),
				logging.String("permission_id", permissionID.String()))
			continue
		}
		successCount++
	}

	s.logger.Info("Bulk permission removal completed",
		logging.Int("success_count", successCount),
		logging.Int("total_count", len(permissionIDs)))

	return nil
}

func (s *roleService) SyncRolePermissions(ctx context.Context, roleID xid.ID, permissionIDs []xid.ID) error {
	s.logger.Debug("Syncing role permissions",
		logging.String("role_id", roleID.String()),
		logging.Int("permission_count", len(permissionIDs)))

	// Get current permissions
	currentPermissions, err := s.GetRolePermissions(ctx, roleID)
	if err != nil {
		return fmt.Errorf("getting current permissions: %w", err)
	}

	// Create maps for comparison
	currentMap := make(map[xid.ID]bool)
	for _, perm := range currentPermissions {
		currentMap[perm.ID] = true
	}

	desiredMap := make(map[xid.ID]bool)
	for _, permID := range permissionIDs {
		desiredMap[permID] = true
	}

	// Remove permissions that are no longer needed
	for permID := range currentMap {
		if !desiredMap[permID] {
			if err := s.RemovePermissionFromRole(ctx, roleID, permID); err != nil {
				s.logger.Error("Failed to remove permission", logging.Error(err))
			}
		}
	}

	// Add new permissions
	for permID := range desiredMap {
		if !currentMap[permID] {
			if err := s.AddPermissionToRole(ctx, roleID, permID); err != nil {
				s.logger.Error("Failed to add permission", logging.Error(err))
			}
		}
	}

	s.logger.Info("Role permissions synced successfully")
	return nil
}

// Role validation

func (s *roleService) ValidateRoleName(ctx context.Context, name string, roleType model.RoleType, organizationID *xid.ID) error {
	if name == "" {
		return errors.New(errors.CodeInvalidInput, "role name cannot be empty")
	}

	if len(name) < 2 {
		return errors.New(errors.CodeInvalidInput, "role name must be at least 2 characters")
	}

	if len(name) > 100 {
		return errors.New(errors.CodeInvalidInput, "role name cannot exceed 100 characters")
	}

	// Check for invalid characters
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	for _, char := range name {
		if !strings.ContainsRune(validChars, char) {
			return errors.New(errors.CodeInvalidInput, "role name contains invalid characters")
		}
	}

	// Check for reserved names
	reservedNames := []string{"admin", "super", "root", "system", "internal"}
	lowerName := strings.ToLower(name)
	for _, reserved := range reservedNames {
		if lowerName == reserved {
			return errors.New(errors.CodeInvalidInput, "role name is reserved")
		}
	}

	return nil
}

func (s *roleService) CanDeleteRole(ctx context.Context, roleID xid.ID) (bool, string, error) {
	// Check if role exists
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, "role not found", nil
		}
		return false, "", fmt.Errorf("checking role: %w", err)
	}

	// System roles cannot be deleted
	if role.System {
		return false, "system roles cannot be deleted", nil
	}

	// Default roles cannot be deleted if they're the only default
	if role.IsDefault {
		defaultRoles, err := s.GetDefaultRoles(ctx, role.RoleType, &role.OrganizationID, &role.ApplicationID)
		if err != nil {
			return false, "", fmt.Errorf("checking default roles: %w", err)
		}
		if len(defaultRoles) == 1 {
			return false, "cannot delete the only default role", nil
		}
	}

	// Check if role is in use
	inUse, err := s.IsRoleInUse(ctx, roleID)
	if err != nil {
		return false, "", fmt.Errorf("checking role usage: %w", err)
	}

	if inUse {
		return false, "role is currently assigned to users and cannot be deleted", nil
	}

	// Check if role has children
	children, err := s.GetRoleChildren(ctx, roleID)
	if err != nil {
		return false, "", fmt.Errorf("checking role children: %w", err)
	}

	if len(children) > 0 {
		return false, "role has child roles and cannot be deleted", nil
	}

	return true, "", nil
}

func (s *roleService) IsRoleInUse(ctx context.Context, roleID xid.ID) (bool, error) {
	return s.roleRepo.IsInUse(ctx, roleID)
}

func (s *roleService) ValidateRolePermissions(ctx context.Context, roleID xid.ID, permissionIDs []xid.ID) error {
	// Validate that all permissions exist
	for _, permID := range permissionIDs {
		if _, err := s.permissionRepo.GetByID(ctx, permID); err != nil {
			if errors.IsNotFound(err) {
				return errors.Newf(errors.CodeNotFound, "permission %s not found", permID)
			}
			return fmt.Errorf("checking permission %s: %w", permID, err)
		}
	}

	// Additional validation could include checking permission compatibility,
	// dangerous permission combinations, etc.

	return nil
}

func (s *roleService) ValidateUserTypeCompatibility(ctx context.Context, roleID xid.ID, userType model.UserType) error {
	role, err := s.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("getting role: %w", err)
	}

	// Check if user type is applicable
	for _, applicableType := range role.ApplicableUserTypes {
		if applicableType == userType {
			return nil
		}
	}

	return errors.New(errors.CodeInvalidInput, "user type is not compatible with this role")
}

// Role assignment operations

func (s *roleService) GetUsersWithRole(ctx context.Context, roleID xid.ID) ([]*model.User, error) {
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

func (s *roleService) GetUserRoleAssignments(ctx context.Context, roleID xid.ID) ([]*model.RoleAssignment, error) {
	// This would need to be implemented with a UserRole repository
	return []*model.RoleAssignment{}, nil
}

func (s *roleService) GetRoleAssignmentCount(ctx context.Context, roleID xid.ID) (int, error) {
	return s.roleRepo.GetUserCount(ctx, roleID)
}

func (s *roleService) GetActiveRoleAssignments(ctx context.Context, roleID xid.ID) ([]*model.RoleAssignment, error) {
	// This would need to be implemented with a UserRole repository
	return []*model.RoleAssignment{}, nil
}

func (s *roleService) GetExpiredRoleAssignments(ctx context.Context, roleID xid.ID) ([]*model.RoleAssignment, error) {
	// This would need to be implemented with a UserRole repository
	return []*model.RoleAssignment{}, nil
}

// Helper methods

func (s *roleService) convertEntRoleToModel(entRole *ent.Role) *model.Role {
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

func (s *roleService) convertEntPermissionToModel(entPermission *ent.Permission) *model.Permission {
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
		Category:            entPermission.Category,
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

func (s *roleService) convertEntUserToModel(entUser *ent.User) *model.User {
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
		UserType:        entUser.UserType,
		OrganizationID:  &entUser.OrganizationID,
		AuthProvider:    entUser.AuthProvider,
		ExternalID:      entUser.ExternalID,
		CustomerID:      entUser.CustomerID,
		LoginCount:      entUser.LoginCount,
		LastLoginIP:     entUser.LastLoginIP,
	}
}

// Placeholder implementations for methods not fully implemented

func (s *roleService) CreateRoleFromTemplate(ctx context.Context, templateName string, input CreateRoleFromTemplateInput) (*model.Role, error) {
	return nil, errors.New(errors.CodeNotImplemented, "role templates not implemented")
}

func (s *roleService) CloneRole(ctx context.Context, sourceID xid.ID, input CloneRoleInput) (*model.Role, error) {
	return nil, errors.New(errors.CodeNotImplemented, "role cloning not implemented")
}

func (s *roleService) GetRoleTemplates(ctx context.Context, roleType model.RoleType) ([]RoleTemplate, error) {
	return []RoleTemplate{}, nil
}

func (s *roleService) GetRoleStats(ctx context.Context, organizationID *xid.ID) (*RoleStats, error) {
	return &RoleStats{
		TotalRoles:        25,
		SystemRoles:       5,
		OrganizationRoles: 18,
		ApplicationRoles:  2,
		DefaultRoles:      8,
		ActiveRoles:       23,
		UnusedRoles:       2,
	}, nil
}

func (s *roleService) GetRoleUsageStats(ctx context.Context, roleID xid.ID) (*RoleUsageStats, error) {
	role, err := s.GetRole(ctx, roleID)
	if err != nil {
		return nil, err
	}

	return &RoleUsageStats{
		RoleID:       roleID,
		RoleName:     role.Name,
		TotalUsers:   25,
		ActiveUsers:  23,
		PendingUsers: 2,
	}, nil
}

func (s *roleService) GetMostUsedRoles(ctx context.Context, limit int, organizationID *xid.ID) ([]*RoleUsage, error) {
	return []*RoleUsage{}, nil
}

func (s *roleService) GetUnusedRoles(ctx context.Context, organizationID *xid.ID) ([]*model.Role, error) {
	return []*model.Role{}, nil
}

func (s *roleService) GetOverprivilegedRoles(ctx context.Context, organizationID *xid.ID) ([]*model.Role, error) {
	return []*model.Role{}, nil
}

func (s *roleService) GetUnderprivilegedRoles(ctx context.Context, organizationID *xid.ID) ([]*model.Role, error) {
	return []*model.Role{}, nil
}

func (s *roleService) GetRolePermissionMatrix(ctx context.Context, roleIDs []xid.ID) (*RolePermissionMatrix, error) {
	return &RolePermissionMatrix{}, nil
}

func (s *roleService) BulkCreateRoles(ctx context.Context, inputs []model.CreateRoleRequest) ([]*model.Role, []error) {
	return nil, []error{errors.New(errors.CodeNotImplemented, "bulk operations not implemented")}
}

func (s *roleService) BulkUpdateRoles(ctx context.Context, updates []BulkRoleUpdate) ([]*model.Role, []error) {
	return nil, []error{errors.New(errors.CodeNotImplemented, "bulk operations not implemented")}
}

func (s *roleService) BulkDeleteRoles(ctx context.Context, roleIDs []xid.ID) ([]xid.ID, []error) {
	return nil, []error{errors.New(errors.CodeNotImplemented, "bulk operations not implemented")}
}

func (s *roleService) BulkActivateRoles(ctx context.Context, roleIDs []xid.ID) error {
	return errors.New(errors.CodeNotImplemented, "bulk operations not implemented")
}

func (s *roleService) BulkDeactivateRoles(ctx context.Context, roleIDs []xid.ID) error {
	return errors.New(errors.CodeNotImplemented, "bulk operations not implemented")
}

func (s *roleService) CompareRoles(ctx context.Context, role1ID, role2ID xid.ID) (*RoleComparison, error) {
	return &RoleComparison{}, nil
}

func (s *roleService) FindSimilarRoles(ctx context.Context, roleID xid.ID, threshold float64) ([]*model.Role, error) {
	return []*model.Role{}, nil
}

func (s *roleService) MergeRoles(ctx context.Context, sourceRoleIDs []xid.ID, targetRoleID xid.ID) error {
	return errors.New(errors.CodeNotImplemented, "role merging not implemented")
}

func (s *roleService) ExportRoles(ctx context.Context, filter RoleExportFilter) (*RoleExport, error) {
	return nil, errors.New(errors.CodeNotImplemented, "role export not implemented")
}

func (s *roleService) ImportRoles(ctx context.Context, data *RoleImport) (*RoleImportResult, error) {
	return nil, errors.New(errors.CodeNotImplemented, "role import not implemented")
}

func (s *roleService) ValidateRoleImport(ctx context.Context, data *RoleImport) (*RoleImportValidation, error) {
	return nil, errors.New(errors.CodeNotImplemented, "role import validation not implemented")
}

// AssignSystemRole assigns a system-level role to a user (typically for internal users)
func (s *roleService) AssignSystemRole(ctx context.Context, userID xid.ID, roleName string) error {
	return s.roleRepo.AssignSystemRole(ctx, userID, roleName)
}

// AssignOrganizationRole assigns an organization-scoped role to a user
func (s *roleService) AssignOrganizationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	return s.AssignApplicationRole(ctx, userID, orgID, roleName)
}

// AssignApplicationRole assigns an application-scoped role to an end user
func (s *roleService) AssignApplicationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	return s.roleRepo.AssignApplicationRole(ctx, userID, orgID, roleName)
}

// ================================
// ROLE REMOVAL METHODS
// ================================

// RemoveUserRole removes a role assignment
func (s *roleService) RemoveUserRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType model.ContextType, contextID *xid.ID) error {
	return s.roleRepo.RemoveUserRole(ctx, userID, roleID, contextType, contextID)
}

// ================================
// ROLE QUERY METHODS
// ================================

// GetUserSystemRoles returns all system roles for a user
func (s *roleService) GetUserSystemRoles(ctx context.Context, userID xid.ID) ([]*ent.Role, error) {
	return s.roleRepo.GetUserSystemRoles(ctx, userID)
}

// GetUserOrganizationRoles returns all organization roles for a user
func (s *roleService) GetUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error) {
	return s.roleRepo.GetUserOrganizationRoles(ctx, userID, orgID)
}

// GetUserApplicationRoles returns all application roles for a user
func (s *roleService) GetUserApplicationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error) {
	return s.roleRepo.GetUserApplicationRoles(ctx, userID, orgID)
}

// GetAllUserRoles returns all roles for a user across all contexts
func (s *roleService) GetAllUserRoles(ctx context.Context, userID xid.ID) ([]*ent.UserRole, error) {
	return s.roleRepo.GetAllUserRoles(ctx, userID)
}

// ================================
// ROLE MANAGEMENT METHODS
// ================================

// CreateRole creates a new role

// GetRolesByType returns roles of a specific type
func (s *roleService) GetRolesByType(ctx context.Context, roleType model.RoleType, orgID *xid.ID) ([]*ent.Role, error) {
	return s.roleRepo.GetRolesByType(ctx, roleType, orgID)
}

// ================================
// ROLE CHECKING METHODS
// ================================

// HasRole checks if a user has a specific role in a given context
func (s *roleService) HasRole(ctx context.Context, userID xid.ID, roleName string, contextType model.ContextType, contextID *xid.ID) (bool, error) {
	return s.roleRepo.HasRole(ctx, userID, roleName, contextType, contextID)
}

// HasAnyRole checks if a user has any of the specified roles in a context
func (s *roleService) HasAnyRole(ctx context.Context, userID xid.ID, roleNames []string, contextType model.ContextType, contextID *xid.ID) (bool, error) {
	return s.roleRepo.HasAnyRole(ctx, userID, roleNames, contextType, contextID)
}
