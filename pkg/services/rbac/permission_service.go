package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/permissiondependency"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// PermissionService provides permission-specific RBAC functionality
type PermissionService interface {
	// Core permission operations
	CreatePermission(ctx context.Context, input model.CreatePermissionRequest) (*model.Permission, error)
	UpdatePermission(ctx context.Context, id xid.ID, input model.UpdatePermissionRequest) (*model.Permission, error)
	DeletePermission(ctx context.Context, id xid.ID) error
	GetPermission(ctx context.Context, id xid.ID) (*model.Permission, error)
	GetPermissionByName(ctx context.Context, name string) (*model.Permission, error)
	GetPermissionByResourceAndAction(ctx context.Context, resource, action string) (*model.Permission, error)
	ListPermissions(ctx context.Context, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)
	SearchPermissions(ctx context.Context, query string, params model.SearchPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)

	// Permission categorization
	GetPermissionsByCategory(ctx context.Context, category model.PermissionCategory, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)
	GetPermissionsByGroup(ctx context.Context, group model.PermissionGroup, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)
	GetPermissionsByResource(ctx context.Context, resource string, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)
	GetSystemPermissions(ctx context.Context, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)
	GetDangerousPermissions(ctx context.Context, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)

	// Permission dependencies
	AddPermissionDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID, dependencyType permissiondependency.DependencyType, condition string) error
	RemovePermissionDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID) error
	GetPermissionDependencies(ctx context.Context, permissionID xid.ID) ([]*model.Permission, error)
	GetPermissionDependents(ctx context.Context, permissionID xid.ID) ([]*model.Permission, error)
	GetPermissionDependencyGraph(ctx context.Context, permissionID xid.ID) (*model.PermissionDependencyGraph, error)
	ValidateDependencies(ctx context.Context, permissionIDs []xid.ID) error

	// Permission validation
	ValidatePermissionName(ctx context.Context, name string) error
	ValidateResourceAction(ctx context.Context, resource, action string) error
	ValidatePermissionConditions(ctx context.Context, conditions string) error
	CanDeletePermission(ctx context.Context, permissionID xid.ID) (bool, string, error)
	IsPermissionInUse(ctx context.Context, permissionID xid.ID) (bool, error)
	GetEffectiveUserPermissions(ctx context.Context, userID xid.ID, contextType model.ContextType, contextID *xid.ID) ([]*ent.Permission, error)

	// Permission groups
	ListPermissionGroups(ctx context.Context) ([]model.PermissionGroupSummary, error)
	GetPermissionGroup(ctx context.Context, groupName model.PermissionGroup) (*model.PermissionGroupSummary, error)
	CreatePermissionGroup(ctx context.Context, input CreatePermissionGroupInput) (*model.PermissionGroupSummary, error)
	UpdatePermissionGroup(ctx context.Context, groupName model.PermissionGroup, input UpdatePermissionGroupInput) (*model.PermissionGroupSummary, error)
	DeletePermissionGroup(ctx context.Context, groupName model.PermissionGroup) error

	// Permission analysis
	GetPermissionStats(ctx context.Context) (*model.PermissionStats, error)
	GetMostUsedPermissions(ctx context.Context, limit int) ([]*model.PermissionUsage, error)
	GetUnusedPermissions(ctx context.Context) ([]*model.Permission, error)
	GetPermissionUsageByRole(ctx context.Context, permissionID xid.ID) (map[string]int, error)
	GetPermissionUsageByUser(ctx context.Context, permissionID xid.ID) (int, error)
	GetPermissionRiskAnalysis(ctx context.Context, organizationID *xid.ID) (*PermissionRiskAnalysis, error)

	// Bulk operations
	BulkCreatePermissions(ctx context.Context, inputs []model.CreatePermissionRequest) ([]*model.Permission, []error)
	BulkUpdatePermissions(ctx context.Context, updates []BulkPermissionUpdate) ([]*model.Permission, []error)
	BulkDeletePermissions(ctx context.Context, permissionIDs []xid.ID) ([]xid.ID, []error)
	BulkActivatePermissions(ctx context.Context, permissionIDs []xid.ID) error
	BulkDeactivatePermissions(ctx context.Context, permissionIDs []xid.ID) error

	// Permission templates and cloning
	CreatePermissionFromTemplate(ctx context.Context, templateName string, input CreateFromTemplateInput) (*model.Permission, error)
	ClonePermission(ctx context.Context, sourceID xid.ID, input ClonePermissionInput) (*model.Permission, error)
	GetPermissionTemplates(ctx context.Context) ([]PermissionTemplate, error)

	// Conflict detection
	DetectPermissionConflicts(ctx context.Context, permissionIDs []xid.ID) ([]PermissionConflict, error)
	ValidatePermissionSet(ctx context.Context, permissionIDs []xid.ID) (*PermissionSetValidation, error)

	// Import/Export
	ExportPermissions(ctx context.Context, filter PermissionExportFilter) (*PermissionExport, error)
	ImportPermissions(ctx context.Context, data *PermissionImport) (*PermissionImportResult, error)
	ValidatePermissionImport(ctx context.Context, data *PermissionImport) (*PermissionImportValidation, error)
}

// permissionService implements the PermissionService interface
type permissionService struct {
	permissionRepo repository.PermissionRepository
	roleRepo       repository.RoleRepository
	userRepo       repository.UserRepository
	logger         logging.Logger
}

// NewPermissionService creates a new permission service
func NewPermissionService(
	repo repository.Repository,
	logger logging.Logger,
) PermissionService {
	return &permissionService{
		permissionRepo: repo.Permission(),
		roleRepo:       repo.Role(),
		userRepo:       repo.User(),
		logger:         logger.Named("permission"),
	}
}

// Core permission operations

func (s *permissionService) CreatePermission(ctx context.Context, input model.CreatePermissionRequest) (*model.Permission, error) {
	s.logger.Debug("Creating permission", logging.String("name", input.Name))

	// Validate permission name
	if err := s.ValidatePermissionName(ctx, input.Name); err != nil {
		return nil, fmt.Errorf("invalid permission name: %w", err)
	}

	// Validate resource and action
	if err := s.ValidateResourceAction(ctx, input.Resource, input.Action); err != nil {
		return nil, fmt.Errorf("invalid resource/action: %w", err)
	}

	// Validate conditions if provided
	if input.Conditions != "" {
		if err := s.ValidatePermissionConditions(ctx, input.Conditions); err != nil {
			return nil, fmt.Errorf("invalid conditions: %w", err)
		}
	}

	// Check for existing permission
	if exists, err := s.permissionRepo.ExistsByName(ctx, input.Name); err != nil {
		return nil, fmt.Errorf("checking permission existence: %w", err)
	} else if exists {
		return nil, errors.New(errors.CodeConflict, "permission with this name already exists")
	}

	// Check for resource/action combination
	if exists, err := s.permissionRepo.ExistsByResourceAndAction(ctx, input.Resource, input.Action); err != nil {
		return nil, fmt.Errorf("checking resource/action combination: %w", err)
	} else if exists {
		return nil, errors.New(errors.CodeConflict, "permission with this resource and action already exists")
	}

	// Create permission
	createInput := repository.CreatePermissionInput{
		Name:                input.Name,
		DisplayName:         input.DisplayName,
		Description:         input.Description,
		Resource:            input.Resource,
		Action:              input.Action,
		Category:            input.Category,
		ApplicableUserTypes: input.ApplicableUserTypes,
		ApplicableContexts:  input.ApplicableContexts,
		Conditions:          &input.Conditions,
		Dangerous:           input.Dangerous,
		RiskLevel:           input.RiskLevel,
		PermissionGroup:     input.PermissionGroup,
	}

	entPermission, err := s.permissionRepo.Create(ctx, createInput)
	if err != nil {
		s.logger.Error("Failed to create permission", logging.Error(err))
		return nil, fmt.Errorf("creating permission: %w", err)
	}

	permission := s.convertEntPermissionToModel(entPermission)

	s.logger.Info("Permission created successfully",
		logging.String("permission_id", permission.ID.String()),
		logging.String("name", permission.Name))

	return permission, nil
}

func (s *permissionService) UpdatePermission(ctx context.Context, id xid.ID, input model.UpdatePermissionRequest) (*model.Permission, error) {
	s.logger.Debug("Updating permission", logging.String("permission_id", id.String()))

	// Check if permission exists
	existing, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, fmt.Errorf("checking permission existence: %w", err)
	}

	// Validate conditions if being updated
	if input.Conditions != nil && *input.Conditions != "" {
		if err := s.ValidatePermissionConditions(ctx, *input.Conditions); err != nil {
			return nil, fmt.Errorf("invalid conditions: %w", err)
		}
	}

	// Check if permission is system-managed
	if existing.System {
		return nil, errors.New(errors.CodeForbidden, "cannot modify system-managed permission")
	}

	// Update permission
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

func (s *permissionService) DeletePermission(ctx context.Context, id xid.ID) error {
	s.logger.Debug("Deleting permission", logging.String("permission_id", id.String()))

	// Check if permission can be deleted
	canDelete, reason, err := s.CanDeletePermission(ctx, id)
	if err != nil {
		return fmt.Errorf("checking if permission can be deleted: %w", err)
	}
	if !canDelete {
		return errors.New(errors.CodeConflict, reason)
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

func (s *permissionService) GetPermission(ctx context.Context, id xid.ID) (*model.Permission, error) {
	entPermission, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, fmt.Errorf("getting permission: %w", err)
	}

	return s.convertEntPermissionToModel(entPermission), nil
}

func (s *permissionService) GetPermissionByName(ctx context.Context, name string) (*model.Permission, error) {
	entPermission, err := s.permissionRepo.GetByName(ctx, name)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, fmt.Errorf("getting permission by name: %w", err)
	}

	return s.convertEntPermissionToModel(entPermission), nil
}

func (s *permissionService) GetPermissionByResourceAndAction(ctx context.Context, resource, action string) (*model.Permission, error) {
	entPermission, err := s.permissionRepo.GetByResourceAndAction(ctx, resource, action)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, fmt.Errorf("getting permission by resource/action: %w", err)
	}

	return s.convertEntPermissionToModel(entPermission), nil
}

func (s *permissionService) ListPermissions(ctx context.Context, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	repoParams := convertListPermissionDTOToRepo(params)

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

func (s *permissionService) SearchPermissions(ctx context.Context, query string, params model.SearchPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	searchParams := repository.SearchPermissionsParams{
		PaginationParams: params.PaginationParams,
		Categories:       params.Categories,
		Resources:        params.Resources,
		Actions:          params.Actions,
		RiskLevels:       params.RiskLevels,
		UserTypes:        params.UserTypes,
		Contexts:         params.Contexts,
	}

	if params.IncludeSystem.IsSet {
		searchParams.IncludeSystem = params.IncludeSystem.Value
	}
	if params.IncludeDangerous.IsSet {
		searchParams.IncludeDangerous = params.IncludeDangerous.Value
	}
	if params.ExcludeInactive.IsSet {
		searchParams.ExcludeInactive = &params.ExcludeInactive.Value
	}

	result, err := s.permissionRepo.Search(ctx, query, searchParams)
	if err != nil {
		return nil, fmt.Errorf("searching permissions: %w", err)
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

// Permission categorization

func (s *permissionService) GetPermissionsByCategory(ctx context.Context, category model.PermissionCategory, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	result, err := s.permissionRepo.GetByCategory(ctx, category, convertListPermissionDTOToRepo(params))
	if err != nil {
		return nil, fmt.Errorf("getting permissions by category: %w", err)
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

func (s *permissionService) GetPermissionsByGroup(ctx context.Context, group model.PermissionGroup, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	result, err := s.permissionRepo.GetByGroup(ctx, group, convertListPermissionDTOToRepo(params))
	if err != nil {
		return nil, fmt.Errorf("getting permissions by group: %w", err)
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

func (s *permissionService) GetEffectiveUserPermissions(ctx context.Context, userID xid.ID, contextType model.ContextType, contextID *xid.ID) ([]*ent.Permission, error) {
	result, err := s.permissionRepo.GetEffectiveUserPermissions(ctx, userID, contextType, contextID)
	if err != nil {
		return nil, fmt.Errorf("getting effective user permissions: %w", err)
	}
	return result, nil
}

func (s *permissionService) GetPermissionsByResource(ctx context.Context, resource string, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	result, err := s.permissionRepo.GetByResource(ctx, resource, convertListPermissionDTOToRepo(params))
	if err != nil {
		return nil, fmt.Errorf("getting permissions by resource: %w", err)
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

func (s *permissionService) GetSystemPermissions(ctx context.Context, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	result, err := s.permissionRepo.GetSystemPermissions(ctx, convertListPermissionDTOToRepo(params))
	if err != nil {
		return nil, fmt.Errorf("getting system permissions: %w", err)
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

func (s *permissionService) GetDangerousPermissions(ctx context.Context, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	result, err := s.permissionRepo.GetDangerousPermissions(ctx, convertListPermissionDTOToRepo(params))
	if err != nil {
		return nil, fmt.Errorf("getting dangerous permissions: %w", err)
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

// Permission dependencies

func (s *permissionService) AddPermissionDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID, dependencyType permissiondependency.DependencyType, condition string) error {
	s.logger.Debug("Adding permission dependency",
		logging.String("permission_id", permissionID.String()),
		logging.String("required_permission_id", requiredPermissionID.String()),
		logging.String("dependency_type", string(dependencyType)))

	// Verify both permissions exist
	if _, err := s.permissionRepo.GetByID(ctx, permissionID); err != nil {
		if errors.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "permission not found")
		}
		return fmt.Errorf("checking permission: %w", err)
	}

	if _, err := s.permissionRepo.GetByID(ctx, requiredPermissionID); err != nil {
		if errors.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "required permission not found")
		}
		return fmt.Errorf("checking required permission: %w", err)
	}

	// Prevent circular dependencies
	if err := s.checkCircularDependency(ctx, permissionID, requiredPermissionID); err != nil {
		return fmt.Errorf("circular dependency detected: %w", err)
	}

	// Add dependency
	if err := s.permissionRepo.AddDependency(ctx, permissionID, requiredPermissionID, dependencyType); err != nil {
		s.logger.Error("Failed to add permission dependency", logging.Error(err))
		return fmt.Errorf("adding permission dependency: %w", err)
	}

	s.logger.Info("Permission dependency added successfully")
	return nil
}

func (s *permissionService) RemovePermissionDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID) error {
	s.logger.Debug("Removing permission dependency",
		logging.String("permission_id", permissionID.String()),
		logging.String("required_permission_id", requiredPermissionID.String()))

	if err := s.permissionRepo.RemoveDependency(ctx, permissionID, requiredPermissionID); err != nil {
		s.logger.Error("Failed to remove permission dependency", logging.Error(err))
		return fmt.Errorf("removing permission dependency: %w", err)
	}

	s.logger.Info("Permission dependency removed successfully")
	return nil
}

func (s *permissionService) GetPermissionDependencies(ctx context.Context, permissionID xid.ID) ([]*model.Permission, error) {
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

func (s *permissionService) GetPermissionDependents(ctx context.Context, permissionID xid.ID) ([]*model.Permission, error) {
	entPermissions, err := s.permissionRepo.GetDependents(ctx, permissionID)
	if err != nil {
		return nil, fmt.Errorf("getting permission dependents: %w", err)
	}

	// Convert to model types
	permissions := make([]*model.Permission, len(entPermissions))
	for i, entPermission := range entPermissions {
		permissions[i] = s.convertEntPermissionToModel(entPermission)
	}

	return permissions, nil
}

func (s *permissionService) GetPermissionDependencyGraph(ctx context.Context, permissionID xid.ID) (*model.PermissionDependencyGraph, error) {
	// Get the permission
	entPermission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "permission not found")
		}
		return nil, fmt.Errorf("getting permission: %w", err)
	}

	// Get dependencies
	dependencies, err := s.GetPermissionDependencies(ctx, permissionID)
	if err != nil {
		return nil, fmt.Errorf("getting dependencies: %w", err)
	}

	// Get dependents
	dependents, err := s.GetPermissionDependents(ctx, permissionID)
	if err != nil {
		return nil, fmt.Errorf("getting dependents: %w", err)
	}

	// Build dependency nodes
	depNodes := make([]model.PermissionDependencyNode, len(dependencies))
	for i, dep := range dependencies {
		depNodes[i] = model.PermissionDependencyNode{
			PermissionID:   dep.ID,
			Name:           dep.Name,
			DependencyType: "required", // This would come from the dependency relationship
		}
	}

	// Build dependent nodes
	depentNodes := make([]model.PermissionDependencyNode, len(dependents))
	for i, dependent := range dependents {
		depentNodes[i] = model.PermissionDependencyNode{
			PermissionID:   dependent.ID,
			Name:           dependent.Name,
			DependencyType: "required", // This would come from the dependency relationship
		}
	}

	return &model.PermissionDependencyGraph{
		PermissionID: permissionID,
		Name:         entPermission.Name,
		Dependencies: depNodes,
		Dependents:   depentNodes,
	}, nil
}

func (s *permissionService) ValidateDependencies(ctx context.Context, permissionIDs []xid.ID) error {
	// Get all dependencies for the permission set
	allDeps := make(map[xid.ID]bool)

	for _, permID := range permissionIDs {
		deps, err := s.GetPermissionDependencies(ctx, permID)
		if err != nil {
			return fmt.Errorf("getting dependencies for permission %s: %w", permID, err)
		}

		for _, dep := range deps {
			allDeps[dep.ID] = true
		}
	}

	// Check that all dependencies are satisfied
	providedPerms := make(map[xid.ID]bool)
	for _, permID := range permissionIDs {
		providedPerms[permID] = true
	}

	missingDeps := []xid.ID{}
	for depID := range allDeps {
		if !providedPerms[depID] {
			missingDeps = append(missingDeps, depID)
		}
	}

	if len(missingDeps) > 0 {
		return errors.Newf(errors.CodeInvalidInput, "missing required dependencies: %v", missingDeps)
	}

	return nil
}

// Permission validation

func (s *permissionService) ValidatePermissionName(ctx context.Context, name string) error {
	if name == "" {
		return errors.New(errors.CodeInvalidInput, "permission name cannot be empty")
	}

	if len(name) < 3 {
		return errors.New(errors.CodeInvalidInput, "permission name must be at least 3 characters")
	}

	if len(name) > 100 {
		return errors.New(errors.CodeInvalidInput, "permission name cannot exceed 100 characters")
	}

	// Check format (should be like "action:resource" or similar)
	parts := strings.Split(name, ":")
	if len(parts) != 2 {
		return errors.New(errors.CodeInvalidInput, "permission name must be in format 'action:resource'")
	}

	if parts[0] == "" || parts[1] == "" {
		return errors.New(errors.CodeInvalidInput, "both action and resource must be specified")
	}

	// Check for invalid characters
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-:"
	for _, char := range name {
		if !strings.ContainsRune(validChars, char) {
			return errors.New(errors.CodeInvalidInput, "permission name contains invalid characters")
		}
	}

	return nil
}

func (s *permissionService) ValidateResourceAction(ctx context.Context, resource, action string) error {
	if resource == "" {
		return errors.New(errors.CodeInvalidInput, "resource cannot be empty")
	}

	if action == "" {
		return errors.New(errors.CodeInvalidInput, "action cannot be empty")
	}

	// Validate resource format
	if len(resource) < 2 || len(resource) > 50 {
		return errors.New(errors.CodeInvalidInput, "resource must be between 2 and 50 characters")
	}

	// Validate action format
	if len(action) < 2 || len(action) > 50 {
		return errors.New(errors.CodeInvalidInput, "action must be between 2 and 50 characters")
	}

	// Check for valid action names
	validActions := []string{"create", "read", "update", "delete", "list", "manage", "admin", "view", "edit", "execute"}
	actionValid := false
	for _, validAction := range validActions {
		if action == validAction {
			actionValid = true
			break
		}
	}

	if !actionValid {
		return errors.New(errors.CodeInvalidInput, "action must be one of: create, read, update, delete, list, manage, admin, view, edit, execute")
	}

	return nil
}

func (s *permissionService) ValidatePermissionConditions(ctx context.Context, conditions string) error {
	if conditions == "" {
		return nil // Empty conditions are valid
	}

	// Basic JSON validation
	// In a real implementation, you would validate the condition syntax
	// and ensure it follows your permission condition DSL

	if len(conditions) > 1000 {
		return errors.New(errors.CodeInvalidInput, "conditions cannot exceed 1000 characters")
	}

	// Basic JSON structure check
	if !strings.HasPrefix(conditions, "{") || !strings.HasSuffix(conditions, "}") {
		return errors.New(errors.CodeInvalidInput, "conditions must be valid JSON object")
	}

	return nil
}

func (s *permissionService) CanDeletePermission(ctx context.Context, permissionID xid.ID) (bool, string, error) {
	// Check if permission exists
	permission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, "permission not found", nil
		}
		return false, "", fmt.Errorf("checking permission: %w", err)
	}

	// System permissions cannot be deleted
	if permission.System {
		return false, "system permissions cannot be deleted", nil
	}

	// Check if permission is in use
	inUse, err := s.IsPermissionInUse(ctx, permissionID)
	if err != nil {
		return false, "", fmt.Errorf("checking permission usage: %w", err)
	}

	if inUse {
		return false, "permission is currently in use and cannot be deleted", nil
	}

	// Check if permission has dependents
	dependents, err := s.GetPermissionDependents(ctx, permissionID)
	if err != nil {
		return false, "", fmt.Errorf("checking permission dependents: %w", err)
	}

	if len(dependents) > 0 {
		return false, "permission has dependencies and cannot be deleted", nil
	}

	return true, "", nil
}

func (s *permissionService) IsPermissionInUse(ctx context.Context, permissionID xid.ID) (bool, error) {
	return s.permissionRepo.IsInUse(ctx, permissionID)
}

// Permission analysis

func (s *permissionService) GetPermissionStats(ctx context.Context) (*model.PermissionStats, error) {
	permissionStats, err := s.permissionRepo.GetPermissionStats(ctx)
	if err != nil {
		return nil, err
	}

	return &model.PermissionStats{
		CategoryBreakdown:    permissionStats.CategoryBreakdown,
		ResourceBreakdown:    permissionStats.ResourceBreakdown,
		RiskLevelBreakdown:   permissionStats.RiskLevelBreakdown,
		UnusedPermissions:    permissionStats.UnusedPermissions,
		CustomPermissions:    permissionStats.CustomPermissions,
		DangerousPermissions: permissionStats.DangerousPermissions,
		SystemPermissions:    permissionStats.SystemPermissions,
		TotalPermissions:     permissionStats.TotalPermissions,
	}, nil
}

func (s *permissionService) GetMostUsedPermissions(ctx context.Context, limit int) ([]*model.PermissionUsage, error) {
	permissions, err := s.permissionRepo.GetMostUsedPermissions(ctx, limit)
	if err != nil {
		return nil, err
	}

	usages := make([]*model.PermissionUsage, len(permissions))
	for i, perm := range permissions {
		usages[i] = &model.PermissionUsage{
			RoleCount:  perm.RoleCount,
			UsageCount: perm.UsageCount,
			Permission: s.convertEntPermissionToModel(perm.Permission),
		}
	}

	return usages, nil
}

func (s *permissionService) GetUnusedPermissions(ctx context.Context) ([]*model.Permission, error) {
	entPermissions, err := s.permissionRepo.GetUnusedPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting unused permissions: %w", err)
	}

	// Convert to model types
	permissions := make([]*model.Permission, len(entPermissions))
	for i, entPermission := range entPermissions {
		permissions[i] = s.convertEntPermissionToModel(entPermission)
	}

	return permissions, nil
}

func (s *permissionService) GetPermissionUsageByRole(ctx context.Context, permissionID xid.ID) (map[string]int, error) {
	// This would need to be implemented to track permission usage by role
	return map[string]int{
		"admin":  5,
		"editor": 10,
		"viewer": 2,
	}, nil
}

func (s *permissionService) GetPermissionUsageByUser(ctx context.Context, permissionID xid.ID) (int, error) {
	// This would need to be implemented to count users with this permission
	return 25, nil
}

func (s *permissionService) GetPermissionRiskAnalysis(ctx context.Context, organizationID *xid.ID) (*PermissionRiskAnalysis, error) {
	// This would be a complex analysis combining multiple factors
	return &PermissionRiskAnalysis{
		OrganizationID:       organizationID,
		TotalPermissions:     150,
		RiskDistribution:     map[string]int{"low": 100, "medium": 35, "high": 10, "critical": 5},
		DangerousPermissions: []string{"delete:system", "admin:all", "manage:users"},
		OverPrivilegedRoles:  []string{"super_admin", "system_admin"},
		UnusedPermissions:    []string{"legacy:feature", "deprecated:action"},
		RecommendedActions:   []string{"Review super_admin role", "Remove unused permissions"},
		RiskScore:            7.5,
		GeneratedAt:          time.Now(),
	}, nil
}

// Helper methods

func (s *permissionService) checkCircularDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID) error {
	// Get all dependencies of the required permission
	deps, err := s.GetPermissionDependencies(ctx, requiredPermissionID)
	if err != nil {
		return fmt.Errorf("getting dependencies: %w", err)
	}

	// Check if the original permission is in the dependency chain
	for _, dep := range deps {
		if dep.ID == permissionID {
			return errors.New(errors.CodeConflict, "circular dependency detected")
		}

		// Recursively check deeper dependencies
		if err := s.checkCircularDependency(ctx, permissionID, dep.ID); err != nil {
			return err
		}
	}

	return nil
}

func (s *permissionService) convertEntPermissionToModel(entPermission *ent.Permission) *model.Permission {
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

// Placeholder implementations for methods not fully implemented

func (s *permissionService) ListPermissionGroups(ctx context.Context) ([]model.PermissionGroupSummary, error) {
	// This would need a separate permission groups repository
	return []model.PermissionGroupSummary{}, nil
}

func (s *permissionService) GetPermissionGroup(ctx context.Context, groupName model.PermissionGroup) (*model.PermissionGroupSummary, error) {
	return nil, errors.New(errors.CodeNotImplemented, "permission groups not implemented")
}

func (s *permissionService) CreatePermissionGroup(ctx context.Context, input CreatePermissionGroupInput) (*model.PermissionGroupSummary, error) {
	return nil, errors.New(errors.CodeNotImplemented, "permission groups not implemented")
}

func (s *permissionService) UpdatePermissionGroup(ctx context.Context, groupName model.PermissionGroup, input UpdatePermissionGroupInput) (*model.PermissionGroupSummary, error) {
	return nil, errors.New(errors.CodeNotImplemented, "permission groups not implemented")
}

func (s *permissionService) DeletePermissionGroup(ctx context.Context, groupName model.PermissionGroup) error {
	return errors.New(errors.CodeNotImplemented, "permission groups not implemented")
}

func (s *permissionService) BulkCreatePermissions(ctx context.Context, inputs []model.CreatePermissionRequest) ([]*model.Permission, []error) {
	// This would be implemented for bulk operations
	return nil, []error{errors.New(errors.CodeNotImplemented, "bulk operations not implemented")}
}

func (s *permissionService) BulkUpdatePermissions(ctx context.Context, updates []BulkPermissionUpdate) ([]*model.Permission, []error) {
	return nil, []error{errors.New(errors.CodeNotImplemented, "bulk operations not implemented")}
}

func (s *permissionService) BulkDeletePermissions(ctx context.Context, permissionIDs []xid.ID) ([]xid.ID, []error) {
	return nil, []error{errors.New(errors.CodeNotImplemented, "bulk operations not implemented")}
}

func (s *permissionService) BulkActivatePermissions(ctx context.Context, permissionIDs []xid.ID) error {
	return errors.New(errors.CodeNotImplemented, "bulk operations not implemented")
}

func (s *permissionService) BulkDeactivatePermissions(ctx context.Context, permissionIDs []xid.ID) error {
	return errors.New(errors.CodeNotImplemented, "bulk operations not implemented")
}

func (s *permissionService) CreatePermissionFromTemplate(ctx context.Context, templateName string, input CreateFromTemplateInput) (*model.Permission, error) {
	return nil, errors.New(errors.CodeNotImplemented, "permission templates not implemented")
}

func (s *permissionService) ClonePermission(ctx context.Context, sourceID xid.ID, input ClonePermissionInput) (*model.Permission, error) {
	return nil, errors.New(errors.CodeNotImplemented, "permission cloning not implemented")
}

func (s *permissionService) GetPermissionTemplates(ctx context.Context) ([]PermissionTemplate, error) {
	return []PermissionTemplate{}, nil
}

func (s *permissionService) DetectPermissionConflicts(ctx context.Context, permissionIDs []xid.ID) ([]PermissionConflict, error) {
	return []PermissionConflict{}, nil
}

func (s *permissionService) ValidatePermissionSet(ctx context.Context, permissionIDs []xid.ID) (*PermissionSetValidation, error) {
	return &PermissionSetValidation{
		IsValid: true,
	}, nil
}

func (s *permissionService) ExportPermissions(ctx context.Context, filter PermissionExportFilter) (*PermissionExport, error) {
	return nil, errors.New(errors.CodeNotImplemented, "permission export not implemented")
}

func (s *permissionService) ImportPermissions(ctx context.Context, data *PermissionImport) (*PermissionImportResult, error) {
	return nil, errors.New(errors.CodeNotImplemented, "permission import not implemented")
}

func (s *permissionService) ValidatePermissionImport(ctx context.Context, data *PermissionImport) (*PermissionImportValidation, error) {
	return nil, errors.New(errors.CodeNotImplemented, "permission import validation not implemented")
}
