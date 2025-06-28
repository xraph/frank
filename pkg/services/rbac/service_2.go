package rbac

import (
	"context"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/ent/permissiondependency"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// ================================
// PERMISSION MANAGEMENT (From rbac2)
// ================================

func (s *service) CreatePermission(ctx context.Context, input model.CreatePermissionRequest) (*model.Permission, error) {
	return s.permissionService.CreatePermission(ctx, input)
}

func (s *service) UpdatePermission(ctx context.Context, id xid.ID, input model.UpdatePermissionRequest) (*model.Permission, error) {
	return s.permissionService.UpdatePermission(ctx, id, input)
}

func (s *service) DeletePermission(ctx context.Context, id xid.ID) error {
	return s.permissionService.DeletePermission(ctx, id)
}

func (s *service) GetPermission(ctx context.Context, id xid.ID) (*model.Permission, error) {
	return s.permissionService.GetPermission(ctx, id)
}

func (s *service) GetPermissionByName(ctx context.Context, name string) (*model.Permission, error) {
	return s.permissionService.GetPermissionByName(ctx, name)
}

func (s *service) GetPermissionByResourceAndAction(ctx context.Context, resource, action string) (*model.Permission, error) {
	return s.permissionService.GetPermissionByResourceAndAction(ctx, resource, action)
}

func (s *service) ListPermissions(ctx context.Context, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	return s.permissionService.ListPermissions(ctx, params)
}

func (s *service) SearchPermissions(ctx context.Context, query string, params model.SearchPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	return s.permissionService.SearchPermissions(ctx, query, params)
}

// Permission categorization
func (s *service) GetPermissionsByCategory(ctx context.Context, category model.PermissionCategory, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	return s.permissionService.GetPermissionsByCategory(ctx, category, params)
}

func (s *service) GetPermissionsByGroup(ctx context.Context, group model.PermissionGroup, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	return s.permissionService.GetPermissionsByGroup(ctx, group, params)
}

func (s *service) GetPermissionsByResource(ctx context.Context, resource string, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	return s.permissionService.GetPermissionsByResource(ctx, resource, params)
}

func (s *service) GetSystemPermissions(ctx context.Context, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	return s.permissionService.GetSystemPermissions(ctx, params)
}

func (s *service) GetDangerousPermissions(ctx context.Context, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	return s.permissionService.GetDangerousPermissions(ctx, params)
}

// Permission dependencies
func (s *service) AddPermissionDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID, dependencyType permissiondependency.DependencyType, condition string) error {
	return s.permissionService.AddPermissionDependency(ctx, permissionID, requiredPermissionID, dependencyType, condition)
}

func (s *service) RemovePermissionDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID) error {
	return s.permissionService.RemovePermissionDependency(ctx, permissionID, requiredPermissionID)
}

func (s *service) GetPermissionDependencies(ctx context.Context, permissionID xid.ID) ([]*model.Permission, error) {
	return s.permissionService.GetPermissionDependencies(ctx, permissionID)
}

func (s *service) GetPermissionDependents(ctx context.Context, permissionID xid.ID) ([]*model.Permission, error) {
	return s.permissionService.GetPermissionDependents(ctx, permissionID)
}

func (s *service) GetPermissionDependencyGraph(ctx context.Context, permissionID xid.ID) (*model.PermissionDependencyGraph, error) {
	return s.permissionService.GetPermissionDependencyGraph(ctx, permissionID)
}

func (s *service) ValidateDependencies(ctx context.Context, permissionIDs []xid.ID) error {
	return s.permissionService.ValidateDependencies(ctx, permissionIDs)
}

// Permission validation
func (s *service) ValidatePermissionName(ctx context.Context, name string) error {
	return s.permissionService.ValidatePermissionName(ctx, name)
}

func (s *service) ValidateResourceAction(ctx context.Context, resource, action string) error {
	return s.permissionService.ValidateResourceAction(ctx, resource, action)
}

func (s *service) ValidatePermissionConditions(ctx context.Context, conditions string) error {
	return s.permissionService.ValidatePermissionConditions(ctx, conditions)
}

func (s *service) CanDeletePermission(ctx context.Context, permissionID xid.ID) (bool, string, error) {
	return s.permissionService.CanDeletePermission(ctx, permissionID)
}

func (s *service) IsPermissionInUse(ctx context.Context, permissionID xid.ID) (bool, error) {
	return s.permissionService.IsPermissionInUse(ctx, permissionID)
}

// Permission groups
func (s *service) ListPermissionGroups(ctx context.Context) ([]model.PermissionGroupSummary, error) {
	return s.permissionService.ListPermissionGroups(ctx)
}

func (s *service) GetPermissionGroup(ctx context.Context, groupName model.PermissionGroup) (*model.PermissionGroupSummary, error) {
	return s.permissionService.GetPermissionGroup(ctx, groupName)
}

func (s *service) CreatePermissionGroup(ctx context.Context, input CreatePermissionGroupInput) (*model.PermissionGroupSummary, error) {
	return s.permissionService.CreatePermissionGroup(ctx, input)
}

func (s *service) UpdatePermissionGroup(ctx context.Context, groupName model.PermissionGroup, input UpdatePermissionGroupInput) (*model.PermissionGroupSummary, error) {
	return s.permissionService.UpdatePermissionGroup(ctx, groupName, input)
}

func (s *service) DeletePermissionGroup(ctx context.Context, groupName model.PermissionGroup) error {
	return s.permissionService.DeletePermissionGroup(ctx, groupName)
}

// Permission analysis
func (s *service) GetPermissionStats(ctx context.Context) (*model.PermissionStats, error) {
	return s.permissionService.GetPermissionStats(ctx)
}

func (s *service) GetMostUsedPermissions(ctx context.Context, limit int) ([]*model.PermissionUsage, error) {
	return s.permissionService.GetMostUsedPermissions(ctx, limit)
}

func (s *service) GetUnusedPermissions(ctx context.Context) ([]*model.Permission, error) {
	return s.permissionService.GetUnusedPermissions(ctx)
}

func (s *service) GetPermissionUsageByRole(ctx context.Context, permissionID xid.ID) (map[string]int, error) {
	return s.permissionService.GetPermissionUsageByRole(ctx, permissionID)
}

func (s *service) GetPermissionUsageByUser(ctx context.Context, permissionID xid.ID) (int, error) {
	return s.permissionService.GetPermissionUsageByUser(ctx, permissionID)
}

func (s *service) GetPermissionRiskAnalysis(ctx context.Context, organizationID *xid.ID) (*PermissionRiskAnalysis, error) {
	return s.permissionService.GetPermissionRiskAnalysis(ctx, organizationID)
}

// Bulk permission operations
func (s *service) BulkCreatePermissions(ctx context.Context, inputs []model.CreatePermissionRequest) ([]*model.Permission, []error) {
	return s.permissionService.BulkCreatePermissions(ctx, inputs)
}

func (s *service) BulkUpdatePermissions(ctx context.Context, updates []BulkPermissionUpdate) ([]*model.Permission, []error) {
	return s.permissionService.BulkUpdatePermissions(ctx, updates)
}

func (s *service) BulkDeletePermissions(ctx context.Context, permissionIDs []xid.ID) ([]xid.ID, []error) {
	return s.permissionService.BulkDeletePermissions(ctx, permissionIDs)
}

func (s *service) BulkActivatePermissions(ctx context.Context, permissionIDs []xid.ID) error {
	return s.permissionService.BulkActivatePermissions(ctx, permissionIDs)
}

func (s *service) BulkDeactivatePermissions(ctx context.Context, permissionIDs []xid.ID) error {
	return s.permissionService.BulkDeactivatePermissions(ctx, permissionIDs)
}

// Permission templates and cloning
func (s *service) CreatePermissionFromTemplate(ctx context.Context, templateName string, input CreateFromTemplateInput) (*model.Permission, error) {
	return s.permissionService.CreatePermissionFromTemplate(ctx, templateName, input)
}

func (s *service) ClonePermission(ctx context.Context, sourceID xid.ID, input ClonePermissionInput) (*model.Permission, error) {
	return s.permissionService.ClonePermission(ctx, sourceID, input)
}

func (s *service) GetPermissionTemplates(ctx context.Context) ([]PermissionTemplate, error) {
	return s.permissionService.GetPermissionTemplates(ctx)
}

// Conflict detection
func (s *service) DetectPermissionConflicts(ctx context.Context, permissionIDs []xid.ID) ([]PermissionConflict, error) {
	return s.permissionService.DetectPermissionConflicts(ctx, permissionIDs)
}

func (s *service) ValidatePermissionSet(ctx context.Context, permissionIDs []xid.ID) (*PermissionSetValidation, error) {
	return s.permissionService.ValidatePermissionSet(ctx, permissionIDs)
}

// Import/Export
func (s *service) ExportPermissions(ctx context.Context, filter PermissionExportFilter) (*PermissionExport, error) {
	return s.permissionService.ExportPermissions(ctx, filter)
}

func (s *service) ImportPermissions(ctx context.Context, data *PermissionImport) (*PermissionImportResult, error) {
	return s.permissionService.ImportPermissions(ctx, data)
}

func (s *service) ValidatePermissionImport(ctx context.Context, data *PermissionImport) (*PermissionImportValidation, error) {
	return s.permissionService.ValidatePermissionImport(ctx, data)
}

// ================================
// ROLE MANAGEMENT (Enhanced from rbac2)
// ================================

func (s *service) CreateRole(ctx context.Context, input model.CreateRoleRequest) (*model.Role, error) {
	return s.roleService.CreateRole(ctx, input)
}

func (s *service) UpdateRole(ctx context.Context, id xid.ID, input model.UpdateRoleRequest) (*model.Role, error) {
	return s.roleService.UpdateRole(ctx, id, input)
}

func (s *service) DeleteRole(ctx context.Context, id xid.ID) error {
	return s.roleService.DeleteRole(ctx, id)
}

func (s *service) GetRole(ctx context.Context, id xid.ID) (*model.Role, error) {
	return s.roleService.GetRole(ctx, id)
}

func (s *service) GetRoleByName(ctx context.Context, name string, roleType model.RoleType, organizationID *xid.ID, applicationID *xid.ID) (*model.Role, error) {
	return s.roleService.GetRoleByName(ctx, name, roleType, organizationID, applicationID)
}

func (s *service) ListRoles(ctx context.Context, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error) {
	return s.roleService.ListRoles(ctx, params)
}

func (s *service) SearchRoles(ctx context.Context, query string, params SearchRolesParams) (*model.PaginatedOutput[*model.Role], error) {
	return s.roleService.SearchRoles(ctx, query, params)
}

// Role type specific operations
func (s *service) GetSystemRoles(ctx context.Context, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error) {
	return s.roleService.GetSystemRoles(ctx, params)
}

func (s *service) GetOrganizationRoles(ctx context.Context, organizationID xid.ID, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error) {
	return s.roleService.GetOrganizationRoles(ctx, organizationID, params)
}

func (s *service) GetApplicationRoles(ctx context.Context, applicationID xid.ID, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error) {
	return s.roleService.GetApplicationRoles(ctx, applicationID, params)
}

// Default role operations
func (s *service) GetDefaultRoles(ctx context.Context, roleType model.RoleType, organizationID *xid.ID, applicationID *xid.ID) ([]*model.Role, error) {
	return s.roleService.GetDefaultRoles(ctx, roleType, organizationID, applicationID)
}

func (s *service) SetAsDefault(ctx context.Context, id xid.ID) error {
	return s.roleService.SetAsDefault(ctx, id)
}

func (s *service) UnsetAsDefault(ctx context.Context, id xid.ID) error {
	return s.roleService.UnsetAsDefault(ctx, id)
}

func (s *service) GetDefaultRoleForUserType(ctx context.Context, userType model.UserType, roleType model.RoleType, organizationID *xid.ID) (*model.Role, error) {
	return s.roleService.GetDefaultRoleForUserType(ctx, userType, roleType, organizationID)
}

// Role hierarchy operations - delegate to hierarchy service
func (s *service) GetRoleHierarchy(ctx context.Context, roleID xid.ID) (*model.RoleHierarchy, error) {
	if s.hierarchyService != nil {
		// return s.hierarchyService.repo(ctx, roleID)
	}
	return s.roleService.GetRoleHierarchy(ctx, roleID)
}

func (s *service) GetRoleAncestors(ctx context.Context, roleID xid.ID) ([]*model.Role, error) {
	return s.roleService.GetRoleAncestors(ctx, roleID)
}

func (s *service) GetRoleDescendants(ctx context.Context, roleID xid.ID) ([]*model.Role, error) {
	return s.roleService.GetRoleDescendants(ctx, roleID)
}

func (s *service) GetRoleChildren(ctx context.Context, roleID xid.ID) ([]*model.Role, error) {
	return s.roleService.GetRoleChildren(ctx, roleID)
}

func (s *service) GetRoleParent(ctx context.Context, roleID xid.ID) (*model.Role, error) {
	return s.roleService.GetRoleParent(ctx, roleID)
}

func (s *service) SetRoleParent(ctx context.Context, roleID, parentID xid.ID) error {
	return s.roleService.SetRoleParent(ctx, roleID, parentID)
}

func (s *service) RemoveRoleParent(ctx context.Context, roleID xid.ID) error {
	return s.roleService.RemoveRoleParent(ctx, roleID)
}

func (s *service) ValidateHierarchy(ctx context.Context, roleID, parentID xid.ID) error {
	return s.roleService.ValidateHierarchy(ctx, roleID, parentID)
}

func (s *service) GetHierarchyDepth(ctx context.Context, roleID xid.ID) (int, error) {
	return s.roleService.GetHierarchyDepth(ctx, roleID)
}

// Role-Permission operations
func (s *service) AddPermissionToRole(ctx context.Context, roleID, permissionID xid.ID) error {
	err := s.roleService.AddPermissionToRole(ctx, roleID, permissionID)

	// Log audit event
	if s.auditService != nil && err == nil {
		s.auditService.LogEvent(ctx, &AuditEvent{
			EventType:  EventTypeRoleManagement,
			Resource:   "role_permission",
			Action:     ActionAssign,
			ResourceID: roleID,
			Context: map[string]interface{}{
				"permission_id": permissionID.String(),
			},
			Success: true,
		})
	}

	return err
}

func (s *service) RemovePermissionFromRole(ctx context.Context, roleID, permissionID xid.ID) error {
	err := s.roleService.RemovePermissionFromRole(ctx, roleID, permissionID)

	// Log audit event
	if s.auditService != nil && err == nil {
		s.auditService.LogEvent(ctx, &AuditEvent{
			EventType:  EventTypeRoleManagement,
			Resource:   "role_permission",
			Action:     ActionRevoke,
			ResourceID: roleID,
			Context: map[string]interface{}{
				"permission_id": permissionID.String(),
			},
			Success: true,
		})
	}

	return err
}

func (s *service) GetRolePermissions(ctx context.Context, roleID xid.ID) ([]*model.Permission, error) {
	return s.roleService.GetRolePermissions(ctx, roleID)
}

func (s *service) GetRoleEffectivePermissions(ctx context.Context, roleID xid.ID) ([]*model.Permission, error) {
	return s.roleService.GetRoleEffectivePermissions(ctx, roleID)
}

func (s *service) RoleHasPermission(ctx context.Context, roleID, permissionID xid.ID) (bool, error) {
	return s.roleService.HasPermission(ctx, roleID, permissionID)
}

func (s *service) BulkAddPermissionsToRole(ctx context.Context, roleID xid.ID, permissionIDs []xid.ID) error {
	return s.roleService.BulkAddPermissionsToRole(ctx, roleID, permissionIDs)
}

func (s *service) BulkRemovePermissionsFromRole(ctx context.Context, roleID xid.ID, permissionIDs []xid.ID) error {
	return s.roleService.BulkRemovePermissionsFromRole(ctx, roleID, permissionIDs)
}

func (s *service) SyncRolePermissions(ctx context.Context, roleID xid.ID, permissionIDs []xid.ID) error {
	return s.roleService.SyncRolePermissions(ctx, roleID, permissionIDs)
}

// ================================
// ENHANCED PERMISSION CHECKING
// ================================

// HasPermissionAdvanced uses the conditional engine if available, falls back to basic checking
func (s *service) HasPermissionAdvanced(ctx context.Context, userID xid.ID, resource, action string) (bool, error) {
	// Try conditional engine first for advanced ABAC
	if s.conditionalEngine != nil {
		decision, err := s.conditionalEngine.EvaluatePermission(ctx, userID, resource, action, nil)
		if err != nil {
			s.logger.Warn("Conditional engine failed, falling back to basic check", logging.Error(err))
		} else {
			// Log the decision
			if s.auditService != nil {
				s.auditService.LogPermissionChecked(ctx, userID, resource, action, decision.Decision == PolicyEffectPermit, nil)
			}
			return decision.Decision == PolicyEffectPermit, nil
		}
	}

	// Fall back to basic permission checking
	return s.enforcer.Enforce(ctx, userID.String(), resource, action)
}

// ================================
// INTEGRATION WITH EXISTING SERVICES
// ================================

// Leverage performance service if available
func (s *service) SetPerformanceService(perfService *PerformanceOptimizedRBACService) {
	s.performanceService = perfService
}

// Example method showing integration
func (s *service) GetUserEffectivePermissions(ctx context.Context, userID xid.ID, contextType model.ContextType, contextID *xid.ID) ([]*model.Permission, error) {
	// Use performance service if available
	if s.performanceService != nil {
		var orgID *xid.ID
		if contextType == model.ContextOrganization && contextID != nil {
			orgID = contextID
		}
		return s.performanceService.GetUserPermissionsOptimized(ctx, userID, orgID)
	}

	// Fall back to repository
	effectiveUserPermissions, err := s.permissionService.GetEffectiveUserPermissions(ctx, userID, contextType, contextID)
	if err != nil {
		return nil, err
	}

	return convertPermissionsToDTO(effectiveUserPermissions), nil
}

// ================================
// HELPER METHODS
// ================================

func (s *service) logOperation(ctx context.Context, operation string, entityType string, entityID xid.ID, success bool, err error) {
	if s.auditService == nil {
		return
	}

	eventType := EventTypeRoleManagement
	if entityType == "permission" {
		eventType = EventTypePermissionManagement
	}

	auditErr := s.auditService.LogEvent(ctx, &AuditEvent{
		EventType:  eventType,
		Resource:   entityType,
		Action:     AuditAction(operation),
		ResourceID: entityID,
		Success:    success,
		ErrorMessage: func() string {
			if err != nil {
				return err.Error()
			}
			return ""
		}(),
	})

	if auditErr != nil {
		s.logger.Warn("Failed to log audit event", logging.Error(auditErr))
	}
}

// ================================
// REMAINING METHODS (Delegate to appropriate services)
// ================================

// Role assignment methods
func (s *service) AssignSystemRole(ctx context.Context, userID xid.ID, roleName string) error {
	return s.roleService.AssignSystemRole(ctx, userID, roleName)
}

func (s *service) AssignOrganizationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	return s.roleService.AssignOrganizationRole(ctx, userID, orgID, roleName)
}

func (s *service) AssignApplicationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	return s.roleService.AssignApplicationRole(ctx, userID, orgID, roleName)
}

func (s *service) RemoveUserRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType model.ContextType, contextID *xid.ID) error {
	return s.roleService.RemoveUserRole(ctx, userID, roleID, contextType, contextID)
}

// Role query methods
func (s *service) GetUserSystemRoles(ctx context.Context, userID xid.ID) ([]*model.Role, error) {
	roles, err := s.roleService.GetUserSystemRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	return convertEntRolesToModel(roles), nil
}

func (s *service) GetUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*model.Role, error) {
	roles, err := s.roleService.GetUserOrganizationRoles(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}
	return convertEntRolesToModel(roles), nil
}

func (s *service) GetUserApplicationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*model.Role, error) {
	roles, err := s.roleService.GetUserApplicationRoles(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}
	return convertEntRolesToModel(roles), nil
}

func (s *service) GetAllUserRoles(ctx context.Context, userID xid.ID) ([]*model.Role, error) {
	_, err := s.roleService.GetAllUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *service) GetRolesByType(ctx context.Context, roleType model.RoleType, orgID *xid.ID) ([]*model.Role, error) {
	roles, err := s.roleService.GetRolesByType(ctx, roleType, orgID)
	if err != nil {
		return nil, err
	}
	return convertEntRolesToModel(roles), nil
}

func (s *service) HasRole(ctx context.Context, userID xid.ID, roleName string, contextType model.ContextType, contextID *xid.ID) (bool, error) {
	return s.roleService.HasRole(ctx, userID, roleName, contextType, contextID)
}

func (s *service) HasAnyRole(ctx context.Context, userID xid.ID, roleNames []string, contextType model.ContextType, contextID *xid.ID) (bool, error) {
	return s.roleService.HasAnyRole(ctx, userID, roleNames, contextType, contextID)
}

// Analytics methods - delegate to analytics service
func (s *service) GetRBACStats(ctx context.Context, organizationID *xid.ID) (*model.RBACStats, error) {
	if s.analyticsService != nil {
		// Use analytics service for comprehensive stats
		analytics, err := s.analyticsService.GeneratePermissionAnalytics(ctx, organizationID, AnalyticsPeriod{
			StartTime: time.Now().AddDate(0, -1, 0), // Last month
			EndTime:   time.Now(),
			Duration:  "30d",
		})
		if err != nil {
			return nil, err
		}

		// Convert to expected format
		return &model.RBACStats{
			TotalRoles:                  analytics.Summary.TotalRoles,
			TotalPermissions:            analytics.Summary.TotalPermissions,
			RoleAssignments:             analytics.Summary.TotalUsers, // Approximate
			DirectPermissionAssignments: 0,                            // Would need additional calculation
		}, nil
	}

	// Fallback to basic stats
	return &model.RBACStats{}, nil
}

func (s *service) GetPermissionUsageStats(ctx context.Context, organizationID *xid.ID) (map[string]int, error) {
	// Implementation using analytics service or basic repository queries
	return map[string]int{}, nil
}

func (s *service) GetRoleUsageStats(ctx context.Context, organizationID *xid.ID) (map[string]int, error) {
	// Implementation using analytics service or basic repository queries
	return map[string]int{}, nil
}
