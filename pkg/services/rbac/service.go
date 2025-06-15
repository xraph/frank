package rbac

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/permissiondependency"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
	"github.com/samber/lo"
)

// Service provides role-based access control operations
type Service interface {

	// ================================
	// BASIC ROLE OPERATIONS (Existing)
	// ================================
	CreateRole(ctx context.Context, roleCreate model.CreateRoleRequest) (*model.Role, error)
	GetRoleByID(ctx context.Context, id xid.ID) (*model.Role, error)
	GetRoleByName(ctx context.Context, name string, roleType model.RoleType, organizationID *xid.ID, applicationID *xid.ID) (*model.Role, error)
	ListRoles(ctx context.Context, input model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error)
	UpdateRole(ctx context.Context, roleID xid.ID, roleUpdate model.UpdateRoleRequest) (*model.Role, error)
	DeleteRole(ctx context.Context, id xid.ID) error
	GetRolesByType(ctx context.Context, roleType model.RoleType, orgID *xid.ID) ([]*model.Role, error)

	// Role existence and validation
	RoleExistsByName(ctx context.Context, name string, roleType model.RoleType, organizationID *xid.ID, applicationID *xid.ID) (bool, error)
	CanDeleteRole(ctx context.Context, roleID xid.ID) (bool, error)
	RoleIsInUse(ctx context.Context, roleID xid.ID) (bool, error)

	// Role hierarchy operations
	GetRoleAncestors(ctx context.Context, roleID xid.ID) ([]*model.Role, error)
	GetRoleDescendants(ctx context.Context, roleID xid.ID) ([]*model.Role, error)
	GetRoleChildren(ctx context.Context, roleID xid.ID) ([]*model.Role, error)
	GetRoleParent(ctx context.Context, roleID xid.ID) (*model.Role, error)
	SetRoleParent(ctx context.Context, roleID, parentID xid.ID) error
	RemoveRoleParent(ctx context.Context, roleID xid.ID) error

	// Default role operations
	GetDefaultRoles(ctx context.Context, roleType model.RoleType, organizationID *xid.ID, applicationID *xid.ID) ([]*model.Role, error)
	SetAsDefault(ctx context.Context, roleID xid.ID) error
	UnsetAsDefault(ctx context.Context, roleID xid.ID) error

	// Role type specific operations
	GetSystemRoles(ctx context.Context, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error)
	GetOrganizationRoles(ctx context.Context, organizationID xid.ID, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error)
	GetApplicationRoles(ctx context.Context, applicationID xid.ID, params model.ListRolesParams) (*model.PaginatedOutput[*model.Role], error)

	// Role search operations
	SearchRoles(ctx context.Context, query string, params SearchRolesParams) (*model.PaginatedOutput[*model.Role], error)

	// Role statistics
	GetRoleStats(ctx context.Context, orgID *xid.ID) (*RoleStats, error)
	GetMostUsedRoles(ctx context.Context, limit int, orgID *xid.ID) ([]*RoleUsage, error)
	GetRoleUserCount(ctx context.Context, roleID xid.ID) (int, error)

	// ================================
	// ROLE ASSIGNMENT METHODS (Enhanced)
	// ================================
	AssignSystemRole(ctx context.Context, userID xid.ID, roleName string) error
	AssignOrganizationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error
	AssignApplicationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error
	RemoveUserRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType model.ContextType, contextID *xid.ID) error

	// ================================
	// ROLE QUERY METHODS (Enhanced)
	// ================================
	GetUserSystemRoles(ctx context.Context, userID xid.ID) ([]*model.Role, error)
	GetUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*model.Role, error)
	GetUserApplicationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*model.Role, error)
	GetAllUserRoles(ctx context.Context, userID xid.ID) ([]*model.Role, error)
	GetUsersWithRole(ctx context.Context, roleID xid.ID) ([]*model.User, error)

	// ================================
	// ROLE CHECKING METHODS (Enhanced)
	// ================================
	HasRole(ctx context.Context, userID xid.ID, roleName string, contextType model.ContextType, contextID *xid.ID) (bool, error)
	HasAnyRole(ctx context.Context, userID xid.ID, roleNames []string, contextType model.ContextType, contextID *xid.ID) (bool, error)
	RoleHasPermission(ctx context.Context, roleID, permissionID xid.ID) (bool, error)
	HasPermission(ctx context.Context, actor, resource, action string) (bool, error)

	// ================================
	// ROLE-PERMISSION OPERATIONS (Enhanced)
	// ================================
	AddPermissionToRole(ctx context.Context, roleID, permissionID xid.ID) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID xid.ID) error
	GetRolePermissions(ctx context.Context, roleID xid.ID) ([]*model.Permission, error)
	ListRolePermissions(ctx context.Context, id xid.ID) ([]*Permission, error)

	// ================================
	// PERMISSION OPERATIONS (Enhanced from rbac2)
	// ================================
	CreatePermission(ctx context.Context, input model.CreatePermissionRequest) (*model.Permission, error)
	GetPermissionByID(ctx context.Context, id xid.ID) (*model.Permission, error)
	GetPermissionByName(ctx context.Context, name string) (*model.Permission, error)
	GetPermissionByResourceAndAction(ctx context.Context, resource, action string) (*model.Permission, error)
	ListPermissions(ctx context.Context, input model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)
	UpdatePermission(ctx context.Context, id xid.ID, input model.UpdatePermissionRequest) (*model.Permission, error)
	DeletePermission(ctx context.Context, id xid.ID) error

	// Permission existence and validation
	PermissionExistsByName(ctx context.Context, name string) (bool, error)
	PermissionExistsByResourceAndAction(ctx context.Context, resource, action string) (bool, error)
	CanDeletePermission(ctx context.Context, permissionID xid.ID) (bool, string, error)
	PermissionIsInUse(ctx context.Context, permissionID xid.ID) (bool, error)

	// Permission categorization
	GetPermissionByCategory(ctx context.Context, category model.ContextType, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)
	GetPermissionByGroup(ctx context.Context, group string, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)
	GetPermissionByResource(ctx context.Context, resource string, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)
	GetSystemPermissions(ctx context.Context, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)
	GetDangerousPermissions(ctx context.Context, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)

	// Permission search operations
	SearchPermission(ctx context.Context, query string, params model.SearchPermissionsParams) (*model.PaginatedOutput[*model.Permission], error)

	// Permission dependencies
	AddPermissionDependency(
		ctx context.Context,
		permissionID, requiredPermissionID xid.ID,
		dependencyType permissiondependency.DependencyType,
		condition string,
	) error
	RemovePermissionDependency(ctx context.Context, permissionID, requiredPermissionID xid.ID) error
	GetPermissionDependencies(ctx context.Context, permissionID xid.ID) ([]*model.Permission, error)
	GetPermissionDependents(ctx context.Context, permissionID xid.ID) ([]*model.Permission, error)

	// Permission statistics and analysis
	GetPermissionStats(ctx context.Context) (*model.PermissionStats, error)
	GetMostUsedPermissions(ctx context.Context, limit int) ([]*model.PermissionUsage, error)
	GetUnusedPermissions(ctx context.Context) ([]*model.Permission, error)
	GetRolesWithPermission(ctx context.Context, permissionID xid.ID) ([]*model.Role, error)

	// ================================
	// USER PERMISSION OPERATIONS (Enhanced)
	// ================================
	GetUserRoles(ctx context.Context, userID xid.ID) ([]*model.Role, error)
	GetUserPermissions(ctx context.Context, userID xid.ID) ([]*model.Permission, error)
	GetUserPermissionsWithContext(ctx context.Context, userID xid.ID, contextType model.ContextType, contextID *xid.ID) ([]*model.Permission, error)
	GetEffectiveUserPermissions(ctx context.Context, userID xid.ID, contextType model.ContextType, contextID *xid.ID) ([]*model.Permission, error)
}

type service struct {
	enforcer           Enforcer
	permissionService  PermissionService // Embedded from rbac2
	roleService        RoleService       // Enhanced with rbac2 functionality
	repo               repository.Repository
	hierarchyService   *RoleHierarchyService
	performanceService *PerformanceOptimizedRBACService
	auditService       *AuditTrailService
	analyticsService   *AnalyticsService
	templateService    *PermissionTemplateService
	discoveryService   *ResourceDiscoveryService
	conditionalEngine  *ConditionalPermissionEngine
	logger             logging.Logger
}

// NewService creates a new RBAC service
func NewService(
	enforcer Enforcer,
	repo repository.Repository,
	hierarchyService *RoleHierarchyService,
	auditService *AuditTrailService,
	analyticsService *AnalyticsService,
	templateService *PermissionTemplateService,
	discoveryService *ResourceDiscoveryService,
	conditionalEngine *ConditionalPermissionEngine,
	logger logging.Logger,
) Service {
	return &service{
		repo:              repo,
		enforcer:          enforcer,
		hierarchyService:  hierarchyService,
		auditService:      auditService,
		analyticsService:  analyticsService,
		templateService:   templateService,
		discoveryService:  discoveryService,
		conditionalEngine: conditionalEngine,
		logger:            logger.Named("rbac-service"),
	}
}

func (s *service) GetRoleByID(ctx context.Context, id xid.ID) (*model.Role, error) {
	return s.roleService.GetRole(ctx, id)
}

func (s *service) RoleExistsByName(ctx context.Context, name string, roleType model.RoleType, organizationID *xid.ID, applicationID *xid.ID) (bool, error) {
	_, err := s.roleService.GetRoleByName(ctx, name, roleType, organizationID, applicationID)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *service) CanDeleteRole(ctx context.Context, roleID xid.ID) (bool, error) {
	canDeleteRole, _, err := s.roleService.CanDeleteRole(ctx, roleID)
	if err != nil {
		return false, err
	}
	return canDeleteRole, nil
}

func (s *service) RoleIsInUse(ctx context.Context, roleID xid.ID) (bool, error) {
	return s.roleService.IsRoleInUse(ctx, roleID)
}

func (s *service) GetRoleStats(ctx context.Context, orgID *xid.ID) (*RoleStats, error) {
	return s.roleService.GetRoleStats(ctx, orgID)
}

func (s *service) GetMostUsedRoles(ctx context.Context, limit int, orgID *xid.ID) ([]*RoleUsage, error) {
	return s.roleService.GetMostUsedRoles(ctx, limit, orgID)
}

func (s *service) GetRoleUserCount(ctx context.Context, roleID xid.ID) (int, error) {
	role, err := s.roleService.GetUsersWithRole(ctx, roleID)
	if err != nil {
		return 0, err
	}

	return len(role), nil
}

func (s *service) GetUsersWithRole(ctx context.Context, roleID xid.ID) ([]*model.User, error) {
	return s.roleService.GetUsersWithRole(ctx, roleID)
}

func (s *service) GetPermissionByID(ctx context.Context, id xid.ID) (*model.Permission, error) {
	return s.permissionService.GetPermission(ctx, id)
}

func (s *service) PermissionExistsByName(ctx context.Context, name string) (bool, error) {
	_, err := s.permissionService.GetPermissionByName(ctx, name)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (s *service) PermissionExistsByResourceAndAction(ctx context.Context, resource, action string) (bool, error) {
	_, err := s.permissionService.GetPermissionByResourceAndAction(ctx, resource, action)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *service) PermissionIsInUse(ctx context.Context, permissionID xid.ID) (bool, error) {
	return s.permissionService.IsPermissionInUse(ctx, permissionID)
}

func (s *service) GetPermissionByCategory(ctx context.Context, category model.ContextType, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	return s.permissionService.GetPermissionsByCategory(ctx, category, params)
}

func (s *service) GetPermissionByGroup(ctx context.Context, group string, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	return s.permissionService.GetPermissionsByGroup(ctx, group, params)
}

func (s *service) GetPermissionByResource(ctx context.Context, resource string, params model.ListPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	return s.permissionService.GetPermissionsByResource(ctx, resource, params)
}

func (s *service) SearchPermission(ctx context.Context, query string, params model.SearchPermissionsParams) (*model.PaginatedOutput[*model.Permission], error) {
	return s.permissionService.SearchPermissions(ctx, query, params)
}

func (s *service) GetRolesWithPermission(ctx context.Context, permissionID xid.ID) ([]*model.Role, error) {
	// todo! fix
	roles, err := s.roleService.ListRoles(ctx, model.ListRolesParams{})
	if err != nil {
		return nil, err
	}

	return roles.Data, err
}

func (s *service) GetUserRoles(ctx context.Context, userID xid.ID) ([]*model.Role, error) {
	userRoles, err := s.roleService.GetAllUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	fmt.Println(userRoles)
	return nil, err
}

func (s *service) GetUserPermissions(ctx context.Context, userID xid.ID) ([]*model.Permission, error) {
	userPermissions, err := s.repo.Permission().GetUserPermissions(ctx, userID, "", nil)
	if err != nil {
		return nil, err
	}

	return convertPermissionsToDTO(userPermissions), err
}

func (s *service) GetUserPermissionsWithContext(ctx context.Context, userID xid.ID, contextType model.ContextType, contextID *xid.ID) ([]*model.Permission, error) {
	userPermissions, err := s.repo.Permission().GetUserPermissions(ctx, userID, contextType, contextID)
	if err != nil {
		return nil, err
	}

	return convertPermissionsToDTO(userPermissions), err
}

func (s *service) GetEffectiveUserPermissions(ctx context.Context, userID xid.ID, contextType model.ContextType, contextID *xid.ID) ([]*model.Permission, error) {
	return s.GetEffectiveUserPermissions(ctx, userID, contextType, contextID)
}

// ================================
// PERMISSION MANAGEMENT
// ================================

func (s *service) ListRolePermissions(ctx context.Context, id xid.ID) ([]*Permission, error) {
	return s.roleService.GetRolePermissions(ctx, id)
}

// ================================
// PERMISSION/ROLE CHECKING
// ================================

func (s *service) HasPermission(ctx context.Context, actor, resource, action string) (bool, error) {
	return s.enforcer.Enforce(ctx, actor, resource, action)
}

// ================================
// CONVERTER FUNCTIONS
// ================================

func convertEntPermissionToModel(entPermission *ent.Permission) *model.Permission {
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

func convertEntRoleToModel(entRole *ent.Role) *model.Role {
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

func convertEntUserToModel(entUser *ent.User) *model.User {
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

func convertPermissionsToDTO(entPermissions []*ent.Permission) []*Permission {
	permissions := make([]*Permission, len(entPermissions))
	for i, entPermission := range entPermissions {
		permissions[i] = convertEntPermissionToModel(entPermission)
	}
	return permissions
}

func convertEntRolesToModel(entRoles []*ent.Role) []*model.Role {
	return lo.Map(entRoles, func(item *ent.Role, index int) *model.Role {
		return convertEntRoleToModel(item)
	})
}

func convertListPermissionDTOToRepo(params model.ListPermissionsParams) repository.ListPermissionsParams {
	repoParams := repository.ListPermissionsParams{
		PaginationParams: params.PaginationParams,
		Resource:         params.Resource,
		Action:           params.Action,
		Search:           params.Search,
	}

	if params.Category != "" {
		repoParams.Category = &params.Category
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
		repoParams.ApplicableUserType = params.ApplicableUserType
	}
	if params.IncludeRoles.IsSet {
		repoParams.IncludeRoles = &params.IncludeRoles.Value
	}
	return repoParams
}
