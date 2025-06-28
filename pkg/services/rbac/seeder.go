package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/authz"
	"github.com/xraph/frank/pkg/data"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// RBACSeeder handles seeding roles and permissions
type RBACSeeder struct {
	client *ent.Client
	logger logging.Logger
}

// NewRBACSeeder creates a new RBAC seeder
func NewRBACSeeder(client *data.Clients, logger logging.Logger) *RBACSeeder {
	return &RBACSeeder{
		client: client.DB,
		logger: logger,
	}
}

// SeedRBACData seeds roles and permissions
func (s *RBACSeeder) SeedRBACData(ctx context.Context) error {
	s.logger.Info("Starting RBAC data seeding...")

	// First, seed all permissions
	permissionMap, err := s.seedPermissions(ctx)
	if err != nil {
		s.logger.Error("Failed to seed permissions", logging.Error(err))
		return fmt.Errorf("failed to seed permissions: %w", err)
	}

	// Then seed roles and assign permissions
	if err := s.seedRoles(ctx, permissionMap); err != nil {
		s.logger.Error("Failed to seed roles", logging.Error(err))
		return fmt.Errorf("failed to seed roles: %w", err)
	}

	s.logger.Info("RBAC data seeding completed successfully")
	return nil
}

// expandRolePermissions expands role permissions to include template permissions, additional permissions, and dependencies
func (s *RBACSeeder) expandRolePermissions(roleDef RoleDefinition) []authz.Permission {
	permissionSet := make(map[authz.Permission]bool)

	// Add base permissions
	for _, perm := range roleDef.Permissions {
		permissionSet[perm] = true
	}

	// Add additional permissions
	for _, perm := range roleDef.AdditionalPermissions {
		permissionSet[perm] = true
	}

	// Add permissions from templates
	for _, templateName := range roleDef.InheritFromTemplates {
		templatePerms := authz.GetPermissionsFromTemplate(templateName)
		for _, perm := range templatePerms {
			permissionSet[perm] = true
		}
	}

	// Convert to slice
	permissions := make([]authz.Permission, 0, len(permissionSet))
	for perm := range permissionSet {
		permissions = append(permissions, perm)
	}

	// Expand with dependencies
	return authz.ExpandPermissionsWithDependencies(permissions)
}

// PermissionDefinition represents a permission with metadata
type PermissionDefinition struct {
	Name            string
	DisplayName     string
	Description     string
	Resource        string
	Action          string
	Category        string
	RiskLevel       int
	Dangerous       bool
	UserTypes       []string
	RequiredContext []string
	System          bool
	PermissionGroup string
}

// Enhanced permission definitions with complete metadata
var AllPermissionDefinitions = authz.AllPermissions

// RoleDefinition represents a role with metadata
type RoleDefinition struct {
	Name                  string
	DisplayName           string
	Description           string
	RoleType              model.RoleType
	OrganizationID        *xid.ID
	ApplicationID         *xid.ID
	System                bool
	IsDefault             bool
	Priority              int
	Color                 string
	ApplicableUserTypes   []model.UserType
	Permissions           []authz.Permission // Base permissions from templates
	AdditionalPermissions []authz.Permission // Additional specific permissions
	ParentRole            string             // Name of parent role for hierarchy
	InheritFromTemplates  []string           // Template names to inherit from
}

// SystemRoles (for internal users - platform staff)
var SystemRoles = []RoleDefinition{
	{
		Name:                "platform_super_admin",
		DisplayName:         "Platform Super Administrator",
		Description:         "Full platform administrative access",
		RoleType:            model.RoleTypeSystem,
		System:              true,
		IsDefault:           false,
		Priority:            100,
		Color:               "#dc2626",
		ApplicableUserTypes: []model.UserType{model.UserTypeInternal},
		Permissions: authz.CombinePermissionTemplates(
			"basic_self_access",
			"platform_read_access",
			"platform_management",
		),
		AdditionalPermissions: []authz.Permission{
			authz.PermissionSystemAdmin,
			authz.PermissionManageSystemSettings,
			authz.PermissionManagePlatform,
			authz.PermissionManageCustomerBilling,
			authz.PermissionSuspendCustomer,
			authz.PermissionViewPlatformAnalytics,
			authz.PermissionDeleteCustomerOrganization,
			authz.PermissionDeleteInternalUser,
		},
	},
	{
		Name:                "platform_admin",
		DisplayName:         "Platform Administrator",
		Description:         "Platform administration with limited destructive access",
		RoleType:            model.RoleTypeSystem,
		System:              true,
		IsDefault:           false,
		Priority:            90,
		Color:               "#ea580c",
		ApplicableUserTypes: []model.UserType{model.UserTypeInternal},
		Permissions: authz.CombinePermissionTemplates(
			"basic_self_access",
			"platform_read_access",
		),
		AdditionalPermissions: []authz.Permission{
			authz.PermissionViewInternalUsers,
			authz.PermissionCreateInternalUser,
			authz.PermissionUpdateInternalUser,
			authz.PermissionCreateCustomerOrganization,
			authz.PermissionUpdateCustomerOrganization,
		},
	},
	{
		Name:                "platform_support",
		DisplayName:         "Platform Support",
		Description:         "Support role for assisting customers",
		RoleType:            model.RoleTypeSystem,
		System:              true,
		IsDefault:           true,
		Priority:            50,
		Color:               "#2563eb",
		ApplicableUserTypes: []model.UserType{model.UserTypeInternal},
		Permissions: authz.CombinePermissionTemplates(
			"basic_self_access",
		),
		AdditionalPermissions: []authz.Permission{
			authz.PermissionViewAllOrganizations,
			authz.PermissionViewAllUsers,
			authz.PermissionViewCustomerOrganizations,
			authz.PermissionViewInternalUsers,
		},
	},
}

// OrganizationRoles Organization Roles (for external users - customer organization members)
var OrganizationRoles = []RoleDefinition{
	{
		Name:                "organization_owner",
		DisplayName:         "Organization Owner",
		Description:         "Full ownership and control of the organization",
		RoleType:            model.RoleTypeOrganization,
		System:              true,
		IsDefault:           false,
		Priority:            100,
		Color:               "#dc2626",
		ApplicableUserTypes: []model.UserType{model.UserTypeExternal},
		Permissions: authz.CombinePermissionTemplates(
			"basic_self_access",
			"organization_basic_management",
			"user_management",
			"end_user_management",
			"security_management",
			"api_management",
			"webhook_management",
		),
		AdditionalPermissions: []authz.Permission{
			// Destructive permissions only for owners
			authz.PermissionDeleteOrganization,
			authz.PermissionRemoveMembers,
			authz.PermissionDeleteUser,
			authz.PermissionDeleteEndUser,
			authz.PermissionBlockEndUser,
			authz.PermissionDeleteAPIKey,
			authz.PermissionDeleteWebhook,

			// RBAC management
			authz.PermissionReadRoles,
			authz.PermissionWriteRole,
			authz.PermissionDeleteRole,
			authz.PermissionAssignRoles,

			// Advanced management
			authz.PermissionManageEndUserSessions,
			authz.PermissionConfigureAuthService,
			authz.PermissionManageAuthServiceDomain,
			authz.PermissionViewAuthServiceAnalytics,
			authz.PermissionDeleteSession,
			authz.PermissionManageMFA,
		},
	},
	{
		Name:                "organization_admin",
		DisplayName:         "Organization Administrator",
		Description:         "Administrative access to the organization without destructive permissions",
		RoleType:            model.RoleTypeOrganization,
		System:              true,
		IsDefault:           false,
		Priority:            90,
		Color:               "#ea580c",
		ApplicableUserTypes: []model.UserType{model.UserTypeExternal},
		ParentRole:          "organization_member",
		Permissions: authz.CombinePermissionTemplates(
			"basic_self_access",
			"organization_basic_management",
			"user_management",
			"end_user_management",
			"security_management",
			"api_management",
			"webhook_management",
		),
		AdditionalPermissions: []authz.Permission{
			// RBAC management (no delete)
			authz.PermissionReadRoles,
			authz.PermissionReadRoles,
			authz.PermissionAssignRoles,

			// Auth service configuration
			authz.PermissionConfigureAuthService,
			authz.PermissionViewAuthServiceAnalytics,
		},
	},
	{
		Name:                "organization_member",
		DisplayName:         "Organization Member",
		Description:         "Standard member access to the organization",
		RoleType:            model.RoleTypeOrganization,
		System:              true,
		IsDefault:           true,
		Priority:            50,
		Color:               "#2563eb",
		ApplicableUserTypes: []model.UserType{model.UserTypeExternal},
		ParentRole:          "organization_viewer",
		Permissions: authz.CombinePermissionTemplates(
			"basic_self_access",
			"organization_viewer",
		),
		AdditionalPermissions: []authz.Permission{
			// Basic user access
			authz.PermissionReadUser,
			authz.PermissionListUsers,

			// Basic end user access
			authz.PermissionViewEndUsers,
			authz.PermissionListEndUsers,

			// View-only access to integrations
			authz.PermissionReadAPIKeys,
			authz.PermissionReadWebhooks,
		},
	},
	{
		Name:                "organization_viewer",
		DisplayName:         "Organization Viewer",
		Description:         "Read-only access to the organization",
		RoleType:            model.RoleTypeOrganization,
		System:              true,
		IsDefault:           false,
		Priority:            10,
		Color:               "#16a34a",
		ApplicableUserTypes: []model.UserType{model.UserTypeExternal},
		Permissions: authz.CombinePermissionTemplates(
			"basic_self_access",
			"organization_viewer",
		),
	},
}

// Application Roles (for end users - auth service users)
var ApplicationRoles = []RoleDefinition{
	{
		Name:                "end_user_admin",
		DisplayName:         "End User Administrator",
		Description:         "Administrative access for end user management",
		RoleType:            model.RoleTypeApplication,
		System:              true,
		IsDefault:           false,
		Priority:            90,
		Color:               "#ea580c",
		ApplicableUserTypes: []model.UserType{model.UserTypeEndUser},
		Permissions: authz.CombinePermissionTemplates(
			"basic_self_access",
		),
		AdditionalPermissions: []authz.Permission{
			// Enhanced self access
			authz.PermissionDeleteSelf,
		},
	},
	{
		Name:                "end_user",
		DisplayName:         "End User",
		Description:         "Standard end user access",
		RoleType:            model.RoleTypeApplication,
		System:              true,
		IsDefault:           true,
		Priority:            50,
		Color:               "#2563eb",
		ApplicableUserTypes: []model.UserType{model.UserTypeEndUser},
		Permissions: authz.CombinePermissionTemplates(
			"basic_self_access",
		),
	},
	{
		Name:                "end_user_readonly",
		DisplayName:         "End User (Read Only)",
		Description:         "Read-only access for end users",
		RoleType:            model.RoleTypeApplication,
		System:              true,
		IsDefault:           false,
		Priority:            10,
		Color:               "#16a34a",
		ApplicableUserTypes: []model.UserType{model.UserTypeEndUser},
		Permissions: []authz.Permission{
			// Minimal self access
			authz.PermissionViewSelf,
			authz.PermissionReadPersonalSessions,
			authz.PermissionViewPersonalMFA,
		},
	},
}

// seedPermissions creates all permissions in the database
func (s *RBACSeeder) seedPermissions(ctx context.Context) (map[string]*ent.Permission, error) {
	s.logger.Info("Seeding permissions...")

	permissionMap := make(map[string]*ent.Permission)

	// Check if permissions already exist
	existingCount, err := s.client.Permission.Query().Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count existing permissions: %w", err)
	}

	if existingCount > 0 {
		s.logger.Info("Permissions already exist, loading existing permissions", logging.Int("count", existingCount))

		// Load existing permissions
		permissions, err := s.client.Permission.Query().All(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load existing permissions: %w", err)
		}

		for _, perm := range permissions {
			permissionMap[perm.Name] = perm
		}

		return permissionMap, nil
	}

	// Create permissions in bulk
	bulk := make([]*ent.PermissionCreate, 0, len(AllPermissionDefinitions))

	for _, def := range AllPermissionDefinitions {
		create := s.client.Permission.Create().
			SetID(xid.New()).
			SetName(def.Name).
			SetDisplayName(def.DisplayName).
			SetDescription(def.Description).
			SetResource(string(def.Resource)).
			SetAction(string(def.Action)).
			SetCategory(def.Category).
			SetRiskLevel(def.RiskLevel).
			SetDangerous(def.Dangerous).
			SetApplicableUserTypes(def.UserTypes).
			SetApplicableContexts(def.RequiredContext).
			SetSystem(def.System).
			SetActive(true).
			SetPermissionGroup(def.Group).
			SetCreatedAt(time.Now()).
			SetUpdatedAt(time.Now())

		bulk = append(bulk, create)
	}

	// Execute bulk creation
	permissions, err := s.client.Permission.CreateBulk(bulk...).Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create permissions: %w", err)
	}

	// Build permission map
	for _, perm := range permissions {
		permissionMap[perm.Name] = perm
	}

	s.logger.Info("Successfully seeded permissions", logging.Int("count", len(permissions)))
	return permissionMap, nil
}

// seedRoles creates all roles and assigns permissions
func (s *RBACSeeder) seedRoles(ctx context.Context, permissionMap map[string]*ent.Permission) error {
	s.logger.Info("Seeding roles...")

	// Check if roles already exist
	existingCount, err := s.client.Role.Query().Count(ctx)
	if err != nil {
		return fmt.Errorf("failed to count existing roles: %w", err)
	}

	if existingCount > 0 {
		s.logger.Info("Roles already exist, skipping role seeding", logging.Int("count", existingCount))
		return nil
	}

	// Seed system roles
	systemRoleMap, err := s.seedSystemRoles(ctx, permissionMap)
	if err != nil {
		return fmt.Errorf("failed to seed system roles: %w", err)
	}

	// Seed organization roles
	orgRoleMap, err := s.seedOrganizationRoles(ctx, permissionMap)
	if err != nil {
		return fmt.Errorf("failed to seed organization roles: %w", err)
	}

	// Seed application roles
	appRoleMap, err := s.seedApplicationRoles(ctx, permissionMap)
	if err != nil {
		return fmt.Errorf("failed to seed application roles: %w", err)
	}

	// Set up role hierarchy
	if err := s.setupRoleHierarchy(ctx, systemRoleMap, orgRoleMap, appRoleMap); err != nil {
		return fmt.Errorf("failed to setup role hierarchy: %w", err)
	}

	totalRoles := len(systemRoleMap) + len(orgRoleMap) + len(appRoleMap)
	s.logger.Info("Successfully seeded all roles", logging.Int("total_count", totalRoles))

	return nil
}

// seedSystemRoles creates system-level roles
func (s *RBACSeeder) seedSystemRoles(ctx context.Context, permissionMap map[string]*ent.Permission) (map[string]*ent.Role, error) {
	s.logger.Info("Seeding system roles...")

	roleMap := make(map[string]*ent.Role)

	for _, roleDef := range SystemRoles {
		// Create role
		roleCreate := s.client.Role.Create().
			SetID(xid.New()).
			SetName(roleDef.Name).
			SetDisplayName(roleDef.DisplayName).
			SetDescription(roleDef.Description).
			SetRoleType(roleDef.RoleType).
			SetSystem(roleDef.System).
			SetIsDefault(roleDef.IsDefault).
			SetPriority(roleDef.Priority).
			SetColor(roleDef.Color).
			SetApplicableUserTypes(roleDef.ApplicableUserTypes).
			SetActive(true).
			SetCreatedAt(time.Now()).
			SetUpdatedAt(time.Now())

		if roleDef.OrganizationID != nil {
			roleCreate.SetOrganizationID(*roleDef.OrganizationID)
		}

		if roleDef.ApplicationID != nil {
			roleCreate.SetApplicationID(*roleDef.ApplicationID)
		}

		role, err := roleCreate.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create system role %s: %w", roleDef.Name, err)
		}

		roleMap[roleDef.Name] = role

		// Assign permissions to role
		allPermissions := s.expandRolePermissions(roleDef)
		for _, permName := range allPermissions {
			perm, exists := permissionMap[string(permName)]
			if !exists {
				s.logger.Warn("Permission not found for role",
					logging.String("role", roleDef.Name),
					logging.String("permission", string(permName)))
				continue
			}

			_, err := s.client.Permission.UpdateOne(perm).
				AddRoleIDs(role.ID).
				Save(ctx)
			if err != nil {
				s.logger.Error("Failed to assign permission to role",
					logging.String("role", roleDef.Name),
					logging.String("permission", string(permName)),
					logging.Error(err))
			}
		}
	}

	s.logger.Info("Successfully seeded system roles", logging.Int("count", len(roleMap)))
	return roleMap, nil
}

// seedOrganizationRoles creates organization-level roles
func (s *RBACSeeder) seedOrganizationRoles(ctx context.Context, permissionMap map[string]*ent.Permission) (map[string]*ent.Role, error) {
	s.logger.Info("Seeding organization roles...")

	roleMap := make(map[string]*ent.Role)

	for _, roleDef := range OrganizationRoles {
		// Create role
		roleCreate := s.client.Role.Create().
			SetID(xid.New()).
			SetName(roleDef.Name).
			SetDisplayName(roleDef.DisplayName).
			SetDescription(roleDef.Description).
			SetRoleType(roleDef.RoleType).
			SetSystem(roleDef.System).
			SetIsDefault(roleDef.IsDefault).
			SetPriority(roleDef.Priority).
			SetColor(roleDef.Color).
			SetApplicableUserTypes(roleDef.ApplicableUserTypes).
			SetActive(true).
			SetCreatedAt(time.Now()).
			SetUpdatedAt(time.Now())

		role, err := roleCreate.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create organization role %s: %w", roleDef.Name, err)
		}

		roleMap[roleDef.Name] = role

		// Assign permissions to role
		allPermissions := s.expandRolePermissions(roleDef)
		for _, permName := range allPermissions {
			perm, exists := permissionMap[string(permName)]
			if !exists {
				s.logger.Warn("Permission not found for role",
					logging.String("role", roleDef.Name),
					logging.String("permission", string(permName)))
				continue
			}

			_, err := s.client.Permission.UpdateOne(perm).
				AddRoleIDs(role.ID).
				Save(ctx)
			if err != nil {
				s.logger.Error("Failed to assign permission to role",
					logging.String("role", roleDef.Name),
					logging.String("permission", string(permName)),
					logging.Error(err))
			}
		}
	}

	s.logger.Info("Successfully seeded organization roles", logging.Int("count", len(roleMap)))
	return roleMap, nil
}

// seedApplicationRoles creates application-level roles
func (s *RBACSeeder) seedApplicationRoles(ctx context.Context, permissionMap map[string]*ent.Permission) (map[string]*ent.Role, error) {
	s.logger.Info("Seeding application roles...")

	roleMap := make(map[string]*ent.Role)

	for _, roleDef := range ApplicationRoles {
		// Create role
		roleCreate := s.client.Role.Create().
			SetID(xid.New()).
			SetName(roleDef.Name).
			SetDisplayName(roleDef.DisplayName).
			SetDescription(roleDef.Description).
			SetRoleType(roleDef.RoleType).
			SetSystem(roleDef.System).
			SetIsDefault(roleDef.IsDefault).
			SetPriority(roleDef.Priority).
			SetColor(roleDef.Color).
			SetApplicableUserTypes(roleDef.ApplicableUserTypes).
			SetActive(true).
			SetCreatedAt(time.Now()).
			SetUpdatedAt(time.Now())

		role, err := roleCreate.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create application role %s: %w", roleDef.Name, err)
		}

		roleMap[roleDef.Name] = role

		// Assign permissions to role
		for _, permName := range roleDef.Permissions {
			perm, exists := permissionMap[string(permName)]
			if !exists {
				s.logger.Warn("Permission not found for role",
					logging.String("role", roleDef.Name),
					logging.String("permission", string(permName)))
				continue
			}

			_, err := s.client.Permission.UpdateOne(perm).
				AddRoleIDs(role.ID).
				Save(ctx)
			if err != nil {
				s.logger.Error("Failed to assign permission to role",
					logging.String("role", roleDef.Name),
					logging.String("permission", string(permName)),
					logging.Error(err))
			}
		}
	}

	s.logger.Info("Successfully seeded application roles", logging.Int("count", len(roleMap)))
	return roleMap, nil
}

// setupRoleHierarchy sets up parent-child relationships between roles
func (s *RBACSeeder) setupRoleHierarchy(ctx context.Context, systemRoles, orgRoles, appRoles map[string]*ent.Role) error {
	s.logger.Info("Setting up role hierarchy...")

	allRoles := make(map[string]*ent.Role)

	// Combine all role maps
	for name, role := range systemRoles {
		allRoles[name] = role
	}
	for name, role := range orgRoles {
		allRoles[name] = role
	}
	for name, role := range appRoles {
		allRoles[name] = role
	}

	// Set up hierarchy for organization roles
	for _, roleDef := range OrganizationRoles {
		if roleDef.ParentRole != "" {
			childRole, childExists := allRoles[roleDef.Name]
			parentRole, parentExists := allRoles[roleDef.ParentRole]

			if childExists && parentExists {
				_, err := s.client.Role.UpdateOneID(childRole.ID).
					SetParentID(parentRole.ID).
					Save(ctx)
				if err != nil {
					s.logger.Error("Failed to set role parent",
						logging.String("child", roleDef.Name),
						logging.String("parent", roleDef.ParentRole),
						logging.Error(err))
				} else {
					s.logger.Debug("Set role hierarchy",
						logging.String("child", roleDef.Name),
						logging.String("parent", roleDef.ParentRole))
				}
			}
		}
	}

	s.logger.Info("Successfully set up role hierarchy")
	return nil
}

// SeedRBAC is the main function to seed RBAC data
func SeedRBAC(ctx context.Context, client *data.Clients, logger logging.Logger) error {
	seeder := NewRBACSeeder(client, logger)
	return seeder.SeedRBACData(ctx)
}
