package model

import (
	"time"

	"github.com/rs/xid"
)

// Role represents a role in the RBAC system
type Role struct {
	Base
	AuditBase
	Name                string         `json:"name" example:"admin" doc:"Role name"`
	DisplayName         string         `json:"displayName,omitempty" example:"Administrator" doc:"Human-readable role name"`
	Description         string         `json:"description,omitempty" example:"Full administrative access" doc:"Role description"`
	RoleType            RoleType       `json:"roleType" example:"organization" doc:"Role type (system, organization, application)"`
	OrganizationID      *xid.ID        `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID (if org-scoped)"`
	ApplicationID       *xid.ID        `json:"applicationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Application ID (if app-scoped)"`
	System              bool           `json:"system" example:"false" doc:"Whether role is system-managed"`
	IsDefault           bool           `json:"isDefault" example:"false" doc:"Whether role is default for new users"`
	Priority            int            `json:"priority" example:"10" doc:"Role priority for hierarchy"`
	Color               string         `json:"color,omitempty" example:"#007bff" doc:"Color for UI display"`
	ApplicableUserTypes []UserType     `json:"applicableUserTypes" example:"[\"external\", \"end_user\"]" doc:"User types this role applies to"`
	Active              bool           `json:"active" example:"true" doc:"Whether role is active"`
	ParentID            *xid.ID        `json:"parentId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Parent role ID for hierarchy"`
	Metadata            map[string]any `json:"metadata,omitempty" example:"{\"key\":\"value\"}" doc:"Metadata for role display"`

	// Relationships
	Permissions     []Permission         `json:"permissions,omitempty" doc:"Permissions assigned to this role"`
	Children        []RoleSummary        `json:"children,omitempty" doc:"Child roles"`
	Parent          *RoleSummary         `json:"parent,omitempty" doc:"Parent role"`
	UserAssignments []RoleAssignment     `json:"userAssignments,omitempty" doc:"User assignments"`
	Organization    *OrganizationSummary `json:"organization,omitempty" doc:"Organization (if org-scoped)"`
}

// Permission represents a permission in the RBAC system
type Permission struct {
	Base
	AuditBase
	Name                string             `json:"name" example:"read:users" doc:"Permission identifier"`
	DisplayName         string             `json:"displayName,omitempty" example:"Read Users" doc:"Human-readable permission name"`
	Description         string             `json:"description" example:"Allow reading user information" doc:"Permission description"`
	Resource            string             `json:"resource" example:"user" doc:"Resource this permission applies to"`
	Action              string             `json:"action" example:"read" doc:"Action this permission allows"`
	Category            PermissionCategory `json:"category" example:"organization" doc:"Permission category"`
	ApplicableUserTypes []UserType         `json:"applicableUserTypes" example:"[\"internal\", \"external\"]" doc:"User types this permission applies to"`
	ApplicableContexts  []ContextType      `json:"applicableContexts" example:"[\"organization\", \"system\"]" doc:"Contexts where permission is valid"`
	Conditions          string             `json:"conditions,omitempty" example:"{\"resource.owner\": \"$user.id\"}" doc:"Conditional access rules"`
	System              bool               `json:"system" example:"false" doc:"Whether permission is system-managed"`
	Dangerous           bool               `json:"dangerous" example:"false" doc:"Whether permission is dangerous"`
	RiskLevel           int                `json:"riskLevel" example:"1" doc:"Risk level (1-5)"`
	Active              bool               `json:"active" example:"true" doc:"Whether permission is active"`
	PermissionGroup     PermissionGroup    `json:"permissionGroup,omitempty" example:"user_management" doc:"Permission group"`

	// Relationships
	Roles        []RoleSummary          `json:"roles,omitempty" doc:"Roles that have this permission"`
	Dependencies []PermissionDependency `json:"dependencies,omitempty" doc:"Permission dependencies"`
}

// PermissionDependency represents a dependency between permissions
type PermissionDependency struct {
	Base
	PermissionID         xid.ID `json:"permissionId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Permission that depends on another"`
	RequiredPermissionID xid.ID `json:"requiredPermissionId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Required permission"`
	DependencyType       string `json:"dependencyType" example:"required" doc:"Dependency type (required, implied, conditional)"`
	Condition            string `json:"condition,omitempty" example:"context.type == 'organization'" doc:"Optional condition"`
	Active               bool   `json:"active" example:"true" doc:"Whether dependency is active"`

	// Relationships
	Permission         *Permission `json:"permission,omitempty" doc:"Dependent permission"`
	RequiredPermission *Permission `json:"requiredPermission,omitempty" doc:"Required permission"`
}

// RoleAssignment represents a user's role assignment
type RoleAssignment struct {
	Base
	UserID      xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	RoleID      xid.ID                 `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	ContextType string                 `json:"contextType" example:"organization" doc:"Assignment context"`
	ContextID   *xid.ID                `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
	AssignedBy  *xid.ID                `json:"assignedBy,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Who assigned the role"`
	AssignedAt  time.Time              `json:"assignedAt" example:"2023-01-01T12:00:00Z" doc:"Assignment timestamp"`
	ExpiresAt   *time.Time             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Assignment expiration"`
	Active      bool                   `json:"active" example:"true" doc:"Whether assignment is active"`
	Conditions  map[string]interface{} `json:"conditions,omitempty" doc:"Assignment conditions"`

	// Relationships
	User     *UserSummary `json:"user,omitempty" doc:"User information"`
	Role     *RoleSummary `json:"role,omitempty" doc:"Role information"`
	Assigner *UserSummary `json:"assigner,omitempty" doc:"User who made assignment"`
}

// PermissionAssignment represents a user's direct permission assignment
type PermissionAssignment struct {
	Base
	UserID         xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	PermissionID   xid.ID                 `json:"permissionId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Permission ID"`
	ContextType    string                 `json:"contextType" example:"organization" doc:"Assignment context"`
	ContextID      *xid.ID                `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
	ResourceType   string                 `json:"resourceType,omitempty" example:"user" doc:"Specific resource type"`
	ResourceID     *xid.ID                `json:"resourceId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Specific resource ID"`
	PermissionType string                 `json:"permissionType" example:"grant" doc:"Permission type (grant, deny)"`
	AssignedBy     *xid.ID                `json:"assignedBy,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Who assigned permission"`
	AssignedAt     time.Time              `json:"assignedAt" example:"2023-01-01T12:00:00Z" doc:"Assignment timestamp"`
	ExpiresAt      *time.Time             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Assignment expiration"`
	Active         bool                   `json:"active" example:"true" doc:"Whether assignment is active"`
	Conditions     map[string]interface{} `json:"conditions,omitempty" doc:"Assignment conditions"`
	Reason         string                 `json:"reason,omitempty" example:"Special project access" doc:"Reason for assignment"`

	// Relationships
	User       *UserSummary `json:"user,omitempty" doc:"User information"`
	Permission *Permission  `json:"permission,omitempty" doc:"Permission information"`
	Assigner   *UserSummary `json:"assigner,omitempty" doc:"User who made assignment"`
}

// CreateRoleRequest represents a request to create a role
type CreateRoleRequest struct {
	Name                string     `json:"name" example:"editor" doc:"Role name"`
	DisplayName         string     `json:"displayName,omitempty" example:"Editor" doc:"Display name"`
	Description         string     `json:"description,omitempty" example:"Can edit content" doc:"Role description"`
	RoleType            RoleType   `json:"roleType" example:"organization" doc:"Role type"`
	OrganizationID      *xid.ID    `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	ApplicationID       *xid.ID    `json:"applicationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Application ID"`
	IsDefault           bool       `json:"isDefault" example:"false" doc:"Set as default role"`
	Priority            int        `json:"priority" example:"5" doc:"Role priority"`
	Color               string     `json:"color,omitempty" example:"#28a745" doc:"Role color"`
	ApplicableUserTypes []UserType `json:"applicableUserTypes" example:"[\"external\"]" doc:"Applicable user types"`
	ParentID            *xid.ID    `json:"parentId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Parent role ID"`
	PermissionIDs       []xid.ID   `json:"permissionIds,omitempty" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Initial permissions"`
	Permissions         []string   `json:"permissions,omitempty"`
	CreatedBy           string     `json:"createdBy,omitempty"`
}

// UpdateRoleRequest represents a request to update a role
type UpdateRoleRequest struct {
	Name                string           `json:"name,omitempty" example:"updated-editor" doc:"Updated name"`
	DisplayName         string           `json:"displayName,omitempty" example:"Updated Editor" doc:"Updated display name"`
	Description         *string          `json:"description,omitempty" example:"Updated description" doc:"Updated description"`
	IsDefault           *bool            `json:"isDefault,omitempty" example:"true" doc:"Updated default status"`
	Priority            *int             `json:"priority,omitempty" example:"10" doc:"Updated priority"`
	Color               *string          `json:"color,omitempty" example:"#007bff" doc:"Updated color"`
	ApplicableUserTypes []UserType       `json:"applicableUserTypes,omitempty" doc:"Updated applicable user types"`
	Active              *bool            `json:"active,omitempty" example:"true" doc:"Updated active status"`
	ParentID            *xid.ID          `json:"parentId,omitempty" doc:"Updated parent role ID"`
	ApplicableContexts  []ContextType    `json:"applicableContexts,omitempty"`
	Conditions          *string          `json:"conditions,omitempty"`
	Dangerous           *bool            `json:"dangerous,omitempty"`
	RiskLevel           *int             `json:"riskLevel,omitempty"`
	PermissionGroup     *PermissionGroup `json:"permissionGroup,omitempty"`
}

// CreatePermissionRequest represents a request to create a permission
type CreatePermissionRequest struct {
	Name                string             `json:"name" example:"create:posts" doc:"Permission identifier"`
	DisplayName         string             `json:"displayName,omitempty" example:"Create Posts" doc:"Display name"`
	Description         string             `json:"description" example:"Allow creating blog posts" doc:"Permission description"`
	Resource            string             `json:"resource" example:"post" doc:"Resource name"`
	Action              string             `json:"action" example:"create" doc:"Action name"`
	Category            PermissionCategory `json:"category" example:"content" doc:"Permission category"`
	ApplicableUserTypes []UserType         `json:"applicableUserTypes" example:"[\"external\", \"end_user\"]" doc:"Applicable user types"`
	ApplicableContexts  []ContextType      `json:"applicableContexts" example:"[\"organization\"]" doc:"Applicable contexts"`
	Conditions          string             `json:"conditions,omitempty" example:"{\"resource.owner\": \"$user.id\"}" doc:"Conditional rules"`
	Dangerous           bool               `json:"dangerous" example:"false" doc:"Whether permission is dangerous"`
	RiskLevel           int                `json:"riskLevel" example:"2" doc:"Risk level (1-5)"`
	PermissionGroup     PermissionGroup    `json:"permissionGroup,omitempty" example:"content_management" doc:"Permission group"`
	System              bool               `json:"system"`
	CreatedBy           *string            `json:"createdBy,omitempty"`
}

// UpdatePermissionRequest represents a request to update a permission
type UpdatePermissionRequest struct {
	Name                string           `json:"name,omitempty"`
	DisplayName         *string          `json:"displayName,omitempty" example:"Updated Create Posts" doc:"Updated display name"`
	Description         *string          `json:"description,omitempty" example:"Updated description" doc:"Updated description"`
	ApplicableUserTypes []UserType       `json:"applicableUserTypes,omitempty" doc:"Updated applicable user types"`
	ApplicableContexts  []ContextType    `json:"applicableContexts,omitempty" doc:"Updated applicable contexts"`
	Conditions          *string          `json:"conditions,omitempty" doc:"Updated conditions"`
	Dangerous           *bool            `json:"dangerous,omitempty" example:"true" doc:"Updated dangerous status"`
	RiskLevel           *int             `json:"riskLevel,omitempty" example:"3" doc:"Updated risk level"`
	Active              *bool            `json:"active,omitempty" example:"true" doc:"Updated active status"`
	PermissionGroup     *PermissionGroup `json:"permissionGroup,omitempty" doc:"Updated permission group"`
}

// AssignRoleToUserRequest represents a request to assign a role to a user
type AssignRoleToUserRequest struct {
	UserID      xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	RoleID      xid.ID                 `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	ContextType ContextType            `json:"contextType" example:"organization" doc:"Assignment context"`
	ContextID   *xid.ID                `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
	ExpiresAt   *time.Time             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Assignment expiration"`
	Conditions  map[string]interface{} `json:"conditions,omitempty" doc:"Assignment conditions"`
}

// AssignPermissionToUserRequest represents a request to assign a permission to a user
type AssignPermissionToUserRequest struct {
	UserID         xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	PermissionID   xid.ID                 `json:"permissionId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Permission ID"`
	ContextType    string                 `json:"contextType" example:"organization" doc:"Assignment context"`
	ContextID      *xid.ID                `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
	ResourceType   string                 `json:"resourceType,omitempty" example:"post" doc:"Resource type"`
	ResourceID     *xid.ID                `json:"resourceId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Resource ID"`
	PermissionType string                 `json:"permissionType" example:"grant" doc:"Permission type (grant, deny)"`
	ExpiresAt      *time.Time             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Assignment expiration"`
	Conditions     map[string]interface{} `json:"conditions,omitempty" doc:"Assignment conditions"`
	Reason         string                 `json:"reason,omitempty" example:"Special project access" doc:"Assignment reason"`
}

// AssignPermissionToRoleRequest represents a request to assign a permission to a role
type AssignPermissionToRoleRequest struct {
	PermissionID xid.ID `json:"permissionId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Permission ID"`
}

// RoleListRequest represents a request to list roles
type RoleListRequest struct {
	PaginationParams
	RoleType        string  `json:"roleType,omitempty" example:"organization" doc:"Filter by role type"`
	OrganizationID  *xid.ID `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization"`
	ApplicationID   *xid.ID `json:"applicationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by application"`
	System          *bool   `json:"system,omitempty" example:"false" doc:"Filter by system status"`
	IsDefault       *bool   `json:"isDefault,omitempty" example:"true" doc:"Filter by default status"`
	Active          *bool   `json:"active,omitempty" example:"true" doc:"Filter by active status"`
	Search          string  `json:"search,omitempty" example:"admin" doc:"Search in name/description"`
	ParentID        *xid.ID `json:"parentId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by parent role"`
	IncludeChildren bool    `json:"includeChildren,omitempty" example:"true" doc:"Include child roles"`
}

// RoleListResponse represents a list of roles
type RoleListResponse = PaginatedOutput[Role]

// PermissionListRequest represents a request to list permissions
type PermissionListRequest struct {
	PaginationParams
	Resource           string              `json:"resource,omitempty" example:"user" doc:"Filter by resource" query:"resource"`
	Action             string              `json:"action,omitempty" example:"read" doc:"Filter by action" query:"action"`
	Category           PermissionCategory  `json:"category,omitempty" example:"organization" doc:"Filter by category" query:"category"`
	System             OptionalParam[bool] `json:"system,omitempty" example:"false" doc:"Filter by system status" query:"system"`
	Dangerous          OptionalParam[bool] `json:"dangerous,omitempty" example:"true" doc:"Filter by dangerous status" query:"dangerous"`
	RiskLevel          OptionalParam[int]  `json:"riskLevel,omitempty" example:"3" doc:"Filter by risk level" query:"riskLevel"`
	Active             OptionalParam[bool] `json:"active,omitempty" example:"true" doc:"Filter by active status" query:"active"`
	PermissionGroup    PermissionGroup     `json:"permissionGroup,omitempty" example:"user_management" doc:"Filter by permission group" query:"permissionGroup"`
	ApplicableUserType UserType            `json:"applicableUserType,omitempty" example:"external" doc:"Filter by applicable user type" query:"applicableUserType"`
	Search             string              `json:"search,omitempty" example:"user" doc:"Search in name/description" query:"search"`
	IncludeRoles       bool                `json:"includeRoles,omitempty" example:"true" doc:"Include associated roles" query:"includeRoles"`
}

// PermissionListResponse represents a list of permissions
type PermissionListResponse = PaginatedOutput[Permission]

// UserPermissionsRequest represents a request to get user permissions
type UserPermissionsRequest struct {
	UserID           xid.ID      `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	ContextType      ContextType `json:"contextType,omitempty" example:"organization" doc:"Filter by context type"`
	ContextID        *xid.ID     `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by context ID"`
	Resource         string      `json:"resource,omitempty" example:"user" doc:"Filter by resource"`
	Action           string      `json:"action,omitempty" example:"read" doc:"Filter by action"`
	IncludeInherited bool        `json:"includeInherited" example:"true" doc:"Include permissions from roles"`
}

// UserPermissionsResponse represents user permissions
type UserPermissionsResponse struct {
	UserID               xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	DirectPermissions    []PermissionAssignment `json:"directPermissions" doc:"Direct permission assignments"`
	RolePermissions      []RolePermission       `json:"rolePermissions" doc:"Permissions from roles"`
	EffectivePermissions []string               `json:"effectivePermissions" example:"[\"read:users\", \"write:posts\"]" doc:"Effective permissions list"`
	DeniedPermissions    []string               `json:"deniedPermissions" example:"[\"delete:system\"]" doc:"Explicitly denied permissions"`
}

// RolePermission represents permissions granted through a role
type RolePermission struct {
	RoleID      xid.ID       `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	RoleName    string       `json:"roleName" example:"admin" doc:"Role name"`
	ContextType string       `json:"contextType" example:"organization" doc:"Role context"`
	ContextID   *xid.ID      `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
	Permissions []Permission `json:"permissions" doc:"Permissions from this role"`
}

// CheckPermissionRequest represents a permission check request
type CheckPermissionRequest struct {
	UserID       xid.ID  `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Permission   string  `json:"permission" example:"read:users" doc:"Permission to check"`
	ContextType  string  `json:"contextType,omitempty" example:"organization" doc:"Context type"`
	ContextID    *xid.ID `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
	ResourceType string  `json:"resourceType,omitempty" example:"user" doc:"Resource type"`
	ResourceID   *xid.ID `json:"resourceId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Resource ID"`
}

// CheckPermissionResponse represents a permission check response
type CheckPermissionResponse struct {
	Allowed   bool       `json:"allowed" example:"true" doc:"Whether permission is allowed"`
	Source    string     `json:"source" example:"role" doc:"Source of permission (role, direct, system)"`
	RoleName  string     `json:"roleName,omitempty" example:"admin" doc:"Role that grants permission"`
	Reason    string     `json:"reason,omitempty" example:"User has admin role in organization" doc:"Reason for decision"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Permission expiration"`
}

// RBACStats represents RBAC statistics
type RBACStats struct {
	TotalRoles                  int            `json:"totalRoles" example:"25" doc:"Total roles"`
	SystemRoles                 int            `json:"systemRoles" example:"5" doc:"System roles"`
	OrganizationRoles           int            `json:"organizationRoles" example:"18" doc:"Organization roles"`
	ApplicationRoles            int            `json:"applicationRoles" example:"2" doc:"Application roles"`
	TotalPermissions            int            `json:"totalPermissions" example:"150" doc:"Total permissions"`
	SystemPermissions           int            `json:"systemPermissions" example:"30" doc:"System permissions"`
	DangerousPermissions        int            `json:"dangerousPermissions" example:"10" doc:"Dangerous permissions"`
	RoleAssignments             int            `json:"roleAssignments" example:"500" doc:"Total role assignments"`
	DirectPermissionAssignments int            `json:"directPermissionAssignments" example:"25" doc:"Direct permission assignments"`
	PermissionsByCategory       map[string]int `json:"permissionsByCategory" example:"{\"system\": 30, \"organization\": 120}" doc:"Permissions by category"`
	RolesByPriority             map[string]int `json:"rolesByPriority" example:"{\"high\": 5, \"medium\": 15, \"low\": 5}" doc:"Roles by priority"`
}

// BulkRoleAssignmentRequest represents a bulk role assignment request
type BulkRoleAssignmentRequest struct {
	UserIDs     []xid.ID               `json:"userIds" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"User IDs"`
	RoleID      xid.ID                 `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	ContextType string                 `json:"contextType" example:"organization" doc:"Assignment context"`
	ContextID   *xid.ID                `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
	ExpiresAt   *time.Time             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Assignment expiration"`
	Conditions  map[string]interface{} `json:"conditions,omitempty" doc:"Assignment conditions"`
}

// BulkRoleAssignmentResponse represents bulk role assignment response
type BulkRoleAssignmentResponse struct {
	Success      []xid.ID `json:"success" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Successful user IDs"`
	Failed       []xid.ID `json:"failed" example:"[]" doc:"Failed user IDs"`
	SuccessCount int      `json:"successCount" example:"5" doc:"Success count"`
	FailureCount int      `json:"failureCount" example:"0" doc:"Failure count"`
	Errors       []string `json:"errors,omitempty" example:"[]" doc:"Error messages"`
}

// RoleHierarchy represents role hierarchy information
type RoleHierarchy struct {
	RoleID   xid.ID          `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	Name     string          `json:"name" example:"manager" doc:"Role name"`
	Level    int             `json:"level" example:"2" doc:"Hierarchy level"`
	Path     []string        `json:"path" example:"[\"admin\", \"manager\"]" doc:"Hierarchy path"`
	Children []RoleHierarchy `json:"children,omitempty" doc:"Child roles"`
	Parent   *RoleSummary    `json:"parent,omitempty" doc:"Parent role"`
}

// PermissionGroupSummary represents a permission group summary
type PermissionGroupSummary struct {
	Name           string `json:"name" example:"user_management" doc:"Group name"`
	DisplayName    string `json:"displayName" example:"User Management" doc:"Group display name"`
	Description    string `json:"description" example:"Permissions for managing users" doc:"Group description"`
	Count          int    `json:"count" example:"15" doc:"Number of permissions in group"`
	DangerousCount int    `json:"dangerousCount" example:"3" doc:"Number of dangerous permissions"`
}

// PermissionDependencyGraph represents permission dependency relationships
type PermissionDependencyGraph struct {
	PermissionID xid.ID                     `json:"permissionId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Permission ID"`
	Name         string                     `json:"name" example:"delete:users" doc:"Permission name"`
	Dependencies []PermissionDependencyNode `json:"dependencies" doc:"Required permissions"`
	Dependents   []PermissionDependencyNode `json:"dependents" doc:"Permissions that depend on this"`
}

// PermissionDependencyNode represents a node in permission dependency graph
type PermissionDependencyNode struct {
	PermissionID   xid.ID `json:"permissionId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Permission ID"`
	Name           string `json:"name" example:"read:users" doc:"Permission name"`
	DependencyType string `json:"dependencyType" example:"required" doc:"Dependency type"`
	Condition      string `json:"condition,omitempty" doc:"Dependency condition"`
}

type PermissionStats struct {
	TotalPermissions     int                        `json:"totalPermissions" doc:"Total permissions"`
	SystemPermissions    int                        `json:"systemPermissions" doc:"System permissions"`
	CustomPermissions    int                        `json:"customPermissions" doc:"Custom permissions"`
	DangerousPermissions int                        `json:"dangerousPermissions" doc:"Dangerous permissions"`
	CategoryBreakdown    map[PermissionCategory]int `json:"categoryBreakdown" doc:"Category breakdown"`
	ResourceBreakdown    map[string]int             `json:"resourceBreakdown" doc:"Resource breakdown"`
	RiskLevelBreakdown   map[int]int                `json:"riskLevelBreakdown" doc:"Risk level breakdown"`
	UnusedPermissions    int                        `json:"unusedPermissions" doc:"Unused permissions"`
}

// PermissionUsage represents permission usage statistics
type PermissionUsage struct {
	Permission *Permission `json:"permission"`
	UsageCount int         `json:"usageCount"`
	RoleCount  int         `json:"roleCount"`
	UserCount  int         `json:"userCount"`
}

type ListRolesParams struct {
	PaginationParams
	RoleType        RoleType
	OrganizationID  OptionalParam[xid.ID]
	ApplicationID   OptionalParam[xid.ID]
	System          OptionalParam[bool]
	IsDefault       OptionalParam[bool]
	Active          OptionalParam[bool]
	Search          string
	ParentID        OptionalParam[xid.ID]
	IncludeChildren bool
}

// ListPermissionsParams represents parameters for listing permissions
type ListPermissionsParams struct {
	PaginationParams
	Category           PermissionCategory  `json:"category,omitempty"`
	Resource           string              `json:"resource,omitempty"`
	Action             string              `json:"action,omitempty"`
	System             OptionalParam[bool] `json:"system,omitempty"`
	Dangerous          OptionalParam[bool] `json:"dangerous,omitempty"`
	RiskLevel          OptionalParam[int]  `json:"riskLevel,omitempty"`
	PermissionGroup    PermissionGroup     `json:"permissionGroup,omitempty"`
	Active             OptionalParam[bool] `json:"active,omitempty"`
	CreatedBy          string              `json:"createdBy,omitempty"`
	ApplicableUserType UserType            `json:"applicableUserType,omitempty"`
	ApplicableContext  ContextType         `json:"applicableContext,omitempty"`
	IncludeRoles       OptionalParam[bool] `json:"include_roles,omitempty"`
	Search             string              `json:"search,omitempty"`
}

// SearchPermissionsParams represents parameters for searching permissions
type SearchPermissionsParams struct {
	PaginationParams
	Resource         string               `json:"resource,omitempty"`
	ExactMatch       bool                 `json:"exact_match"`
	Categories       []PermissionCategory `json:"categories"`
	Resources        []string             `json:"resources"`
	Actions          []string             `json:"actions"`
	RiskLevels       []int                `json:"riskLevels"`
	UserTypes        []UserType           `json:"userTypes"`
	Contexts         []ContextType        `json:"contexts"`
	IncludeSystem    OptionalParam[bool]  `json:"includeSystem,omitempty"`
	IncludeDangerous OptionalParam[bool]  `json:"includeDangerous,omitempty"`
	ExcludeInactive  OptionalParam[bool]  `json:"excludeInactive,omitempty"`
}
