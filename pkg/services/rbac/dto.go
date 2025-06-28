package rbac

import (
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/model"
)

// ================================
// ROLE INPUT TYPES
// ================================

// AddRolePermissionInput represents the input structure for adding a permission to a role
type AddRolePermissionInput struct {
	PermissionID xid.ID `json:"permissionId" validate:"required"`
}

// PermissionStats represents permission statistics
type PermissionStats struct {
	TotalPermissions     int                       `json:"total_permissions"`
	SystemPermissions    int                       `json:"system_permissions"`
	CustomPermissions    int                       `json:"custom_permissions"`
	DangerousPermissions int                       `json:"dangerous_permissions"`
	CategoryBreakdown    map[model.ContextType]int `json:"category_breakdown"`
	ResourceBreakdown    map[string]int            `json:"resource_breakdown"`
	RiskLevelBreakdown   map[int]int               `json:"risk_level_breakdown"`
	UnusedPermissions    int                       `json:"unused_permissions"`
}

// // PermissionUsage represents permission usage statistics
// type PermissionUsage struct {
// 	Permission *ent.Permission `json:"permission"`
// 	UsageCount int             `json:"usage_count"`
// 	RoleCount  int             `json:"role_count"`
// 	UserCount  int             `json:"user_count"`
// }

// ================================
// PAGINATION PARAMS
// ================================

// ================================
// RESPONSE TYPES
// ================================

// Permission represents a permission entity
type Permission = model.Permission

// ================================
// ROLE ASSIGNMENT TYPES
// ================================

// RoleAssignmentInput represents input for role assignment operations
type RoleAssignmentInput struct {
	UserID   xid.ID `json:"user_id" validate:"required"`
	RoleName string `json:"role_name" validate:"required"`
}

// SystemRoleAssignmentInput represents input for system role assignment
type SystemRoleAssignmentInput struct {
	RoleAssignmentInput
}

// OrganizationRoleAssignmentInput represents input for organization role assignment
type OrganizationRoleAssignmentInput struct {
	RoleAssignmentInput
	OrganizationID xid.ID `json:"organization_id" validate:"required"`
}

// ApplicationRoleAssignmentInput represents input for application role assignment
type ApplicationRoleAssignmentInput struct {
	RoleAssignmentInput
	OrganizationID xid.ID `json:"organization_id" validate:"required"`
}

// RemoveRoleInput represents input for removing role assignments
type RemoveRoleInput struct {
	UserID      xid.ID            `json:"user_id" validate:"required"`
	RoleID      xid.ID            `json:"role_id" validate:"required"`
	ContextType model.ContextType `json:"context_type" validate:"required"` // system, organization, application
	ContextID   *xid.ID           `json:"context_id,omitempty"`
}

// ================================
// ROLE QUERY TYPES
// ================================

// UserRoleQuery represents input for querying user roles
type UserRoleQuery struct {
	UserID         xid.ID         `json:"user_id" validate:"required"`
	OrganizationID *xid.ID        `json:"organization_id,omitempty"`
	RoleType       model.RoleType `json:"role_type,omitempty"` // system, organization, application
}

// RoleCheckInput represents input for role checking operations
type RoleCheckInput struct {
	UserID      xid.ID            `json:"user_id" validate:"required"`
	RoleName    string            `json:"role_name" validate:"required"`
	ContextType model.ContextType `json:"context_type" validate:"required"`
	ContextID   *xid.ID           `json:"context_id,omitempty"`
}

// MultiRoleCheckInput represents input for checking multiple roles
type MultiRoleCheckInput struct {
	UserID      xid.ID            `json:"user_id" validate:"required"`
	RoleNames   []string          `json:"role_names" validate:"required,min=1"`
	ContextType model.ContextType `json:"context_type" validate:"required"`
	ContextID   *xid.ID           `json:"context_id,omitempty"`
}

// ================================
// RESPONSE WRAPPERS
// ================================

// RoleResponse represents a role response with additional metadata
type RoleResponse struct {
	*model.Role
	Permissions []*Permission `json:"permissions,omitempty"`
	UserCount   int           `json:"user_count,omitempty"`
}

// UserRolesResponse represents user roles grouped by context
type UserRolesResponse struct {
	UserID               xid.ID        `json:"user_id"`
	SystemRoles          []*model.Role `json:"system_roles,omitempty"`
	OrganizationRoles    []*model.Role `json:"organization_roles,omitempty"`
	ApplicationRoles     []*model.Role `json:"application_roles,omitempty"`
	EffectivePermissions []*Permission `json:"effective_permissions,omitempty"`
}

// RoleCheckResponse represents the result of a role check
type RoleCheckResponse struct {
	HasRole bool    `json:"has_role"`
	RoleID  *xid.ID `json:"role_id,omitempty"`
}

// MultiRoleCheckResponse represents the result of checking multiple roles
type MultiRoleCheckResponse struct {
	HasAnyRole   bool     `json:"has_any_role"`
	MatchedRoles []string `json:"matched_roles,omitempty"`
}

// ================================
// FILTER AND SORT TYPES
// ================================

// RoleFilter represents filtering options for role queries
type RoleFilter struct {
	Names           []string         `json:"names,omitempty"`
	RoleTypes       []model.RoleType `json:"role_types,omitempty"`
	OrganizationIDs []xid.ID         `json:"organization_ids,omitempty"`
	ApplicationIDs  []xid.ID         `json:"application_ids,omitempty"`
	IsDefault       *bool            `json:"is_default,omitempty"`
	System          *bool            `json:"system,omitempty"`
	Active          *bool            `json:"active,omitempty"`
}

// PermissionFilter represents filtering options for permission queries
type PermissionFilter struct {
	Names     []string `json:"names,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Actions   []string `json:"actions,omitempty"`
	System    *bool    `json:"system,omitempty"`

	IncludeResources []string `json:"include_resources,omitempty"`
	ExcludeResources []string `json:"exclude_resources,omitempty"`
	IncludeActions   []string `json:"include_actions,omitempty"`
	ExcludeActions   []string `json:"exclude_actions,omitempty"`
	RiskLevelMax     int      `json:"risk_level_max,omitempty"`
	Categories       []string `json:"categories,omitempty"`
}

// SortOption represents sorting options
type SortOption struct {
	Field string `json:"field"`
	Desc  bool   `json:"desc,omitempty"`
}

// ================================
// BULK OPERATION TYPES
// ================================

// BulkRoleAssignmentInput represents input for bulk role assignments
type BulkRoleAssignmentInput struct {
	UserIDs        []xid.ID          `json:"user_ids" validate:"required,min=1"`
	RoleNames      []string          `json:"role_names" validate:"required,min=1"`
	OrganizationID *xid.ID           `json:"organization_id,omitempty"`
	ContextType    model.ContextType `json:"context_type" validate:"required"`
}

// BulkRoleRemovalInput represents input for bulk role removals
type BulkRoleRemovalInput struct {
	UserIDs        []xid.ID          `json:"user_ids" validate:"required,min=1"`
	RoleIDs        []xid.ID          `json:"role_ids" validate:"required,min=1"`
	OrganizationID *xid.ID           `json:"organization_id,omitempty"`
	ContextType    model.ContextType `json:"context_type" validate:"required"`
}

// BulkOperationResult represents the result of a bulk operation
type BulkOperationResult struct {
	SuccessCount int      `json:"success_count"`
	FailureCount int      `json:"failure_count"`
	Errors       []string `json:"errors,omitempty"`
}
