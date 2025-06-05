package rbac

import (
	entRole "github.com/juicycleff/frank/ent/role"
	entUserRole "github.com/juicycleff/frank/ent/userrole"
	"github.com/juicycleff/frank/internal/model"
	"github.com/rs/xid"
)

// ================================
// ROLE INPUT TYPES
// ================================

// CreateRoleInput represents enhanced input for creating a role with RoleService functionality
type CreateRoleInput struct {
	Name                string           `json:"name" validate:"required"`
	DisplayName         string           `json:"display_name,omitempty"`
	Description         string           `json:"description,omitempty"`
	RoleType            entRole.RoleType `json:"role_type" validate:"required"` // system, organization, application
	OrganizationID      *xid.ID          `json:"organization_id,omitempty"`
	ApplicationID       *xid.ID          `json:"application_id,omitempty"`
	ApplicableUserTypes []string         `json:"applicable_user_types,omitempty"`
	Permissions         []string         `json:"permissions,omitempty"`
	Priority            int              `json:"priority,omitempty"`
	Color               string           `json:"color,omitempty"`
	IsDefault           bool             `json:"is_default,omitempty"`
	CreatedBy           string           `json:"created_by,omitempty"`
}

// CreateRoleRequest represents the request structure for RoleService
type CreateRoleRequest struct {
	Name                string           `json:"name"`
	DisplayName         string           `json:"display_name"`
	Description         string           `json:"description"`
	RoleType            entRole.RoleType `json:"role_type"` // system, organization, application
	OrganizationID      *xid.ID          `json:"organization_id,omitempty"`
	ApplicationID       *xid.ID          `json:"application_id,omitempty"`
	ApplicableUserTypes []string         `json:"applicable_user_types"`
	Permissions         []string         `json:"permissions"`
	Priority            int              `json:"priority"`
	Color               string           `json:"color,omitempty"`
	CreatedBy           string           `json:"created_by,omitempty"`
}

// Enhanced UpdateRoleBody to include RoleService fields
type UpdateRoleBody struct {
	Name        *string `json:"name,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Description *string `json:"description,omitempty"`
	IsDefault   *bool   `json:"is_default,omitempty"`
	Priority    *int    `json:"priority,omitempty"`
	Color       *string `json:"color,omitempty"`
	Active      *bool   `json:"active,omitempty"`
}

// ================================
// PERMISSION INPUT TYPES
// ================================

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

// AddRolePermissionInput represents the input structure for adding a permission to a role
type AddRolePermissionInput struct {
	PermissionID xid.ID `json:"permissionId" validate:"required"`
}

// ================================
// PAGINATION PARAMS
// ================================

// ListRolesParams represents pagination parameters for roles
type ListRolesParams struct {
	model.PaginationParams
	OrgID    model.OptionalParam[xid.ID]           `json:"org_id" query:"org_id"`
	RoleType model.OptionalParam[entRole.RoleType] `json:"role_type,omitempty" query:"roleType"`
	Search   string                                `json:"search" query:"search"`
}

// ListPermissionsParams represents pagination parameters for permissions
type ListPermissionsParams struct {
	model.PaginationParams
	Resource string `json:"resource" query:"resource"`
	Action   string `json:"action" query:"action"`
	Search   string `json:"search" query:"search"`
}

// ================================
// RESPONSE TYPES
// ================================

// Enhanced Role DTO to include RoleService fields
type Role struct {
	model.Base
	Name           string           `json:"name"`
	DisplayName    string           `json:"display_name,omitempty"`
	Description    string           `json:"description,omitempty"`
	RoleType       entRole.RoleType `json:"role_type,omitempty"`
	IsDefault      bool             `json:"is_default"`
	OrganizationID *xid.ID          `json:"organization_id,omitempty"`
	ApplicationID  *xid.ID          `json:"application_id,omitempty"`
	System         bool             `json:"system"`
	Priority       int              `json:"priority,omitempty"`
	Color          string           `json:"color,omitempty"`
	Active         bool             `json:"active"`
}

// Permission represents a permission entity
type Permission struct {
	model.Base
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Conditions  string `json:"conditions,omitempty"`
}

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
	UserID      xid.ID                  `json:"user_id" validate:"required"`
	RoleID      xid.ID                  `json:"role_id" validate:"required"`
	ContextType entUserRole.ContextType `json:"context_type" validate:"required"` // system, organization, application
	ContextID   *xid.ID                 `json:"context_id,omitempty"`
}

// ================================
// ROLE QUERY TYPES
// ================================

// UserRoleQuery represents input for querying user roles
type UserRoleQuery struct {
	UserID         xid.ID           `json:"user_id" validate:"required"`
	OrganizationID *xid.ID          `json:"organization_id,omitempty"`
	RoleType       entRole.RoleType `json:"role_type,omitempty"` // system, organization, application
}

// RoleCheckInput represents input for role checking operations
type RoleCheckInput struct {
	UserID      xid.ID                  `json:"user_id" validate:"required"`
	RoleName    string                  `json:"role_name" validate:"required"`
	ContextType entUserRole.ContextType `json:"context_type" validate:"required"`
	ContextID   *xid.ID                 `json:"context_id,omitempty"`
}

// MultiRoleCheckInput represents input for checking multiple roles
type MultiRoleCheckInput struct {
	UserID      xid.ID                  `json:"user_id" validate:"required"`
	RoleNames   []string                `json:"role_names" validate:"required,min=1"`
	ContextType entUserRole.ContextType `json:"context_type" validate:"required"`
	ContextID   *xid.ID                 `json:"context_id,omitempty"`
}

// ================================
// RESPONSE WRAPPERS
// ================================

// RoleResponse represents a role response with additional metadata
type RoleResponse struct {
	*Role
	Permissions []*Permission `json:"permissions,omitempty"`
	UserCount   int           `json:"user_count,omitempty"`
}

// UserRolesResponse represents user roles grouped by context
type UserRolesResponse struct {
	UserID               xid.ID        `json:"user_id"`
	SystemRoles          []*Role       `json:"system_roles,omitempty"`
	OrganizationRoles    []*Role       `json:"organization_roles,omitempty"`
	ApplicationRoles     []*Role       `json:"application_roles,omitempty"`
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
	Names           []string           `json:"names,omitempty"`
	RoleTypes       []entRole.RoleType `json:"role_types,omitempty"`
	OrganizationIDs []xid.ID           `json:"organization_ids,omitempty"`
	ApplicationIDs  []xid.ID           `json:"application_ids,omitempty"`
	IsDefault       *bool              `json:"is_default,omitempty"`
	System          *bool              `json:"system,omitempty"`
	Active          *bool              `json:"active,omitempty"`
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
	UserIDs        []xid.ID                `json:"user_ids" validate:"required,min=1"`
	RoleNames      []string                `json:"role_names" validate:"required,min=1"`
	OrganizationID *xid.ID                 `json:"organization_id,omitempty"`
	ContextType    entUserRole.ContextType `json:"context_type" validate:"required"`
}

// BulkRoleRemovalInput represents input for bulk role removals
type BulkRoleRemovalInput struct {
	UserIDs        []xid.ID                `json:"user_ids" validate:"required,min=1"`
	RoleIDs        []xid.ID                `json:"role_ids" validate:"required,min=1"`
	OrganizationID *xid.ID                 `json:"organization_id,omitempty"`
	ContextType    entUserRole.ContextType `json:"context_type" validate:"required"`
}

// BulkOperationResult represents the result of a bulk operation
type BulkOperationResult struct {
	SuccessCount int      `json:"success_count"`
	FailureCount int      `json:"failure_count"`
	Errors       []string `json:"errors,omitempty"`
}
