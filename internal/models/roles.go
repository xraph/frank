package models

import (
	"time"

	"github.com/uptrace/bun"
	"github.com/xraph/frank/pkg/model"
)

// Role model
type Role struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:roles,alias:r"`

	Name                string           `bun:"name,notnull" json:"name"`
	DisplayName         *string          `bun:"display_name" json:"display_name,omitempty"`
	Description         *string          `bun:"description" json:"description,omitempty"`
	RoleType            model.RoleType   `bun:"role_type,notnull" json:"role_type"`
	OrganizationID      *string          `bun:"organization_id,type:varchar(20)" json:"organization_id,omitempty"`
	ApplicationID       *string          `bun:"application_id,type:varchar(20)" json:"application_id,omitempty"`
	System              bool             `bun:"system,notnull,default:false" json:"system"`
	IsDefault           bool             `bun:"is_default,notnull,default:false" json:"is_default"`
	Priority            int              `bun:"priority,notnull,default:0" json:"priority"`
	Color               *string          `bun:"color" json:"color,omitempty"`
	ApplicableUserTypes []model.UserType `bun:"applicable_user_types,type:jsonb" json:"applicable_user_types,omitempty"`
	CreatedBy           *string          `bun:"created_by,type:varchar(20)" json:"created_by,omitempty"`
	Active              bool             `bun:"active,notnull,default:true" json:"active"`
	ParentID            *string          `bun:"parent_id,type:varchar(20)" json:"parent_id,omitempty"`

	// Relations
	Organization    *Organization `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
	UserAssignments []*UserRole   `bun:"rel:has-many,join:id=role_id" json:"user_assignments,omitempty"`
	Memberships     []*Membership `bun:"rel:has-many,join:id=role_id" json:"memberships,omitempty"`
	Permissions     []*Permission `bun:"rel:many-to-many,join:RolePermissions" json:"permissions,omitempty"`
	Parent          *Role         `bun:"rel:belongs-to,join:parent_id=id" json:"parent,omitempty"`
	Children        []*Role       `bun:"rel:has-many,join:id=parent_id" json:"children,omitempty"`
}

// UserRole model - context-aware role assignments
type UserRole struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:user_roles,alias:ur"`

	UserID      string                 `bun:"user_id,notnull,type:varchar(20)" json:"user_id"`
	RoleID      string                 `bun:"role_id,notnull,type:varchar(20)" json:"role_id"`
	ContextType model.ContextType      `bun:"context_type,notnull" json:"context_type"`
	ContextID   *string                `bun:"context_id,type:varchar(20)" json:"context_id,omitempty"`
	AssignedBy  *string                `bun:"assigned_by,type:varchar(20)" json:"assigned_by,omitempty"`
	AssignedAt  time.Time              `bun:"assigned_at,notnull" json:"assigned_at"`
	ExpiresAt   *time.Time             `bun:"expires_at" json:"expires_at,omitempty"`
	Active      bool                   `bun:"active,notnull,default:true" json:"active"`
	Conditions  map[string]interface{} `bun:"conditions,type:jsonb" json:"conditions,omitempty"`

	// Relations
	User                *User         `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	Role                *Role         `bun:"rel:belongs-to,join:role_id=id" json:"role,omitempty"`
	OrganizationContext *Organization `bun:"rel:belongs-to,join:context_id=id" json:"organization_context,omitempty"`
	AssignedByUser      *User         `bun:"rel:belongs-to,join:assigned_by=id" json:"assigned_by_user,omitempty"`
}

// Permission model
type Permission struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:permissions,alias:p"`

	Name                string                   `bun:"name,unique,notnull" json:"name"`
	DisplayName         *string                  `bun:"display_name" json:"display_name,omitempty"`
	Description         string                   `bun:"description,notnull" json:"description"`
	Resource            string                   `bun:"resource,notnull" json:"resource"`
	Action              string                   `bun:"action,notnull" json:"action"`
	Category            model.PermissionCategory `bun:"category,notnull" json:"category"`
	ApplicableUserTypes []model.UserType         `bun:"applicable_user_types,type:jsonb" json:"applicable_user_types,omitempty"`
	ApplicableContexts  []model.ContextType      `bun:"applicable_contexts,type:jsonb" json:"applicable_contexts,omitempty"`
	Conditions          *string                  `bun:"conditions" json:"conditions,omitempty"`
	System              bool                     `bun:"system,notnull,default:false" json:"system"`
	Dangerous           bool                     `bun:"dangerous,notnull,default:false" json:"dangerous"`
	RiskLevel           int                      `bun:"risk_level,notnull,default:1" json:"risk_level"`
	CreatedBy           *string                  `bun:"created_by,type:varchar(20)" json:"created_by,omitempty"`
	Active              bool                     `bun:"active,notnull,default:true" json:"active"`
	PermissionGroup     *model.PermissionGroup   `bun:"permission_group" json:"permission_group,omitempty"`

	// Relations
	Roles                []*Role                 `bun:"rel:many-to-many,join:RolePermissions" json:"roles,omitempty"`
	UserAssignments      []*UserPermission       `bun:"rel:has-many,join:id=permission_id" json:"user_assignments,omitempty"`
	Dependencies         []*PermissionDependency `bun:"rel:has-many,join:id=permission_id" json:"dependencies,omitempty"`
	Dependents           []*PermissionDependency `bun:"rel:has-many,join:id=required_permission_id" json:"dependents,omitempty"`
	RequiredPermissions  []*Permission           `bun:"rel:many-to-many,join:PermissionDependencies" json:"required_permissions,omitempty"`
	DependentPermissions []*Permission           `bun:"rel:many-to-many,join:PermissionDependencies" json:"dependent_permissions,omitempty"`
}

// UserPermission model - direct permission assignments
type UserPermission struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:user_permissions,alias:up"`

	UserID         string                 `bun:"user_id,notnull,type:varchar(20)" json:"user_id"`
	PermissionID   string                 `bun:"permission_id,notnull,type:varchar(20)" json:"permission_id"`
	ContextType    model.ContextType      `bun:"context_type,notnull" json:"context_type"`
	ContextID      *string                `bun:"context_id,type:varchar(20)" json:"context_id,omitempty"`
	ResourceType   *string                `bun:"resource_type" json:"resource_type,omitempty"`
	ResourceID     *string                `bun:"resource_id,type:varchar(20)" json:"resource_id,omitempty"`
	PermissionType model.PermissionType   `bun:"permission_type,notnull,default:'grant'" json:"permission_type"`
	AssignedBy     *string                `bun:"assigned_by,type:varchar(20)" json:"assigned_by,omitempty"`
	AssignedAt     time.Time              `bun:"assigned_at,notnull" json:"assigned_at"`
	ExpiresAt      *time.Time             `bun:"expires_at" json:"expires_at,omitempty"`
	Active         bool                   `bun:"active,notnull,default:true" json:"active"`
	Conditions     map[string]interface{} `bun:"conditions,type:jsonb" json:"conditions,omitempty"`
	Reason         *string                `bun:"reason" json:"reason,omitempty"`

	// Relations
	User                *User         `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	Permission          *Permission   `bun:"rel:belongs-to,join:permission_id=id" json:"permission,omitempty"`
	AssignedByUser      *User         `bun:"rel:belongs-to,join:assigned_by=id" json:"assigned_by_user,omitempty"`
	OrganizationContext *Organization `bun:"rel:belongs-to,join:context_id=id" json:"organization_context,omitempty"`
}

// DependencyType enum
type DependencyType string

const (
	DependencyTypeRequired    DependencyType = "required"
	DependencyTypeImplied     DependencyType = "implied"
	DependencyTypeConditional DependencyType = "conditional"
)

// PermissionDependency model
type PermissionDependency struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:permission_dependencies,alias:pd"`

	PermissionID         string         `bun:"permission_id,notnull,type:varchar(20)" json:"permission_id"`
	RequiredPermissionID string         `bun:"required_permission_id,notnull,type:varchar(20)" json:"required_permission_id"`
	DependencyType       DependencyType `bun:"dependency_type,notnull,default:'required'" json:"dependency_type"`
	Condition            *string        `bun:"condition" json:"condition,omitempty"`
	Active               bool           `bun:"active,notnull,default:true" json:"active"`
	CreatedBy            *string        `bun:"created_by,type:varchar(20)" json:"created_by,omitempty"`

	// Relations
	Permission         *Permission `bun:"rel:belongs-to,join:permission_id=id" json:"permission,omitempty"`
	RequiredPermission *Permission `bun:"rel:belongs-to,join:required_permission_id=id" json:"required_permission,omitempty"`
}

// RolePermission is a join table for many-to-many relationship
type RolePermission struct {
	RoleID       string    `bun:"role_id,pk,type:varchar(20)" json:"role_id"`
	PermissionID string    `bun:"permission_id,pk,type:varchar(20)" json:"permission_id"`
	CreatedAt    time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`

	Role       *Role       `bun:"rel:belongs-to,join:role_id=id"`
	Permission *Permission `bun:"rel:belongs-to,join:permission_id=id"`
}
