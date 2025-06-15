package rbac

import (
	"time"

	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// ================================
// PAGINATION PARAMS
// ================================

// Input/Output type definitions

type CreatePermissionGroupInput struct {
	Name        string `json:"name" validate:"required"`
	DisplayName string `json:"displayName" validate:"required"`
	Description string `json:"description,omitempty"`
}

type UpdatePermissionGroupInput struct {
	DisplayName *string `json:"displayName,omitempty"`
	Description *string `json:"description,omitempty"`
}

type BulkPermissionUpdate struct {
	ID    xid.ID                        `json:"id"`
	Input model.UpdatePermissionRequest `json:"input"`
}

type CreateFromTemplateInput struct {
	Name        string            `json:"name" validate:"required"`
	DisplayName string            `json:"displayName,omitempty"`
	Description string            `json:"description,omitempty"`
	Variables   map[string]string `json:"variables,omitempty"`
}

type ClonePermissionInput struct {
	Name        string `json:"name" validate:"required"`
	DisplayName string `json:"displayName,omitempty"`
	Description string `json:"description,omitempty"`
}

type PermissionSetValidation struct {
	IsValid         bool                 `json:"isValid"`
	Conflicts       []PermissionConflict `json:"conflicts"`
	MissingDeps     []string             `json:"missingDependencies"`
	RedundantPerms  []string             `json:"redundantPermissions"`
	Recommendations []string             `json:"recommendations"`
}

type PermissionRiskAnalysis struct {
	OrganizationID       *xid.ID        `json:"organizationId,omitempty"`
	TotalPermissions     int            `json:"totalPermissions"`
	RiskDistribution     map[string]int `json:"riskDistribution"`
	DangerousPermissions []string       `json:"dangerousPermissions"`
	OverPrivilegedRoles  []string       `json:"overPrivilegedRoles"`
	UnusedPermissions    []string       `json:"unusedPermissions"`
	RecommendedActions   []string       `json:"recommendedActions"`
	RiskScore            float64        `json:"riskScore"`
	GeneratedAt          time.Time      `json:"generatedAt"`
}

type PermissionExportFilter struct {
	Categories    []model.ContextType `json:"categories,omitempty"`
	Resources     []string            `json:"resources,omitempty"`
	Groups        []string            `json:"groups,omitempty"`
	IncludeSystem bool                `json:"includeSystem"`
	Format        string              `json:"format"` // json, yaml, csv
}

type PermissionExport struct {
	Permissions []model.Permission `json:"permissions"`
	Metadata    ExportMetadata     `json:"metadata"`
	Format      string             `json:"format"`
	ExportedAt  time.Time          `json:"exportedAt"`
}

type PermissionImport struct {
	Permissions []model.Permission `json:"permissions"`
	Options     ImportOptions      `json:"options"`
}

type PermissionImportResult struct {
	Imported []xid.ID `json:"imported"`
	Skipped  []xid.ID `json:"skipped"`
	Failed   []xid.ID `json:"failed"`
	Errors   []string `json:"errors"`
}

type PermissionImportValidation struct {
	IsValid    bool     `json:"isValid"`
	Errors     []string `json:"errors"`
	Warnings   []string `json:"warnings"`
	WillImport int      `json:"willImport"`
	WillSkip   int      `json:"willSkip"`
	Conflicts  []string `json:"conflicts"`
}

type ExportMetadata struct {
	Version    string    `json:"version"`
	Source     string    `json:"source"`
	ExportedBy string    `json:"exportedBy"`
	ExportedAt time.Time `json:"exportedAt"`
	TotalCount int       `json:"totalCount"`
	Filter     string    `json:"filter"`
}

type ImportOptions struct {
	OverwriteExisting bool `json:"overwriteExisting"`
	SkipConflicts     bool `json:"skipConflicts"`
	CreateGroups      bool `json:"createGroups"`
	DryRun            bool `json:"dryRun"`
}

// ================================
// PERMISSION INPUT TYPES
// ================================
