package rbac

import (
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/model"
)

// Input/Output type definitions

type SearchRolesParams struct {
	model.PaginationParams
	RoleTypes       []model.RoleType
	OrganizationIDs []xid.ID
	ApplicationIDs  []xid.ID
	UserTypes       []string
	IncludeSystem   bool
	IncludeDefault  bool
	ExcludeInactive bool
	HasPermissions  bool
	HasUsers        bool
}

type CreateRoleFromTemplateInput struct {
	Name           string            `json:"name" validate:"required"`
	DisplayName    string            `json:"displayName,omitempty"`
	Description    string            `json:"description,omitempty"`
	OrganizationID *xid.ID           `json:"organizationId,omitempty"`
	ApplicationID  *xid.ID           `json:"applicationId,omitempty"`
	Variables      map[string]string `json:"variables,omitempty"`
}

type CloneRoleInput struct {
	Name           string  `json:"name" validate:"required"`
	DisplayName    string  `json:"displayName,omitempty"`
	Description    string  `json:"description,omitempty"`
	OrganizationID *xid.ID `json:"organizationId,omitempty"`
	ApplicationID  *xid.ID `json:"applicationId,omitempty"`
	CloneHierarchy bool    `json:"cloneHierarchy"`
	CloneUsers     bool    `json:"cloneUsers"`
}

type BulkRoleUpdate struct {
	ID    xid.ID                  `json:"id"`
	Input model.UpdateRoleRequest `json:"input"`
}

type RoleTemplate struct {
	Name          string            `json:"name"`
	DisplayName   string            `json:"displayName"`
	Description   string            `json:"description"`
	RoleType      model.RoleType    `json:"roleType"`
	Permissions   []string          `json:"permissions"`
	Variables     []string          `json:"variables"`
	UserTypes     []string          `json:"userTypes"`
	Metadata      map[string]string `json:"metadata"`
	Prerequisites []string          `json:"prerequisites"`
}

type RoleStats struct {
	TotalRoles        int            `json:"totalRoles"`
	SystemRoles       int            `json:"systemRoles"`
	OrganizationRoles int            `json:"organizationRoles"`
	ApplicationRoles  int            `json:"applicationRoles"`
	DefaultRoles      int            `json:"defaultRoles"`
	ActiveRoles       int            `json:"activeRoles"`
	UnusedRoles       int            `json:"unusedRoles"`
	RolesByPriority   map[string]int `json:"rolesByPriority"`
	RolesByUserType   map[string]int `json:"rolesByUserType"`
	PermissionCount   map[string]int `json:"permissionCount"`
	UserAssignments   map[string]int `json:"userAssignments"`
	HierarchyDepth    int            `json:"hierarchyDepth"`
	CreatedThisMonth  int            `json:"createdThisMonth"`
	ModifiedThisWeek  int            `json:"modifiedThisWeek"`
}

type RoleUsageStats struct {
	RoleID            xid.ID     `json:"roleId"`
	RoleName          string     `json:"roleName"`
	TotalUsers        int        `json:"totalUsers"`
	ActiveUsers       int        `json:"activeUsers"`
	PendingUsers      int        `json:"pendingUsers"`
	RecentAssignments int        `json:"recentAssignments"`
	PermissionCount   int        `json:"permissionCount"`
	LastUsed          *time.Time `json:"lastUsed"`
	UsageFrequency    string     `json:"usageFrequency"`
	TrendDirection    string     `json:"trendDirection"`
}

type RoleUsage struct {
	Role      *model.Role `json:"role"`
	UserCount int         `json:"userCount"`
	Frequency float64     `json:"frequency"`
	LastUsed  time.Time   `json:"lastUsed"`
}

type RolePermissionMatrix struct {
	Roles       []model.RoleSummary `json:"roles"`
	Permissions []model.Permission  `json:"permissions"`
	Matrix      [][]bool            `json:"matrix"`
	Summary     MatrixSummary       `json:"summary"`
}

type MatrixSummary struct {
	TotalRoles         int     `json:"totalRoles"`
	TotalPermissions   int     `json:"totalPermissions"`
	TotalGrants        int     `json:"totalGrants"`
	AveragePermissions float64 `json:"averagePermissions"`
	MaxPermissions     int     `json:"maxPermissions"`
	MinPermissions     int     `json:"minPermissions"`
}

type RoleComparison struct {
	Role1                *model.Role `json:"role1"`
	Role2                *model.Role `json:"role2"`
	CommonPermissions    []string    `json:"commonPermissions"`
	Role1OnlyPermissions []string    `json:"role1OnlyPermissions"`
	Role2OnlyPermissions []string    `json:"role2OnlyPermissions"`
	Similarity           float64     `json:"similarity"`
	Differences          []string    `json:"differences"`
	Recommendations      []string    `json:"recommendations"`
}

type RoleExportFilter struct {
	RoleTypes          []model.RoleType `json:"roleTypes,omitempty"`
	OrganizationIDs    []xid.ID         `json:"organizationIds,omitempty"`
	ApplicationIDs     []xid.ID         `json:"applicationIds,omitempty"`
	IncludeSystem      bool             `json:"includeSystem"`
	IncludeHierarchy   bool             `json:"includeHierarchy"`
	IncludePermissions bool             `json:"includePermissions"`
	Format             string           `json:"format"` // json, yaml, csv
}

type RoleExport struct {
	Roles    []model.Role   `json:"roles"`
	Metadata ExportMetadata `json:"metadata"`
	Format   string         `json:"format"`
}

type RoleImport struct {
	Roles   []model.Role  `json:"roles"`
	Options ImportOptions `json:"options"`
}

type RoleImportResult struct {
	Imported []xid.ID `json:"imported"`
	Skipped  []xid.ID `json:"skipped"`
	Failed   []xid.ID `json:"failed"`
	Errors   []string `json:"errors"`
}

type RoleImportValidation struct {
	IsValid    bool     `json:"isValid"`
	Errors     []string `json:"errors"`
	Warnings   []string `json:"warnings"`
	WillImport int      `json:"willImport"`
	WillSkip   int      `json:"willSkip"`
	Conflicts  []string `json:"conflicts"`
}
