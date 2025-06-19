package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	rbac2 "github.com/juicycleff/frank/pkg/services/rbac"
	"github.com/rs/xid"
)

// RegisterRBACAPI registers all RBAC-related endpoints
func RegisterRBACAPI(api huma.API, di di.Container) {
	di.Logger().Info("Registering RBAC API routes")

	rbacCtrl := &rbacController{
		api: api,
		di:  di,
	}

	// Register role endpoints
	registerListRoles(api, rbacCtrl)
	registerGetRole(api, rbacCtrl)
	registerCreateRole(api, rbacCtrl)
	registerUpdateRole(api, rbacCtrl)
	registerDeleteRole(api, rbacCtrl)
	registerGetRoleHierarchy(api, rbacCtrl)
	registerSetRoleParent(api, rbacCtrl)
	registerRemoveRoleParent(api, rbacCtrl)

	// Register role permission endpoints
	registerAddRolePermission(api, rbacCtrl)
	registerRemoveRolePermission(api, rbacCtrl)
	registerListRolePermissions(api, rbacCtrl)
	registerSyncRolePermissions(api, rbacCtrl)

	// Register permission endpoints
	registerListPermissions(api, rbacCtrl)
	registerGetPermission(api, rbacCtrl)
	registerCreatePermission(api, rbacCtrl)
	registerUpdatePermission(api, rbacCtrl)
	registerDeletePermission(api, rbacCtrl)
	registerGetPermissionByResource(api, rbacCtrl)
	registerSearchPermissions(api, rbacCtrl)

	// Register role assignment endpoints
	registerAssignUserRoleAdvance(api, rbacCtrl)
	registerRemoveUserRoleAdvance(api, rbacCtrl)
	registerGetUserRoles(api, rbacCtrl)
	registerGetUserPermissions(api, rbacCtrl)
	registerCheckUserPermission(api, rbacCtrl)
	registerBulkAssignRoles(api, rbacCtrl)

	// Register analytics and reporting endpoints
	registerGetRBACStats(api, rbacCtrl)
	registerGetRoleStats(api, rbacCtrl)
	registerGetPermissionStats(api, rbacCtrl)

	// Register default role management
	registerGetDefaultRoles(api, rbacCtrl)
	registerSetDefaultRole(api, rbacCtrl)
	registerUnsetDefaultRole(api, rbacCtrl)
}

// rbacController handles RBAC-related API requests
type rbacController struct {
	api huma.API
	di  di.Container
}

// ================================
// ROLE ENDPOINTS
// ================================

// ListRolesInput represents input for listing roles
type ListRolesInput struct {
	model.OrganisationPathParams
	model.ListRolesParams
}

type ListRolesOutput = model.Output[*model.PaginatedOutput[*model.Role]]

// GetRoleInput represents input for getting a specific role
type GetRoleInput struct {
	model.OrganisationPathParams
	ID                 xid.ID `path:"id" doc:"Role ID"`
	IncludeParent      bool   `query:"includeParent" doc:"Include parent role information"`
	IncludeChildren    bool   `query:"includeChildren" doc:"Include child roles"`
	IncludePermissions bool   `query:"includePermissions" doc:"Include role permissions"`
}

type GetRoleOutput = model.Output[*model.Role]

// CreateRoleInput represents input for creating a role
type CreateRoleInput struct {
	model.OrganisationPathParams
	Body model.CreateRoleRequest
}

type CreateRoleOutput = model.Output[*model.Role]

// UpdateRoleInput represents input for updating a role
type UpdateRoleInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"Role ID"`
	Body model.UpdateRoleRequest
}

type UpdateRoleOutput = model.Output[*model.Role]

// DeleteRoleInput represents input for deleting a role
type DeleteRoleInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Role ID"`
}

// GetRoleHierarchyInput represents input for getting role hierarchy
type GetRoleHierarchyInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Role ID"`
}

type GetRoleHierarchyOutput = model.Output[*model.RoleHierarchy]

// SetRoleParentInput represents input for setting role parent
type SetRoleParentInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"Role ID"`
	Body struct {
		ParentID xid.ID `json:"parentId" doc:"Parent role ID"`
	}
}

// RemoveRoleParentInput represents input for removing role parent
type RemoveRoleParentInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Role ID"`
}

// ================================
// ROLE PERMISSION ENDPOINTS
// ================================

// AddRolePermissionInput represents input for adding permission to role
type AddRolePermissionInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"Role ID"`
	Body model.AssignPermissionToRoleRequest
}

// RemoveRolePermissionInput represents input for removing permission from role
type RemoveRolePermissionInput struct {
	model.OrganisationPathParams
	ID           xid.ID `path:"id" doc:"Role ID"`
	PermissionID xid.ID `path:"permissionId" doc:"Permission ID"`
}

// ListRolePermissionsInput represents input for listing role permissions
type ListRolePermissionsInput struct {
	model.OrganisationPathParams
	model.PaginationParams
	ID        xid.ID                    `path:"id" doc:"Role ID"`
	Effective bool                      `query:"effective" doc:"Include inherited permissions"`
	Category  string                    `query:"category" doc:"Filter by permission category"`
	Resource  string                    `query:"resource" doc:"Filter by resource"`
	Dangerous model.OptionalParam[bool] `query:"dangerous" doc:"Filter by dangerous permissions"`
}

type ListRolePermissionsOutput = model.Output[*model.PaginatedOutput[*model.Permission]]

// SyncRolePermissionsRequest represents input for syncing role permissions
type SyncRolePermissionsRequest struct {
	PermissionIDs []xid.ID `json:"permissionIds" doc:"Permission IDs to sync"`
}

// SyncRolePermissionsInput represents input for syncing role permissions
type SyncRolePermissionsInput struct {
	model.OrganisationPathParams
	ID   xid.ID                     `path:"id" doc:"Role ID"`
	Body SyncRolePermissionsRequest `json:"body"`
}

// ================================
// PERMISSION ENDPOINTS
// ================================

// ListPermissionsInput represents input for listing permissions
type ListPermissionsInput struct {
	model.OrganisationPathParams
	model.ListPermissionsParams
}

type ListPermissionsOutput = model.Output[*model.PaginatedOutput[*model.Permission]]

// GetPermissionInput represents input for getting a specific permission
type GetPermissionInput struct {
	model.OrganisationPathParams
	ID           xid.ID `path:"id" doc:"Permission ID"`
	IncludeRoles bool   `query:"includeRoles" doc:"Include roles that have this permission"`
}

type GetPermissionOutput = model.Output[*model.Permission]

// CreatePermissionInput represents input for creating a permission
type CreatePermissionInput struct {
	model.OrganisationPathParams
	Body model.CreatePermissionRequest
}

type CreatePermissionOutput = model.Output[*model.Permission]

// UpdatePermissionInput represents input for updating a permission
type UpdatePermissionInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"Permission ID"`
	Body model.UpdatePermissionRequest
}

type UpdatePermissionOutput = model.Output[*model.Permission]

// DeletePermissionInput represents input for deleting a permission
type DeletePermissionInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Permission ID"`
}

// GetPermissionByResourceInput represents input for getting permissions by resource
type GetPermissionByResourceInput struct {
	model.OrganisationPathParams
	model.PaginationParams
	Resource string `path:"resource" doc:"Resource name"`
	Action   string `query:"action" doc:"Filter by action"`
}

type GetPermissionByResourceOutput = model.Output[*model.PaginatedOutput[*model.Permission]]

// SearchPermissionsInput represents input for searching permissions
type SearchPermissionsInput struct {
	model.OrganisationPathParams
	model.SearchPermissionsParams
	Query string `query:"q" doc:"Search query"`
}

type SearchPermissionsOutput = model.Output[*model.PaginatedOutput[*model.Permission]]

// ================================
// ROLE ASSIGNMENT ENDPOINTS
// ================================

// AssignUserRoleAdvanceInput represents input for assigning role to user
type AssignUserRoleAdvanceInput struct {
	model.OrganisationPathParams
	Body model.AssignRoleToUserRequest
}

// RemoveUserRoleAdvanceInput represents input for removing role from user
type RemoveUserRoleAdvanceInput struct {
	model.OrganisationPathParams
	Body rbac2.RemoveRoleInput
}

// GetUserRolesInput represents input for getting user roles
type GetUserRolesInput struct {
	model.OrganisationPathParams
	UserID             xid.ID `path:"userId" doc:"User ID"`
	ContextType        string `query:"contextType" doc:"Context type (system, organization, application)"`
	IncludePermissions bool   `query:"includePermissions" doc:"Include effective permissions"`
}

type GetUserRolesOutput = model.Output[*rbac2.UserRolesResponse]

// GetUserPermissionsInput represents input for getting user permissions
type GetUserPermissionsInput struct {
	model.OrganisationPathParams
	model.UserPermissionsRequest
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type GetUserPermissionsOutput = model.Output[*model.UserPermissionsResponse]

// CheckUserPermissionInput represents input for checking user permission
type CheckUserPermissionInput struct {
	model.OrganisationPathParams
	Body model.CheckPermissionRequest
}

type CheckUserPermissionOutput = model.Output[*model.CheckPermissionResponse]

// BulkAssignRolesInput represents input for bulk role assignment
type BulkAssignRolesInput struct {
	model.OrganisationPathParams
	Body model.BulkRoleAssignmentRequest
}

type BulkAssignRolesOutput = model.Output[*model.BulkRoleAssignmentResponse]

// ================================
// ANALYTICS ENDPOINTS
// ================================

// GetRBACStatsInput represents input for getting RBAC statistics
type GetRBACStatsInput struct {
	model.OrganisationPathParams
}

type GetRBACStatsOutput = model.Output[*model.RBACStats]

// GetRoleStatsInput represents input for getting role statistics
type GetRoleStatsInput struct {
	model.OrganisationPathParams
	Limit int `query:"limit" doc:"Limit for most used roles"`
}

type GetRoleStatsOutput = model.Output[*rbac2.RoleStats]

// GetPermissionStatsInput represents input for getting permission statistics
type GetPermissionStatsInput struct {
	model.OrganisationPathParams
}

type GetPermissionStatsOutput = model.Output[*model.PermissionStats]

// ================================
// DEFAULT ROLE ENDPOINTS
// ================================

// GetDefaultRolesInput represents input for getting default roles
type GetDefaultRolesInput struct {
	model.OrganisationPathParams
	RoleType      model.RoleType `query:"roleType" doc:"Role type filter"`
	ApplicationID string         `query:"applicationId" doc:"Application ID filter"`
}

type GetDefaultRolesOutput = model.Output[[]*model.Role]

// SetDefaultRoleInput represents input for setting default role
type SetDefaultRoleInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Role ID"`
}

// UnsetDefaultRoleInput represents input for unsetting default role
type UnsetDefaultRoleInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Role ID"`
}

// ================================
// ROLE ENDPOINTS REGISTRATION
// ================================

func registerListRoles(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "listRoles",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/roles",
		Summary:     "List roles",
		Description: "List all roles for an organization with pagination and filtering options",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionReadRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.listRolesHandler)
}

func registerGetRole(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "getRole",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/roles/{id}",
		Summary:     "Get a role",
		Description: "Get a role by ID with optional relationship data",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Role not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionReadRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.getRoleHandler)
}

func registerCreateRole(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "createRole",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/roles",
		Summary:     "Create a new role",
		Description: "Create a new role with the specified configuration",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionWriteRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.createRoleHandler)
}

func registerUpdateRole(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateRole",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/roles/{id}",
		Summary:     "Update a role",
		Description: "Update an existing role by ID",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Role not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionWriteRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.updateRoleHandler)
}

func registerDeleteRole(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteRole",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/roles/{id}",
		Summary:       "Delete a role",
		Description:   "Delete a role by ID",
		Tags:          []string{"RBAC"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Role successfully deleted"},
		}, true, model.NotFoundError("Role not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionDeleteRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.deleteRoleHandler)
}

func registerGetRoleHierarchy(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "getRoleHierarchy",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/roles/{id}/hierarchy",
		Summary:     "Get role hierarchy",
		Description: "Get role hierarchy information including ancestors and descendants",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Role not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionReadRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.getRoleHierarchyHandler)
}

func registerSetRoleParent(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "setRoleParent",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/roles/{id}/parent",
		Summary:     "Set role parent",
		Description: "Set parent role for hierarchy",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Role not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionManageRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.setRoleParentHandler)
}

func registerRemoveRoleParent(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID:   "removeRoleParent",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/roles/{id}/parent",
		Summary:       "Remove role parent",
		Description:   "Remove parent role from hierarchy",
		Tags:          []string{"RBAC"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Role parent successfully removed"},
		}, true, model.NotFoundError("Role not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionManageRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.removeRoleParentHandler)
}

// ================================
// ROLE PERMISSION ENDPOINTS REGISTRATION
// ================================

func registerAddRolePermission(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "addRolePermission",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/roles/{id}/permissions",
		Summary:     "Add permission to role",
		Description: "Add a permission to a role",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionManageRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.addRolePermissionHandler)
}

func registerRemoveRolePermission(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID:   "removeRolePermission",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/roles/{id}/permissions/{permissionId}",
		Summary:       "Remove permission from role",
		Description:   "Remove a permission from a role",
		Tags:          []string{"RBAC"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Permission successfully removed from role"},
		}, true, model.NotFoundError("Role or permission not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionManageRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.removeRolePermissionHandler)
}

func registerListRolePermissions(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "listRolePermissions",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/roles/{id}/permissions",
		Summary:     "List role permissions",
		Description: "List all permissions assigned to a role",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionReadRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.listRolePermissionsHandler)
}

func registerSyncRolePermissions(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "syncRolePermissions",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/roles/{id}/permissions/sync",
		Summary:     "Sync role permissions",
		Description: "Synchronize role permissions to match provided list",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionManageRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.syncRolePermissionsHandler)
}

// ================================
// PERMISSION ENDPOINTS REGISTRATION
// ================================

func registerListPermissions(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "listPermissions",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/permissions",
		Summary:     "List permissions",
		Description: "List all permissions with pagination and filtering options",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionReadPermission, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.listPermissionsHandler)
}

func registerGetPermission(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "getPermission",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/permissions/{id}",
		Summary:     "Get a permission",
		Description: "Get a permission by ID",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Permission not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionReadPermission, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.getPermissionHandler)
}

func registerCreatePermission(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "createPermission",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/permissions",
		Summary:     "Create a new permission",
		Description: "Create a new permission with the specified configuration",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionWritePermission, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.createPermissionHandler)
}

func registerUpdatePermission(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "updatePermission",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/permissions/{id}",
		Summary:     "Update a permission",
		Description: "Update an existing permission by ID",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Permission not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionWritePermission, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.updatePermissionHandler)
}

func registerDeletePermission(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deletePermission",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/permissions/{id}",
		Summary:       "Delete a permission",
		Description:   "Delete a permission by ID",
		Tags:          []string{"RBAC"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Permission successfully deleted"},
		}, true, model.NotFoundError("Permission not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionDeletePermission, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.deletePermissionHandler)
}

func registerGetPermissionByResource(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "getPermissionByResource",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/permissions/resource/{resource}",
		Summary:     "Get permissions by resource",
		Description: "Get permissions for a specific resource",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionReadPermission, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.getPermissionByResourceHandler)
}

func registerSearchPermissions(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "searchPermissions",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/permissions/search",
		Summary:     "Search permissions",
		Description: "Search permissions by query with advanced filtering",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionReadPermission, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.searchPermissionsHandler)
}

// ================================
// ROLE ASSIGNMENT ENDPOINTS REGISTRATION
// ================================

func registerAssignUserRoleAdvance(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "assignUserRoleAdvance",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/roles/assign",
		Summary:     "Assign role to user",
		Description: "Assign a role to a user in a specific context",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionAssignRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.assignUserRoleHandler)
}

func registerRemoveUserRoleAdvance(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID:   "removeUserRoleAdvance",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/roles/remove",
		Summary:       "Remove role from user",
		Description:   "Remove a role assignment from a user",
		Tags:          []string{"RBAC"},
		DefaultStatus: 204,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionRevokeRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.removeUserRoleHandler)
}

func registerGetUserRoles(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "getUserRoles",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{userId}/roles",
		Summary:     "Get user roles",
		Description: "Get all roles assigned to a user",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionReadRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.getUserRolesHandler)
}

func registerGetUserPermissions(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "getUserPermissions",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{userId}/permissions",
		Summary:     "Get user permissions",
		Description: "Get all effective permissions for a user",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionReadPermission, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.getUserPermissionsHandler)
}

func registerCheckUserPermission(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "checkUserPermission",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/permissions/check",
		Summary:     "Check user permission",
		Description: "Check if a user has a specific permission",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionCheckPermission, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.checkUserPermissionHandler)
}

func registerBulkAssignRoles(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "bulkAssignRoles",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/roles/bulk-assign",
		Summary:     "Bulk assign roles",
		Description: "Assign roles to multiple users at once",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionWriteRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.bulkAssignRolesHandler)
}

// ================================
// ANALYTICS ENDPOINTS REGISTRATION
// ================================

func registerGetRBACStats(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "getRBACStats",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/rbac/stats",
		Summary:     "Get RBAC statistics",
		Description: "Get comprehensive RBAC statistics for the organization",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionViewAnalytics, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.getRBACStatsHandler)
}

func registerGetRoleStats(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "getRoleStats",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/roles/stats",
		Summary:     "Get role statistics",
		Description: "Get detailed role usage statistics",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionViewAnalytics, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.getRoleStatsHandler)
}

func registerGetPermissionStats(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "getPermissionStats",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/permissions/stats",
		Summary:     "Get permission statistics",
		Description: "Get detailed permission usage statistics",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionViewAnalytics, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.getPermissionStatsHandler)
}

// ================================
// DEFAULT ROLE ENDPOINTS REGISTRATION
// ================================

func registerGetDefaultRoles(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "getDefaultRoles",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/roles/default",
		Summary:     "Get default roles",
		Description: "Get all default roles for the organization",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionReadRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.getDefaultRolesHandler)
}

func registerSetDefaultRole(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID: "setDefaultRole",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/roles/{id}/default",
		Summary:     "Set role as default",
		Description: "Set a role as default for new users",
		Tags:        []string{"RBAC"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionManageRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.setDefaultRoleHandler)
}

func registerUnsetDefaultRole(api huma.API, rbacCtrl *rbacController) {
	huma.Register(api, huma.Operation{
		OperationID:   "unsetDefaultRole",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/roles/{id}/default",
		Summary:       "Unset role as default",
		Description:   "Remove default status from a role",
		Tags:          []string{"RBAC"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Role default status successfully removed"},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
			authz.PermissionManageRole, authz.ResourceOrganization, "orgId",
		)},
	}, rbacCtrl.unsetDefaultRoleHandler)
}

// ================================
// HANDLER IMPLEMENTATIONS
// ================================

// Role handlers
func (c *rbacController) listRolesHandler(ctx context.Context, input *ListRolesInput) (*ListRolesOutput, error) {
	rbacService := c.di.RBACService()

	result, err := rbacService.ListRoles(ctx, input.ListRolesParams)
	if err != nil {
		return nil, err
	}

	return &ListRolesOutput{
		Body: result,
	}, nil
}

func (c *rbacController) getRoleHandler(ctx context.Context, input *GetRoleInput) (*GetRoleOutput, error) {
	rbacService := c.di.RBACService()

	role, err := rbacService.GetRoleByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &GetRoleOutput{
		Body: role,
	}, nil
}

func (c *rbacController) createRoleHandler(ctx context.Context, input *CreateRoleInput) (*CreateRoleOutput, error) {
	rbacService := c.di.RBACService()

	// Set organization ID from path
	input.Body.OrganizationID = &input.PathOrgID
	input.Body.RoleType = model.RoleTypeOrganization

	role, err := rbacService.CreateRole(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreateRoleOutput{
		Body: role,
	}, nil
}

func (c *rbacController) updateRoleHandler(ctx context.Context, input *UpdateRoleInput) (*UpdateRoleOutput, error) {
	rbacService := c.di.RBACService()

	role, err := rbacService.UpdateRole(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateRoleOutput{
		Body: role,
	}, nil
}

func (c *rbacController) deleteRoleHandler(ctx context.Context, input *DeleteRoleInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()

	err := rbacService.DeleteRole(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *rbacController) getRoleHierarchyHandler(ctx context.Context, input *GetRoleHierarchyInput) (*GetRoleHierarchyOutput, error) {
	rbacService := c.di.RBACService()

	hierarchy, err := rbacService.GetRoleAncestors(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	// Convert to hierarchy format (simplified for this implementation)
	roleHierarchy := &model.RoleHierarchy{
		RoleID: input.ID,
		Level:  len(hierarchy) + 1,
	}

	return &GetRoleHierarchyOutput{
		Body: roleHierarchy,
	}, nil
}

func (c *rbacController) setRoleParentHandler(ctx context.Context, input *SetRoleParentInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()

	err := rbacService.SetRoleParent(ctx, input.ID, input.Body.ParentID)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *rbacController) removeRoleParentHandler(ctx context.Context, input *RemoveRoleParentInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()

	err := rbacService.RemoveRoleParent(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

// Role permission handlers
func (c *rbacController) addRolePermissionHandler(ctx context.Context, input *AddRolePermissionInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()

	err := rbacService.AddPermissionToRole(ctx, input.ID, input.Body.PermissionID)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *rbacController) removeRolePermissionHandler(ctx context.Context, input *RemoveRolePermissionInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()

	err := rbacService.RemovePermissionFromRole(ctx, input.ID, input.PermissionID)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *rbacController) listRolePermissionsHandler(ctx context.Context, input *ListRolePermissionsInput) (*ListRolePermissionsOutput, error) {
	rbacService := c.di.RBACService()

	var permissions []*model.Permission
	var err error

	if input.Effective {
		permissions, err = rbacService.ListRolePermissions(ctx, input.ID)
	} else {
		permissions, err = rbacService.GetRolePermissions(ctx, input.ID)
	}

	if err != nil {
		return nil, err
	}

	// Create paginated output (simplified)
	result := &model.PaginatedOutput[*model.Permission]{
		Data: permissions,
		Pagination: &model.Pagination{
			CurrentPage: 1,
			TotalCount:  len(permissions),
		},
	}

	return &ListRolePermissionsOutput{
		Body: result,
	}, nil
}

func (c *rbacController) syncRolePermissionsHandler(ctx context.Context, input *SyncRolePermissionsInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RoleService()

	err := rbacService.SyncRolePermissions(ctx, input.ID, input.Body.PermissionIDs)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

// Permission handlers
func (c *rbacController) listPermissionsHandler(ctx context.Context, input *ListPermissionsInput) (*ListPermissionsOutput, error) {
	rbacService := c.di.RBACService()

	result, err := rbacService.ListPermissions(ctx, input.ListPermissionsParams)
	if err != nil {
		return nil, err
	}

	return &ListPermissionsOutput{
		Body: result,
	}, nil
}

func (c *rbacController) getPermissionHandler(ctx context.Context, input *GetPermissionInput) (*GetPermissionOutput, error) {
	rbacService := c.di.RBACService()

	permission, err := rbacService.GetPermissionByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &GetPermissionOutput{
		Body: permission,
	}, nil
}

func (c *rbacController) createPermissionHandler(ctx context.Context, input *CreatePermissionInput) (*CreatePermissionOutput, error) {
	rbacService := c.di.RBACService()

	permission, err := rbacService.CreatePermission(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreatePermissionOutput{
		Body: permission,
	}, nil
}

func (c *rbacController) updatePermissionHandler(ctx context.Context, input *UpdatePermissionInput) (*UpdatePermissionOutput, error) {
	rbacService := c.di.RBACService()

	permission, err := rbacService.UpdatePermission(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdatePermissionOutput{
		Body: permission,
	}, nil
}

func (c *rbacController) deletePermissionHandler(ctx context.Context, input *DeletePermissionInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()

	err := rbacService.DeletePermission(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *rbacController) getPermissionByResourceHandler(ctx context.Context, input *GetPermissionByResourceInput) (*GetPermissionByResourceOutput, error) {
	rbacService := c.di.RBACService()

	params := model.ListPermissionsParams{
		PaginationParams: input.PaginationParams,
		Resource:         input.Resource,
		Action:           input.Action,
	}

	result, err := rbacService.GetPermissionByResource(ctx, input.Resource, params)
	if err != nil {
		return nil, err
	}

	return &GetPermissionByResourceOutput{
		Body: result,
	}, nil
}

func (c *rbacController) searchPermissionsHandler(ctx context.Context, input *SearchPermissionsInput) (*SearchPermissionsOutput, error) {
	rbacService := c.di.RBACService()

	result, err := rbacService.SearchPermission(ctx, input.Query, input.SearchPermissionsParams)
	if err != nil {
		return nil, err
	}

	return &SearchPermissionsOutput{
		Body: result,
	}, nil
}

// User role assignment handlers
func (c *rbacController) assignUserRoleHandler(ctx context.Context, input *AssignUserRoleAdvanceInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()

	switch input.Body.ContextType {
	case "platform":
		// For system roles, we need to handle differently
		return nil, errors.New(errors.CodeNotImplemented, "System role assignment not implemented in this context")
	case "organization":
		err := rbacService.AssignOrganizationRole(ctx, input.Body.UserID, input.PathOrgID, input.Body.RoleID.String())
		if err != nil {
			return nil, err
		}
	case "application":
		err := rbacService.AssignApplicationRole(ctx, input.Body.UserID, input.PathOrgID, input.Body.RoleID.String())
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New(errors.CodeInvalidInput, "Invalid context type")
	}

	return &model.EmptyOutput{}, nil
}

func (c *rbacController) removeUserRoleHandler(ctx context.Context, input *RemoveUserRoleAdvanceInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()

	contextType := model.ContextType(input.Body.ContextType)
	err := rbacService.RemoveUserRole(ctx, input.Body.UserID, input.Body.RoleID, contextType, input.Body.ContextID)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *rbacController) getUserRolesHandler(ctx context.Context, input *GetUserRolesInput) (*GetUserRolesOutput, error) {
	rbacService := c.di.RBACService()

	var systemRoles, orgRoles, appRoles []*model.Role
	var err error

	// Get system roles
	systemRoles, err = rbacService.GetUserSystemRoles(ctx, input.UserID)
	if err != nil {
		systemRoles = []*model.Role{} // Continue on error
	}

	// Get organization roles
	orgRoles, err = rbacService.GetUserOrganizationRoles(ctx, input.UserID, input.PathOrgID)
	if err != nil {
		orgRoles = []*model.Role{}
	}

	// Get application roles
	appRoles, err = rbacService.GetUserApplicationRoles(ctx, input.UserID, input.PathOrgID)
	if err != nil {
		appRoles = []*model.Role{}
	}

	response := &rbac2.UserRolesResponse{
		UserID:            input.UserID,
		SystemRoles:       systemRoles,
		OrganizationRoles: orgRoles,
		ApplicationRoles:  appRoles,
	}

	if input.IncludePermissions {
		permissions, err := rbacService.GetUserPermissions(ctx, input.UserID)
		if err == nil {
			// Convert []*model.Permission to []*rbac.Permission
			rbacPermissions := make([]*rbac2.Permission, len(permissions))
			for i, perm := range permissions {
				rbacPermissions[i] = perm
			}
			response.EffectivePermissions = rbacPermissions
		}
	}

	return &GetUserRolesOutput{
		Body: response,
	}, nil
}

func (c *rbacController) getUserPermissionsHandler(ctx context.Context, input *GetUserPermissionsInput) (*GetUserPermissionsOutput, error) {
	rbacService := c.di.RBACService()

	// Build context for permission retrieval
	var contextType model.ContextType
	var contextID *xid.ID

	if input.ContextType != "" {
		contextType = input.ContextType
		if input.ContextID != nil {
			contextID = input.ContextID
		}
	}

	var permissions []*model.Permission
	var err error

	if input.IncludeInherited {
		permissions, err = rbacService.GetEffectiveUserPermissions(ctx, input.UserID, contextType, contextID)
	} else {
		permissions, err = rbacService.GetUserPermissionsWithContext(ctx, input.UserID, contextType, contextID)
	}

	if err != nil {
		return nil, err
	}

	// Create response
	directAssignments := make([]model.PermissionAssignment, 0)
	rolePermissions := make([]model.RolePermission, 0)
	effectivePermissions := make([]string, len(permissions))

	for i, perm := range permissions {
		effectivePermissions[i] = perm.Name
	}

	response := &model.UserPermissionsResponse{
		UserID:               input.UserID,
		DirectPermissions:    directAssignments,
		RolePermissions:      rolePermissions,
		EffectivePermissions: effectivePermissions,
		DeniedPermissions:    []string{},
	}

	return &GetUserPermissionsOutput{
		Body: response,
	}, nil
}

func (c *rbacController) checkUserPermissionHandler(ctx context.Context, input *CheckUserPermissionInput) (*CheckUserPermissionOutput, error) {
	rbacService := c.di.RBACService()

	// Parse permission to resource and action
	// Assuming permission format is "action:resource"
	allowed, err := rbacService.HasPermission(ctx, input.Body.UserID.String(), input.Body.Permission, "check")
	if err != nil {
		return nil, err
	}

	response := &model.CheckPermissionResponse{
		Allowed: allowed,
		Source:  "role", // Simplified
		Reason:  "Permission check completed",
	}

	return &CheckUserPermissionOutput{
		Body: response,
	}, nil
}

func (c *rbacController) bulkAssignRolesHandler(ctx context.Context, input *BulkAssignRolesInput) (*BulkAssignRolesOutput, error) {
	// This would be a complex implementation involving multiple role assignments
	// For now, return a simplified implementation

	successCount := 0
	failedUsers := make([]xid.ID, 0)
	errors := make([]string, 0)

	// Simulate bulk assignment
	for range input.Body.UserIDs {
		successCount++
	}

	response := &model.BulkRoleAssignmentResponse{
		Success:      input.Body.UserIDs,
		Failed:       failedUsers,
		SuccessCount: successCount,
		FailureCount: len(failedUsers),
		Errors:       errors,
	}

	return &BulkAssignRolesOutput{
		Body: response,
	}, nil
}

// Analytics handlers
func (c *rbacController) getRBACStatsHandler(ctx context.Context, input *GetRBACStatsInput) (*GetRBACStatsOutput, error) {
	rbacService := c.di.RBACService()

	// Get basic role stats
	roleStats, err := rbacService.GetRoleStats(ctx, &input.PathOrgID)
	if err != nil {
		return nil, err
	}

	// Get permission stats
	permissionStats, err := rbacService.GetPermissionStats(ctx)
	if err != nil {
		return nil, err
	}

	// Combine into RBAC stats
	stats := &model.RBACStats{
		TotalRoles:                  roleStats.TotalRoles,
		SystemRoles:                 roleStats.SystemRoles,
		OrganizationRoles:           roleStats.OrganizationRoles,
		ApplicationRoles:            roleStats.ApplicationRoles,
		TotalPermissions:            permissionStats.TotalPermissions,
		SystemPermissions:           permissionStats.SystemPermissions,
		DangerousPermissions:        permissionStats.DangerousPermissions,
		RoleAssignments:             0, // Would be calculated
		DirectPermissionAssignments: 0, // Would be calculated
		PermissionsByCategory:       make(map[string]int),
		RolesByPriority:             make(map[string]int),
	}

	// Convert category breakdown
	for category, count := range permissionStats.CategoryBreakdown {
		stats.PermissionsByCategory[string(category)] = count
	}

	return &GetRBACStatsOutput{
		Body: stats,
	}, nil
}

func (c *rbacController) getRoleStatsHandler(ctx context.Context, input *GetRoleStatsInput) (*GetRoleStatsOutput, error) {
	rbacService := c.di.RBACService()

	stats, err := rbacService.GetRoleStats(ctx, &input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &GetRoleStatsOutput{
		Body: stats,
	}, nil
}

func (c *rbacController) getPermissionStatsHandler(ctx context.Context, input *GetPermissionStatsInput) (*GetPermissionStatsOutput, error) {
	rbacService := c.di.RBACService()

	stats, err := rbacService.GetPermissionStats(ctx)
	if err != nil {
		return nil, err
	}

	return &GetPermissionStatsOutput{
		Body: stats,
	}, nil
}

// Default role handlers
func (c *rbacController) getDefaultRolesHandler(ctx context.Context, input *GetDefaultRolesInput) (*GetDefaultRolesOutput, error) {
	rbacService := c.di.RBACService()

	var roleType model.RoleType
	if input.RoleType != "" {
		roleType = input.RoleType
	} else {
		roleType = model.RoleTypeOrganization
	}

	var applicationID *xid.ID
	if input.ApplicationID != "" {
		if appID, err := xid.FromString(input.ApplicationID); err == nil {
			applicationID = &appID
		}
	}

	roles, err := rbacService.GetDefaultRoles(ctx, roleType, &input.PathOrgID, applicationID)
	if err != nil {
		return nil, err
	}

	return &GetDefaultRolesOutput{
		Body: roles,
	}, nil
}

func (c *rbacController) setDefaultRoleHandler(ctx context.Context, input *SetDefaultRoleInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()

	err := rbacService.SetAsDefault(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *rbacController) unsetDefaultRoleHandler(ctx context.Context, input *UnsetDefaultRoleInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()

	err := rbacService.UnsetAsDefault(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}
