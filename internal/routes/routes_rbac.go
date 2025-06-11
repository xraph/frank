package routes

// import (
// 	"context"
// 	"net/http"
//
// 	"github.com/danielgtaylor/huma/v2"
// 	"github.com/juicycleff/frank/ent"
// 	"github.com/juicycleff/frank/internal/authz"
// 	"github.com/juicycleff/frank/internal/di"
// 	"github.com/juicycleff/frank/internal/model"
// 	"github.com/juicycleff/frank/internal/rbac"
// 	"github.com/rs/xid"
// )
//
// // RegisterRBACAPI registers all RBAC-related endpoints
// func RegisterRBACAPI(api huma.API, di di.Container) {
// 	rbacCtrl := &rbacController{
// 		api: api,
// 		di:  di,
// 	}
//
// 	// Register role endpoints
// 	registerListRoles(api, rbacCtrl)
// 	registerGetRole(api, rbacCtrl)
// 	registerCreateRole(api, rbacCtrl)
// 	registerUpdateRole(api, rbacCtrl)
// 	registerDeleteRole(api, rbacCtrl)
// 	registerAddRolePermission(api, rbacCtrl)
// 	registerRemoveRolePermission(api, rbacCtrl)
// 	registerListRolePermissions(api, rbacCtrl)
//
// 	// Register permission endpoints
// 	registerListPermissions(api, rbacCtrl)
// 	registerGetPermission(api, rbacCtrl)
// 	registerCreatePermission(api, rbacCtrl)
// 	registerUpdatePermission(api, rbacCtrl)
// 	registerDeletePermission(api, rbacCtrl)
// }
//
// func registerListRoles(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "listRoles",
// 		Method:      http.MethodGet,
// 		Path:        "/organizations/{orgId}/roles",
// 		Summary:     "List roles",
// 		Description: "List all roles for an organization with pagination and filtering options",
// 		Tags:        []string{"RBAC", "Roles"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionListRoles, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.listRolesHandler)
// }
//
// func registerGetRole(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "getRole",
// 		Method:      http.MethodGet,
// 		Path:        "/organizations/{orgId}/roles/{id}",
// 		Summary:     "Get a role",
// 		Description: "Get a role by ID",
// 		Tags:        []string{"RBAC", "Roles"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Role not found")),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionViewRoles, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.getRoleHandler)
// }
//
// func registerCreateRole(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "createRole",
// 		Method:      http.MethodPost,
// 		Path:        "/organizations/{orgId}/roles",
// 		Summary:     "Create a new role",
// 		Description: "Create a new role with the specified configuration",
// 		Tags:        []string{"RBAC", "Roles"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionCreateRole, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.createRoleHandler)
// }
//
// func registerUpdateRole(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "updateRole",
// 		Method:      http.MethodPut,
// 		Path:        "/organizations/{orgId}/roles/{id}",
// 		Summary:     "Update a role",
// 		Description: "Update an existing role by ID",
// 		Tags:        []string{"RBAC", "Roles"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Role not found")),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionUpdateRole, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.updateRoleHandler)
// }
//
// func registerDeleteRole(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID:   "deleteRole",
// 		Method:        http.MethodDelete,
// 		Path:          "/organizations/{orgId}/roles/{id}",
// 		Summary:       "Delete a role",
// 		Description:   "Delete a role by ID",
// 		Tags:          []string{"RBAC", "Roles"},
// 		DefaultStatus: 204,
// 		Responses: model.MergeErrorResponses(map[string]*huma.Response{
// 			"204": {
// 				Description: "Role successfully deleted",
// 			},
// 		}, true, model.NotFoundError("Role not found")),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionDeleteRole, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.deleteRoleHandler)
// }
//
// func registerAddRolePermission(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "addRolePermission",
// 		Method:      http.MethodPost,
// 		Path:        "/organizations/{orgId}/roles/{id}/permissions",
// 		Summary:     "Add permission to role",
// 		Description: "Add a permission to a role",
// 		Tags:        []string{"RBAC", "Roles"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionManageRoles, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.addRolePermissionHandler)
// }
//
// func registerRemoveRolePermission(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID:   "removeRolePermission",
// 		Method:        http.MethodDelete,
// 		Path:          "/organizations/{orgId}/roles/{id}/permissions/{permissionId}",
// 		Summary:       "Remove permission from role",
// 		Description:   "Remove a permission from a role",
// 		Tags:          []string{"RBAC", "Roles"},
// 		DefaultStatus: 204,
// 		Responses: model.MergeErrorResponses(map[string]*huma.Response{
// 			"204": {
// 				Description: "Permission successfully removed from role",
// 			},
// 		}, true, model.NotFoundError("Role or permission not found")),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionManageRoles, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.removeRolePermissionHandler)
// }
//
// func registerListRolePermissions(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "listRolePermissions",
// 		Method:      http.MethodGet,
// 		Path:        "/organizations/{orgId}/roles/{id}/permissions",
// 		Summary:     "List role permissions",
// 		Description: "List all permissions assigned to a role",
// 		Tags:        []string{"RBAC", "Roles"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionViewRoles, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.listRolePermissionsHandler)
// }
//
// func registerListPermissions(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "listPermissions",
// 		Method:      http.MethodGet,
// 		Path:        "/organizations/{orgId}/permissions",
// 		Summary:     "List permissions",
// 		Description: "List all permissions with pagination and filtering options",
// 		Tags:        []string{"RBAC", "Permissions"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionViewPermissions, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.listPermissionsHandler)
// }
//
// func registerGetPermission(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "getPermission",
// 		Method:      http.MethodGet,
// 		Path:        "/organizations/{orgId}/permissions/{id}",
// 		Summary:     "Get a permission",
// 		Description: "Get a permission by ID",
// 		Tags:        []string{"RBAC", "Permissions"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Permission not found")),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionViewPermissions, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.getPermissionHandler)
// }
//
// func registerCreatePermission(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "createPermission",
// 		Method:      http.MethodPost,
// 		Path:        "/organizations/{orgId}/permissions",
// 		Summary:     "Create a new permission",
// 		Description: "Create a new permission with the specified configuration",
// 		Tags:        []string{"RBAC", "Permissions"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionCreatePermission, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.createPermissionHandler)
// }
//
// func registerUpdatePermission(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "updatePermission",
// 		Method:      http.MethodPut,
// 		Path:        "/organizations/{orgId}/permissions/{id}",
// 		Summary:     "Update a permission",
// 		Description: "Update an existing permission by ID",
// 		Tags:        []string{"RBAC", "Permissions"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Permission not found")),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionUpdatePermission, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.updatePermissionHandler)
// }
//
// func registerDeletePermission(api huma.API, rbacCtrl *rbacController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID:   "deletePermission",
// 		Method:        http.MethodDelete,
// 		Path:          "/organizations/{orgId}/permissions/{id}",
// 		Summary:       "Delete a permission",
// 		Description:   "Delete a permission by ID",
// 		Tags:          []string{"RBAC", "Permissions"},
// 		DefaultStatus: 204,
// 		Responses: model.MergeErrorResponses(map[string]*huma.Response{
// 			"204": {
// 				Description: "Permission successfully deleted",
// 			},
// 		}, true, model.NotFoundError("Permission not found")),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, rbacCtrl.di.AuthZ().Checker(), rbacCtrl.di.Logger())(
// 			authz.PermissionDeletePermission, authz.ResourceOrganization, "orgId",
// 		)},
// 	}, rbacCtrl.deletePermissionHandler)
// }
//
// // rbacController handles RBAC-related API requests
// type rbacController struct {
// 	api huma.API
// 	di  di.Container
// }
//
// // Input/Output type definitions for RBAC handlers
//
// // ListRolesInput represents input for listing roles
// type ListRolesInput struct {
// 	model.OrganisationPathParams
// 	rbac.ListRolesParams
// }
//
// type ListRolesOutput = model.Output[*model.PaginatedOutput[*rbac.Role]]
//
// // GetRoleInput represents input for getting a specific role
// type GetRoleInput struct {
// 	model.OrganisationParams
// 	ID xid.ID `path:"id" doc:"Role ID"`
// }
//
// type GetRoleOutput = model.Output[*ent.Role]
//
// // CreateRoleRequest represents the input for creating a role
// type CreateRoleRequest struct {
// 	Name        string `json:"name" validate:"required"`
// 	Description string `json:"description,omitempty"`
// 	IsDefault   bool   `json:"is_default,omitempty"`
// }
//
// // CreateRoleInput represents input for creating a role
// type CreateRoleInput struct {
// 	model.OrganisationPathParams
// 	Body CreateRoleRequest
// }
//
// type CreateRoleOutput = model.Output[*rbac.Role]
//
// // UpdateRoleInput represents input for updating a role
// type UpdateRoleInput struct {
// 	model.OrganisationPathParams
// 	ID   xid.ID `path:"id" doc:"Role ID"`
// 	Body rbac.UpdateRoleBody
// }
//
// type UpdateRoleOutput = model.Output[*rbac.Role]
//
// // DeleteRoleInput represents input for deleting a role
// type DeleteRoleInput struct {
// 	model.OrganisationPathParams
// 	ID xid.ID `path:"id" doc:"Role ID"`
// }
//
// // AddRolePermissionRequest represents the input for adding a permission to a role
// type AddRolePermissionRequest struct {
// 	PermissionID xid.ID `json:"permission_id" validate:"required"`
// }
//
// // AddRolePermissionInput represents input for adding a permission to a role
// type AddRolePermissionInput struct {
// 	model.OrganisationPathParams
// 	ID   xid.ID `path:"id" doc:"Role ID"`
// 	Body AddRolePermissionRequest
// }
//
// // RemoveRolePermissionInput represents input for removing a permission from a role
// type RemoveRolePermissionInput struct {
// 	model.OrganisationPathParams
// 	ID           xid.ID `path:"id" doc:"Role ID"`
// 	PermissionID xid.ID `path:"permissionId" doc:"Permission ID"`
// }
//
// // ListRolePermissionsInput represents input for listing role permissions
// type ListRolePermissionsInput struct {
// 	model.OrganisationPathParams
// 	ID xid.ID `path:"id" doc:"Role ID"`
// }
//
// type ListRolePermissionsOutput = model.Output[[]*rbac.Permission]
//
// // ListPermissionsInput represents input for listing permissions
// type ListPermissionsInput struct {
// 	model.OrganisationPathParams
// 	rbac.ListPermissionsParams
// }
//
// type ListPermissionsOutput = model.Output[*model.PaginatedOutput[*rbac.Permission]]
//
// // GetPermissionInput represents input for getting a specific permission
// type GetPermissionInput struct {
// 	model.OrganisationPathParams
// 	ID xid.ID `path:"id" doc:"Permission ID"`
// }
//
// type GetPermissionOutput = model.Output[*rbac.Permission]
//
// // CreatePermissionRequest represents the input for creating a permission
// type CreatePermissionRequest struct {
// 	Name        string `json:"name" validate:"required"`
// 	Description string `json:"description,omitempty"`
// 	Resource    string `json:"resource" validate:"required"`
// 	Action      string `json:"action" validate:"required"`
// 	Conditions  string `json:"conditions,omitempty"`
// }
//
// // CreatePermissionInput represents input for creating a permission
// type CreatePermissionInput struct {
// 	model.OrganisationPathParams
// 	Body CreatePermissionRequest
// }
//
// type CreatePermissionOutput = model.Output[*rbac.Permission]
//
// // UpdatePermissionRequest represents the input for updating a permission
// type UpdatePermissionRequest struct {
// 	Name        *string `json:"name,omitempty"`
// 	Description *string `json:"description,omitempty"`
// 	Conditions  *string `json:"conditions,omitempty"`
// }
//
// // UpdatePermissionInput represents input for updating a permission
// type UpdatePermissionInput struct {
// 	model.OrganisationPathParams
// 	ID   xid.ID `path:"id" doc:"Permission ID"`
// 	Body UpdatePermissionRequest
// }
//
// type UpdatePermissionOutput = model.Output[*rbac.Permission]
//
// // DeletePermissionInput represents input for deleting a permission
// type DeletePermissionInput struct {
// 	model.OrganisationPathParams
// 	ID xid.ID `path:"id" doc:"Permission ID"`
// }
//
// // Handler implementations
//
// func (c *rbacController) listRolesHandler(ctx context.Context, input *ListRolesInput) (*ListRolesOutput, error) {
// 	// Set organization ID from path parameter
// 	input.ListRolesParams.OrgID = model.OptionalParam[xid.ID]{}
//
// 	result, err := c.di.RBACService().ListRoles(ctx, input.ListRolesParams)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &ListRolesOutput{
// 		Body: result,
// 	}, nil
// }
//
// func (c *rbacController) getRoleHandler(ctx context.Context, input *GetRoleInput) (*GetRoleOutput, error) {
// 	role, err := c.di.RBACService().GetRole(ctx, input.ID)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &GetRoleOutput{
// 		Body: role,
// 	}, nil
// }
//
// func (c *rbacController) createRoleHandler(ctx context.Context, input *CreateRoleInput) (*CreateRoleOutput, error) {
// 	// Map to service input
// 	createInput := rbac.CreateRoleInput{
// 		Name:           input.Body.Name,
// 		Description:    input.Body.Description,
// 		OrganizationID: &input.PathOrgID,
// 		IsDefault:      input.Body.IsDefault,
// 	}
//
// 	role, err := c.di.RBACService().CreateRole(ctx, createInput)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &CreateRoleOutput{
// 		Body: role,
// 	}, nil
// }
//
// func (c *rbacController) updateRoleHandler(ctx context.Context, input *UpdateRoleInput) (*UpdateRoleOutput, error) {
// 	role, err := c.di.RBACService().UpdateRole(ctx, input.ID, input.Body)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &UpdateRoleOutput{
// 		Body: role,
// 	}, nil
// }
//
// func (c *rbacController) deleteRoleHandler(ctx context.Context, input *DeleteRoleInput) (*model.EmptyOutput, error) {
// 	err := c.di.RBACService().DeleteRole(ctx, input.ID)
// 	return nil, err
// }
//
// func (c *rbacController) addRolePermissionHandler(ctx context.Context, input *AddRolePermissionInput) (*model.EmptyOutput, error) {
// 	err := c.di.RBACService().AddPermissionToRole(ctx, input.ID, input.Body.PermissionID)
// 	return nil, err
// }
//
// func (c *rbacController) removeRolePermissionHandler(ctx context.Context, input *RemoveRolePermissionInput) (*model.EmptyOutput, error) {
// 	err := c.di.RBACService().RemovePermissionFromRole(ctx, input.ID, input.PermissionID)
// 	return nil, err
// }
//
// func (c *rbacController) listRolePermissionsHandler(ctx context.Context, input *ListRolePermissionsInput) (*ListRolePermissionsOutput, error) {
// 	// Get role permissions using the service
// 	permissions, err := c.di.RBACService().ListRolePermissions(ctx, input.ID)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &ListRolePermissionsOutput{
// 		Body: permissions,
// 	}, nil
// }
//
// func (c *rbacController) listPermissionsHandler(ctx context.Context, input *ListPermissionsInput) (*ListPermissionsOutput, error) {
// 	result, err := c.di.RBACService().ListPermissions(ctx, input.ListPermissionsParams)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &ListPermissionsOutput{
// 		Body: result,
// 	}, nil
// }
//
// func (c *rbacController) getPermissionHandler(ctx context.Context, input *GetPermissionInput) (*GetPermissionOutput, error) {
// 	permission, err := c.di.RBACService().GetPermission(ctx, input.ID)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &GetPermissionOutput{
// 		Body: permission,
// 	}, nil
// }
//
// func (c *rbacController) createPermissionHandler(ctx context.Context, input *CreatePermissionInput) (*CreatePermissionOutput, error) {
// 	// Map to service input
// 	createInput := rbac.CreatePermissionInput{
// 		Name:        input.Body.Name,
// 		Description: input.Body.Description,
// 		Resource:    input.Body.Resource,
// 		Action:      input.Body.Action,
// 		Conditions:  input.Body.Conditions,
// 	}
//
// 	permission, err := c.di.RBACService().CreatePermission(ctx, createInput)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &CreatePermissionOutput{
// 		Body: permission,
// 	}, nil
// }
//
// func (c *rbacController) updatePermissionHandler(ctx context.Context, input *UpdatePermissionInput) (*UpdatePermissionOutput, error) {
// 	// Map to service input
// 	updateInput := rbac.UpdatePermissionInput{
// 		Name:        input.Body.Name,
// 		Description: input.Body.Description,
// 		Conditions:  input.Body.Conditions,
// 	}
//
// 	permission, err := c.di.RBACService().UpdatePermission(ctx, input.ID, updateInput)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &UpdatePermissionOutput{
// 		Body: permission,
// 	}, nil
// }
//
// func (c *rbacController) deletePermissionHandler(ctx context.Context, input *DeletePermissionInput) (*model.EmptyOutput, error) {
// 	err := c.di.RBACService().DeletePermission(ctx, input.ID)
// 	return nil, err
// }
