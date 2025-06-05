package handlers

import (
	"net/http"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/rbac"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// RBACHandler handles Single Sign-On operations
type RBACHandler struct {
	rbacService rbac.Service
	config      *config.Config
	logger      logging.Logger
}

// NewRBACHandler creates a new RBAC handler
func NewRBACHandler(
	rbacService rbac.Service,
	config *config.Config,
	logger logging.Logger,
) *RBACHandler {
	return &RBACHandler{
		rbacService: rbacService,
		config:      config,
		logger:      logger,
	}
}

// PermissionInitiateRequest represents the input for initiating Permission
type PermissionInitiateRequest struct {
	ProviderID  string                 `json:"provider_id" validate:"required"`
	RedirectURI string                 `json:"redirect_uri,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
}

// PermissionCompleteRequest represents the input for completing Permission
type PermissionCompleteRequest struct {
	ProviderID string `json:"provider_id" validate:"required"`
	State      string `json:"state" validate:"required"`
	Code       string `json:"code" validate:"required"`
}

// ListPermissions handles listing Permission providers
func (h *RBACHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	params := rbac.ListPermissionsParams{
		Offset:   0,
		Limit:    0,
		Resource: "",
		Action:   "",
		Search:   "",
	}

	// Get providers
	perms, totalCount, err := h.rbacService.ListPermissions(r.Context(), params)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return providers
	utils.RespondPagedJSON(w, http.StatusOK, utils.PagedResponse{
		Items: perms,
		PageInfo: utils.PageInfo{
			TotalCount: totalCount,
		},
	})
}

// CreatePermission handles create Permission providers
func (h *RBACHandler) CreatePermission(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input rbac.CreatePermissionInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Create permission
	perms, err := h.rbacService.CreatePermission(r.Context(), input)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return permission
	utils.RespondJSON(w, http.StatusOK, perms)
}

// GetPermission handles get permission
func (h *RBACHandler) GetPermission(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input rbac.CreatePermissionInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Create permission
	perms, err := h.rbacService.CreatePermission(r.Context(), input)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return permission
	utils.RespondJSON(w, http.StatusOK, perms)
}

// UpdatePermission handles update permission
func (h *RBACHandler) UpdatePermission(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input rbac.UpdatePermissionInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	id := utils.GetPathVar(r, "id")
	if id == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "permission id is required"))
		return
	}

	// Update permission
	perms, err := h.rbacService.UpdatePermission(r.Context(), id, input)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return permission
	utils.RespondJSON(w, http.StatusOK, perms)
}

// DeletePermission handles update permission
func (h *RBACHandler) DeletePermission(w http.ResponseWriter, r *http.Request) {
	id := utils.GetPathVar(r, "id")
	if id == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "permission id is required"))
		return
	}

	// Delete permission
	err := h.rbacService.DeletePermission(r.Context(), id)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return permission
	utils.RespondJSON(w, http.StatusOK, nil)
}

// ListRoles retrieves and lists roles associated with the specified permission ID from the request context.
func (h *RBACHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	params := rbac.ListRolesParams{
		Offset: 0,
		Limit:  0,
		Search: "",
		OrgID:  "",
	}

	// List roles
	roles, count, err := h.rbacService.ListRoles(r.Context(), params)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return roles
	utils.RespondPagedJSON(w, http.StatusOK, utils.PagedResponse{
		Items: roles,
		PageInfo: utils.PageInfo{
			TotalCount: count,
		},
	})
}

// GetRole retrieves a specific role by its ID, provided as a path parameter from the HTTP request.
func (h *RBACHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	id := utils.GetPathVar(r, "id")
	if id == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "role id is required"))
		return
	}

	// Get role
	role, err := h.rbacService.GetRole(r.Context(), id)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return role
	utils.RespondJSON(w, http.StatusOK, role)
}

// DeleteRole deletes a role identified by its ID, provided as a path parameter in the HTTP request. Responds with the deleted role.
func (h *RBACHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	id := utils.GetPathVar(r, "id")
	if id == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "role id is required"))
		return
	}

	err := h.rbacService.DeleteRole(r.Context(), id)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondJSON(w, http.StatusOK, nil)
}

// UpdateRole updates a role identified by its ID, provided as a path parameter in the HTTP request. Responds with status OK.
func (h *RBACHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	id := utils.GetPathVar(r, "id")
	if id == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "role id is required"))
		return
	}

	// Parse input
	var input rbac.UpdateRoleBody
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	role, err := h.rbacService.UpdateRole(r.Context(), id, input)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondJSON(w, http.StatusOK, role)
}

// CreateRole handles HTTP requests for creating a new role in the RBAC system with the specified ID and input data.
func (h *RBACHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input rbac.CreateRoleInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	role, err := h.rbacService.CreateRole(r.Context(), input)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondJSON(w, http.StatusOK, role)
}

// ListRolePermissions retrieves the list of permissions associated with a specific role using the role ID from the request path.
func (h *RBACHandler) ListRolePermissions(w http.ResponseWriter, r *http.Request) {
	id := utils.GetPathVar(r, "id")
	if id == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "role id is required"))
		return
	}

	params := rbac.ListPermissionsParams{
		Offset:   0,
		Limit:    0,
		Resource: "",
		Action:   "",
		Search:   "",
	}

	// Get role
	perms, count, err := h.rbacService.ListPermissions(r.Context(), params)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return role
	utils.RespondPagedJSON(w, http.StatusOK, utils.PagedResponse{
		Items: perms,
		PageInfo: utils.PageInfo{
			TotalCount: count,
		},
	})
}

// AddRolePermission handles adding permissions to a specific role identified by its ID from the request path.
func (h *RBACHandler) AddRolePermission(w http.ResponseWriter, r *http.Request) {
	id := utils.GetPathVar(r, "id")
	if id == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "role id is required"))
		return
	}

	// Parse input
	var input rbac.AddRolePermissionInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	err := h.rbacService.AddPermissionToRole(r.Context(), id, input.PermissionID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondJSON(w, http.StatusOK, nil)
}

// RemoveRolePermission removes a permission from a role identified by its ID, based on the input provided in the request body.
func (h *RBACHandler) RemoveRolePermission(w http.ResponseWriter, r *http.Request) {
	id := utils.GetPathVar(r, "id")
	if id == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "role id is required"))
		return
	}

	permissionId := utils.GetPathVar(r, "permissionId")
	if permissionId == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "permission id is required"))
		return
	}

	err := h.rbacService.RemovePermissionFromRole(r.Context(), id, permissionId)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondJSON(w, http.StatusOK, nil)
}

// Static handler functions for direct router registration

// RBACListPermissions handles the HTTP request for listing permissions using Role-Based Access Control (RBAC).
func RBACListPermissions(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.ListPermissions(w, r)
}

// RBACCreatePermission creates a new RBAC permission by delegating to the RBAC handler's CreatePermission function.
func RBACCreatePermission(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.CreatePermission(w, r)
}

// RBACGetPermission retrieves a specific permission using the Request context and writes the response to the ResponseWriter.
func RBACGetPermission(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.GetPermission(w, r)
}

// RBACUpdatePermission invokes the UpdatePermission method from the RBAC handler to update a permission in the system.
func RBACUpdatePermission(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.UpdatePermission(w, r)
}

// RBACDeletePermission removes a permission resource using the RBACHandler's DeletePermission method.
func RBACDeletePermission(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.DeletePermission(w, r)
}

// RBACListRoles handles the retrieval and listing of roles using the RBAC handler extracted from the request context.
func RBACListRoles(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.ListRoles(w, r)
}

// RBACGetRole handles HTTP requests to fetch a specific role by delegating to the RBAC handler from the request context.
func RBACGetRole(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.GetRole(w, r)
}

// RBACListRolePermissions handles listing the permissions associated with a specific role.
func RBACListRolePermissions(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.ListRolePermissions(w, r)
}

// RBACAddRolePermission handles HTTP requests to add a permission to a role in the Role-Based Access Control system.
func RBACAddRolePermission(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.AddRolePermission(w, r)
}

// RBACRemoveRolePermission removes a specified permission from a role in the RBAC system. Processes the HTTP request and response.
func RBACRemoveRolePermission(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.RemoveRolePermission(w, r)
}

// RBACDeleteRole handles HTTP requests to delete a role in the RBAC system using data from the request context.
func RBACDeleteRole(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.DeleteRole(w, r)
}

// RBACUpdateRole handles HTTP requests to update an existing role in the RBAC system.
func RBACUpdateRole(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.UpdateRole(w, r)
}

// RBACCreateRole handles HTTP requests to create a new role in the Role-Based Access Control (RBAC) system.
func RBACCreateRole(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).RBAC.CreateRole(w, r)
}
