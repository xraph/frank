package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// RegisterUserAPI registers all user management endpoints
func RegisterUserAPI(api huma.API, di di.Container) {
	userCtrl := &userController{
		api: api,
		di:  di,
	}

	// User CRUD endpoints
	registerListUsers(api, userCtrl)
	registerGetUser(api, userCtrl)
	registerCreateUser(api, userCtrl)
	registerUpdateUser(api, userCtrl)
	registerDeleteUser(api, userCtrl)
	registerBulkUserOperations(api, userCtrl)

	// User profile management
	registerGetUserProfile(api, userCtrl)
	registerUpdateUserProfile(api, userCtrl)
	registerChangePassword(api, userCtrl)
	registerSetPassword(api, userCtrl)

	// User role and permission management
	registerListUserRoles(api, userCtrl)
	registerAssignUserRole(api, userCtrl)
	registerRemoveUserRole(api, userCtrl)
	registerListUserPermissions(api, userCtrl)

	// User activity and sessions
	registerGetUserActivity(api, userCtrl)
	registerGetUserSessions(api, userCtrl)
	registerRevokeUserSession(api, userCtrl)
	registerRevokeAllUserSessions(api, userCtrl)

	// User MFA management
	registerGetUserMFA(api, userCtrl)
	registerEnableUserMFA(api, userCtrl)
	registerDisableUserMFA(api, userCtrl)
	registerResetUserMFA(api, userCtrl)

	// User statistics and analytics
	registerGetUserStats(api, userCtrl)
	registerExportUsers(api, userCtrl)
}

// userController handles user management API requests
type userController struct {
	api huma.API
	di  di.Container
}

// User CRUD Endpoints

func registerListUsers(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "listUsers",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users",
		Summary:     "List users",
		Description: "List users in an organization with pagination and filtering",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionListUsers, authz.ResourceOrganization, "orgId",
		)},
	}, userCtrl.listUsersHandler)
}

func registerGetUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "getUser",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{id}",
		Summary:     "Get user",
		Description: "Get user by ID",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionReadUser, authz.ResourceUser, "id",
		)},
	}, userCtrl.getUserHandler)
}

func registerCreateUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "createUser",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users",
		Summary:     "Create user",
		Description: "Create a new user in the organization",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionCreateUser, authz.ResourceOrganization, "orgId",
		)},
	}, userCtrl.createUserHandler)
}

func registerUpdateUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateUser",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/users/{id}",
		Summary:     "Update user",
		Description: "Update user information",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionUpdateUser, authz.ResourceUser, "id",
		)},
	}, userCtrl.updateUserHandler)
}

func registerDeleteUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteUser",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/{id}",
		Summary:       "Delete user",
		Description:   "Delete user account",
		Tags:          []string{"Users"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "User successfully deleted"},
		}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionDeleteUser, authz.ResourceUser, "id",
		)},
	}, userCtrl.deleteUserHandler)
}

func registerBulkUserOperations(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "bulkUserOperations",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/bulk",
		Summary:     "Bulk user operations",
		Description: "Perform bulk operations on multiple users",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionManageUsers, authz.ResourceOrganization, "orgId",
		)},
	}, userCtrl.bulkUserOperationsHandler)
}

// User Profile Management Endpoints

func registerGetUserProfile(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "getUserProfile",
		Method:      http.MethodGet,
		Path:        "/user/profile",
		Summary:     "Get current user profile",
		Description: "Get the current authenticated user's profile",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, userCtrl.getUserProfileHandler)
}

func registerUpdateUserProfile(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateUserProfile",
		Method:      http.MethodPut,
		Path:        "/user/profile",
		Summary:     "Update current user profile",
		Description: "Update the current authenticated user's profile",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, userCtrl.updateUserProfileHandler)
}

func registerChangePassword(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "changePassword",
		Method:      http.MethodPost,
		Path:        "/user/change-password",
		Summary:     "Change password",
		Description: "Change the current user's password",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, userCtrl.changePasswordHandler)
}

func registerSetPassword(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "setUserPassword",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{id}/set-password",
		Summary:     "Set user password",
		Description: "Set password for a user (admin only)",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionManageUsers, authz.ResourceUser, "id",
		)},
	}, userCtrl.setPasswordHandler)
}

// User Role Management Endpoints

func registerListUserRoles(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "listUserRoles",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{id}/roles",
		Summary:     "List user roles",
		Description: "List all roles assigned to a user",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionReadRole, authz.ResourceUser, "id",
		)},
	}, userCtrl.listUserRolesHandler)
}

func registerAssignUserRole(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "assignUserRole",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{id}/roles",
		Summary:     "Assign role to user",
		Description: "Assign a role to a user",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionManageRole, authz.ResourceUser, "id",
		)},
	}, userCtrl.assignUserRoleHandler)
}

func registerRemoveUserRole(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID:   "removeUserRole",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/{id}/roles/{roleId}",
		Summary:       "Remove role from user",
		Description:   "Remove a role assignment from a user",
		Tags:          []string{"Users"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Role successfully removed from user"},
		}, true, model.NotFoundError("User or role not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionManageRole, authz.ResourceUser, "id",
		)},
	}, userCtrl.removeUserRoleHandler)
}

// User Permission Management Endpoints

func registerListUserPermissions(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "listUserPermissions",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{id}/permissions",
		Summary:     "List user permissions",
		Description: "List all permissions for a user (direct and inherited from roles)",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionReadPermission, authz.ResourceUser, "id",
		)},
	}, userCtrl.listUserPermissionsHandler)
}

// User Activity and Session Endpoints

func registerGetUserActivity(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "getUserActivity",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{id}/activity",
		Summary:     "Get user activity",
		Description: "Get user activity log with pagination",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionViewAuditLogs, authz.ResourceUser, "id",
		)},
	}, userCtrl.getUserActivityHandler)
}

func registerGetUserSessions(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "getUserSessions",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{id}/sessions",
		Summary:     "Get user sessions",
		Description: "Get active sessions for a user",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionReadUser, authz.ResourceUser, "id",
		)},
	}, userCtrl.getUserSessionsHandler)
}

func registerRevokeUserSession(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID:   "revokeUserSession",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/{id}/sessions/{sessionId}",
		Summary:       "Revoke user session",
		Description:   "Revoke a specific session for a user",
		Tags:          []string{"Users"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Session successfully revoked"},
		}, true, model.NotFoundError("User or session not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionManageUsers, authz.ResourceUser, "id",
		)},
	}, userCtrl.revokeUserSessionHandler)
}

func registerRevokeAllUserSessions(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID:   "revokeAllUserSessions",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/{id}/sessions",
		Summary:       "Revoke all user sessions",
		Description:   "Revoke all sessions for a user",
		Tags:          []string{"Users"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "All sessions successfully revoked"},
		}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionManageUsers, authz.ResourceUser, "id",
		)},
	}, userCtrl.revokeAllUserSessionsHandler)
}

// User MFA Management Endpoints

func registerGetUserMFA(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "getUserMFA",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{id}/mfa",
		Summary:     "Get user MFA status",
		Description: "Get MFA configuration and status for a user",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionReadUser, authz.ResourceUser, "id",
		)},
	}, userCtrl.getUserMFAHandler)
}

func registerEnableUserMFA(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "enableUserMFA",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{id}/mfa/enable",
		Summary:     "Enable MFA for user",
		Description: "Enable MFA for a user (admin action)",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionManageUsers, authz.ResourceUser, "id",
		)},
	}, userCtrl.enableUserMFAHandler)
}

func registerDisableUserMFA(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID:   "disableUserMFA",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/{id}/mfa",
		Summary:       "Disable MFA for user",
		Description:   "Disable MFA for a user (admin action)",
		Tags:          []string{"Users"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "MFA successfully disabled"},
		}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionManageUsers, authz.ResourceUser, "id",
		)},
	}, userCtrl.disableUserMFAHandler)
}

func registerResetUserMFA(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "resetUserMFA",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{id}/mfa/reset",
		Summary:     "Reset user MFA",
		Description: "Reset MFA configuration for a user (admin action)",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionManageUsers, authz.ResourceUser, "id",
		)},
	}, userCtrl.resetUserMFAHandler)
}

// User Statistics and Analytics

func registerGetUserStats(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "getUserStats",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/stats",
		Summary:     "Get user statistics",
		Description: "Get user statistics for the organization",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionViewAnalytics, authz.ResourceOrganization, "orgId",
		)},
	}, userCtrl.getUserStatsHandler)
}

func registerExportUsers(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "exportUsers",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/export",
		Summary:     "Export users",
		Description: "Export user data to CSV or JSON format",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionExportUsers, authz.ResourceOrganization, "orgId",
		)},
	}, userCtrl.exportUsersHandler)
}

// Input/Output type definitions

type ListUsersInput struct {
	model.OrganisationPathParams
	model.UserListRequest
}

type ListUsersOutput = model.Output[*model.UserListResponse]

type GetUserInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"User ID"`
}

type GetUserOutput = model.Output[*model.User]

type CreateUserInput struct {
	model.OrganisationPathParams
	Body model.CreateUserRequest
}

type CreateUserOutput = model.Output[*model.User]

type UpdateUserInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"User ID"`
	Body model.UpdateUserRequest
}

type UpdateUserOutput = model.Output[*model.User]

type DeleteUserInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"User ID"`
	Body model.DeleteUserRequest
}

type BulkUserOperationsInput struct {
	model.OrganisationPathParams
	Body model.BulkUserOperation
}

type BulkUserOperationsOutput = model.Output[*model.BulkUserOperationResponse]

type UpdateUserProfileInput struct {
	Body model.UserProfileUpdateRequest
}

type UpdateUserProfileOutput = model.Output[*model.User]

type ChangePasswordInput struct {
	Body model.ChangePasswordRequest
}

type SetPasswordInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"User ID"`
	Body model.SetPasswordRequest
}

type AssignUserRoleInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"User ID"`
	Body model.AssignRoleRequest
}

type RemoveUserRoleInput struct {
	model.OrganisationPathParams
	ID     xid.ID `path:"id" doc:"User ID"`
	RoleID xid.ID `path:"roleId" doc:"Role ID"`
}

type ListUserRolesOutput = model.Output[[]*model.Role]

type AssignUserPermissionInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"User ID"`
	Body model.AssignPermissionRequest
}

type RemoveUserPermissionInput struct {
	model.OrganisationPathParams
	ID           xid.ID `path:"id" doc:"User ID"`
	PermissionID xid.ID `path:"permissionId" doc:"Permission ID"`
}

type ListUserPermissionsOutput = model.Output[[]*model.Permission]

type GetUserActivityInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"User ID"`
	model.UserActivityRequest
}

type GetUserActivityOutput = model.Output[*model.UserActivityResponse]

type RevokeUserSessionInput struct {
	model.OrganisationPathParams
	ID        xid.ID `path:"id" doc:"User ID"`
	SessionID xid.ID `path:"sessionId" doc:"Session ID"`
}

type GetUserStatsOutput = model.Output[*model.UserStats]

func (c *userController) listUsersHandler(ctx context.Context, input *ListUsersInput) (*ListUsersOutput, error) {
	// Get user service from DI container
	userService := c.di.UserService()

	// Create list request with organization filtering
	listReq := model.UserListRequest{
		PaginationParams: input.PaginationParams,
		// Add organization filtering based on path parameter
		OrganizationID: &input.PathOrgID,
	}

	// Call user service to list users
	result, err := userService.ListUsers(ctx, listReq)
	if err != nil {
		return nil, err
	}

	return &ListUsersOutput{
		Body: result,
	}, nil
}

func (c *userController) getUserHandler(ctx context.Context, input *GetUserInput) (*GetUserOutput, error) {
	userService := c.di.UserService()

	// Get user by ID
	user, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	// Verify user belongs to the organization
	if user.OrganizationID == nil || *user.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	return &GetUserOutput{
		Body: user,
	}, nil
}

func (c *userController) createUserHandler(ctx context.Context, input *CreateUserInput) (*CreateUserOutput, error) {
	userService := c.di.UserService()

	// Set organization ID from path parameter
	input.Body.OrganizationID = &input.PathOrgID

	// Create user
	user, err := userService.CreateUser(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreateUserOutput{
		Body: user,
	}, nil
}

func (c *userController) updateUserHandler(ctx context.Context, input *UpdateUserInput) (*UpdateUserOutput, error) {
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// Update user
	user, err := userService.UpdateUser(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateUserOutput{
		Body: user,
	}, nil
}

func (c *userController) deleteUserHandler(ctx context.Context, input *DeleteUserInput) (*model.EmptyOutput, error) {
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// Delete user
	err = userService.DeleteUser(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *userController) bulkUserOperationsHandler(ctx context.Context, input *BulkUserOperationsInput) (*BulkUserOperationsOutput, error) {
	userService := c.di.UserService()

	// Set organization context
	input.Body.OrganizationID = &input.PathOrgID

	// Perform bulk operation
	result, err := userService.BulkUpdateUsers(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &BulkUserOperationsOutput{
		Body: result,
	}, nil
}

func (c *userController) getUserProfileHandler(ctx context.Context, input *struct{}) (*GetUserOutput, error) {
	// Get current user ID from context (this should be set by authentication middleware)
	userID, err := c.getCurrentUserID(ctx)
	if err != nil {
		return nil, err
	}

	userService := c.di.UserService()

	// Get current user's profile
	user, err := userService.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &GetUserOutput{
		Body: user,
	}, nil
}

func (c *userController) updateUserProfileHandler(ctx context.Context, input *UpdateUserProfileInput) (*UpdateUserProfileOutput, error) {
	// Get current user ID from context
	userID, err := c.getCurrentUserID(ctx)
	if err != nil {
		return nil, err
	}

	profileService := c.di.ProfileService()

	// Update user profile
	user, err := profileService.UpdateProfile(ctx, userID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateUserProfileOutput{
		Body: user,
	}, nil
}

func (c *userController) changePasswordHandler(ctx context.Context, input *ChangePasswordInput) (*model.EmptyOutput, error) {
	// Get current user ID from context
	userID, err := c.getCurrentUserID(ctx)
	if err != nil {
		return nil, err
	}

	userService := c.di.UserService()

	// Change password
	err = userService.ChangePassword(ctx, userID, input.Body)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *userController) setPasswordHandler(ctx context.Context, input *SetPasswordInput) (*model.EmptyOutput, error) {
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// Set password (admin operation)
	err = userService.SetPassword(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *userController) listUserRolesHandler(ctx context.Context, input *GetUserInput) (*ListUserRolesOutput, error) {
	rbacService := c.di.RBACService()

	// First verify user exists and belongs to organization
	userService := c.di.UserService()
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// Get user roles with organization context
	roles, err := rbacService.GetUserRoles(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &ListUserRolesOutput{
		Body: roles,
	}, nil
}

func (c *userController) assignUserRoleHandler(ctx context.Context, input *AssignUserRoleInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// Get current user for audit trail
	currentUserID, _ := c.getCurrentUserID(ctx)
	err = rbacService.AssignOrganizationRole(ctx, currentUserID, input.PathOrgID, "")
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *userController) removeUserRoleHandler(ctx context.Context, input *RemoveUserRoleInput) (*model.EmptyOutput, error) {
	rbacService := c.di.RBACService()
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// Remove role from user
	err = rbacService.RemoveUserRole(ctx, input.ID, input.RoleID, model.ContextTypeOrganization, &input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *userController) listUserPermissionsHandler(ctx context.Context, input *GetUserInput) (*ListUserPermissionsOutput, error) {
	rbacService := c.di.RBACService()
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// Get user permission summary
	// summary, err := rbacService.GetUserPermissions(ctx, input.ID, userrole.ContextTypeOrganization, &input.PathOrgID)
	summary, err := rbacService.GetUserPermissions(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &ListUserPermissionsOutput{
		Body: summary,
	}, nil
}

func (c *userController) getUserActivityHandler(ctx context.Context, input *GetUserActivityInput) (*GetUserActivityOutput, error) {
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// Get user activity
	activity, err := userService.GetUserActivity(ctx, input.ID, input.UserActivityRequest)
	if err != nil {
		return nil, err
	}

	return &GetUserActivityOutput{
		Body: activity,
	}, nil
}

type GetUserSessionsOutput = model.Output[[]*model.Session]

func (c *userController) getUserSessionsHandler(ctx context.Context, input *GetUserInput) (*GetUserSessionsOutput, error) {
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	c.di.Logger().Info("Getting user sessions", logging.String("user_id", input.ID.String()))
	sessions, err := c.di.SessionService().GetUserSessions(ctx, existingUser.ID, false)
	if err != nil {
		return nil, err
	}

	return &GetUserSessionsOutput{
		Body: sessions,
	}, nil
}

func (c *userController) revokeUserSessionHandler(ctx context.Context, input *RevokeUserSessionInput) (*model.EmptyOutput, error) {
	// This would require a session service to be implemented
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	err = c.di.SessionService().InvalidateSession(ctx, input.SessionID)
	if err != nil {
		return nil, err
	}

	//  Revoke specific session
	c.di.Logger().Info("Revoked user session",
		logging.String("user_id", input.ID.String()),
		logging.String("session_id", input.SessionID.String()))

	return &model.EmptyOutput{}, nil
}

func (c *userController) revokeAllUserSessionsHandler(ctx context.Context, input *GetUserInput) (*model.EmptyOutput, error) {
	// This would require a session service to be implemented
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// Revoke all user sessions
	_, err = c.di.SessionService().InvalidateAllUserSessions(ctx, existingUser.ID)
	if err != nil {
		return nil, err
	}
	c.di.Logger().Info("Revoked all user sessions", logging.String("user_id", input.ID.String()))

	return &model.EmptyOutput{}, nil
}

func (c *userController) getUserMFAHandler(ctx context.Context, input *GetUserInput) (*model.EmptyOutput, error) {
	// This would require an MFA service to be implemented
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// TODO: Get user MFA status from MFA service
	c.di.Logger().Info("Getting user MFA status", logging.String("user_id", input.ID.String()))

	return &model.EmptyOutput{}, nil
}

func (c *userController) enableUserMFAHandler(ctx context.Context, input *GetUserInput) (*model.EmptyOutput, error) {
	// This would require an MFA service to be implemented
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// TODO: Enable MFA for user
	c.di.Logger().Info("Enabling MFA for user", logging.String("user_id", input.ID.String()))

	return &model.EmptyOutput{}, nil
}

func (c *userController) disableUserMFAHandler(ctx context.Context, input *GetUserInput) (*model.EmptyOutput, error) {
	// This would require an MFA service to be implemented
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// TODO: Disable MFA for user
	c.di.Logger().Info("Disabling MFA for user", logging.String("user_id", input.ID.String()))

	return &model.EmptyOutput{}, nil
}

func (c *userController) resetUserMFAHandler(ctx context.Context, input *GetUserInput) (*model.EmptyOutput, error) {
	// This would require an MFA service to be implemented
	userService := c.di.UserService()

	// First verify user exists and belongs to organization
	existingUser, err := userService.GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if existingUser.OrganizationID == nil || *existingUser.OrganizationID != input.PathOrgID {
		return nil, errors.New(errors.CodeNotFound, "user not found in organization")
	}

	// TODO: Reset MFA for user
	c.di.Logger().Info("Resetting MFA for user", logging.String("user_id", input.ID.String()))

	return &model.EmptyOutput{}, nil
}

func (c *userController) getUserStatsHandler(ctx context.Context, input *model.OrganisationPathParams) (*GetUserStatsOutput, error) {
	userService := c.di.UserService()

	// Get user statistics for the organization
	stats, err := userService.GetUserStats(ctx, &input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &GetUserStatsOutput{
		Body: stats,
	}, nil
}

func (c *userController) exportUsersHandler(ctx context.Context, input *model.OrganisationPathParams) (*model.EmptyOutput, error) {
	// This would require an export service to be implemented
	// For now, just log the export request
	c.di.Logger().Info("Exporting users", logging.String("org_id", input.PathOrgID.String()))

	// TODO: Implement user export functionality
	// 1. Generate export file (CSV/JSON)
	// 2. Store temporarily or send via email
	// 3. Return download URL or success message

	return &model.EmptyOutput{}, nil
}

// Helper method to get current user ID from context
func (c *userController) getCurrentUserID(ctx context.Context) (xid.ID, error) {
	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return xid.NilID(), err
	}

	return user.ID, nil
}

// Additional helper methods that may be needed

func (c *userController) validateOrganizationAccess(ctx context.Context, userID, orgID xid.ID) error {
	// Verify user has access to the organization
	// This could check membership, permissions, etc.

	userService := c.di.UserService()
	user, err := userService.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	if user.OrganizationID == nil || *user.OrganizationID != orgID {
		return errors.New(errors.CodeForbidden, "user does not have access to this organization")
	}

	return nil
}
