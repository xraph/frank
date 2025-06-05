package routes

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/model"
	userService "github.com/juicycleff/frank/internal/services/user"
	"github.com/rs/xid"
)

// RegisterUserAPI registers all user-related endpoints
func RegisterUserAPI(api huma.API, di di.Container) {
	userCtrl := &userController{
		api: api,
		di:  di,
	}

	// User management endpoints
	registerCreateUser(api, userCtrl)
	registerGetUser(api, userCtrl)
	registerUpdateUser(api, userCtrl)
	registerDeleteUser(api, userCtrl)
	registerListUsers(api, userCtrl)
	registerGetCurrentUser(api, userCtrl)
	registerUpdateCurrentUser(api, userCtrl)

	// Organization-scoped user endpoints
	registerListOrganizationUsers(api, userCtrl)
	registerGetOrganizationUser(api, userCtrl)
	registerCreateOrganizationUser(api, userCtrl)

	// Password management endpoints
	registerChangePassword(api, userCtrl)
	registerInitiatePasswordReset(api, userCtrl)
	registerCompletePasswordReset(api, userCtrl)

	// User profile endpoints
	registerGetUserProfile(api, userCtrl)
	registerUpdateUserProfile(api, userCtrl)
	registerGetUserMemberships(api, userCtrl)
	registerVerifyUserAccess(api, userCtrl)
}

// userController handles user-related API requests
type userController struct {
	api huma.API
	di  di.Container
}

// User Management Endpoints

func registerCreateUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "createUser",
		Method:      http.MethodPost,
		Path:        "/users",
		Summary:     "Create a new user",
		Description: "Create a new user (platform admin only)",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionCreateUser, authz.ResourceSystem, "",
		)},
	}, userCtrl.createUserHandler)
}

func registerGetUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "getUser",
		Method:      http.MethodGet,
		Path:        "/users/{userId}",
		Summary:     "Get user details",
		Description: "Get detailed information about a user",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionViewUser, authz.ResourceUser, "userId",
		)},
	}, userCtrl.getUserHandler)
}

func registerUpdateUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateUser",
		Method:      http.MethodPut,
		Path:        "/users/{userId}",
		Summary:     "Update user",
		Description: "Update user information",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionUpdateUser, authz.ResourceUser, "userId",
		)},
	}, userCtrl.updateUserHandler)
}

func registerDeleteUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteUser",
		Method:        http.MethodDelete,
		Path:          "/users/{userId}",
		Summary:       "Delete user",
		Description:   "Delete a user (soft delete)",
		Tags:          []string{"Users"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "User successfully deleted",
			},
		}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionDeleteUser, authz.ResourceUser, "userId",
		)},
	}, userCtrl.deleteUserHandler)
}

func registerListUsers(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "listUsers",
		Method:      http.MethodGet,
		Path:        "/users",
		Summary:     "List users",
		Description: "List users with filtering and pagination",
		Tags:        []string{"Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionListUsers, authz.ResourceSystem, "",
		)},
	}, userCtrl.listUsersHandler)
}

// Current User Endpoints

func registerGetCurrentUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "getCurrentUser",
		Method:      http.MethodGet,
		Path:        "/users/me",
		Summary:     "Get current user",
		Description: "Get current user's information",
		Tags:        []string{"Users", "Profile"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, userCtrl.getCurrentUserHandler)
}

func registerUpdateCurrentUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateCurrentUser",
		Method:      http.MethodPut,
		Path:        "/users/me",
		Summary:     "Update current user",
		Description: "Update current user's information",
		Tags:        []string{"Users", "Profile"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, userCtrl.updateCurrentUserHandler)
}

// Organization-Scoped User Endpoints

func registerListOrganizationUsers(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "listOrganizationUsers",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users",
		Summary:     "List organization users",
		Description: "List all users in an organization",
		Tags:        []string{"Organizations", "Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionViewMembers, authz.ResourceOrganization, "orgId",
		)},
	}, userCtrl.listOrganizationUsersHandler)
}

func registerGetOrganizationUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganizationUser",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{userId}",
		Summary:     "Get organization user",
		Description: "Get a specific user within an organization context",
		Tags:        []string{"Organizations", "Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionViewMembers, authz.ResourceOrganization, "orgId",
		)},
	}, userCtrl.getOrganizationUserHandler)
}

func registerCreateOrganizationUser(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "createOrganizationUser",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users",
		Summary:     "Create organization user",
		Description: "Create a new user within an organization (external or end user)",
		Tags:        []string{"Organizations", "Users"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionCreateUser, authz.ResourceOrganization, "orgId",
		)},
	}, userCtrl.createOrganizationUserHandler)
}

// Password Management Endpoints

func registerChangePassword(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID:   "changePassword",
		Method:        http.MethodPost,
		Path:          "/users/me/change-password",
		Summary:       "Change password",
		Description:   "Change current user's password",
		Tags:          []string{"Users", "Authentication"],
			DefaultStatus: 204,
			Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
			Description: "Password successfully changed",
		},
		// }, true),
		// 	Security: []map[string][]string{
		// {"jwt": {}},
		},
		}, userCtrl.changePasswordHandler),
	}})
}

func registerInitiatePasswordReset(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID:   "initiatePasswordReset",
		Method:        http.MethodPost,
		Path:          "/auth/password-reset/initiate",
		Summary:       "Initiate password reset",
		Description:   "Initiate password reset process",
		Tags:          []string{"Authentication"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "Password reset initiated (email sent if user exists)",
			},
		}, true),
	}, userCtrl.initiatePasswordResetHandler)
}

func registerCompletePasswordReset(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID:   "completePasswordReset",
		Method:        http.MethodPost,
		Path:          "/auth/password-reset/complete",
		Summary:       "Complete password reset",
		Description:   "Complete password reset process with token",
		Tags:          []string{"Authentication"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "Password successfully reset",
			},
		}, true),
	}, userCtrl.completePasswordResetHandler)
}

// Profile and Access Endpoints

func registerGetUserProfile(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "getUserProfile",
		Method:      http.MethodGet,
		Path:        "/users/{userId}/profile",
		Summary:     "Get user profile",
		Description: "Get user profile information",
		Tags:        []string{"Users", "Profile"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionViewUser, authz.ResourceUser, "userId",
		)},
	}, userCtrl.getUserProfileHandler)
}

func registerUpdateUserProfile(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateUserProfile",
		Method:      http.MethodPut,
		Path:        "/users/{userId}/profile",
		Summary:     "Update user profile",
		Description: "Update user profile information",
		Tags:        []string{"Users", "Profile"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionUpdateUser, authz.ResourceUser, "userId",
		)},
	}, userCtrl.updateUserProfileHandler)
}

func registerGetUserMemberships(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "getUserMemberships",
		Method:      http.MethodGet,
		Path:        "/users/{userId}/memberships",
		Summary:     "Get user memberships",
		Description: "Get all organization memberships for a user",
		Tags:        []string{"Users", "Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionViewUser, authz.ResourceUser, "userId",
		)},
	}, userCtrl.getUserMembershipsHandler)
}

func registerVerifyUserAccess(api huma.API, userCtrl *userController) {
	huma.Register(api, huma.Operation{
		OperationID: "verifyUserAccess",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{userId}/access",
		Summary:     "Verify user access",
		Description: "Verify if a user has access to an organization",
		Tags:        []string{"Organizations", "Users", "Access"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, userCtrl.di.AuthZ().Checker(), userCtrl.di.Logger())(
			authz.PermissionViewMembers, authz.ResourceOrganization, "orgId",
		)},
	}, userCtrl.verifyUserAccessHandler)
}

// Input/Output Type Definitions

// User Management Types
type CreateUserInput struct {
	Body userService.CreateUserInput `json:"body"`
}

type CreateUserOutput = model.Output[*ent.User]

type GetUserInput struct {
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type GetUserOutput = model.Output[*ent.User]

type UpdateUserInput struct {
	UserID xid.ID                      `path:"userId" doc:"User ID"`
	Body   userService.UpdateUserInput `json:"body"`
}

type UpdateUserOutput = model.Output[*ent.User]

type DeleteUserInput struct {
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type ListUsersInput struct {
	model.PaginationParams
	OrganizationID *xid.ID           `query:"organization_id" doc:"Filter by organization"`
	UserType       *user.UserType    `query:"user_type" doc:"Filter by user type"`
	Active         *bool             `query:"active" doc:"Filter by active status"`
	Blocked        *bool             `query:"blocked" doc:"Filter by blocked status"`
	AuthProvider   *string           `query:"auth_provider" doc:"Filter by auth provider"`
	Search         *string           `query:"search" doc:"Search in name, email, username"`
}

type ListUsersOutput = model.Output[*model.PaginatedOutput[*ent.User]]

// Current User Types
type GetCurrentUserOutput = model.Output[*ent.User]

type UpdateCurrentUserInput struct {
	Body userService.UpdateUserInput `json:"body"`
}

type UpdateCurrentUserOutput = model.Output[*ent.User]

// Organization User Types
type ListOrganizationUsersInput struct {
	model.PaginationParams
	OrgID    xid.ID         `path:"orgId" doc:"Organization ID"`
	UserType *user.UserType `query:"user_type" doc:"Filter by user type"`
	Active   *bool          `query:"active" doc:"Filter by active status"`
	Search   *string        `query:"search" doc:"Search in name, email, username"`
}

type ListOrganizationUsersOutput = model.Output[*model.PaginatedOutput[*ent.User]]

type GetOrganizationUserInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type GetOrganizationUserOutput = model.Output[*ent.User]

type CreateOrganizationUserInput struct {
	OrgID xid.ID                      `path:"orgId" doc:"Organization ID"`
	Body  userService.CreateUserInput `json:"body"`
}

type CreateOrganizationUserOutput = model.Output[*ent.User]

// Password Management Types
type ChangePasswordInput struct {
	Body userService.ChangePasswordInput `json:"body"`
}

type InitiatePasswordResetInput struct {
	Body userService.ResetPasswordInput `json:"body"`
}

type CompletePasswordResetInput struct {
	Body userService.CompletePasswordResetInput `json:"body"`
}

// Profile and Access Types
type GetUserProfileOutput = model.Output[*ent.User]

type UpdateUserProfileInput struct {
	UserID xid.ID                      `path:"userId" doc:"User ID"`
	Body   userService.UpdateUserInput `json:"body"`
}

type UpdateUserProfileOutput = model.Output[*ent.User]

type GetUserMembershipsInput struct {
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type GetUserMembershipsOutput = model.Output[[]*ent.Membership]

type VerifyUserAccessInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type VerifyUserAccessOutput = model.Output[bool]

// Handler Implementations

// User Management Handlers

func (c *userController) createUserHandler(ctx context.Context, input *CreateUserInput) (*CreateUserOutput, error) {
	// Get current user from context for created_by
	currentUserID, err := c.di.Auth().GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	input.Body.CreatedBy = &currentUserID

	user, err := c.di.UserService().CreateUser(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreateUserOutput{
		Body: user,
	}, nil
}

func (c *userController) getUserHandler(ctx context.Context, input *GetUserInput) (*GetUserOutput, error) {
	// Get current user's organization context for access validation
	currentUserID, err := c.di.Auth().GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Get current user's organization context
	currentUser, err := c.di.UserService().GetUser(ctx, currentUserID, nil)
	if err != nil {
		return nil, err
	}

	user, err := c.di.UserService().GetUser(ctx, input.UserID, currentUser.OrganizationID)
	if err != nil {
		return nil, err
	}

	return &GetUserOutput{
		Body: user,
	}, nil
}

func (c *userController) updateUserHandler(ctx context.Context, input *UpdateUserInput) (*UpdateUserOutput, error) {
	user, err := c.di.UserService().UpdateUser(ctx, input.UserID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateUserOutput{
		Body: user,
	}, nil
}

func (c *userController) deleteUserHandler(ctx context.Context, input *DeleteUserInput) (*model.EmptyOutput, error) {
	err := c.di.UserService().DeleteUser(ctx, input.UserID)
	return nil, err
}

func (c *userController) listUsersHandler(ctx context.Context, input *ListUsersInput) (*ListUsersOutput, error) {
	// Convert pagination params to service input
	serviceInput := userService.ListUsersInput{
		OrganizationID: input.OrganizationID,
		UserType:       input.UserType,
		Active:         input.Active,
		Blocked:        input.Blocked,
		AuthProvider:   input.AuthProvider,
		Search:         input.Search,
		Limit:          input.Limit,
		Offset:         input.Offset,
	}

	// Set default limit if not provided
	if serviceInput.Limit == 0 {
		serviceInput.Limit = 20
	}

	users, totalCount, err := c.di.UserService().ListUsers(ctx, serviceInput)
	if err != nil {
		return nil, err
	}

	return &ListUsersOutput{
		Body: &model.PaginatedOutput[*ent.User]{
			Data: users,
			Pagination: &model.Pagination{
				TotalCount:      totalCount,
				HasNextPage:     (input.Offset + len(users)) < totalCount,
				HasPreviousPage: input.Offset > 0,
				PageSize:        serviceInput.Limit,
			},
		},
	}, nil
}

// Current User Handlers

func (c *userController) getCurrentUserHandler(ctx context.Context, input *struct{}) (*GetCurrentUserOutput, error) {
	currentUserID, err := c.di.Auth().GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	user, err := c.di.UserService().GetUser(ctx, currentUserID, nil)
	if err != nil {
		return nil, err
	}

	return &GetCurrentUserOutput{
		Body: user,
	}, nil
}

func (c *userController) updateCurrentUserHandler(ctx context.Context, input *UpdateCurrentUserInput) (*UpdateCurrentUserOutput, error) {
	currentUserID, err := c.di.Auth().GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	user, err := c.di.UserService().UpdateUser(ctx, currentUserID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateCurrentUserOutput{
		Body: user,
	}, nil
}

// Organization User Handlers

func (c *userController) listOrganizationUsersHandler(ctx context.Context, input *ListOrganizationUsersInput) (*ListOrganizationUsersOutput, error) {
	users, err := c.di.UserService().GetUsersByOrganization(ctx, input.OrgID, input.UserType)
	if err != nil {
		return nil, err
	}

	// Apply search filter if provided
	if input.Search != nil && *input.Search != "" {
		// Simple filtering - in production, this should be done at the database level
		var filteredUsers []*ent.User
		searchTerm := strings.ToLower(*input.Search)
		for _, u := range users {
			if strings.Contains(strings.ToLower(u.Email), searchTerm) ||
				(u.FirstName != nil && strings.Contains(strings.ToLower(*u.FirstName), searchTerm)) ||
				(u.LastName != nil && strings.Contains(strings.ToLower(*u.LastName), searchTerm)) ||
				(u.Username != nil && strings.Contains(strings.ToLower(*u.Username), searchTerm)) {
				filteredUsers = append(filteredUsers, u)
			}
		}
		users = filteredUsers
	}

	// Apply active filter if provided
	if input.Active != nil {
		var filteredUsers []*ent.User
		for _, u := range users {
			if u.Active == *input.Active {
				filteredUsers = append(filteredUsers, u)
			}
		}
		users = filteredUsers
	}

	return &ListOrganizationUsersOutput{
		Body: &model.PaginatedOutput[*ent.User]{
			Data: users,
			Pagination: &model.Pagination{
				TotalCount: len(users),
			},
		},
	}, nil
}

func (c *userController) getOrganizationUserHandler(ctx context.Context, input *GetOrganizationUserInput) (*GetOrganizationUserOutput, error) {
	user, err := c.di.UserService().GetUser(ctx, input.UserID, &input.OrgID)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationUserOutput{
		Body: user,
	}, nil
}

func (c *userController) createOrganizationUserHandler(ctx context.Context, input *CreateOrganizationUserInput) (*CreateOrganizationUserOutput, error) {
	// Get current user from context for created_by
	currentUserID, err := c.di.Auth().GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Set organization ID and created by
	input.Body.OrganizationID = &input.OrgID
	input.Body.CreatedBy = &currentUserID

	// Default to external user type if not specified
	if input.Body.UserType == "" {
		input.Body.UserType = user.UserTypeExternal
	}

	user, err := c.di.UserService().CreateUser(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreateOrganizationUserOutput{
		Body: user,
	}, nil
}

// Password Management Handlers

func (c *userController) changePasswordHandler(ctx context.Context, input *ChangePasswordInput) (*model.EmptyOutput, error) {
	currentUserID, err := c.di.Auth().GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	err = c.di.UserService().ChangePassword(ctx, currentUserID, input.Body)
	return nil, err
}

func (c *userController) initiatePasswordResetHandler(ctx context.Context, input *InitiatePasswordResetInput) (*model.EmptyOutput, error) {
	err := c.di.UserService().InitiatePasswordReset(ctx, input.Body)
	return nil, err
}

func (c *userController) completePasswordResetHandler(ctx context.Context, input *CompletePasswordResetInput) (*model.EmptyOutput, error) {
	err := c.di.UserService().CompletePasswordReset(ctx, input.Body)
	return nil, err
}

// Profile and Access Handlers

func (c *userController) getUserProfileHandler(ctx context.Context, input *GetUserInput) (*GetUserProfileOutput, error) {
	// Same as getUserHandler but can have different response model in future
	currentUserID, err := c.di.Auth().GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	currentUser, err := c.di.UserService().GetUser(ctx, currentUserID, nil)
	if err != nil {
		return nil, err
	}

	user, err := c.di.UserService().GetUser(ctx, input.UserID, currentUser.OrganizationID)
	if err != nil {
		return nil, err
	}

	return &GetUserProfileOutput{
		Body: user,
	}, nil
}

func (c *userController) updateUserProfileHandler(ctx context.Context, input *UpdateUserProfileInput) (*UpdateUserProfileOutput, error) {
	user, err := c.di.UserService().UpdateUser(ctx, input.UserID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateUserProfileOutput{
		Body: user,
	}, nil
}

func (c *userController) getUserMembershipsHandler(ctx context.Context, input *GetUserMembershipsInput) (*GetUserMembershipsOutput, error) {
	memberships, err := c.di.UserService().GetUserMemberships(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetUserMembershipsOutput{
		Body: memberships,
	}, nil
}

func (c *userController) verifyUserAccessHandler(ctx context.Context, input *VerifyUserAccessInput) (*VerifyUserAccessOutput, error) {
	hasAccess, err := c.di.UserService().VerifyUserAccess(ctx, input.UserID, input.OrgID)
	if err != nil {
		return nil, err
	}

	return &VerifyUserAccessOutput{
		Body: hasAccess,
	}, nil
}