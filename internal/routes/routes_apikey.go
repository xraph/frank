package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/juicycleff/frank/pkg/services/apikey"
	"github.com/rs/xid"
)

// RegisterAPIKeyAPI registers API key management endpoints (protected routes)
func RegisterAPIKeyAPI(group huma.API, di di.Container) {
	di.Logger().Info("Registering API key management API routes")

	apikeyCtrl := &apikeyController{
		api:     group,
		di:      di,
		service: apikey.NewService(di.Repo(), di.Crypto(), di.AuditService(), di.ActivityService(), di.Logger()),
	}

	// API Key CRUD operations
	registerListAPIKeys(group, apikeyCtrl)
	registerCreateAPIKey(group, apikeyCtrl)
	registerGetAPIKey(group, apikeyCtrl)
	registerUpdateAPIKey(group, apikeyCtrl)
	registerDeleteAPIKey(group, apikeyCtrl)

	// API Key management operations
	registerRotateAPIKey(group, apikeyCtrl)
	registerValidateAPIKey(group, apikeyCtrl)
	registerActivateAPIKey(group, apikeyCtrl)
	registerDeactivateAPIKey(group, apikeyCtrl)

	// Bulk operations
	registerBulkAPIKeyOperation(group, apikeyCtrl)

	// Analytics and reporting
	registerGetAPIKeyStats(group, apikeyCtrl)
	registerGetAPIKeyUsage(group, apikeyCtrl)
	registerGetAPIKeyActivity(group, apikeyCtrl)

	// Export and utilities
	registerExportAPIKeyData(group, apikeyCtrl)
	registerCheckAPIKeyPermissions(group, apikeyCtrl)
}

// apikeyController handles API key-related API requests
type apikeyController struct {
	api     huma.API
	di      di.Container
	service apikey.Service
}

// Input/Output type definitions for API key handlers

// ListAPIKeysInput represents input for listing API keys
type ListAPIKeysInput struct {
	model.OrganisationPathParams
	model.APIKeyListRequest
}

type ListAPIKeysOutput = model.Output[*model.APIKeyListResponse]

// CreateAPIKeyInput represents input for creating API keys
type CreateAPIKeyInput struct {
	model.OrganisationPathParams
	Body model.CreateAPIKeyRequest `json:"body"`
}

type CreateAPIKeyOutput = model.Output[*model.CreateAPIKeyResponse]

type EndpointUsage struct {
	Endpoint        string  `json:"endpoint"`
	Method          string  `json:"method"`
	RequestCount    int     `json:"requestCount"`
	SuccessRate     float64 `json:"successRate"`
	AvgResponseTime int     `json:"avgResponseTime"`
}

// GetAPIKeyInput represents input for getting a specific API key
type GetAPIKeyInput struct {
	model.OrganisationPathParams
	ID           xid.ID `path:"id" doc:"API Key ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
	IncludeUsage bool   `query:"includeUsage" doc:"Include usage statistics"`
	IncludeUser  bool   `query:"includeUser" doc:"Include user information"`
	IncludeOrg   bool   `query:"includeOrg" doc:"Include organization information"`
}
type GetAPIKeyOutput = model.Output[*model.APIKey]

// UpdateAPIKeyInput represents input for updating an API key
type UpdateAPIKeyInput struct {
	model.OrganisationPathParams
	ID   xid.ID                    `path:"id" doc:"API Key ID"`
	Body model.UpdateAPIKeyRequest `json:"body"`
}

type UpdateAPIKeyOutput = model.Output[*model.APIKey]

// DeleteAPIKeyInput represents input for deleting an API key
type DeleteAPIKeyInput struct {
	model.OrganisationPathParams
	ID     xid.ID `path:"id" doc:"API Key ID"`
	Reason string `query:"reason" doc:"Reason for deletion"`
}

type DeleteAPIKeyOutput = model.Output[any]

// RotateAPIKeyInput represents input for rotating an API key
type RotateAPIKeyInput struct {
	model.OrganisationPathParams
	ID   xid.ID                    `path:"id" doc:"API Key ID"`
	Body model.RotateAPIKeyRequest `json:"body"`
}

type RotateAPIKeyOutput = model.Output[*model.RotateAPIKeyResponse]

// ValidateAPIKeyInput represents input for validating an API key
type ValidateAPIKeyInput struct {
	Body model.ValidateAPIKeyRequest `json:"body"`
}

type ValidateAPIKeyOutput = model.Output[*model.ValidateAPIKeyResponse]

type RateLimitInfo struct {
	Limit     int `json:"limit"`
	Remaining int `json:"remaining"`
	Reset     int `json:"reset"`
	Window    int `json:"window"`
}

// ActivateAPIKeyInput represents input for activating an API key
type ActivateAPIKeyInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"API Key ID"`
}

type ActivateAPIKeyOutput = model.EmptyOutput

// DeactivateAPIKeyInput represents input for deactivating an API key
type DeactivateAPIKeyInput struct {
	model.OrganisationPathParams
	ID     xid.ID `path:"id" doc:"API Key ID"`
	Reason string `query:"reason" doc:"Reason for deactivation"`
}

type DeactivateAPIKeyOutput = model.EmptyOutput

// BulkAPIKeyOperationInput represents input for bulk API key operations
type BulkAPIKeyOperationInput struct {
	model.OrganisationPathParams
	Body model.BulkAPIKeyOperationRequest `json:"body"`
}

type BulkAPIKeyOperationOutput = model.Output[*model.BulkAPIKeyOperationResponse]

// GetAPIKeyStatsInput represents input for getting API key statistics
type GetAPIKeyStatsInput struct {
	model.OrganisationPathParams
}

type GetAPIKeyStatsOutput = model.Output[*model.APIKeyStats]

// GetAPIKeyUsageInput represents input for getting API key usage
type GetAPIKeyUsageInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"API Key ID"`
}

type GetAPIKeyUsageOutput = model.Output[*model.APIKeyUsage]

// GetAPIKeyActivityInput represents input for getting API key activity
type GetAPIKeyActivityInput struct {
	model.OrganisationPathParams
	model.APIKeyActivityRequest
}

type GetAPIKeyActivityOutput = model.Output[*model.APIKeyActivityResponse]

// ExportAPIKeyDataInput represents input for exporting API key data
type ExportAPIKeyDataInput struct {
	model.OrganisationPathParams
	Body model.APIKeyExportRequest `json:"body"`
}

type ExportAPIKeyDataOutput = model.Output[*model.APIKeyExportResponse]

// CheckAPIKeyPermissionsInput represents input for checking API key permissions
type CheckAPIKeyPermissionsInput struct {
	model.OrganisationPathParams
	ID   xid.ID                  `path:"id" doc:"API Key ID"`
	Body CheckPermissionsRequest `json:"body"`
}

type CheckPermissionsRequest struct {
	Permissions []string `json:"permissions" validate:"required" doc:"List of permissions to check"`
}

type CheckAPIKeyPermissionsOutput = model.Output[*CheckPermissionsResponse]

type CheckPermissionsResponse struct {
	HasPermissions bool     `json:"hasPermissions"`
	Missing        []string `json:"missing,omitempty"`
	Granted        []string `json:"granted"`
}

// Route registration functions

func registerListAPIKeys(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listAPIKeys",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/api-keys",
		Summary:       "List API keys",
		Description:   "List API keys for an organization with filtering and pagination",
		Tags:          []string{"API Keys"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Successfully retrieved API keys",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionReadAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.listAPIKeysHandler)
}

func registerCreateAPIKey(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "createAPIKey",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/api-keys",
		Summary:       "Create API key",
		Description:   "Create a new API key for an organization",
		Tags:          []string{"API Keys"},
		DefaultStatus: 201,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"201": {
				Description: "API key successfully created",
			},
		}, true, model.ValidationError("Invalid request data")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionWriteAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.createAPIKeyHandler)
}

func registerGetAPIKey(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getAPIKey",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/api-keys/{id}",
		Summary:       "Get API key",
		Description:   "Get a specific API key by ID",
		Tags:          []string{"API Keys"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Successfully retrieved API key",
			},
		}, true, model.NotFoundError("API key not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionReadAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.getAPIKeyHandler)
}

func registerUpdateAPIKey(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "updateAPIKey",
		Method:        http.MethodPut,
		Path:          "/organizations/{orgId}/api-keys/{id}",
		Summary:       "Update API key",
		Description:   "Update an existing API key",
		Tags:          []string{"API Keys"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "API key successfully updated",
			},
		}, true, model.NotFoundError("API key not found"), model.ValidationError("Invalid request data")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionWriteAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.updateAPIKeyHandler)
}

func registerDeleteAPIKey(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteAPIKey",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/api-keys/{id}",
		Summary:       "Delete API key",
		Description:   "Delete an API key",
		Tags:          []string{"API Keys"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "API key successfully deleted",
			},
		}, true, model.NotFoundError("API key not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionDeleteAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.deleteAPIKeyHandler)
}

func registerRotateAPIKey(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "rotateAPIKey",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/api-keys/{id}/rotate",
		Summary:       "Rotate API key",
		Description:   "Rotate an API key to generate a new key value",
		Tags:          []string{"API Keys"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "API key successfully rotated",
			},
		}, true, model.NotFoundError("API key not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionWriteAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.rotateAPIKeyHandler)
}

func registerValidateAPIKey(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "validateAPIKey",
		Method:        http.MethodPost,
		Path:          "/api-keys/validate",
		Summary:       "Validate API key",
		Description:   "Validate an API key and return its details",
		Tags:          []string{"API Keys"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "API key validation result",
			},
		}, false),
	}, apikeyCtrl.validateAPIKeyHandler)
}

func registerActivateAPIKey(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "activateAPIKey",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/api-keys/{id}/activate",
		Summary:       "Activate API key",
		Description:   "Activate a deactivated API key",
		Tags:          []string{"API Keys"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "API key successfully activated",
			},
		}, true, model.NotFoundError("API key not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionWriteAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.activateAPIKeyHandler)
}

func registerDeactivateAPIKey(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deactivateAPIKey",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/api-keys/{id}/deactivate",
		Summary:       "Deactivate API key",
		Description:   "Deactivate an active API key",
		Tags:          []string{"API Keys"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "API key successfully deactivated",
			},
		}, true, model.NotFoundError("API key not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionWriteAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.deactivateAPIKeyHandler)
}

func registerBulkAPIKeyOperation(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "bulkAPIKeyOperation",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/api-keys/bulk",
		Summary:       "Bulk API key operations",
		Description:   "Perform bulk operations on multiple API keys",
		Tags:          []string{"API Keys"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Bulk operation completed",
			},
		}, true, model.ValidationError("Invalid operation or API key IDs")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionWriteAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.bulkAPIKeyOperationHandler)
}

func registerGetAPIKeyStats(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getAPIKeyStats",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/api-keys/stats",
		Summary:       "Get API key statistics",
		Description:   "Get statistical information about API keys for an organization",
		Tags:          []string{"API Keys", "Analytics"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Successfully retrieved API key statistics",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionReadAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.getAPIKeyStatsHandler)
}

func registerGetAPIKeyUsage(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getAPIKeyUsage",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/api-keys/{id}/usage",
		Summary:       "Get API key usage",
		Description:   "Get usage statistics for a specific API key",
		Tags:          []string{"API Keys", "Analytics"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Successfully retrieved API key usage",
			},
		}, true, model.NotFoundError("API key not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionReadAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.getAPIKeyUsageHandler)
}

func registerGetAPIKeyActivity(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getAPIKeyActivity",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/api-keys/activity",
		Summary:       "Get API key activity",
		Description:   "Get activity logs for API keys",
		Tags:          []string{"API Keys", "Analytics"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Successfully retrieved API key activity",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionReadAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.getAPIKeyActivityHandler)
}

func registerExportAPIKeyData(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "exportAPIKeyData",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/api-keys/export",
		Summary:       "Export API key data",
		Description:   "Export API key data and activity logs",
		Tags:          []string{"API Keys", "Export"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Export initiated successfully",
			},
		}, true, model.ValidationError("Invalid export parameters")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionReadAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.exportAPIKeyDataHandler)
}

func registerCheckAPIKeyPermissions(api huma.API, apikeyCtrl *apikeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "checkAPIKeyPermissions",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/api-keys/{id}/check-permissions",
		Summary:       "Check API key permissions",
		Description:   "Check if an API key has specific permissions",
		Tags:          []string{"API Keys", "Permissions"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Permission check completed",
			},
		}, true, model.NotFoundError("API key not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, apikeyCtrl.di.AuthZ().Checker(), apikeyCtrl.di.Logger())(
			authz.PermissionReadAPIKey, authz.ResourceOrganization, "orgId",
		)},
	}, apikeyCtrl.checkAPIKeyPermissionsHandler)
}

// Handler implementations

func (ctrl *apikeyController) listAPIKeysHandler(ctx context.Context, input *ListAPIKeysInput) (*ListAPIKeysOutput, error) {
	// Call service
	result, err := ctrl.service.ListAPIKeys(ctx, &input.APIKeyListRequest)
	if err != nil {
		return nil, err
	}

	return &ListAPIKeysOutput{
		Body: result,
	}, nil
}

func (ctrl *apikeyController) createAPIKeyHandler(ctx context.Context, input *CreateAPIKeyInput) (*CreateAPIKeyOutput, error) {
	// Call service
	result, err := ctrl.service.CreateAPIKey(ctx, &input.Body)
	if err != nil {
		return nil, err
	}

	// Convert service response to API response
	return &CreateAPIKeyOutput{
		Body: result,
	}, nil
}

func (ctrl *apikeyController) getAPIKeyHandler(ctx context.Context, input *GetAPIKeyInput) (*GetAPIKeyOutput, error) {
	opts := &apikey.GetOptions{
		OrganizationID: &input.PathOrgID,
		IncludeUsage:   input.IncludeUsage,
		IncludeUser:    input.IncludeUser,
		IncludeOrg:     input.IncludeOrg,
	}

	// Call service
	result, err := ctrl.service.GetAPIKey(ctx, input.ID, opts)
	if err != nil {
		return nil, err
	}

	// Convert service response to API response
	return &GetAPIKeyOutput{
		Body: result,
	}, nil
}

func (ctrl *apikeyController) updateAPIKeyHandler(ctx context.Context, input *UpdateAPIKeyInput) (*UpdateAPIKeyOutput, error) {
	// Call service
	result, err := ctrl.service.UpdateAPIKey(ctx, input.ID, &input.Body)
	if err != nil {
		return nil, err
	}

	// Convert service response to API response
	return &UpdateAPIKeyOutput{
		Body: result,
	}, nil
}

func (ctrl *apikeyController) deleteAPIKeyHandler(ctx context.Context, input *DeleteAPIKeyInput) (*DeleteAPIKeyOutput, error) {
	opts := &apikey.DeleteOptions{
		OrganizationID: &input.PathOrgID,
		Reason:         input.Reason,
	}

	// Call service
	err := ctrl.service.DeleteAPIKey(ctx, input.ID, opts)
	if err != nil {
		return nil, err
	}

	return &DeleteAPIKeyOutput{
		Body: struct{}{},
	}, nil
}

func (ctrl *apikeyController) rotateAPIKeyHandler(ctx context.Context, input *RotateAPIKeyInput) (*RotateAPIKeyOutput, error) {

	// Call service
	result, err := ctrl.service.RotateAPIKey(ctx, input.ID, &input.Body)
	if err != nil {
		return nil, err
	}

	// Convert service response to API response
	return &RotateAPIKeyOutput{
		Body: result,
	}, nil
}

func (ctrl *apikeyController) validateAPIKeyHandler(ctx context.Context, input *ValidateAPIKeyInput) (*ValidateAPIKeyOutput, error) {
	// Call service
	result, err := ctrl.service.ValidateAPIKey(ctx, &input.Body)
	if err != nil {
		return nil, err
	}

	// Convert service response to API response
	return &ValidateAPIKeyOutput{
		Body: result,
	}, nil
}

func (ctrl *apikeyController) activateAPIKeyHandler(ctx context.Context, input *ActivateAPIKeyInput) (*ActivateAPIKeyOutput, error) {
	opts := &apikey.ActivateOptions{
		OrganizationID: &input.PathOrgID,
	}

	// Call service
	err := ctrl.service.ActivateAPIKey(ctx, input.ID, opts)
	if err != nil {
		return nil, err
	}

	return &ActivateAPIKeyOutput{
		Body: struct{}{},
	}, nil
}

func (ctrl *apikeyController) deactivateAPIKeyHandler(ctx context.Context, input *DeactivateAPIKeyInput) (*DeactivateAPIKeyOutput, error) {
	opts := &apikey.DeactivateOptions{
		OrganizationID: &input.PathOrgID,
	}

	// Call service
	err := ctrl.service.DeactivateAPIKey(ctx, input.ID, input.Reason, opts)
	if err != nil {
		return nil, err
	}

	return &DeactivateAPIKeyOutput{
		Body: struct{}{},
	}, nil
}

func (ctrl *apikeyController) bulkAPIKeyOperationHandler(ctx context.Context, input *BulkAPIKeyOperationInput) (*BulkAPIKeyOperationOutput, error) {

	opts := &apikey.BulkOptions{
		OrganizationID: &input.PathOrgID,
	}

	// Call service
	result, err := ctrl.service.BulkAPIKeyOperation(ctx, &input.Body, opts)
	if err != nil {
		return nil, err
	}

	// Convert service response to API response
	return &BulkAPIKeyOperationOutput{
		Body: result,
	}, nil
}

func (ctrl *apikeyController) getAPIKeyStatsHandler(ctx context.Context, input *GetAPIKeyStatsInput) (*GetAPIKeyStatsOutput, error) {
	// Call service
	result, err := ctrl.service.GetAPIKeyStats(ctx, &input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &GetAPIKeyStatsOutput{
		Body: result,
	}, nil
}

func (ctrl *apikeyController) getAPIKeyUsageHandler(ctx context.Context, input *GetAPIKeyUsageInput) (*GetAPIKeyUsageOutput, error) {
	// Call service
	result, err := ctrl.service.GetAPIKeyUsage(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &GetAPIKeyUsageOutput{
		Body: result,
	}, nil
}

func (ctrl *apikeyController) getAPIKeyActivityHandler(ctx context.Context, input *GetAPIKeyActivityInput) (*GetAPIKeyActivityOutput, error) {

	// Call service
	result, err := ctrl.service.GetAPIKeyActivity(ctx, &input.APIKeyActivityRequest)
	if err != nil {
		return nil, err
	}

	return &GetAPIKeyActivityOutput{
		Body: result,
	}, nil
}

func (ctrl *apikeyController) exportAPIKeyDataHandler(ctx context.Context, input *ExportAPIKeyDataInput) (*ExportAPIKeyDataOutput, error) {
	opts := &apikey.ExportOptions{
		OrganizationID: &input.PathOrgID,
	}

	// Call service
	result, err := ctrl.service.ExportAPIKeyData(ctx, &input.Body, opts)
	if err != nil {
		return nil, err
	}

	// Convert service response to API response
	return &ExportAPIKeyDataOutput{
		Body: result,
	}, nil
}

func (ctrl *apikeyController) checkAPIKeyPermissionsHandler(ctx context.Context, input *CheckAPIKeyPermissionsInput) (*CheckAPIKeyPermissionsOutput, error) {
	// Call service
	err := ctrl.service.CheckAPIKeyPermissions(ctx, input.ID, input.Body.Permissions)
	if err != nil {
		// Parse the error to determine missing permissions
		return &CheckAPIKeyPermissionsOutput{
			Body: &CheckPermissionsResponse{
				HasPermissions: false,
				Missing:        input.Body.Permissions, // In a real implementation, parse the error
				Granted:        []string{},
			},
		}, nil
	}

	return &CheckAPIKeyPermissionsOutput{
		Body: &CheckPermissionsResponse{
			HasPermissions: true,
			Missing:        []string{},
			Granted:        input.Body.Permissions,
		},
	}, nil
}
