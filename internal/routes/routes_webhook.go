package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// RegisterWebhookAPI registers webhook management endpoints (protected routes)
func RegisterWebhookAPI(group huma.API, di di.Container) {
	di.Logger().Info("Registering webhook management API routes")

	webhookCtrl := &webhookController{
		api: group,
		di:  di,
	}

	// Webhook CRUD operations
	registerListWebhooks(group, webhookCtrl)
	registerCreateWebhook(group, webhookCtrl)
	registerGetWebhook(group, webhookCtrl)
	registerUpdateWebhook(group, webhookCtrl)
	registerDeleteWebhook(group, webhookCtrl)

	// Webhook management
	registerActivateWebhook(group, webhookCtrl)
	registerDeactivateWebhook(group, webhookCtrl)
	registerRegenerateWebhookSecret(group, webhookCtrl)

	// Webhook testing and validation
	registerTestWebhook(group, webhookCtrl)
	registerValidateWebhookURL(group, webhookCtrl)

	// Event management
	registerListWebhookEvents(group, webhookCtrl)
	registerGetWebhookEvent(group, webhookCtrl)
	registerRetryWebhookEvent(group, webhookCtrl)

	// Security management
	registerGetWebhookSecurity(group, webhookCtrl)
	registerUpdateWebhookSecurity(group, webhookCtrl)

	// Analytics and statistics
	registerGetWebhookStats(group, webhookCtrl)
	registerGetGlobalWebhookStats(group, webhookCtrl)

	// Bulk operations
	registerBulkWebhookOperation(group, webhookCtrl)
	registerBulkRetryEvents(group, webhookCtrl)

	// Export and health
	registerExportWebhookData(group, webhookCtrl)
	registerGetWebhookHealth(group, webhookCtrl)
}

// RegisterWebhookPublicAPI registers public webhook endpoints
func RegisterWebhookPublicAPI(group huma.API, di di.Container) {
	di.Logger().Info("Registering public webhook API routes")

	webhookCtrl := &webhookController{
		api: group,
		di:  di,
	}

	// Public webhook endpoints for receiving webhooks from external services
	registerReceiveWebhook(group, webhookCtrl)
}

// RegisterWebhookEndpointsAPI registers webhook endpoint routes
func RegisterWebhookEndpointsAPI(group huma.API, di di.Container) {
	di.Logger().Info("Registering webhook endpoint API routes")

	webhookCtrl := &webhookController{
		api: group,
		di:  di,
	}

	// Webhook delivery endpoints (for our system to deliver webhooks)
	// These are internal endpoints used by the delivery service
	registerWebhookDeliveryEndpoints(group, webhookCtrl)
}

// webhookController handles webhook-related API requests
type webhookController struct {
	api huma.API
	di  di.Container
}

// Input/Output type definitions for webhook handlers

// ListWebhooksInput represents input for listing webhooks
type ListWebhooksInput struct {
	model.OrganisationPathParams
	model.WebhookListRequest
}

type ListWebhooksOutput = model.Output[*model.WebhookListResponse]

// CreateWebhookInput represents input for creating a webhook
type CreateWebhookInput struct {
	model.OrganisationPathParams
	Body model.CreateWebhookRequest `json:"body"`
}

type CreateWebhookOutput = model.Output[*model.Webhook]

// GetWebhookInput represents input for getting a specific webhook
type GetWebhookInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Webhook ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
}

type GetWebhookOutput = model.Output[*model.Webhook]

// UpdateWebhookInput represents input for updating a webhook
type UpdateWebhookInput struct {
	model.OrganisationPathParams
	ID   xid.ID                     `path:"id" doc:"Webhook ID"`
	Body model.UpdateWebhookRequest `json:"body"`
}

type UpdateWebhookOutput = model.Output[*model.Webhook]

// DeleteWebhookInput represents input for deleting a webhook
type DeleteWebhookInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Webhook ID"`
}

type DeleteWebhookOutput = model.Output[any]

// ActivateWebhookInput represents input for activating a webhook
type ActivateWebhookInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Webhook ID"`
}

type ActivateWebhookOutput = model.Output[any]

// DeactivateWebhookInput represents input for deactivating a webhook
type DeactivateWebhookInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Webhook ID"`
}

type DeactivateWebhookOutput = model.Output[any]

// RegenerateWebhookSecretInput represents input for regenerating webhook secret
type RegenerateWebhookSecretInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Webhook ID"`
}

type RegenerateWebhookSecretOutput = model.Output[map[string]string]

// TestWebhookInput represents input for testing a webhook
type TestWebhookInput struct {
	model.OrganisationPathParams
	Body model.TestWebhookRequest `json:"body"`
}

type TestWebhookOutput = model.Output[*model.TestWebhookResponse]

// ValidateWebhookURLInput represents input for validating a webhook URL
type ValidateWebhookURLInput struct {
	URL string `json:"url" example:"https://api.example.com/webhooks" doc:"Webhook URL to validate"`
}

type ValidateWebhookURLOutput = model.Output[map[string]interface{}]

// ListWebhookEventsInput represents input for listing webhook events
type ListWebhookEventsInput struct {
	model.OrganisationPathParams
	model.WebhookEventListRequest
}

type ListWebhookEventsOutput = model.Output[*model.WebhookEventListResponse]

// GetWebhookEventInput represents input for getting a webhook event
type GetWebhookEventInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Event ID"`
}

type GetWebhookEventOutput = model.Output[*model.WebhookEvent]

// RetryWebhookEventInput represents input for retrying a webhook event
type RetryWebhookEventInput struct {
	model.OrganisationPathParams
	Body model.RetryWebhookEventRequest `json:"body"`
}

type RetryWebhookEventOutput = model.Output[*model.RetryWebhookEventResponse]

// GetWebhookSecurityInput represents input for getting webhook security settings
type GetWebhookSecurityInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Webhook ID"`
}

type GetWebhookSecurityOutput = model.Output[*model.WebhookSecuritySettings]

// UpdateWebhookSecurityInput represents input for updating webhook security
type UpdateWebhookSecurityInput struct {
	model.OrganisationPathParams
	ID   xid.ID                             `path:"id" doc:"Webhook ID"`
	Body model.UpdateWebhookSecurityRequest `json:"body"`
}

type UpdateWebhookSecurityOutput = model.Output[*model.WebhookSecuritySettings]

// GetWebhookStatsInput represents input for getting webhook statistics
type GetWebhookStatsInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Webhook ID"`
}

type GetWebhookStatsOutput = model.Output[*model.WebhookStats]

// GetGlobalWebhookStatsInput represents input for getting global webhook statistics
type GetGlobalWebhookStatsInput struct {
	model.OrganisationPathParams
}

type GetGlobalWebhookStatsOutput = model.Output[*model.WebhookGlobalStats]

// BulkWebhookOperationInput represents input for bulk webhook operations
type BulkWebhookOperationInput struct {
	model.OrganisationPathParams
	Body model.BulkWebhookOperationRequest `json:"body"`
}

type BulkWebhookOperationOutput = model.Output[*model.BulkWebhookOperationResponse]

// BulkRetryEventsInput represents input for bulk retry operations
type BulkRetryEventsInput struct {
	model.OrganisationPathParams
	Body model.WebhookDeliveryRetryRequest `json:"body"`
}

type BulkRetryEventsOutput = model.Output[*model.WebhookDeliveryRetryResponse]

// ExportWebhookDataInput represents input for exporting webhook data
type ExportWebhookDataInput struct {
	model.OrganisationPathParams
	Body model.WebhookExportRequest `json:"body"`
}

type ExportWebhookDataOutput = model.Output[*model.WebhookExportResponse]

// GetWebhookHealthInput represents input for getting webhook health
type GetWebhookHealthInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Webhook ID"`
}

type GetWebhookHealthOutput = model.Output[*model.WebhookHealthCheck]

// ReceiveWebhookInput represents input for receiving webhook from external service
type ReceiveWebhookInput struct {
	WebhookID xid.ID                 `path:"webhookId" doc:"Webhook ID"`
	Headers   map[string]string      `header:"*" doc:"All headers"`
	Body      map[string]interface{} `json:"body"`
}

type ReceiveWebhookOutput = model.Output[map[string]interface{}]

// Route registration functions

func registerListWebhooks(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listWebhooks",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/webhooks",
		Summary:       "List webhooks",
		Description:   "Get a paginated list of webhooks for the organization",
		Tags:          []string{"Webhooks"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionReadWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.listWebhooksHandler)
}

func registerCreateWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "createWebhook",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/webhooks",
		Summary:       "Create webhook",
		Description:   "Create a new webhook for the organization",
		Tags:          []string{"Webhooks"},
		DefaultStatus: 201,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Invalid webhook configuration")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionWriteWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.createWebhookHandler)
}

func registerGetWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getWebhook",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/webhooks/{id}",
		Summary:       "Get webhook",
		Description:   "Get details of a specific webhook",
		Tags:          []string{"Webhooks"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionReadWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.getWebhookHandler)
}

func registerUpdateWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "updateWebhook",
		Method:        http.MethodPut,
		Path:          "/organizations/{orgId}/webhooks/{id}",
		Summary:       "Update webhook",
		Description:   "Update an existing webhook configuration",
		Tags:          []string{"Webhooks"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook not found"), model.ValidationError("Invalid webhook configuration")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionWriteWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.updateWebhookHandler)
}

func registerDeleteWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteWebhook",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/webhooks/{id}",
		Summary:       "Delete webhook",
		Description:   "Delete a webhook",
		Tags:          []string{"Webhooks"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "Webhook deleted successfully",
			},
		}, true, model.NotFoundError("Webhook not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionDeleteWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.deleteWebhookHandler)
}

func registerActivateWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "activateWebhook",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/webhooks/{id}/activate",
		Summary:       "Activate webhook",
		Description:   "Activate a webhook to start receiving events",
		Tags:          []string{"Webhooks"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Webhook activated successfully",
			},
		}, true, model.NotFoundError("Webhook not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionWriteWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.activateWebhookHandler)
}

func registerDeactivateWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deactivateWebhook",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/webhooks/{id}/deactivate",
		Summary:       "Deactivate webhook",
		Description:   "Deactivate a webhook to stop receiving events",
		Tags:          []string{"Webhooks"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Webhook deactivated successfully",
			},
		}, true, model.NotFoundError("Webhook not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionWriteWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.deactivateWebhookHandler)
}

func registerRegenerateWebhookSecret(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "regenerateWebhookSecret",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/webhooks/{id}/regenerate-secret",
		Summary:       "Regenerate webhook secret",
		Description:   "Generate a new secret for webhook signature verification",
		Tags:          []string{"Webhooks", "Security"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionWriteWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.regenerateWebhookSecretHandler)
}

func registerTestWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "testWebhook",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/webhooks/test",
		Summary:       "Test webhook",
		Description:   "Send a test event to a webhook endpoint",
		Tags:          []string{"Webhooks", "Testing"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionReadWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.testWebhookHandler)
}

func registerValidateWebhookURL(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "validateWebhookURL",
		Method:        http.MethodPost,
		Path:          "/webhooks/validate-url",
		Summary:       "Validate webhook URL",
		Description:   "Validate a webhook URL for security and accessibility",
		Tags:          []string{"Webhooks", "Validation"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.ValidationError("Invalid URL")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, webhookCtrl.validateWebhookURLHandler)
}

func registerListWebhookEvents(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listWebhookEvents",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/webhook-events",
		Summary:       "List webhook events",
		Description:   "Get a paginated list of webhook events",
		Tags:          []string{"Webhooks", "Events"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionReadWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.listWebhookEventsHandler)
}

func registerGetWebhookEvent(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getWebhookEvent",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/webhook-events/{id}",
		Summary:       "Get webhook event",
		Description:   "Get details of a specific webhook event",
		Tags:          []string{"Webhooks", "Events"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook event not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionReadWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.getWebhookEventHandler)
}

func registerRetryWebhookEvent(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "retryWebhookEvent",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/webhook-events/retry",
		Summary:       "Retry webhook event",
		Description:   "Retry delivery of a failed webhook event",
		Tags:          []string{"Webhooks", "Events"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook event not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionWriteWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.retryWebhookEventHandler)
}

func registerGetWebhookSecurity(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getWebhookSecurity",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/webhooks/{id}/security",
		Summary:       "Get webhook security settings",
		Description:   "Get security configuration for a webhook",
		Tags:          []string{"Webhooks", "Security"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionReadWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.getWebhookSecurityHandler)
}

func registerUpdateWebhookSecurity(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "updateWebhookSecurity",
		Method:        http.MethodPut,
		Path:          "/organizations/{orgId}/webhooks/{id}/security",
		Summary:       "Update webhook security settings",
		Description:   "Update security configuration for a webhook",
		Tags:          []string{"Webhooks", "Security"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook not found"), model.ValidationError("Invalid security configuration")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionWriteWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.updateWebhookSecurityHandler)
}

func registerGetWebhookStats(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getWebhookStats",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/webhooks/{id}/stats",
		Summary:       "Get webhook statistics",
		Description:   "Get detailed statistics for a specific webhook",
		Tags:          []string{"Webhooks", "Analytics"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionReadWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.getWebhookStatsHandler)
}

func registerGetGlobalWebhookStats(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getGlobalWebhookStats",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/webhooks/stats",
		Summary:       "Get global webhook statistics",
		Description:   "Get statistics for all webhooks in the organization",
		Tags:          []string{"Webhooks", "Analytics"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionReadWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.getGlobalWebhookStatsHandler)
}

func registerBulkWebhookOperation(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "bulkWebhookOperation",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/webhooks/bulk",
		Summary:       "Bulk webhook operation",
		Description:   "Perform bulk operations on multiple webhooks",
		Tags:          []string{"Webhooks", "Bulk Operations"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.ValidationError("Invalid bulk operation request")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionWriteWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.bulkWebhookOperationHandler)
}

func registerBulkRetryEvents(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "bulkRetryEvents",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/webhooks/bulk-retry",
		Summary:       "Bulk retry webhook events",
		Description:   "Retry multiple failed webhook events",
		Tags:          []string{"Webhooks", "Events", "Bulk Operations"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.ValidationError("Invalid bulk retry request")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionWriteWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.bulkRetryEventsHandler)
}

func registerExportWebhookData(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "exportWebhookData",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/webhooks/export",
		Summary:       "Export webhook data",
		Description:   "Export webhook configuration and event data",
		Tags:          []string{"Webhooks", "Export"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionReadWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.exportWebhookDataHandler)
}

func registerGetWebhookHealth(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getWebhookHealth",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/webhooks/{id}/health",
		Summary:       "Get webhook health",
		Description:   "Check the health status of a webhook endpoint",
		Tags:          []string{"Webhooks", "Health"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionReadWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.getWebhookHealthHandler)
}

func registerReceiveWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "receiveWebhook",
		Method:        http.MethodPost,
		Path:          "/webhooks/receive/{webhookId}",
		Summary:       "Receive webhook",
		Description:   "Endpoint for receiving webhooks from external services",
		Tags:          []string{"Webhooks", "Public"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook not found"), model.UnauthorizedErrorWithMessage("Invalid webhook signature")),
	}, webhookCtrl.receiveWebhookHandler)
}

func registerWebhookDeliveryEndpoints(api huma.API, webhookCtrl *webhookController) {
	// Register internal endpoints used by the delivery service
	// These would typically be used for webhook delivery status updates, etc.
	// Implementation would depend on specific internal requirements
}

// Handler implementations

func (ctrl *webhookController) listWebhooksHandler(ctx context.Context, input *ListWebhooksInput) (*ListWebhooksOutput, error) {
	webhookService := ctrl.di.WebhookService()

	result, err := webhookService.ListWebhooks(ctx, input.WebhookListRequest, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &ListWebhooksOutput{
		Body: result,
	}, nil
}

func (ctrl *webhookController) createWebhookHandler(ctx context.Context, input *CreateWebhookInput) (*CreateWebhookOutput, error) {
	webhookService := ctrl.di.WebhookService()

	webhook, err := webhookService.CreateWebhook(ctx, input.Body, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &CreateWebhookOutput{
		Body: webhook,
	}, nil
}

func (ctrl *webhookController) getWebhookHandler(ctx context.Context, input *GetWebhookInput) (*GetWebhookOutput, error) {
	webhookService := ctrl.di.WebhookService()

	webhook, err := webhookService.GetWebhook(ctx, input.ID, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &GetWebhookOutput{
		Body: webhook,
	}, nil
}

func (ctrl *webhookController) updateWebhookHandler(ctx context.Context, input *UpdateWebhookInput) (*UpdateWebhookOutput, error) {
	webhookService := ctrl.di.WebhookService()

	webhook, err := webhookService.UpdateWebhook(ctx, input.ID, input.Body, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &UpdateWebhookOutput{
		Body: webhook,
	}, nil
}

func (ctrl *webhookController) deleteWebhookHandler(ctx context.Context, input *DeleteWebhookInput) (*DeleteWebhookOutput, error) {
	webhookService := ctrl.di.WebhookService()

	err := webhookService.DeleteWebhook(ctx, input.ID, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &DeleteWebhookOutput{}, nil
}

func (ctrl *webhookController) activateWebhookHandler(ctx context.Context, input *ActivateWebhookInput) (*ActivateWebhookOutput, error) {
	webhookService := ctrl.di.WebhookService()

	err := webhookService.ActivateWebhook(ctx, input.ID, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &ActivateWebhookOutput{}, nil
}

func (ctrl *webhookController) deactivateWebhookHandler(ctx context.Context, input *DeactivateWebhookInput) (*DeactivateWebhookOutput, error) {
	webhookService := ctrl.di.WebhookService()

	err := webhookService.DeactivateWebhook(ctx, input.ID, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &DeactivateWebhookOutput{}, nil
}

func (ctrl *webhookController) regenerateWebhookSecretHandler(ctx context.Context, input *RegenerateWebhookSecretInput) (*RegenerateWebhookSecretOutput, error) {
	webhookService := ctrl.di.WebhookService()

	secret, err := webhookService.RegenerateSecret(ctx, input.ID, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &RegenerateWebhookSecretOutput{
		Body: map[string]string{
			"secret": secret,
		},
	}, nil
}

func (ctrl *webhookController) testWebhookHandler(ctx context.Context, input *TestWebhookInput) (*TestWebhookOutput, error) {
	webhookService := ctrl.di.WebhookService()

	result, err := webhookService.TestWebhook(ctx, input.Body, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &TestWebhookOutput{
		Body: result,
	}, nil
}

func (ctrl *webhookController) validateWebhookURLHandler(ctx context.Context, input *ValidateWebhookURLInput) (*ValidateWebhookURLOutput, error) {
	webhookService := ctrl.di.WebhookService()

	err := webhookService.ValidateWebhookURL(ctx, input.URL)
	if err != nil {
		return &ValidateWebhookURLOutput{
			Body: map[string]interface{}{
				"valid": false,
				"error": err.Error(),
			},
		}, nil
	}

	return &ValidateWebhookURLOutput{
		Body: map[string]interface{}{
			"valid": true,
		},
	}, nil
}

func (ctrl *webhookController) listWebhookEventsHandler(ctx context.Context, input *ListWebhookEventsInput) (*ListWebhookEventsOutput, error) {
	webhookService := ctrl.di.WebhookService()

	result, err := webhookService.ListWebhookEvents(ctx, input.WebhookEventListRequest, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &ListWebhookEventsOutput{
		Body: result,
	}, nil
}

func (ctrl *webhookController) getWebhookEventHandler(ctx context.Context, input *GetWebhookEventInput) (*GetWebhookEventOutput, error) {
	webhookService := ctrl.di.WebhookService()

	event, err := webhookService.GetWebhookEvent(ctx, input.ID, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &GetWebhookEventOutput{
		Body: event,
	}, nil
}

func (ctrl *webhookController) retryWebhookEventHandler(ctx context.Context, input *RetryWebhookEventInput) (*RetryWebhookEventOutput, error) {
	webhookService := ctrl.di.WebhookService()

	result, err := webhookService.RetryWebhookEvent(ctx, input.Body, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &RetryWebhookEventOutput{
		Body: result,
	}, nil
}

func (ctrl *webhookController) getWebhookSecurityHandler(ctx context.Context, input *GetWebhookSecurityInput) (*GetWebhookSecurityOutput, error) {
	webhookService := ctrl.di.WebhookService()

	security, err := webhookService.GetWebhookSecurity(ctx, input.ID, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &GetWebhookSecurityOutput{
		Body: security,
	}, nil
}

func (ctrl *webhookController) updateWebhookSecurityHandler(ctx context.Context, input *UpdateWebhookSecurityInput) (*UpdateWebhookSecurityOutput, error) {
	webhookService := ctrl.di.WebhookService()

	security, err := webhookService.UpdateWebhookSecurity(ctx, input.ID, input.Body, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &UpdateWebhookSecurityOutput{
		Body: security,
	}, nil
}

func (ctrl *webhookController) getWebhookStatsHandler(ctx context.Context, input *GetWebhookStatsInput) (*GetWebhookStatsOutput, error) {
	webhookService := ctrl.di.WebhookService()

	stats, err := webhookService.GetWebhookStats(ctx, input.ID, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &GetWebhookStatsOutput{
		Body: stats,
	}, nil
}

func (ctrl *webhookController) getGlobalWebhookStatsHandler(ctx context.Context, input *GetGlobalWebhookStatsInput) (*GetGlobalWebhookStatsOutput, error) {
	webhookService := ctrl.di.WebhookService()

	stats, err := webhookService.GetGlobalStats(ctx, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &GetGlobalWebhookStatsOutput{
		Body: stats,
	}, nil
}

func (ctrl *webhookController) bulkWebhookOperationHandler(ctx context.Context, input *BulkWebhookOperationInput) (*BulkWebhookOperationOutput, error) {
	webhookService := ctrl.di.WebhookService()

	result, err := webhookService.BulkWebhookOperation(ctx, input.Body, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &BulkWebhookOperationOutput{
		Body: result,
	}, nil
}

func (ctrl *webhookController) bulkRetryEventsHandler(ctx context.Context, input *BulkRetryEventsInput) (*BulkRetryEventsOutput, error) {
	webhookService := ctrl.di.WebhookService()

	result, err := webhookService.BulkRetryEvents(ctx, input.Body, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &BulkRetryEventsOutput{
		Body: result,
	}, nil
}

func (ctrl *webhookController) exportWebhookDataHandler(ctx context.Context, input *ExportWebhookDataInput) (*ExportWebhookDataOutput, error) {
	webhookService := ctrl.di.WebhookService()

	result, err := webhookService.ExportWebhookData(ctx, input.Body, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &ExportWebhookDataOutput{
		Body: result,
	}, nil
}

func (ctrl *webhookController) getWebhookHealthHandler(ctx context.Context, input *GetWebhookHealthInput) (*GetWebhookHealthOutput, error) {
	webhookService := ctrl.di.WebhookService()

	health, err := webhookService.GetWebhookHealth(ctx, input.ID, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &GetWebhookHealthOutput{
		Body: health,
	}, nil
}

func (ctrl *webhookController) receiveWebhookHandler(ctx context.Context, input *ReceiveWebhookInput) (*ReceiveWebhookOutput, error) {
	// This handler would process incoming webhooks from external services
	// It would typically:
	// 1. Validate the webhook signature
	// 2. Process the webhook payload
	// 3. Store the webhook event
	// 4. Return appropriate response

	// For now, return a simple acknowledgment
	return &ReceiveWebhookOutput{
		Body: map[string]interface{}{
			"status":     "received",
			"webhook_id": input.WebhookID.String(),
			"timestamp":  "2023-01-01T12:00:00Z",
		},
	}, nil
}
