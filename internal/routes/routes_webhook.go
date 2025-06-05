package routes

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/internal/webhook"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

// RegisterWebhookAPI registers all webhook-related endpoints
func RegisterWebhookAPI(api huma.API, di di.Container) {
	webhookCtrl := &webhookController{
		api: api,
		di:  di,
	}

	// Register webhook endpoints
	registerListWebhooks(api, webhookCtrl)
	registerGetWebhook(api, webhookCtrl)
	registerCreateWebhook(api, webhookCtrl)
	registerUpdateWebhook(api, webhookCtrl)
	registerDeleteWebhook(api, webhookCtrl)
	registerTriggerWebhookEvent(api, webhookCtrl)
	registerGetWebhookEvents(api, webhookCtrl)
	registerReplayWebhookEvent(api, webhookCtrl)
}

// RegisterWebhookPublicAPI registers all webhook-related endpoints
func RegisterWebhookPublicAPI(api huma.API, di di.Container) {
	webhookCtrl := &webhookController{
		api: api,
		di:  di,
	}

	// Register webhook endpoints
	registerReceiveWebhook(api, webhookCtrl)
}

func registerListWebhooks(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID: "listWebhooks",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/webhooks",
		Summary:     "List webhooks",
		Description: "List all webhooks for an organization with pagination and filtering options",
		Tags:        []string{"Webhooks"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionListWebhooks, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.listWebhooksHandler)
}

func registerGetWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID: "getWebhook",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/webhooks/{id}",
		Summary:     "Get a webhook",
		Description: "Get a webhook by ID",
		Tags:        []string{"Webhooks"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionViewWebhooks, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.getWebhookHandler)
}

func registerCreateWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID: "createWebhook",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/webhooks",
		Summary:     "Create a new webhook",
		Description: "Create a new webhook with the specified configuration",
		Tags:        []string{"Webhooks"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionCreateWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.createWebhookHandler)
}

func registerUpdateWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateWebhook",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/webhooks/{id}",
		Summary:     "Update a webhook",
		Description: "Update an existing webhook by ID",
		Tags:        []string{"Webhooks"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Webhook not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionUpdateWebhook, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.updateWebhookHandler)
}

func registerDeleteWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteWebhook",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/webhooks/{id}",
		Summary:       "Delete a webhook",
		Description:   "Delete a webhook by ID",
		Tags:          []string{"Webhooks"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "Webhook successfully deleted",
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

func registerTriggerWebhookEvent(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID: "triggerWebhookEvent",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/webhooks/trigger",
		Summary:     "Trigger a webhook event",
		Description: "Trigger a webhook event for all matching webhooks",
		Tags:        []string{"Webhooks"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionCreateWebhookEvent, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.triggerWebhookEventHandler)
}

func registerGetWebhookEvents(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID: "getWebhookEvents",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/webhooks/{id}/events",
		Summary:     "Get webhook events",
		Description: "Get events for a webhook with pagination",
		Tags:        []string{"Webhooks"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionViewWebhookEvents, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.getWebhookEventsHandler)
}

func registerReplayWebhookEvent(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID: "replayWebhookEvent",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/webhooks/{id}/events/{eventId}/replay",
		Summary:     "Replay a webhook event",
		Description: "Replay a webhook event by creating a new delivery attempt",
		Tags:        []string{"Webhooks"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, webhookCtrl.di.AuthZ().Checker(), webhookCtrl.di.Logger())(
			authz.PermissionManageWebhookEvents, authz.ResourceOrganization, "orgId",
		)},
	}, webhookCtrl.replayWebhookEventHandler)
}

func registerReceiveWebhook(api huma.API, webhookCtrl *webhookController) {
	huma.Register(api, huma.Operation{
		OperationID: "receiveWebhook",
		Method:      http.MethodPost,
		Path:        "/webhooks/{id}",
		Summary:     "Receive webhook",
		Description: "Receive incoming webhook requests",
		Tags:        []string{"Webhooks"},
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Webhook received successfully",
				Content: map[string]*huma.MediaType{
					"application/json": {
						Schema: &huma.Schema{
							Type: "object",
							Properties: map[string]*huma.Schema{
								"message": {Type: "string"},
							},
						},
					},
				},
			},
		},
	}, webhookCtrl.receiveWebhookHandler)
}

// webhookController handles webhook-related API requests
type webhookController struct {
	api huma.API
	di  di.Container
}

// Input/Output type definitions for webhook handlers

// ListWebhooksInput represents input for listing webhooks
type ListWebhooksInput struct {
	webhook.ListWebhooksParams
}

type ListWebhooksOutput = model.Output[*model.PaginatedOutput[*webhook.Webhook]]

// GetWebhookInput represents input for getting a specific webhook
type GetWebhookInput struct {
	model.OrganisationParams
	ID string `path:"id" doc:"Webhook ID"`
}

type GetWebhookOutput = model.Output[*webhook.Webhook]

// CreateWebhookRequest represents the input for creating a webhook
type CreateWebhookRequest struct {
	Name       string                 `json:"name" validate:"required"`
	URL        string                 `json:"url" validate:"required,url"`
	EventTypes []string               `json:"event_types" validate:"required"`
	RetryCount *int                   `json:"retry_count,omitempty"`
	TimeoutMs  *int                   `json:"timeout_ms,omitempty"`
	Format     string                 `json:"format,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// CreateWebhookInput represents input for creating a webhook
type CreateWebhookInput struct {
	model.OrganisationParams
	Body CreateWebhookRequest
}

type CreateWebhookOutput = model.Output[*webhook.Webhook]

// UpdateWebhookRequest represents the input for updating a webhook
type UpdateWebhookRequest struct {
	Name       *string                `json:"name,omitempty"`
	URL        *string                `json:"url,omitempty"`
	Active     *bool                  `json:"active,omitempty"`
	EventTypes []string               `json:"event_types,omitempty"`
	RetryCount *int                   `json:"retry_count,omitempty"`
	TimeoutMs  *int                   `json:"timeout_ms,omitempty"`
	Format     *string                `json:"format,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateWebhookInput represents input for updating a webhook
type UpdateWebhookInput struct {
	model.OrganisationParams
	ID   string `path:"id" doc:"Webhook ID"`
	Body UpdateWebhookRequest
}

type UpdateWebhookOutput = model.Output[*webhook.Webhook]

// DeleteWebhookInput represents input for deleting a webhook
type DeleteWebhookInput struct {
	model.OrganisationParams
	ID string `path:"id" doc:"Webhook ID"`
}

// TriggerEventRequest represents the input for triggering a webhook event
type TriggerEventRequest struct {
	EventType string                 `json:"event_type" validate:"required"`
	Payload   map[string]interface{} `json:"payload" validate:"required"`
	Headers   map[string]string      `json:"headers,omitempty"`
}

// TriggerWebhookEventInput represents input for triggering a webhook event
type TriggerWebhookEventInput struct {
	model.OrganisationParams
	Body TriggerEventRequest
}

type TriggerWebhookEventOutput = model.Output[*webhook.WebhookEvent]

// GetWebhookEventsInput represents input for getting webhook events
type GetWebhookEventsInput struct {
	model.OrganisationParams
	ID xid.ID `path:"id" doc:"Webhook ID"`
	webhook.ListWebhookEventsParams
}

type GetWebhookEventsOutput = model.Output[model.PaginatedOutput[*webhook.WebhookEvent]]

// ReplayWebhookEventInput represents input for replaying a webhook event
type ReplayWebhookEventInput struct {
	model.OrganisationParams
	ID      string `path:"id" doc:"Webhook ID"`
	EventID string `path:"eventId" doc:"Event ID"`
}

type ReplayWebhookEventOutput = model.Output[*webhook.WebhookEvent]

// ReceiveWebhookInput represents input for receiving a webhook
type ReceiveWebhookInput struct {
	ID        string            `path:"id" doc:"Webhook ID"`
	Signature string            `header:"X-Signature" doc:"Webhook signature"`
	Body      any               `doc:"Raw webhook payload"`
	Headers   map[string]string `header:"*" doc:"All headers"`
}

type ReceiveWebhookOutput = model.Output[map[string]string]

// Handler implementations

func (c *webhookController) listWebhooksHandler(ctx context.Context, input *ListWebhooksInput) (*ListWebhooksOutput, error) {
	result, err := c.di.WebhookService().List(ctx, input.ListWebhooksParams)
	if err != nil {
		return nil, err
	}

	return &ListWebhooksOutput{
		Body: result,
	}, nil
}

func (c *webhookController) getWebhookHandler(ctx context.Context, input *GetWebhookInput) (*GetWebhookOutput, error) {
	// Convert string ID to xid.ID
	id, err := xid.FromString(input.ID)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidInput, "invalid webhook ID")
	}

	webhook, err := c.di.WebhookService().Get(ctx, id)
	if err != nil {
		return nil, err
	}

	return &GetWebhookOutput{
		Body: webhook,
	}, nil
}

func (c *webhookController) createWebhookHandler(ctx context.Context, input *CreateWebhookInput) (*CreateWebhookOutput, error) {
	// Convert organization ID to xid.ID
	orgID, err := xid.FromString(input.OrgID)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidInput, "invalid organization ID")
	}

	// Validate URL format
	if !isValidURL(input.Body.URL) {
		return nil, errors.New(errors.CodeInvalidInput, "invalid webhook URL")
	}

	// Map to service input
	createInput := webhook.CreateWebhookInput{
		Name:           input.Body.Name,
		URL:            input.Body.URL,
		OrganizationID: orgID,
		EventTypes:     input.Body.EventTypes,
		RetryCount:     input.Body.RetryCount,
		TimeoutMs:      input.Body.TimeoutMs,
		Format:         input.Body.Format,
		Metadata:       input.Body.Metadata,
	}

	webhook, err := c.di.WebhookService().Create(ctx, createInput)
	if err != nil {
		return nil, err
	}

	return &CreateWebhookOutput{
		Body: webhook,
	}, nil
}

func (c *webhookController) updateWebhookHandler(ctx context.Context, input *UpdateWebhookInput) (*UpdateWebhookOutput, error) {
	// Convert string ID to xid.ID
	id, err := xid.FromString(input.ID)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidInput, "invalid webhook ID")
	}

	// Validate URL format if provided
	if input.Body.URL != nil && !isValidURL(*input.Body.URL) {
		return nil, errors.New(errors.CodeInvalidInput, "invalid webhook URL")
	}

	// Map to service input
	updateInput := webhook.UpdateWebhookInput{
		Name:       input.Body.Name,
		URL:        input.Body.URL,
		Active:     input.Body.Active,
		EventTypes: input.Body.EventTypes,
		RetryCount: input.Body.RetryCount,
		TimeoutMs:  input.Body.TimeoutMs,
		Format:     input.Body.Format,
		Metadata:   input.Body.Metadata,
	}

	webhook, err := c.di.WebhookService().Update(ctx, id, updateInput)
	if err != nil {
		return nil, err
	}

	return &UpdateWebhookOutput{
		Body: webhook,
	}, nil
}

func (c *webhookController) deleteWebhookHandler(ctx context.Context, input *DeleteWebhookInput) (*model.EmptyOutput, error) {
	// Convert string ID to xid.ID
	id, err := xid.FromString(input.ID)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidInput, "invalid webhook ID")
	}

	err = c.di.WebhookService().Delete(ctx, id)
	return nil, err
}

func (c *webhookController) triggerWebhookEventHandler(ctx context.Context, input *TriggerWebhookEventInput) (*TriggerWebhookEventOutput, error) {
	// Convert organization ID to xid.ID
	orgID, err := xid.FromString(input.OrgID)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidInput, "invalid organization ID")
	}

	// Map to service input
	triggerInput := webhook.TriggerEventInput{
		EventType:      input.Body.EventType,
		OrganizationID: orgID,
		Payload:        input.Body.Payload,
		Headers:        input.Body.Headers,
	}

	event, err := c.di.WebhookService().TriggerEvent(ctx, triggerInput)
	if err != nil {
		return nil, err
	}

	return &TriggerWebhookEventOutput{
		Body: event,
	}, nil
}

func (c *webhookController) getWebhookEventsHandler(ctx context.Context, input *GetWebhookEventsInput) (*GetWebhookEventsOutput, error) {
	result, err := c.di.WebhookService().GetEvents(ctx, input.ID, input.ListWebhookEventsParams)
	if err != nil {
		return nil, err
	}

	return &GetWebhookEventsOutput{
		Body: *result,
	}, nil
}

func (c *webhookController) replayWebhookEventHandler(ctx context.Context, input *ReplayWebhookEventInput) (*ReplayWebhookEventOutput, error) {
	// Convert string ID to xid.ID
	eventID, err := xid.FromString(input.EventID)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidInput, "invalid event ID")
	}

	event, err := c.di.WebhookService().ReplayEvent(ctx, eventID)
	if err != nil {
		return nil, err
	}

	return &ReplayWebhookEventOutput{
		Body: event,
	}, nil
}

func (c *webhookController) receiveWebhookHandler(ctx context.Context, input *ReceiveWebhookInput) (*ReceiveWebhookOutput, error) {
	// Convert string ID to xid.ID
	webhookID, err := xid.FromString(input.ID)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidInput, "invalid webhook ID")
	}

	// Read request body
	bodyBytes, err := json.Marshal(input.Body)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidInput, "invalid webhook body")
	}

	// Validate signature if provided
	if input.Signature != "" {
		webhook, err := c.di.WebhookService().Get(ctx, webhookID)
		if err != nil {
			return nil, err
		}

		// Calculate expected signature
		mac := hmac.New(sha256.New, []byte(webhook.Secret))
		mac.Write(bodyBytes)
		expectedSignature := hex.EncodeToString(mac.Sum(nil))

		// Compare signatures
		if !hmac.Equal([]byte(input.Signature), []byte(expectedSignature)) {
			return nil, errors.New(errors.CodeInvalidInput, "invalid webhook signature")
		}
	}

	// Process webhook (implementation depends on requirements)
	// For now, just return success
	return &ReceiveWebhookOutput{
		Body: map[string]string{
			"message": "Webhook received successfully",
		},
	}, nil
}

// Helper function to validate URL
func isValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	// Check if URL has a scheme and host
	return u.Scheme != "" && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}
