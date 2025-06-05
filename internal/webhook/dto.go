package webhook

import (
	"time"

	"github.com/juicycleff/frank/ent/webhook"
	"github.com/juicycleff/frank/internal/model"
	"github.com/rs/xid"
)

// ListWebhooksParams defines the parameters for listing webhooks
type ListWebhooksParams struct {
	model.PaginationParams
	OrgID      model.OptionalParam[xid.ID] `query:"orgID"`
	EventTypes []string                    `query:"eventTypes"`
	Active     model.OptionalParam[bool]   `query:"active"`
}

// CreateWebhookInput represents input for creating a webhook
type CreateWebhookInput struct {
	Name           string                 `json:"name" validate:"required"`
	URL            string                 `json:"url" validate:"required,url"`
	OrganizationID xid.ID                 `json:"organization_id" validate:"required"`
	EventTypes     []string               `json:"event_types" validate:"required"`
	RetryCount     *int                   `json:"retry_count,omitempty"`
	TimeoutMs      *int                   `json:"timeout_ms,omitempty"`
	Format         string                 `json:"format,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateWebhookInput represents input for updating a webhook
type UpdateWebhookInput struct {
	Name       *string                `json:"name,omitempty"`
	URL        *string                `json:"url,omitempty"`
	Active     *bool                  `json:"active,omitempty"`
	EventTypes []string               `json:"event_types,omitempty"`
	RetryCount *int                   `json:"retry_count,omitempty"`
	TimeoutMs  *int                   `json:"timeout_ms,omitempty"`
	Format     *string                `json:"format,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// TriggerEventInput represents input for triggering a webhook event
type TriggerEventInput struct {
	EventType      string                 `json:"event_type" validate:"required"`
	OrganizationID xid.ID                 `json:"organization_id" validate:"required"`
	Payload        map[string]interface{} `json:"payload" validate:"required"`
	Headers        map[string]string      `json:"headers,omitempty"`
}

// ListWebhookEventsParams defines the parameters for listing webhook events
type ListWebhookEventsParams struct {
	model.PaginationParams
	WebhookID model.OptionalParam[xid.ID] `query:"webhookId"`
	EventType string                      `query:"eventType"`
	Delivered model.OptionalParam[bool]   `query:"delivered"`
}

// WebhookEvent is the model entity for the WebhookEvent schema.
type WebhookEvent struct {
	model.Base
	// WebhookID holds the value of the "webhook_id" field.
	WebhookID xid.ID `json:"webhookId,omitempty"`
	// EventType holds the value of the "event_type" field.
	EventType string `json:"eventType,omitempty"`
	// Headers holds the value of the "headers" field.
	Headers map[string]string `json:"headers,omitempty"`
	// Payload holds the value of the "payload" field.
	Payload map[string]interface{} `json:"payload,omitempty"`
	// Delivered holds the value of the "delivered" field.
	Delivered bool `json:"delivered,omitempty"`
	// DeliveredAt holds the value of the "delivered_at" field.
	DeliveredAt *time.Time `json:"deliveredAt,omitempty"`
	// Attempts holds the value of the "attempts" field.
	Attempts int `json:"attempts,omitempty"`
	// NextRetry holds the value of the "next_retry" field.
	NextRetry *time.Time `json:"nextRetry,omitempty"`
	// StatusCode holds the value of the "status_code" field.
	StatusCode *int `json:"status_code,omitempty"`
	// ResponseBody holds the value of the "response_body" field.
	ResponseBody string `json:"responseBody,omitempty"`
	// Error holds the value of the "error" field.
	Error string `json:"error,omitempty"`
}

// Webhook is the model entity for the Webhook schema.
type Webhook struct {
	model.Base
	// Name holds the value of the "name" field.
	Name string `json:"name,omitempty"`
	// URL holds the value of the "url" field.
	URL string `json:"url,omitempty"`
	// OrganizationID holds the value of the "organization_id" field.
	OrganizationID xid.ID `json:"organizationId,omitempty"`
	// Secret holds the value of the "secret" field.
	Secret string `json:"-"`
	// Active holds the value of the "active" field.
	Active bool `json:"active,omitempty"`
	// EventTypes holds the value of the "event_types" field.
	EventTypes []string `json:"eventTypes,omitempty"`
	// Version holds the value of the "version" field.
	Version string `json:"version,omitempty"`
	// RetryCount holds the value of the "retry_count" field.
	RetryCount int `json:"retryCount,omitempty"`
	// TimeoutMs holds the value of the "timeout_ms" field.
	TimeoutMs int `json:"timeoutMs,omitempty"`
	// Format holds the value of the "format" field.
	Format webhook.Format `json:"format,omitempty"`
	// Metadata holds the value of the "metadata" field.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}
