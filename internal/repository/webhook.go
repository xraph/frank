package repository

import (
	"context"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/webhook"
	"github.com/juicycleff/frank/ent/webhookevent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// WebhookRepository defines the interface for webhook data operations
type WebhookRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateWebhookInput) (*ent.Webhook, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Webhook, error)
	Update(ctx context.Context, id xid.ID, input UpdateWebhookInput) (*ent.Webhook, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Webhook], error)
	ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Webhook, error)
	ListByEventType(ctx context.Context, eventType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Webhook], error)

	// Utility operations
	DeactivateByOrganizationID(ctx context.Context, orgID xid.ID) error
	CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)

	// Advanced queries
	GetActiveByOrganizationIDAndEventType(ctx context.Context, orgID xid.ID, eventType string) ([]*ent.Webhook, error)
	ListByURL(ctx context.Context, url string) ([]*ent.Webhook, error)
}

// WebhookEventRepository defines the interface for webhook event data operations
type WebhookEventRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateWebhookEventInput) (*ent.WebhookEvent, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.WebhookEvent, error)
	Update(ctx context.Context, id xid.ID, input UpdateWebhookEventInput) (*ent.WebhookEvent, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	ListByWebhookID(ctx context.Context, webhookID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.WebhookEvent], error)
	ListPending(ctx context.Context, limit int) ([]*ent.WebhookEvent, error)
	ListFailedRetries(ctx context.Context, before time.Time, limit int) ([]*ent.WebhookEvent, error)

	// Delivery operations
	MarkAsDelivered(ctx context.Context, id xid.ID, statusCode int, responseBody string) error
	MarkAsFailed(ctx context.Context, id xid.ID, statusCode *int, errorMsg string) error
	IncrementAttempts(ctx context.Context, id xid.ID, nextRetry time.Time) error

	// Utility operations
	CountByWebhookID(ctx context.Context, webhookID xid.ID) (int, error)
	CountPendingByWebhookID(ctx context.Context, webhookID xid.ID) (int, error)
	DeleteOldEvents(ctx context.Context, before time.Time) (int, error)

	// Advanced queries
	ListByEventType(ctx context.Context, eventType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.WebhookEvent], error)
	GetDeliveryStats(ctx context.Context, webhookID xid.ID, since time.Time) (*WebhookDeliveryStats, error)
}

// webhookRepository implements WebhookRepository interface
type webhookRepository struct {
	client *ent.Client
}

// webhookEventRepository implements WebhookEventRepository interface
type webhookEventRepository struct {
	client *ent.Client
}

// NewWebhookRepository creates a new webhook repository
func NewWebhookRepository(client *ent.Client) WebhookRepository {
	return &webhookRepository{
		client: client,
	}
}

// NewWebhookEventRepository creates a new webhook event repository
func NewWebhookEventRepository(client *ent.Client) WebhookEventRepository {
	return &webhookEventRepository{
		client: client,
	}
}

// CreateWebhookInput defines the input for creating a webhook
type CreateWebhookInput struct {
	Name           string              `json:"name"`
	URL            string              `json:"url"`
	OrganizationID xid.ID              `json:"organization_id"`
	Secret         string              `json:"secret"`
	Active         bool                `json:"active"`
	EventTypes     []string            `json:"event_types"`
	Version        string              `json:"version"`
	RetryCount     int                 `json:"retry_count"`
	TimeoutMs      int                 `json:"timeout_ms"`
	Format         model.WebhookFormat `json:"format"`
	Metadata       map[string]any      `json:"metadata,omitempty"`
	Headers        map[string]string   `json:"headers,omitempty"`
}

// UpdateWebhookInput defines the input for updating a webhook
type UpdateWebhookInput struct {
	Name       *string              `json:"name,omitempty"`
	URL        *string              `json:"url,omitempty"`
	Secret     *string              `json:"secret,omitempty"`
	Active     *bool                `json:"active,omitempty"`
	EventTypes []string             `json:"event_types,omitempty"`
	Version    *string              `json:"version,omitempty"`
	RetryCount *int                 `json:"retry_count,omitempty"`
	TimeoutMs  *int                 `json:"timeout_ms,omitempty"`
	Format     *model.WebhookFormat `json:"format,omitempty"`
	Metadata   map[string]any       `json:"metadata,omitempty"`
	Headers    map[string]string    `json:"headers,omitempty"`
}

// CreateWebhookEventInput defines the input for creating a webhook event
type CreateWebhookEventInput struct {
	WebhookID xid.ID            `json:"webhook_id"`
	EventType string            `json:"event_type"`
	Headers   map[string]string `json:"headers"`
	Payload   map[string]any    `json:"payload"`
	NextRetry *time.Time        `json:"next_retry,omitempty"`
}

// UpdateWebhookEventInput defines the input for updating a webhook event
type UpdateWebhookEventInput struct {
	Delivered    *bool      `json:"delivered,omitempty"`
	DeliveredAt  *time.Time `json:"delivered_at,omitempty"`
	Attempts     *int       `json:"attempts,omitempty"`
	NextRetry    *time.Time `json:"next_retry,omitempty"`
	StatusCode   *int       `json:"status_code,omitempty"`
	ResponseBody *string    `json:"response_body,omitempty"`
	Error        *string    `json:"error,omitempty"`
}

// WebhookDeliveryStats represents delivery statistics for a webhook
type WebhookDeliveryStats struct {
	TotalEvents     int     `json:"total_events"`
	DeliveredEvents int     `json:"delivered_events"`
	FailedEvents    int     `json:"failed_events"`
	PendingEvents   int     `json:"pending_events"`
	SuccessRate     float64 `json:"success_rate"`
}

// Webhook Repository Implementation

// Create creates a new webhook
func (r *webhookRepository) Create(ctx context.Context, input CreateWebhookInput) (*ent.Webhook, error) {
	builder := r.client.Webhook.Create().
		SetName(input.Name).
		SetURL(input.URL).
		SetOrganizationID(input.OrganizationID).
		SetSecret(input.Secret).
		SetActive(input.Active).
		SetEventTypes(input.EventTypes).
		SetVersion(input.Version).
		SetRetryCount(input.RetryCount).
		SetTimeoutMs(input.TimeoutMs).
		SetFormat(input.Format)

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	webhook, err := builder.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to create webhook")
	}

	return webhook, nil
}

// GetByID retrieves a webhook by its ID
func (r *webhookRepository) GetByID(ctx context.Context, id xid.ID) (*ent.Webhook, error) {
	webhook, err := r.client.Webhook.
		Query().
		Where(webhook.ID(id)).
		WithOrganization().
		WithEvents().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Webhook not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get webhook")
	}

	return webhook, nil
}

// Update updates a webhook
func (r *webhookRepository) Update(ctx context.Context, id xid.ID, input UpdateWebhookInput) (*ent.Webhook, error) {
	builder := r.client.Webhook.UpdateOneID(id)

	if input.Name != nil {
		builder.SetName(*input.Name)
	}

	if input.URL != nil {
		builder.SetURL(*input.URL)
	}

	if input.Secret != nil {
		builder.SetSecret(*input.Secret)
	}

	if input.Active != nil {
		builder.SetActive(*input.Active)
	}

	if input.EventTypes != nil {
		builder.SetEventTypes(input.EventTypes)
	}

	if input.Version != nil {
		builder.SetVersion(*input.Version)
	}

	if input.RetryCount != nil {
		builder.SetRetryCount(*input.RetryCount)
	}

	if input.TimeoutMs != nil {
		builder.SetTimeoutMs(*input.TimeoutMs)
	}

	if input.Format != nil {
		builder.SetFormat(*input.Format)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	webhook, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Webhook not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to update webhook")
	}

	return webhook, nil
}

// Delete deletes a webhook
func (r *webhookRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.Webhook.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Webhook not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete webhook")
	}

	return nil
}

// ListByOrganizationID retrieves paginated webhooks for an organization
func (r *webhookRepository) ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Webhook], error) {
	query := r.client.Webhook.
		Query().
		Where(webhook.OrganizationID(orgID)).
		WithOrganization()

	// Apply ordering
	query.Order(ent.Desc(webhook.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.Webhook, *ent.WebhookQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list webhooks by organization ID")
	}

	return result, nil
}

// ListActiveByOrganizationID retrieves all active webhooks for an organization
func (r *webhookRepository) ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Webhook, error) {
	webhooks, err := r.client.Webhook.
		Query().
		Where(
			webhook.OrganizationID(orgID),
			webhook.Active(true),
		).
		WithOrganization().
		Order(ent.Desc(webhook.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list active webhooks")
	}

	return webhooks, nil
}

// ListByEventType retrieves paginated webhooks that handle a specific event type
func (r *webhookRepository) ListByEventType(ctx context.Context, eventType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Webhook], error) {
	query := r.client.Webhook.
		Query().
		Where(func(s *sql.Selector) {
			s.Where(sqljson.ValueContains(webhook.FieldEventTypes, eventType))
		}).
		WithOrganization()

	// Apply ordering
	query.Order(ent.Desc(webhook.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.Webhook, *ent.WebhookQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list webhooks by event type %s", eventType))
	}

	return result, nil
}

// DeactivateByOrganizationID deactivates all webhooks for an organization
func (r *webhookRepository) DeactivateByOrganizationID(ctx context.Context, orgID xid.ID) error {
	_, err := r.client.Webhook.
		Update().
		Where(webhook.OrganizationID(orgID)).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to deactivate webhooks")
	}

	return nil
}

// CountByOrganizationID counts the number of webhooks for an organization
func (r *webhookRepository) CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error) {
	count, err := r.client.Webhook.
		Query().
		Where(webhook.OrganizationID(orgID)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count webhooks")
	}

	return count, nil
}

// GetActiveByOrganizationIDAndEventType retrieves active webhooks for an organization and event type
func (r *webhookRepository) GetActiveByOrganizationIDAndEventType(ctx context.Context, orgID xid.ID, eventType string) ([]*ent.Webhook, error) {
	webhooks, err := r.client.Webhook.
		Query().
		Where(
			webhook.OrganizationID(orgID),
			webhook.Active(true),
		).
		Where(func(s *sql.Selector) {
			s.Where(sqljson.ValueContains(webhook.FieldEventTypes, eventType))
		}).
		WithOrganization().
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get active webhooks by organization and event type")
	}

	return webhooks, nil
}

// ListByURL retrieves webhooks by URL
func (r *webhookRepository) ListByURL(ctx context.Context, url string) ([]*ent.Webhook, error) {
	webhooks, err := r.client.Webhook.
		Query().
		Where(webhook.URL(url)).
		WithOrganization().
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list webhooks by URL")
	}

	return webhooks, nil
}

// Webhook Event Repository Implementation

// Create creates a new webhook event
func (r *webhookEventRepository) Create(ctx context.Context, input CreateWebhookEventInput) (*ent.WebhookEvent, error) {
	builder := r.client.WebhookEvent.Create().
		SetWebhookID(input.WebhookID).
		SetEventType(input.EventType).
		SetHeaders(input.Headers).
		SetPayload(input.Payload)

	if input.NextRetry != nil {
		builder.SetNextRetry(*input.NextRetry)
	}

	event, err := builder.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to create webhook event")
	}

	return event, nil
}

// GetByID retrieves a webhook event by its ID
func (r *webhookEventRepository) GetByID(ctx context.Context, id xid.ID) (*ent.WebhookEvent, error) {
	event, err := r.client.WebhookEvent.
		Query().
		Where(webhookevent.ID(id)).
		WithWebhook().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Webhook event not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get webhook event")
	}

	return event, nil
}

// Update updates a webhook event
func (r *webhookEventRepository) Update(ctx context.Context, id xid.ID, input UpdateWebhookEventInput) (*ent.WebhookEvent, error) {
	builder := r.client.WebhookEvent.UpdateOneID(id)

	if input.Delivered != nil {
		builder.SetDelivered(*input.Delivered)
	}

	if input.DeliveredAt != nil {
		builder.SetDeliveredAt(*input.DeliveredAt)
	}

	if input.Attempts != nil {
		builder.SetAttempts(*input.Attempts)
	}

	if input.NextRetry != nil {
		builder.SetNextRetry(*input.NextRetry)
	}

	if input.StatusCode != nil {
		builder.SetStatusCode(*input.StatusCode)
	}

	if input.ResponseBody != nil {
		builder.SetResponseBody(*input.ResponseBody)
	}

	if input.Error != nil {
		builder.SetError(*input.Error)
	}

	event, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Webhook event not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to update webhook event")
	}

	return event, nil
}

// Delete deletes a webhook event
func (r *webhookEventRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.WebhookEvent.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Webhook event not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete webhook event")
	}

	return nil
}

// ListByWebhookID retrieves paginated webhook events for a webhook
func (r *webhookEventRepository) ListByWebhookID(ctx context.Context, webhookID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.WebhookEvent], error) {
	query := r.client.WebhookEvent.
		Query().
		Where(webhookevent.WebhookID(webhookID)).
		WithWebhook()

	// Apply ordering
	query.Order(ent.Desc(webhookevent.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.WebhookEvent, *ent.WebhookEventQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list webhook events by webhook ID")
	}

	return result, nil
}

// ListPending retrieves pending webhook events
func (r *webhookEventRepository) ListPending(ctx context.Context, limit int) ([]*ent.WebhookEvent, error) {
	events, err := r.client.WebhookEvent.
		Query().
		Where(
			webhookevent.Delivered(false),
			webhookevent.Or(
				webhookevent.NextRetryIsNil(),
				webhookevent.NextRetryLTE(time.Now()),
			),
		).
		WithWebhook().
		Order(ent.Asc(webhookevent.FieldCreatedAt)).
		Limit(limit).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list pending webhook events")
	}

	return events, nil
}

// ListFailedRetries retrieves webhook events that need to be retried
func (r *webhookEventRepository) ListFailedRetries(ctx context.Context, before time.Time, limit int) ([]*ent.WebhookEvent, error) {
	events, err := r.client.WebhookEvent.
		Query().
		Where(
			webhookevent.Delivered(false),
			webhookevent.NextRetryNotNil(),
			webhookevent.NextRetryLTE(before),
		).
		WithWebhook().
		Order(ent.Asc(webhookevent.FieldNextRetry)).
		Limit(limit).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list failed webhook events for retry")
	}

	return events, nil
}

// MarkAsDelivered marks a webhook event as successfully delivered
func (r *webhookEventRepository) MarkAsDelivered(ctx context.Context, id xid.ID, statusCode int, responseBody string) error {
	err := r.client.WebhookEvent.
		UpdateOneID(id).
		SetDelivered(true).
		SetDeliveredAt(time.Now()).
		SetStatusCode(statusCode).
		SetResponseBody(responseBody).
		ClearError().
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Webhook event not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to mark webhook event as delivered")
	}

	return nil
}

// MarkAsFailed marks a webhook event as failed
func (r *webhookEventRepository) MarkAsFailed(ctx context.Context, id xid.ID, statusCode *int, errorMsg string) error {
	builder := r.client.WebhookEvent.
		UpdateOneID(id).
		SetError(errorMsg)

	if statusCode != nil {
		builder.SetStatusCode(*statusCode)
	}

	err := builder.Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Webhook event not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to mark webhook event as failed")
	}

	return nil
}

// IncrementAttempts increments the attempt count and sets next retry time
func (r *webhookEventRepository) IncrementAttempts(ctx context.Context, id xid.ID, nextRetry time.Time) error {
	// Get current attempts count
	event, err := r.client.WebhookEvent.
		Query().
		Where(webhookevent.ID(id)).
		Select(webhookevent.FieldAttempts).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Webhook event not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to get webhook event for attempt increment")
	}

	err = r.client.WebhookEvent.
		UpdateOneID(id).
		SetAttempts(event.Attempts + 1).
		SetNextRetry(nextRetry).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to increment webhook event attempts")
	}

	return nil
}

// CountByWebhookID counts the number of webhook events for a webhook
func (r *webhookEventRepository) CountByWebhookID(ctx context.Context, webhookID xid.ID) (int, error) {
	count, err := r.client.WebhookEvent.
		Query().
		Where(webhookevent.WebhookID(webhookID)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count webhook events")
	}

	return count, nil
}

// CountPendingByWebhookID counts the number of pending webhook events for a webhook
func (r *webhookEventRepository) CountPendingByWebhookID(ctx context.Context, webhookID xid.ID) (int, error) {
	count, err := r.client.WebhookEvent.
		Query().
		Where(
			webhookevent.WebhookID(webhookID),
			webhookevent.Delivered(false),
		).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count pending webhook events")
	}

	return count, nil
}

// DeleteOldEvents deletes webhook events older than the specified time
func (r *webhookEventRepository) DeleteOldEvents(ctx context.Context, before time.Time) (int, error) {
	count, err := r.client.WebhookEvent.
		Delete().
		Where(webhookevent.CreatedAtLT(before)).
		Exec(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete old webhook events")
	}

	return count, nil
}

// ListByEventType retrieves paginated webhook events by event type
func (r *webhookEventRepository) ListByEventType(ctx context.Context, eventType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.WebhookEvent], error) {
	query := r.client.WebhookEvent.
		Query().
		Where(webhookevent.EventType(eventType)).
		WithWebhook()

	// Apply ordering
	query.Order(ent.Desc(webhookevent.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.WebhookEvent, *ent.WebhookEventQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list webhook events by event type %s", eventType))
	}

	return result, nil
}

// GetDeliveryStats retrieves delivery statistics for a webhook
func (r *webhookEventRepository) GetDeliveryStats(ctx context.Context, webhookID xid.ID, since time.Time) (*WebhookDeliveryStats, error) {
	stats := &WebhookDeliveryStats{}

	// Count total events
	totalEvents, err := r.client.WebhookEvent.
		Query().
		Where(
			webhookevent.WebhookID(webhookID),
			webhookevent.CreatedAtGTE(since),
		).
		Count(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count total webhook events")
	}

	// Count delivered events
	deliveredEvents, err := r.client.WebhookEvent.
		Query().
		Where(
			webhookevent.WebhookID(webhookID),
			webhookevent.CreatedAtGTE(since),
			webhookevent.Delivered(true),
		).
		Count(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count delivered webhook events")
	}

	// Count pending events
	pendingEvents, err := r.client.WebhookEvent.
		Query().
		Where(
			webhookevent.WebhookID(webhookID),
			webhookevent.CreatedAtGTE(since),
			webhookevent.Delivered(false),
		).
		Count(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count pending webhook events")
	}

	stats.TotalEvents = totalEvents
	stats.DeliveredEvents = deliveredEvents
	stats.PendingEvents = pendingEvents
	stats.FailedEvents = totalEvents - deliveredEvents - pendingEvents

	if totalEvents > 0 {
		stats.SuccessRate = float64(deliveredEvents) / float64(totalEvents) * 100
	}

	return stats, nil
}
