package webhook

import (
	"context"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/predicate"
	"github.com/juicycleff/frank/ent/webhook"
	"github.com/juicycleff/frank/ent/webhookevent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/utils"
)

// EventRepository provides access to webhook event storage
type EventRepository interface {
	// Create creates a new webhook event
	Create(ctx context.Context, input EventRepositoryCreateInput) (*ent.WebhookEvent, error)

	// GetByID retrieves a webhook event by ID
	GetByID(ctx context.Context, id string) (*ent.WebhookEvent, error)

	// List retrieves webhook events with pagination
	List(ctx context.Context, input EventRepositoryListInput) ([]*ent.WebhookEvent, int, error)

	// Update updates a webhook event
	Update(ctx context.Context, id string, input EventRepositoryUpdateInput) (*ent.WebhookEvent, error)

	// DeleteByWebhookID deletes all events for a webhook
	DeleteByWebhookID(ctx context.Context, webhookID string) error

	// GetPendingEvents gets events that need to be retried
	GetPendingEvents(ctx context.Context, limit int) ([]*ent.WebhookEvent, error)
}

// EventRepositoryCreateInput represents input for creating a webhook event
type EventRepositoryCreateInput struct {
	WebhookID string
	EventType string
	Payload   map[string]interface{}
	Headers   map[string]string
}

// EventRepositoryUpdateInput represents input for updating a webhook event
type EventRepositoryUpdateInput struct {
	Delivered    *bool
	DeliveredAt  *time.Time
	Attempts     *int
	NextRetry    *time.Time
	StatusCode   *int
	ResponseBody *string
	Error        *string
}

// EventRepositoryListInput represents input for listing webhook events
type EventRepositoryListInput struct {
	WebhookID string
	Offset    int
	Limit     int
	EventType string
	Delivered *bool
}

type eventRepository struct {
	client *ent.Client
}

// NewEventRepository creates a new webhook event repository
func NewEventRepository(client *ent.Client) EventRepository {
	return &eventRepository{
		client: client,
	}
}

// Create creates a new webhook event
func (r *eventRepository) Create(ctx context.Context, input EventRepositoryCreateInput) (*ent.WebhookEvent, error) {
	// Generate UUID
	id := utils.NewID()

	// Check if webhook exists
	exists, err := r.client.Webhook.
		Query().
		Where(webhook.ID(input.WebhookID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check webhook existence")
	}

	if !exists {
		return nil, errors.New(errors.CodeNotFound, "webhook not found")
	}

	// Create webhook event
	event, err := r.client.WebhookEvent.
		Create().
		SetID(id.String()).
		SetWebhookID(input.WebhookID).
		SetEventType(input.EventType).
		SetPayload(input.Payload).
		SetHeaders(input.Headers).
		Save(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create webhook event")
	}

	return event, nil
}

// GetByID retrieves a webhook event by ID
func (r *eventRepository) GetByID(ctx context.Context, id string) (*ent.WebhookEvent, error) {
	event, err := r.client.WebhookEvent.
		Query().
		Where(webhookevent.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "webhook event not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get webhook event")
	}

	return event, nil
}

// List retrieves webhook events with pagination
func (r *eventRepository) List(ctx context.Context, input EventRepositoryListInput) ([]*ent.WebhookEvent, int, error) {
	// Build query predicates
	var predicates []predicate.WebhookEvent

	if input.WebhookID != "" {
		predicates = append(predicates, webhookevent.WebhookID(input.WebhookID))
	}

	if input.EventType != "" {
		predicates = append(predicates, webhookevent.EventType(input.EventType))
	}

	if input.Delivered != nil {
		predicates = append(predicates, webhookevent.Delivered(*input.Delivered))
	}

	// Create query with predicates
	query := r.client.WebhookEvent.Query()
	if len(predicates) > 0 {
		query = query.Where(webhookevent.And(predicates...))
	}

	// Count total results
	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to count webhook events")
	}

	// Apply pagination
	events, err := query.
		Limit(input.Limit).
		Offset(input.Offset).
		Order(ent.Desc(webhookevent.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to list webhook events")
	}

	return events, total, nil
}

// Update updates a webhook event
func (r *eventRepository) Update(ctx context.Context, id string, input EventRepositoryUpdateInput) (*ent.WebhookEvent, error) {
	// Check if webhook event exists
	exists, err := r.client.WebhookEvent.
		Query().
		Where(webhookevent.ID(id)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check webhook event existence")
	}

	if !exists {
		return nil, errors.New(errors.CodeNotFound, "webhook event not found")
	}

	// Build update query
	update := r.client.WebhookEvent.
		UpdateOneID(id)

	// Apply updates
	if input.Delivered != nil {
		update = update.SetDelivered(*input.Delivered)
	}

	if input.DeliveredAt != nil {
		update = update.SetDeliveredAt(*input.DeliveredAt)
	}

	if input.Attempts != nil {
		update = update.SetAttempts(*input.Attempts)
	}

	if input.NextRetry != nil {
		update = update.SetNextRetry(*input.NextRetry)
	}

	if input.StatusCode != nil {
		update = update.SetStatusCode(*input.StatusCode)
	}

	if input.ResponseBody != nil {
		update = update.SetResponseBody(*input.ResponseBody)
	}

	if input.Error != nil {
		update = update.SetError(*input.Error)
	}

	// Execute update
	event, err := update.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to update webhook event")
	}

	return event, nil
}

// DeleteByWebhookID deletes all events for a webhook
func (r *eventRepository) DeleteByWebhookID(ctx context.Context, webhookID string) error {
	_, err := r.client.WebhookEvent.
		Delete().
		Where(webhookevent.WebhookID(webhookID)).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete webhook events")
	}

	return nil
}

// GetPendingEvents gets events that need to be retried
func (r *eventRepository) GetPendingEvents(ctx context.Context, limit int) ([]*ent.WebhookEvent, error) {
	now := time.Now()

	events, err := r.client.WebhookEvent.
		Query().
		Where(
			webhookevent.Delivered(false),
			webhookevent.NextRetryLT(now),
		).
		Limit(limit).
		Order(ent.Asc(webhookevent.FieldNextRetry)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get pending webhook events")
	}

	return events, nil
}
