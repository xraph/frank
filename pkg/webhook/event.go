package webhook

import (
	"context"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/predicate"
	"github.com/juicycleff/frank/ent/webhook"
	"github.com/juicycleff/frank/ent/webhookevent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

var (
	ErrWebhookEventNotFound = errors.New(errors.CodeNotFound, "webhook event not found")
	ErrEventDeliveryFailed  = errors.New(errors.CodeInternalServer, "webhook event delivery failed")
)

// EventRepository provides access to webhook event storage
type EventRepository interface {
	// Create creates a new webhook event
	Create(ctx context.Context, eventCreate *ent.WebhookEventCreate) (*ent.WebhookEvent, error)

	// GetByID retrieves a webhook event by ID
	GetByID(ctx context.Context, id xid.ID) (*ent.WebhookEvent, error)

	// List retrieves webhook events with pagination
	List(ctx context.Context, params ListWebhookEventsParams) (*model.PaginatedOutput[*ent.WebhookEvent], error)

	// Update updates a webhook event
	Update(ctx context.Context, eventUpdate *ent.WebhookEventUpdateOne) (*ent.WebhookEvent, error)

	// Delete deletes a webhook event
	Delete(ctx context.Context, id xid.ID) error

	// DeleteByWebhookID deletes all events for a webhook
	DeleteByWebhookID(ctx context.Context, webhookID xid.ID) error

	// GetPendingEvents gets events that need to be retried
	GetPendingEvents(ctx context.Context, limit int) ([]*ent.WebhookEvent, error)

	// BulkCreate creates multiple webhook events in a single operation
	BulkCreate(ctx context.Context, events []*ent.WebhookEventCreate) ([]*ent.WebhookEvent, error)

	// BulkUpdate updates multiple webhook events in a single operation
	BulkUpdate(ctx context.Context, updates []*ent.WebhookEventUpdateOne) ([]*ent.WebhookEvent, error)

	// ExportAll exports all webhook events
	ExportAll(ctx context.Context) ([]*ent.WebhookEvent, error)

	// Client returns the database client
	Client() *ent.Client
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
func (r *eventRepository) Create(ctx context.Context, eventCreate *ent.WebhookEventCreate) (*ent.WebhookEvent, error) {
	// Check if webhook exists
	webhookID, _ := eventCreate.Mutation().WebhookID()
	if !webhookID.IsNil() {
		exists, err := r.client.Webhook.
			Query().
			Where(webhook.ID(webhookID)).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check webhook existence")
		}

		if !exists {
			return nil, ErrWebhookNotFound
		}
	}

	// Create webhook event
	event, err := eventCreate.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "webhook event already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create webhook event")
	}

	return event, nil
}

// GetByID retrieves a webhook event by ID
func (r *eventRepository) GetByID(ctx context.Context, id xid.ID) (*ent.WebhookEvent, error) {
	event, err := r.client.WebhookEvent.
		Query().
		Where(webhookevent.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrWebhookEventNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get webhook event")
	}

	return event, nil
}

// List retrieves webhook events with pagination
func (r *eventRepository) List(ctx context.Context, params ListWebhookEventsParams) (*model.PaginatedOutput[*ent.WebhookEvent], error) {
	// Build query predicates
	var predicates []predicate.WebhookEvent

	if params.WebhookID.IsSet {
		predicates = append(predicates, webhookevent.WebhookID(params.WebhookID.Value))
	}

	if params.EventType != "" {
		predicates = append(predicates, webhookevent.EventType(params.EventType))
	}

	if params.Delivered.IsSet {
		predicates = append(predicates, webhookevent.Delivered(params.Delivered.Value))
	}

	// Create query with predicates
	query := r.client.WebhookEvent.Query()
	if len(predicates) > 0 {
		query = query.Where(webhookevent.And(predicates...))
	}

	// Apply ordering
	for _, o := range model.GetOrdering(params.PaginationParams) {
		if o.Desc {
			query = query.Order(ent.Desc(o.Field))
			continue
		}
		query = query.Order(ent.Asc(o.Field))
	}

	return model.WithPaginationAndOptions[*ent.WebhookEvent, *ent.WebhookEventQuery](ctx, query, params.PaginationParams)
}

// Update updates a webhook event
func (r *eventRepository) Update(ctx context.Context, eventUpdate *ent.WebhookEventUpdateOne) (*ent.WebhookEvent, error) {
	// Get the event ID from the update mutation
	eventID, _ := eventUpdate.Mutation().ID()

	// Check if webhook event exists
	exists, err := r.client.WebhookEvent.
		Query().
		Where(webhookevent.ID(eventID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check webhook event existence")
	}

	if !exists {
		return nil, ErrWebhookEventNotFound
	}

	// Execute update
	event, err := eventUpdate.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrWebhookEventNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update webhook event")
	}

	return event, nil
}

// Delete deletes a webhook event
func (r *eventRepository) Delete(ctx context.Context, id xid.ID) error {
	// Check if webhook event exists
	exists, err := r.client.WebhookEvent.
		Query().
		Where(webhookevent.ID(id)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to check webhook event existence")
	}

	if !exists {
		return ErrWebhookEventNotFound
	}

	// Delete webhook event
	err = r.client.WebhookEvent.
		DeleteOneID(id).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return ErrWebhookEventNotFound
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete webhook event")
	}

	return nil
}

// DeleteByWebhookID deletes all events for a webhook
func (r *eventRepository) DeleteByWebhookID(ctx context.Context, webhookID xid.ID) error {
	_, err := r.client.WebhookEvent.
		Delete().
		Where(webhookevent.WebhookID(webhookID)).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete webhook events")
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
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get pending webhook events")
	}

	return events, nil
}

// BulkCreate creates multiple webhook events in a single operation
func (r *eventRepository) BulkCreate(ctx context.Context, events []*ent.WebhookEventCreate) ([]*ent.WebhookEvent, error) {
	// Create events in a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]*ent.WebhookEvent, 0, len(events))

	for _, eventCreate := range events {
		// Get fields from mutation
		webhookID, _ := eventCreate.Mutation().WebhookID()
		eventType, _ := eventCreate.Mutation().EventType()
		payload, _ := eventCreate.Mutation().Payload()

		// Clone the create action for transaction
		creator := tx.WebhookEvent.Create().
			SetWebhookID(webhookID).
			SetEventType(eventType).
			SetPayload(payload)

		// Add optional fields
		if headers, exists := eventCreate.Mutation().Headers(); exists {
			creator.SetHeaders(headers)
		}

		if delivered, exists := eventCreate.Mutation().Delivered(); exists {
			creator.SetDelivered(delivered)
		} else {
			creator.SetDelivered(false) // Default to not delivered
		}

		if attempts, exists := eventCreate.Mutation().Attempts(); exists {
			creator.SetAttempts(attempts)
		} else {
			creator.SetAttempts(0) // Default to 0 attempts
		}

		if nextRetry, exists := eventCreate.Mutation().NextRetry(); exists {
			creator.SetNextRetry(nextRetry)
		}

		if statusCode, exists := eventCreate.Mutation().StatusCode(); exists {
			creator.SetStatusCode(statusCode)
		}

		if responseBody, exists := eventCreate.Mutation().ResponseBody(); exists {
			creator.SetResponseBody(responseBody)
		}

		if errorMsg, exists := eventCreate.Mutation().Error(); exists {
			creator.SetError(errorMsg)
		}

		// Create event
		event, err := creator.Save(ctx)
		if err != nil {
			tx.Rollback()
			return nil, err
		}

		results = append(results, event)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return results, nil
}

// BulkUpdate updates multiple webhook events in a single operation
func (r *eventRepository) BulkUpdate(ctx context.Context, updates []*ent.WebhookEventUpdateOne) ([]*ent.WebhookEvent, error) {
	// Update events in a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]*ent.WebhookEvent, 0, len(updates))

	for _, update := range updates {
		// Get ID for the update
		p := update.Mutation()
		eventID, _ := p.ID()

		// Create updater
		updater := tx.WebhookEvent.UpdateOneID(eventID)

		// Apply all updates from the original update
		if delivered, exists := p.Delivered(); exists {
			updater.SetDelivered(delivered)
		}

		if deliveredAt, exists := p.DeliveredAt(); exists {
			updater.SetDeliveredAt(deliveredAt)
		}

		if attempts, exists := p.Attempts(); exists {
			updater.SetAttempts(attempts)
		}

		if nextRetry, exists := p.NextRetry(); exists {
			updater.SetNextRetry(nextRetry)
		}

		if statusCode, exists := p.StatusCode(); exists {
			updater.SetStatusCode(statusCode)
		}

		if responseBody, exists := p.ResponseBody(); exists {
			updater.SetResponseBody(responseBody)
		}

		if errorMsg, exists := p.Error(); exists {
			updater.SetError(errorMsg)
		}

		// Update event
		event, err := updater.Save(ctx)
		if err != nil {
			tx.Rollback()
			return nil, err
		}

		results = append(results, event)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return results, nil
}

// ExportAll exports all webhook events
func (r *eventRepository) ExportAll(ctx context.Context) ([]*ent.WebhookEvent, error) {
	events, err := r.client.WebhookEvent.Query().All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to export webhook events")
	}
	return events, nil
}

// Client returns the database client
func (r *eventRepository) Client() *ent.Client {
	return r.client
}
