package webhook

import (
	"context"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/ent/predicate"
	"github.com/juicycleff/frank/ent/webhook"
	"github.com/juicycleff/frank/ent/webhookevent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

var (
	ErrWebhookNotFound      = errors.New(errors.CodeNotFound, "webhook not found")
	ErrOrganizationNotFound = errors.New(errors.CodeNotFound, "organization not found")
	ErrWebhookInactive      = errors.New(errors.CodeBadRequest, "webhook is inactive")
)

// Repository provides access to webhook storage
type Repository interface {
	// Create creates a new webhook
	Create(ctx context.Context, webhookCreate *ent.WebhookCreate) (*ent.Webhook, error)

	// GetByID retrieves a webhook by ID
	GetByID(ctx context.Context, id xid.ID) (*ent.Webhook, error)

	// List retrieves webhooks with pagination
	List(ctx context.Context, params ListWebhooksParams) (*model.PaginatedOutput[*ent.Webhook], error)

	// Update updates a webhook
	Update(ctx context.Context, webhookUpdate *ent.WebhookUpdateOne) (*ent.Webhook, error)

	// Delete deletes a webhook
	Delete(ctx context.Context, id xid.ID) error

	// FindByEventTypeAndOrganization finds webhooks by event type and organization
	FindByEventTypeAndOrganization(ctx context.Context, eventType string, organizationID xid.ID) ([]*ent.Webhook, error)

	// BulkCreate creates multiple webhooks in a single operation
	BulkCreate(ctx context.Context, webhooks []*ent.WebhookCreate) ([]*ent.Webhook, error)

	// BulkUpdate updates multiple webhooks in a single operation
	BulkUpdate(ctx context.Context, updates []*ent.WebhookUpdateOne) ([]*ent.Webhook, error)

	// ExportAll exports all webhooks
	ExportAll(ctx context.Context) ([]*ent.Webhook, error)

	// Client returns the database client
	Client() *ent.Client
}

type repository struct {
	client *ent.Client
}

// NewRepository creates a new webhook repository
func NewRepository(client *ent.Client) Repository {
	return &repository{
		client: client,
	}
}

// Create creates a new webhook
func (r *repository) Create(ctx context.Context, webhookCreate *ent.WebhookCreate) (*ent.Webhook, error) {
	// Check if organization exists
	organizationID, _ := webhookCreate.Mutation().OrganizationID()
	if !organizationID.IsNil() {
		exists, err := r.client.Organization.
			Query().
			Where(organization.ID(organizationID)).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check organization existence")
		}

		if !exists {
			return nil, ErrOrganizationNotFound
		}
	}

	// Create webhook
	hook, err := webhookCreate.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "webhook already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create webhook")
	}

	return hook, nil
}

// GetByID retrieves a webhook by ID
func (r *repository) GetByID(ctx context.Context, id xid.ID) (*ent.Webhook, error) {
	hook, err := r.client.Webhook.
		Query().
		Where(webhook.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrWebhookNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get webhook")
	}

	return hook, nil
}

// List retrieves webhooks with pagination
func (r *repository) List(ctx context.Context, params ListWebhooksParams) (*model.PaginatedOutput[*ent.Webhook], error) {
	// Build query predicates
	var predicates []predicate.Webhook

	if params.OrgID.IsSet {
		predicates = append(predicates, webhook.OrganizationID(params.OrgID.Value))
	}

	if len(params.EventTypes) > 0 {
		// Find webhooks that have any of the specified event types
		eventTypePredicates := make([]predicate.Webhook, len(params.EventTypes))
		for i, eventType := range params.EventTypes {
			eventTypePredicates[i] = webhook.HasEventsWith(webhookevent.EventTypeContains(eventType))
		}
		predicates = append(predicates, webhook.Or(eventTypePredicates...))
	}

	if params.Active.IsSet {
		predicates = append(predicates, webhook.Active(params.Active.Value))
	}

	// Create query with predicates
	query := r.client.Webhook.Query()
	if len(predicates) > 0 {
		query = query.Where(webhook.And(predicates...))
	}

	// Apply ordering
	for _, o := range model.GetOrdering(params.PaginationParams) {
		if o.Desc {
			query = query.Order(ent.Desc(o.Field))
			continue
		}
		query = query.Order(ent.Asc(o.Field))
	}

	return model.WithPaginationAndOptions[*ent.Webhook, *ent.WebhookQuery](ctx, query, params.PaginationParams)
}

// Update updates a webhook
func (r *repository) Update(ctx context.Context, webhookUpdate *ent.WebhookUpdateOne) (*ent.Webhook, error) {
	// Get the webhook ID from the update mutation
	webhookID, _ := webhookUpdate.Mutation().ID()

	// Check if webhook exists
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

	// Execute update
	hook, err := webhookUpdate.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrWebhookNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update webhook")
	}

	return hook, nil
}

// Delete deletes a webhook
func (r *repository) Delete(ctx context.Context, id xid.ID) error {
	// Check if webhook exists
	exists, err := r.client.Webhook.
		Query().
		Where(webhook.ID(id)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to check webhook existence")
	}

	if !exists {
		return ErrWebhookNotFound
	}

	// Delete webhook
	err = r.client.Webhook.
		DeleteOneID(id).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return ErrWebhookNotFound
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete webhook")
	}

	return nil
}

// FindByEventTypeAndOrganization finds webhooks by event type and organization
func (r *repository) FindByEventTypeAndOrganization(ctx context.Context, eventType string, orgID xid.ID) ([]*ent.Webhook, error) {
	hooks, err := r.client.Webhook.
		Query().
		Where(
			webhook.OrganizationID(orgID),
			webhook.HasEventsWith(webhookevent.EventTypeContains(eventType)),
			webhook.Active(true),
		).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to find webhooks")
	}

	return hooks, nil
}

// BulkCreate creates multiple webhooks in a single operation
func (r *repository) BulkCreate(ctx context.Context, webhooks []*ent.WebhookCreate) ([]*ent.Webhook, error) {
	// Create webhooks in a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]*ent.Webhook, 0, len(webhooks))

	for _, webhookCreate := range webhooks {
		// Get fields from mutation
		name, _ := webhookCreate.Mutation().Name()
		url, _ := webhookCreate.Mutation().URL()
		organizationID, _ := webhookCreate.Mutation().OrganizationID()
		secret, _ := webhookCreate.Mutation().Secret()
		eventTypes, _ := webhookCreate.Mutation().EventTypes()

		// Clone the create action for transaction
		creator := tx.Webhook.Create().
			SetName(name).
			SetURL(url).
			SetOrganizationID(organizationID).
			SetSecret(secret).
			SetEventTypes(eventTypes)

		// Add optional fields
		if retryCount, exists := webhookCreate.Mutation().RetryCount(); exists {
			creator.SetRetryCount(retryCount)
		}

		if timeoutMs, exists := webhookCreate.Mutation().TimeoutMs(); exists {
			creator.SetTimeoutMs(timeoutMs)
		}

		if format, exists := webhookCreate.Mutation().Format(); exists {
			creator.SetFormat(format)
		}

		if active, exists := webhookCreate.Mutation().Active(); exists {
			creator.SetActive(active)
		} else {
			creator.SetActive(true) // Default to active
		}

		if metadata, exists := webhookCreate.Mutation().Metadata(); exists {
			creator.SetMetadata(metadata)
		}

		// Create webhook
		hook, err := creator.Save(ctx)
		if err != nil {
			tx.Rollback()
			return nil, err
		}

		results = append(results, hook)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return results, nil
}

// BulkUpdate updates multiple webhooks in a single operation
func (r *repository) BulkUpdate(ctx context.Context, updates []*ent.WebhookUpdateOne) ([]*ent.Webhook, error) {
	// Update webhooks in a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]*ent.Webhook, 0, len(updates))

	for _, update := range updates {
		// Get ID for the update
		p := update.Mutation()
		webhookID, _ := p.ID()

		// Create updater
		updater := tx.Webhook.UpdateOneID(webhookID)

		// Apply all updates from the original update
		if name, exists := p.Name(); exists {
			updater.SetName(name)
		}

		if url, exists := p.URL(); exists {
			updater.SetURL(url)
		}

		if active, exists := p.Active(); exists {
			updater.SetActive(active)
		}

		if eventTypes, exists := p.EventTypes(); exists {
			updater.SetEventTypes(eventTypes)
		}

		if retryCount, exists := p.RetryCount(); exists {
			updater.SetRetryCount(retryCount)
		}

		if timeoutMs, exists := p.TimeoutMs(); exists {
			updater.SetTimeoutMs(timeoutMs)
		}

		if format, exists := p.Format(); exists {
			updater.SetFormat(format)
		}

		if metadata, exists := p.Metadata(); exists {
			updater.SetMetadata(metadata)
		}

		// Update webhook
		hook, err := updater.Save(ctx)
		if err != nil {
			tx.Rollback()
			return nil, err
		}

		results = append(results, hook)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return results, nil
}

// ExportAll exports all webhooks
func (r *repository) ExportAll(ctx context.Context) ([]*ent.Webhook, error) {
	hooks, err := r.client.Webhook.Query().All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to export webhooks")
	}
	return hooks, nil
}

// Client returns the database client
func (r *repository) Client() *ent.Client {
	return r.client
}
