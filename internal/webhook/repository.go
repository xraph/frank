package webhook

import (
	"context"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/ent/predicate"
	"github.com/juicycleff/frank/ent/webhook"
	"github.com/juicycleff/frank/ent/webhookevent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/utils"
)

// Repository provides access to webhook storage
type Repository interface {
	// Create creates a new webhook
	Create(ctx context.Context, input RepositoryCreateInput) (*ent.Webhook, error)

	// GetByID retrieves a webhook by ID
	GetByID(ctx context.Context, id string) (*ent.Webhook, error)

	// List retrieves webhooks with pagination
	List(ctx context.Context, input RepositoryListInput) ([]*ent.Webhook, int, error)

	// Update updates a webhook
	Update(ctx context.Context, id string, input RepositoryUpdateInput) (*ent.Webhook, error)

	// Delete deletes a webhook
	Delete(ctx context.Context, id string) error

	// FindByEventTypeAndOrganization finds webhooks by event type and organization
	FindByEventTypeAndOrganization(ctx context.Context, eventType, organizationID string) ([]*ent.Webhook, error)
}

// RepositoryCreateInput represents input for creating a webhook
type RepositoryCreateInput struct {
	Name           string
	URL            string
	OrganizationID string
	Secret         string
	EventTypes     []string
	RetryCount     int
	TimeoutMs      int
	Format         string
	Metadata       map[string]interface{}
}

// RepositoryUpdateInput represents input for updating a webhook
type RepositoryUpdateInput struct {
	Name       *string
	URL        *string
	Active     *bool
	EventTypes []string
	RetryCount *int
	TimeoutMs  *int
	Format     *string
	Metadata   map[string]interface{}
}

// RepositoryListInput represents input for listing webhooks
type RepositoryListInput struct {
	Offset         int
	Limit          int
	OrganizationID string
	EventTypes     []string
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
func (r *repository) Create(ctx context.Context, input RepositoryCreateInput) (*ent.Webhook, error) {
	// Generate UUID
	id := utils.NewID()

	// Check if organization exists
	exists, err := r.client.Organization.
		Query().
		Where(organization.ID(input.OrganizationID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !exists {
		return nil, errors.New(errors.CodeNotFound, "organization not found")
	}

	// Create webhook
	hook, err := r.client.Webhook.
		Create().
		SetID(id.String()).
		SetName(input.Name).
		SetURL(input.URL).
		SetOrganizationID(input.OrganizationID).
		SetSecret(input.Secret).
		SetEventTypes(input.EventTypes).
		SetRetryCount(input.RetryCount).
		SetTimeoutMs(input.TimeoutMs).
		SetFormat(webhook.Format(input.Format)).
		SetMetadata(input.Metadata).
		Save(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create webhook")
	}

	return hook, nil
}

// GetByID retrieves a webhook by ID
func (r *repository) GetByID(ctx context.Context, id string) (*ent.Webhook, error) {
	hook, err := r.client.Webhook.
		Query().
		Where(webhook.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "webhook not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get webhook")
	}

	return hook, nil
}

// List retrieves webhooks with pagination
func (r *repository) List(ctx context.Context, input RepositoryListInput) ([]*ent.Webhook, int, error) {
	// Build query predicates
	var predicates []predicate.Webhook

	if input.OrganizationID != "" {
		predicates = append(predicates, webhook.OrganizationID(input.OrganizationID))
	}

	if len(input.EventTypes) > 0 {
		// Find webhooks that have any of the specified event types
		eventTypePredicates := make([]predicate.Webhook, len(input.EventTypes))
		for i, eventType := range input.EventTypes {
			eventTypePredicates[i] = webhook.HasEventsWith(webhookevent.EventTypeContains(eventType))
		}
		predicates = append(predicates, webhook.Or(eventTypePredicates...))
	}

	// Create query with predicates
	query := r.client.Webhook.Query()
	if len(predicates) > 0 {
		query = query.Where(webhook.And(predicates...))
	}

	// Count total results
	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to count webhooks")
	}

	// Apply pagination
	hooks, err := query.
		Limit(input.Limit).
		Offset(input.Offset).
		Order(ent.Desc(webhook.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to list webhooks")
	}

	return hooks, total, nil
}

// Update updates a webhook
func (r *repository) Update(ctx context.Context, id string, input RepositoryUpdateInput) (*ent.Webhook, error) {
	// Check if webhook exists
	exists, err := r.client.Webhook.
		Query().
		Where(webhook.ID(id)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check webhook existence")
	}

	if !exists {
		return nil, errors.New(errors.CodeNotFound, "webhook not found")
	}

	// Build update query
	update := r.client.Webhook.
		UpdateOneID(id)

	// Apply updates
	if input.Name != nil {
		update = update.SetName(*input.Name)
	}

	if input.URL != nil {
		update = update.SetURL(*input.URL)
	}

	if input.Active != nil {
		update = update.SetActive(*input.Active)
	}

	if input.EventTypes != nil {
		update = update.SetEventTypes(input.EventTypes)
	}

	if input.RetryCount != nil {
		update = update.SetRetryCount(*input.RetryCount)
	}

	if input.TimeoutMs != nil {
		update = update.SetTimeoutMs(*input.TimeoutMs)
	}

	if input.Format != nil {
		update = update.SetFormat(webhook.Format(*input.Format))
	}

	if input.Metadata != nil {
		update = update.SetMetadata(input.Metadata)
	}

	// Execute update
	hook, err := update.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to update webhook")
	}

	return hook, nil
}

// Delete deletes a webhook
func (r *repository) Delete(ctx context.Context, id string) error {
	// Check if webhook exists
	exists, err := r.client.Webhook.
		Query().
		Where(webhook.ID(id)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check webhook existence")
	}

	if !exists {
		return errors.New(errors.CodeNotFound, "webhook not found")
	}

	// Delete webhook
	err = r.client.Webhook.
		DeleteOneID(id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete webhook")
	}

	return nil
}

// FindByEventTypeAndOrganization finds webhooks by event type and organization
func (r *repository) FindByEventTypeAndOrganization(ctx context.Context, eventType, organizationID string) ([]*ent.Webhook, error) {
	hooks, err := r.client.Webhook.
		Query().
		Where(
			webhook.OrganizationID(organizationID),
			webhook.HasEventsWith(webhookevent.EventTypeContains(eventType)),
			webhook.Active(true),
		).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to find webhooks")
	}

	return hooks, nil
}
