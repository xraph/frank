package webhook

import (
	"context"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/logging"
)

// Service provides webhook operations
type Service interface {
	// Create creates a new webhook
	Create(ctx context.Context, input CreateWebhookInput) (*ent.Webhook, error)

	// Get retrieves a webhook by ID
	Get(ctx context.Context, id string) (*ent.Webhook, error)

	// List retrieves webhooks with pagination
	List(ctx context.Context, params ListParams) ([]*ent.Webhook, int, error)

	// Update updates a webhook
	Update(ctx context.Context, id string, input UpdateWebhookInput) (*ent.Webhook, error)

	// Delete deletes a webhook
	Delete(ctx context.Context, id string) error

	// TriggerEvent triggers a webhook event
	TriggerEvent(ctx context.Context, input TriggerEventInput) (*ent.WebhookEvent, error)

	// GetEvents retrieves webhook events with pagination
	GetEvents(ctx context.Context, webhookID string, params EventListParams) ([]*ent.WebhookEvent, int, error)

	// ReplayEvent replays a webhook event
	ReplayEvent(ctx context.Context, eventID string) (*ent.WebhookEvent, error)
}

// CreateWebhookInput represents input for creating a webhook
type CreateWebhookInput struct {
	Name           string                 `json:"name" validate:"required"`
	URL            string                 `json:"url" validate:"required,url"`
	OrganizationID string                 `json:"organization_id" validate:"required"`
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
	OrganizationID string                 `json:"organization_id" validate:"required"`
	Payload        map[string]interface{} `json:"payload" validate:"required"`
	Headers        map[string]string      `json:"headers,omitempty"`
}

// ListParams represents pagination parameters for webhooks
type ListParams struct {
	Offset         int      `json:"offset" query:"offset"`
	Limit          int      `json:"limit" query:"limit"`
	OrganizationID string   `json:"organization_id" query:"organization_id"`
	EventTypes     []string `json:"event_types" query:"event_types"`
}

// EventListParams represents pagination parameters for webhook events
type EventListParams struct {
	Offset    int    `json:"offset" query:"offset"`
	Limit     int    `json:"limit" query:"limit"`
	EventType string `json:"event_type" query:"event_type"`
	Delivered *bool  `json:"delivered" query:"delivered"`
}

type service struct {
	repo      Repository
	eventRepo EventRepository
	deliverer Deliverer
	config    *config.Config
	logger    logging.Logger
}

// NewService creates a new webhook service
func NewService(
	repo Repository,
	eventRepo EventRepository,
	deliverer Deliverer,
	cfg *config.Config,
	logger logging.Logger,
) Service {
	return &service{
		repo:      repo,
		eventRepo: eventRepo,
		deliverer: deliverer,
		config:    cfg,
		logger:    logger,
	}
}

// Create creates a new webhook
func (s *service) Create(ctx context.Context, input CreateWebhookInput) (*ent.Webhook, error) {
	// Generate a secret for signing webhook payloads
	secret := crypto.GenerateWebhookSecret()
	// if err != nil {
	// 	return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate webhook secret")
	// }

	// Set default values
	retryCount := s.config.Webhooks.DefaultRetries
	if input.RetryCount != nil {
		retryCount = *input.RetryCount
	}

	timeoutMs := int(s.config.Webhooks.DefaultTimeout.Milliseconds())
	if input.TimeoutMs != nil {
		timeoutMs = *input.TimeoutMs
	}

	format := "json"
	if input.Format != "" {
		format = input.Format
	}

	// Create webhook in repository
	webhook, err := s.repo.Create(ctx, RepositoryCreateInput{
		Name:           input.Name,
		URL:            input.URL,
		OrganizationID: input.OrganizationID,
		Secret:         secret,
		EventTypes:     input.EventTypes,
		RetryCount:     retryCount,
		TimeoutMs:      timeoutMs,
		Format:         format,
		Metadata:       input.Metadata,
	})

	if err != nil {
		return nil, err
	}

	return webhook, nil
}

// Get retrieves a webhook by ID
func (s *service) Get(ctx context.Context, id string) (*ent.Webhook, error) {
	return s.repo.GetByID(ctx, id)
}

// List retrieves webhooks with pagination
func (s *service) List(ctx context.Context, params ListParams) ([]*ent.Webhook, int, error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	// Map service input to repository input
	repoInput := RepositoryListInput{
		Offset:         params.Offset,
		Limit:          params.Limit,
		OrganizationID: params.OrganizationID,
		EventTypes:     params.EventTypes,
	}

	return s.repo.List(ctx, repoInput)
}

// Update updates a webhook
func (s *service) Update(ctx context.Context, id string, input UpdateWebhookInput) (*ent.Webhook, error) {
	// Map service input to repository input
	repoInput := RepositoryUpdateInput{}

	if input.Name != nil {
		repoInput.Name = input.Name
	}

	if input.URL != nil {
		repoInput.URL = input.URL
	}

	if input.Active != nil {
		repoInput.Active = input.Active
	}

	if input.EventTypes != nil {
		repoInput.EventTypes = input.EventTypes
	}

	if input.RetryCount != nil {
		repoInput.RetryCount = input.RetryCount
	}

	if input.TimeoutMs != nil {
		repoInput.TimeoutMs = input.TimeoutMs
	}

	if input.Format != nil {
		repoInput.Format = input.Format
	}

	if input.Metadata != nil {
		repoInput.Metadata = input.Metadata
	}

	return s.repo.Update(ctx, id, repoInput)
}

// Delete deletes a webhook
func (s *service) Delete(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

// TriggerEvent triggers a webhook event
func (s *service) TriggerEvent(ctx context.Context, input TriggerEventInput) (*ent.WebhookEvent, error) {
	// Find webhooks that match the event type and organization
	webhooks, err := s.repo.FindByEventTypeAndOrganization(
		ctx,
		input.EventType,
		input.OrganizationID,
	)

	if err != nil {
		return nil, err
	}

	if len(webhooks) == 0 {
		// No webhooks configured for this event, return nil without error
		return nil, nil
	}

	// Create webhook event for the first matching webhook
	// In a production system, you might want to create events for all matching webhooks
	webhook := webhooks[0]

	// Create webhook event
	event, err := s.eventRepo.Create(ctx, EventRepositoryCreateInput{
		WebhookID: webhook.ID,
		EventType: input.EventType,
		Payload:   input.Payload,
		Headers:   input.Headers,
	})

	if err != nil {
		return nil, err
	}

	// Deliver event asynchronously
	go func() {
		// Create background context for delivery
		deliveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		// Deliver event
		s.deliverer.DeliverEvent(deliveryCtx, event, webhook)
	}()

	return event, nil
}

// GetEvents retrieves webhook events with pagination
func (s *service) GetEvents(ctx context.Context, webhookID string, params EventListParams) ([]*ent.WebhookEvent, int, error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	// Map service input to repository input
	repoInput := EventRepositoryListInput{
		WebhookID: webhookID,
		Offset:    params.Offset,
		Limit:     params.Limit,
		EventType: params.EventType,
		Delivered: params.Delivered,
	}

	return s.eventRepo.List(ctx, repoInput)
}

// ReplayEvent replays a webhook event
func (s *service) ReplayEvent(ctx context.Context, eventID string) (*ent.WebhookEvent, error) {
	// Get event
	event, err := s.eventRepo.GetByID(ctx, eventID)
	if err != nil {
		return nil, err
	}

	// Get webhook
	webhook, err := s.repo.GetByID(ctx, event.WebhookID)
	if err != nil {
		return nil, err
	}

	// Create a new event (copy of the original)
	newEvent, err := s.eventRepo.Create(ctx, EventRepositoryCreateInput{
		WebhookID: webhook.ID,
		EventType: event.EventType,
		Payload:   event.Payload,
		Headers:   event.Headers,
	})

	if err != nil {
		return nil, err
	}

	// Deliver event asynchronously
	go func() {
		// Create background context for delivery
		deliveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		// Deliver event
		s.deliverer.DeliverEvent(deliveryCtx, newEvent, webhook)
	}()

	return newEvent, nil
}
