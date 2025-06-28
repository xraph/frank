package webhook

import (
	"context"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/webhook"
	"github.com/xraph/frank/pkg/cryptoold"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// Service provides webhook operations
type Service interface {
	// Create creates a new webhook
	Create(ctx context.Context, input CreateWebhookInput) (*Webhook, error)

	// Get retrieves a webhook by ID
	Get(ctx context.Context, id xid.ID) (*Webhook, error)

	// List retrieves webhooks with pagination
	List(ctx context.Context, params ListWebhooksParams) (*model.PaginatedOutput[*Webhook], error)

	// Update updates a webhook
	Update(ctx context.Context, id xid.ID, input UpdateWebhookInput) (*Webhook, error)

	// Delete deletes a webhook
	Delete(ctx context.Context, id xid.ID) error

	// TriggerEvent triggers a webhook event
	TriggerEvent(ctx context.Context, input TriggerEventInput) (*WebhookEvent, error)

	// GetEvents retrieves webhook events with pagination
	GetEvents(ctx context.Context, webhookID xid.ID, params ListWebhookEventsParams) (*model.PaginatedOutput[*WebhookEvent], error)

	// ReplayEvent replays a webhook event
	ReplayEvent(ctx context.Context, eventID xid.ID) (*WebhookEvent, error)
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
func (s *service) Create(ctx context.Context, input CreateWebhookInput) (*Webhook, error) {
	// Generate a secret for signing webhook payloads
	secret := cryptoold.GenerateWebhookSecret()

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

	// Create ent.WebhookCreate
	webhookCreate := s.repo.Client().Webhook.Create().
		SetName(input.Name).
		SetURL(input.URL).
		SetOrganizationID(input.OrganizationID).
		SetSecret(secret).
		SetEventTypes(input.EventTypes).
		SetRetryCount(retryCount).
		SetTimeoutMs(timeoutMs).
		SetFormat(webhook.Format(format)).
		SetActive(true)

	// Set optional fields
	if input.Metadata != nil {
		webhookCreate = webhookCreate.SetMetadata(input.Metadata)
	}

	// Create webhook in repository
	entWebhook, err := s.repo.Create(ctx, webhookCreate)
	if err != nil {
		return nil, err
	}

	return convertWebhookToDTO(entWebhook), nil
}

// Get retrieves a webhook by ID
func (s *service) Get(ctx context.Context, id xid.ID) (*Webhook, error) {
	entWebhook, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return convertWebhookToDTO(entWebhook), nil
}

// List retrieves webhooks with pagination
func (s *service) List(ctx context.Context, params ListWebhooksParams) (*model.PaginatedOutput[*Webhook], error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	entResult, err := s.repo.List(ctx, params)
	if err != nil {
		return nil, err
	}

	// Convert the paginated result
	webhooks := convertWebhooksToDTO(entResult.Data)

	return &model.PaginatedOutput[*Webhook]{
		Data:       webhooks,
		Pagination: entResult.Pagination,
	}, nil
}

// Update updates a webhook
func (s *service) Update(ctx context.Context, id xid.ID, input UpdateWebhookInput) (*Webhook, error) {
	// Create ent.WebhookUpdateOne
	webhookUpdate := s.repo.Client().Webhook.UpdateOneID(id)

	// Apply updates conditionally
	if input.Name != nil {
		webhookUpdate = webhookUpdate.SetName(*input.Name)
	}

	if input.URL != nil {
		webhookUpdate = webhookUpdate.SetURL(*input.URL)
	}

	if input.Active != nil {
		webhookUpdate = webhookUpdate.SetActive(*input.Active)
	}

	if input.EventTypes != nil {
		webhookUpdate = webhookUpdate.SetEventTypes(input.EventTypes)
	}

	if input.RetryCount != nil {
		webhookUpdate = webhookUpdate.SetRetryCount(*input.RetryCount)
	}

	if input.TimeoutMs != nil {
		webhookUpdate = webhookUpdate.SetTimeoutMs(*input.TimeoutMs)
	}

	if input.Format != nil {
		webhookUpdate = webhookUpdate.SetFormat(webhook.Format(*input.Format))
	}

	if input.Metadata != nil {
		webhookUpdate = webhookUpdate.SetMetadata(input.Metadata)
	}

	entWebhook, err := s.repo.Update(ctx, webhookUpdate)
	if err != nil {
		return nil, err
	}

	return convertWebhookToDTO(entWebhook), nil
}

// Delete deletes a webhook
func (s *service) Delete(ctx context.Context, id xid.ID) error {
	return s.repo.Delete(ctx, id)
}

// TriggerEvent triggers a webhook event
func (s *service) TriggerEvent(ctx context.Context, input TriggerEventInput) (*WebhookEvent, error) {
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

	// Create webhook event using ent builder
	eventCreate := s.eventRepo.Client().WebhookEvent.Create().
		SetWebhookID(webhook.ID).
		SetEventType(input.EventType).
		SetPayload(input.Payload).
		SetDelivered(false)

	// Set optional fields
	if input.Headers != nil {
		eventCreate = eventCreate.SetHeaders(input.Headers)
	}

	// Create event
	entEvent, err := s.eventRepo.Create(ctx, eventCreate)
	if err != nil {
		return nil, err
	}

	// Deliver event asynchronously
	go func() {
		// Create background context for delivery
		deliveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		// Deliver event
		s.deliverer.DeliverEvent(deliveryCtx, entEvent, webhook)
	}()

	return convertWebhookEventToDTO(entEvent), nil
}

// GetEvents retrieves webhook events with pagination
func (s *service) GetEvents(ctx context.Context, webhookID xid.ID, params ListWebhookEventsParams) (*model.PaginatedOutput[*WebhookEvent], error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	entResult, err := s.eventRepo.List(ctx, params)
	if err != nil {
		return nil, err
	}

	// Convert the paginated result
	events := convertWebhookEventsToDTO(entResult.Data)

	return &model.PaginatedOutput[*WebhookEvent]{
		Data:       events,
		Pagination: entResult.Pagination,
	}, nil
}

// ReplayEvent replays a webhook event
func (s *service) ReplayEvent(ctx context.Context, eventID xid.ID) (*WebhookEvent, error) {
	// Get event
	event, err := s.eventRepo.GetByID(ctx, eventID)
	if err != nil {
		return nil, err
	}

	webhook, err := s.repo.GetByID(ctx, event.WebhookID)
	if err != nil {
		return nil, err
	}

	// Create a new event using ent builder (copy of the original)
	eventCreate := s.eventRepo.Client().WebhookEvent.Create().
		SetID(xid.New()).
		SetWebhookID(webhook.ID).
		SetEventType(event.EventType).
		SetPayload(event.Payload).
		SetDelivered(false).
		SetAttempts(0)

	// Set optional fields
	if event.Headers != nil {
		eventCreate = eventCreate.SetHeaders(event.Headers)
	}

	newEntEvent, err := s.eventRepo.Create(ctx, eventCreate)
	if err != nil {
		return nil, err
	}

	// Deliver event asynchronously
	go func() {
		// Create background context for delivery
		deliveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		// Deliver event
		s.deliverer.DeliverEvent(deliveryCtx, newEntEvent, webhook)
	}()

	return convertWebhookEventToDTO(newEntEvent), nil
}

// convertWebhookToDTO converts an ent.Webhook to Webhook DTO
func convertWebhookToDTO(entWebhook *ent.Webhook) *Webhook {
	return &Webhook{
		Base: model.Base{
			ID:        entWebhook.ID,
			CreatedAt: entWebhook.CreatedAt,
			UpdatedAt: entWebhook.UpdatedAt,
		},
		Name:           entWebhook.Name,
		URL:            entWebhook.URL,
		OrganizationID: entWebhook.OrganizationID,
		Secret:         entWebhook.Secret,
		Active:         entWebhook.Active,
		EventTypes:     entWebhook.EventTypes,
		Version:        entWebhook.Version,
		RetryCount:     entWebhook.RetryCount,
		TimeoutMs:      entWebhook.TimeoutMs,
		Format:         entWebhook.Format,
		Metadata:       entWebhook.Metadata,
	}
}

// convertWebhooksToDTO converts a slice of ent.Webhook to Webhook DTOs
func convertWebhooksToDTO(entWebhooks []*ent.Webhook) []*Webhook {
	webhooks := make([]*Webhook, len(entWebhooks))
	for i, entWebhook := range entWebhooks {
		webhooks[i] = convertWebhookToDTO(entWebhook)
	}
	return webhooks
}

// convertWebhookEventToDTO converts an ent.WebhookEvent to WebhookEvent DTO
func convertWebhookEventToDTO(entEvent *ent.WebhookEvent) *WebhookEvent {
	return &WebhookEvent{
		Base: model.Base{
			ID:        entEvent.ID,
			CreatedAt: entEvent.CreatedAt,
			UpdatedAt: entEvent.UpdatedAt,
		},
		WebhookID:    entEvent.WebhookID,
		EventType:    entEvent.EventType,
		Headers:      entEvent.Headers,
		Payload:      entEvent.Payload,
		Delivered:    entEvent.Delivered,
		DeliveredAt:  entEvent.DeliveredAt,
		Attempts:     entEvent.Attempts,
		NextRetry:    entEvent.NextRetry,
		StatusCode:   entEvent.StatusCode,
		ResponseBody: entEvent.ResponseBody,
		Error:        entEvent.Error,
	}
}

// convertWebhookEventsToDTO converts a slice of ent.WebhookEvent to WebhookEvent DTOs
func convertWebhookEventsToDTO(entEvents []*ent.WebhookEvent) []*WebhookEvent {
	events := make([]*WebhookEvent, len(entEvents))
	for i, entEvent := range entEvents {
		events[i] = convertWebhookEventToDTO(entEvent)
	}
	return events
}
