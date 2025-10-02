package repository

import (
	"context"
	"time"

	"github.com/uptrace/bun"
	"github.com/xraph/frank/internal/models"
	"github.com/xraph/frank/pkg/model"
)

// ===== WEBHOOK REPOSITORY =====

type WebhookRepository interface {
	Create(ctx context.Context, input CreateWebhookInput) (*models.Webhook, error)
	GetByID(ctx context.Context, id string) (*models.Webhook, error)
	Update(ctx context.Context, id string, input UpdateWebhookInput) (*models.Webhook, error)
	Delete(ctx context.Context, id string) error

	ListByOrganizationID(ctx context.Context, orgID string, opts PaginationParams) (*PaginatedOutput[*models.Webhook], error)
	ListActiveByOrganizationID(ctx context.Context, orgID string) ([]*models.Webhook, error)
	ListByEventType(ctx context.Context, eventType string, opts PaginationParams) (*PaginatedOutput[*models.Webhook], error)

	DeactivateByOrganizationID(ctx context.Context, orgID string) error
	CountByOrganizationID(ctx context.Context, orgID string) (int, error)

	GetActiveByOrganizationIDAndEventType(ctx context.Context, orgID string, eventType string) ([]*models.Webhook, error)
	ListByURL(ctx context.Context, url string) ([]*models.Webhook, error)
}

type CreateWebhookInput struct {
	Name           string
	URL            string
	OrganizationID string
	Secret         string
	Active         bool
	EventTypes     []string
	Version        string
	RetryCount     int
	TimeoutMS      int
	Format         model.WebhookFormat
	Metadata       map[string]interface{}
	Headers        map[string]string
}

type UpdateWebhookInput struct {
	Name       *string
	URL        *string
	Secret     *string
	Active     *bool
	EventTypes []string
	Version    *string
	RetryCount *int
	TimeoutMS  *int
	Format     *model.WebhookFormat
	Metadata   map[string]interface{}
	Headers    map[string]string
}

type webhookRepository struct {
	db *bun.DB
}

func NewWebhookRepository(db *bun.DB) WebhookRepository {
	return &webhookRepository{db: db}
}

func (r *webhookRepository) Create(ctx context.Context, input CreateWebhookInput) (*models.Webhook, error) {
	webhook := &models.Webhook{
		Name:           input.Name,
		URL:            input.URL,
		OrganizationID: input.OrganizationID,
		Secret:         input.Secret,
		Active:         input.Active,
		EventTypes:     input.EventTypes,
		Version:        input.Version,
		RetryCount:     input.RetryCount,
		TimeoutMS:      input.TimeoutMS,
		Format:         input.Format,
		Metadata:       input.Metadata,
		Headers:        input.Headers,
	}

	_, err := r.db.NewInsert().Model(webhook).Exec(ctx)
	if err != nil {
		return nil, WrapError(err, CodeDatabaseError, "failed to create webhook")
	}
	return webhook, nil
}

func (r *webhookRepository) GetByID(ctx context.Context, id string) (*models.Webhook, error) {
	webhook := new(models.Webhook)
	err := r.db.NewSelect().
		Model(webhook).
		Relation("Organization").
		Relation("Events").
		Where("wh.id = ?", id).
		Where("wh.deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Webhook not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get webhook")
	}
	return webhook, nil
}

func (r *webhookRepository) Update(ctx context.Context, id string, input UpdateWebhookInput) (*models.Webhook, error) {
	webhook, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	query := r.db.NewUpdate().
		Model(webhook).
		Where("id = ?", id).
		Where("deleted_at IS NULL")

	if input.Name != nil {
		query = query.Set("name = ?", *input.Name)
		webhook.Name = *input.Name
	}
	if input.URL != nil {
		query = query.Set("url = ?", *input.URL)
		webhook.URL = *input.URL
	}
	if input.Secret != nil {
		query = query.Set("secret = ?", *input.Secret)
		webhook.Secret = *input.Secret
	}
	if input.Active != nil {
		query = query.Set("active = ?", *input.Active)
		webhook.Active = *input.Active
	}
	if input.EventTypes != nil {
		query = query.Set("event_types = ?", input.EventTypes)
		webhook.EventTypes = input.EventTypes
	}
	if input.Version != nil {
		query = query.Set("version = ?", *input.Version)
		webhook.Version = *input.Version
	}
	if input.RetryCount != nil {
		query = query.Set("retry_count = ?", *input.RetryCount)
		webhook.RetryCount = *input.RetryCount
	}
	if input.TimeoutMS != nil {
		query = query.Set("timeout_ms = ?", *input.TimeoutMS)
		webhook.TimeoutMS = *input.TimeoutMS
	}
	if input.Format != nil {
		query = query.Set("format = ?", *input.Format)
		webhook.Format = *input.Format
	}
	if input.Metadata != nil {
		query = query.Set("metadata = ?", input.Metadata)
		webhook.Metadata = input.Metadata
	}
	if input.Headers != nil {
		query = query.Set("headers = ?", input.Headers)
		webhook.Headers = input.Headers
	}

	_, err = query.Exec(ctx)
	if err != nil {
		return nil, WrapError(err, CodeDatabaseError, "failed to update webhook")
	}
	return webhook, nil
}

func (r *webhookRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.NewDelete().
		Model((*models.Webhook)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

func (r *webhookRepository) ListByOrganizationID(ctx context.Context, orgID string, opts PaginationParams) (*PaginatedOutput[*models.Webhook], error) {
	query := r.db.NewSelect().
		Model((*models.Webhook)(nil)).
		Relation("Organization").
		Where("wh.organization_id = ?", orgID).
		Where("wh.deleted_at IS NULL")

	return Paginate[*models.Webhook](ctx, query, opts)
}

func (r *webhookRepository) ListActiveByOrganizationID(ctx context.Context, orgID string) ([]*models.Webhook, error) {
	var webhooks []*models.Webhook
	err := r.db.NewSelect().
		Model(&webhooks).
		Relation("Organization").
		Where("wh.organization_id = ?", orgID).
		Where("wh.active = ?", true).
		Where("wh.deleted_at IS NULL").
		Order("wh.created_at DESC").
		Scan(ctx)
	return webhooks, err
}

func (r *webhookRepository) ListByEventType(ctx context.Context, eventType string, opts PaginationParams) (*PaginatedOutput[*models.Webhook], error) {
	query := r.db.NewSelect().
		Model((*models.Webhook)(nil)).
		Relation("Organization").
		Where("? = ANY(event_types)", eventType).
		Where("deleted_at IS NULL")

	return Paginate[*models.Webhook](ctx, query, opts)
}

func (r *webhookRepository) DeactivateByOrganizationID(ctx context.Context, orgID string) error {
	_, err := r.db.NewUpdate().
		Model((*models.Webhook)(nil)).
		Set("active = ?", false).
		Where("organization_id = ?", orgID).
		Exec(ctx)
	return err
}

func (r *webhookRepository) CountByOrganizationID(ctx context.Context, orgID string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.Webhook)(nil)).
		Where("organization_id = ?", orgID).
		Where("deleted_at IS NULL").
		Count(ctx)
	return count, err
}

func (r *webhookRepository) GetActiveByOrganizationIDAndEventType(ctx context.Context, orgID string, eventType string) ([]*models.Webhook, error) {
	var webhooks []*models.Webhook
	err := r.db.NewSelect().
		Model(&webhooks).
		Relation("Organization").
		Where("wh.organization_id = ?", orgID).
		Where("wh.active = ?", true).
		Where("? = ANY(wh.event_types)", eventType).
		Where("wh.deleted_at IS NULL").
		Scan(ctx)
	return webhooks, err
}

func (r *webhookRepository) ListByURL(ctx context.Context, url string) ([]*models.Webhook, error) {
	var webhooks []*models.Webhook
	err := r.db.NewSelect().
		Model(&webhooks).
		Relation("Organization").
		Where("url = ?", url).
		Where("deleted_at IS NULL").
		Scan(ctx)
	return webhooks, err
}

// ===== WEBHOOK EVENT REPOSITORY =====

type WebhookEventRepository interface {
	Create(ctx context.Context, input CreateWebhookEventInput) (*models.WebhookEvent, error)
	GetByID(ctx context.Context, id string) (*models.WebhookEvent, error)
	Update(ctx context.Context, id string, input UpdateWebhookEventInput) (*models.WebhookEvent, error)
	Delete(ctx context.Context, id string) error

	ListByWebhookID(ctx context.Context, webhookID string, opts PaginationParams) (*PaginatedOutput[*models.WebhookEvent], error)
	ListPending(ctx context.Context, limit int) ([]*models.WebhookEvent, error)
	ListFailedRetries(ctx context.Context, before time.Time, limit int) ([]*models.WebhookEvent, error)

	MarkAsDelivered(ctx context.Context, id string, statusCode int, responseBody string) error
	MarkAsFailed(ctx context.Context, id string, statusCode *int, errorMsg string) error
	IncrementAttempts(ctx context.Context, id string, nextRetry time.Time) error

	CountByWebhookID(ctx context.Context, webhookID string) (int, error)
	CountPendingByWebhookID(ctx context.Context, webhookID string) (int, error)
	DeleteOldEvents(ctx context.Context, before time.Time) (int, error)

	ListByEventType(ctx context.Context, eventType string, opts PaginationParams) (*PaginatedOutput[*models.WebhookEvent], error)
	GetDeliveryStats(ctx context.Context, webhookID string, since time.Time) (*WebhookDeliveryStats, error)
}

type CreateWebhookEventInput struct {
	WebhookID string
	EventType string
	Headers   map[string]string
	Payload   map[string]interface{}
	NextRetry *time.Time
}

type UpdateWebhookEventInput struct {
	Delivered    *bool
	DeliveredAt  *time.Time
	Attempts     *int
	NextRetry    *time.Time
	StatusCode   *int
	ResponseBody *string
	Error        *string
}

type WebhookDeliveryStats struct {
	TotalEvents     int     `json:"total_events"`
	DeliveredEvents int     `json:"delivered_events"`
	FailedEvents    int     `json:"failed_events"`
	PendingEvents   int     `json:"pending_events"`
	SuccessRate     float64 `json:"success_rate"`
}

type webhookEventRepository struct {
	db *bun.DB
}

func NewWebhookEventRepository(db *bun.DB) WebhookEventRepository {
	return &webhookEventRepository{db: db}
}

func (r *webhookEventRepository) Create(ctx context.Context, input CreateWebhookEventInput) (*models.WebhookEvent, error) {
	event := &models.WebhookEvent{
		WebhookID: input.WebhookID,
		EventType: input.EventType,
		Headers:   input.Headers,
		Payload:   input.Payload,
		NextRetry: input.NextRetry,
	}

	_, err := r.db.NewInsert().Model(event).Exec(ctx)
	if err != nil {
		return nil, WrapError(err, CodeDatabaseError, "failed to create webhook event")
	}
	return event, nil
}

func (r *webhookEventRepository) GetByID(ctx context.Context, id string) (*models.WebhookEvent, error) {
	event := new(models.WebhookEvent)
	err := r.db.NewSelect().
		Model(event).
		Relation("Webhook").
		Where("we.id = ?", id).
		Where("we.deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Webhook event not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get webhook event")
	}
	return event, nil
}

func (r *webhookEventRepository) Update(ctx context.Context, id string, input UpdateWebhookEventInput) (*models.WebhookEvent, error) {
	event, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	query := r.db.NewUpdate().
		Model(event).
		Where("id = ?", id).
		Where("deleted_at IS NULL")

	if input.Delivered != nil {
		query = query.Set("delivered = ?", *input.Delivered)
		event.Delivered = *input.Delivered
	}
	if input.DeliveredAt != nil {
		query = query.Set("delivered_at = ?", *input.DeliveredAt)
		event.DeliveredAt = input.DeliveredAt
	}
	if input.Attempts != nil {
		query = query.Set("attempts = ?", *input.Attempts)
		event.Attempts = *input.Attempts
	}
	if input.NextRetry != nil {
		query = query.Set("next_retry = ?", *input.NextRetry)
		event.NextRetry = input.NextRetry
	}
	if input.StatusCode != nil {
		query = query.Set("status_code = ?", *input.StatusCode)
		event.StatusCode = input.StatusCode
	}
	if input.ResponseBody != nil {
		query = query.Set("response_body = ?", *input.ResponseBody)
		event.ResponseBody = input.ResponseBody
	}
	if input.Error != nil {
		query = query.Set("error = ?", *input.Error)
		event.Error = input.Error
	}

	_, err = query.Exec(ctx)
	if err != nil {
		return nil, WrapError(err, CodeDatabaseError, "failed to update webhook event")
	}
	return event, nil
}

func (r *webhookEventRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.NewDelete().
		Model((*models.WebhookEvent)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

func (r *webhookEventRepository) ListByWebhookID(ctx context.Context, webhookID string, opts PaginationParams) (*PaginatedOutput[*models.WebhookEvent], error) {
	query := r.db.NewSelect().
		Model((*models.WebhookEvent)(nil)).
		Relation("Webhook").
		Where("we.webhook_id = ?", webhookID).
		Where("we.deleted_at IS NULL")

	return Paginate[*models.WebhookEvent](ctx, query, opts)
}

func (r *webhookEventRepository) ListPending(ctx context.Context, limit int) ([]*models.WebhookEvent, error) {
	var events []*models.WebhookEvent
	err := r.db.NewSelect().
		Model(&events).
		Relation("Webhook").
		Where("we.delivered = ?", false).
		Where("(we.next_retry IS NULL OR we.next_retry <= ?)", time.Now()).
		Where("we.deleted_at IS NULL").
		Order("we.created_at ASC").
		Limit(limit).
		Scan(ctx)
	return events, err
}

func (r *webhookEventRepository) ListFailedRetries(ctx context.Context, before time.Time, limit int) ([]*models.WebhookEvent, error) {
	var events []*models.WebhookEvent
	err := r.db.NewSelect().
		Model(&events).
		Relation("Webhook").
		Where("we.delivered = ?", false).
		Where("we.next_retry IS NOT NULL").
		Where("we.next_retry <= ?", before).
		Where("we.deleted_at IS NULL").
		Order("we.next_retry ASC").
		Limit(limit).
		Scan(ctx)
	return events, err
}

func (r *webhookEventRepository) MarkAsDelivered(ctx context.Context, id string, statusCode int, responseBody string) error {
	_, err := r.db.NewUpdate().
		Model((*models.WebhookEvent)(nil)).
		Set("delivered = ?", true).
		Set("delivered_at = ?", time.Now()).
		Set("status_code = ?", statusCode).
		Set("response_body = ?", responseBody).
		Set("error = NULL").
		Where("id = ?", id).
		Exec(ctx)
	return err
}

func (r *webhookEventRepository) MarkAsFailed(ctx context.Context, id string, statusCode *int, errorMsg string) error {
	query := r.db.NewUpdate().
		Model((*models.WebhookEvent)(nil)).
		Set("error = ?", errorMsg).
		Where("id = ?", id)

	if statusCode != nil {
		query = query.Set("status_code = ?", *statusCode)
	}

	_, err := query.Exec(ctx)
	return err
}

func (r *webhookEventRepository) IncrementAttempts(ctx context.Context, id string, nextRetry time.Time) error {
	_, err := r.db.NewUpdate().
		Model((*models.WebhookEvent)(nil)).
		Set("attempts = attempts + 1").
		Set("next_retry = ?", nextRetry).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

func (r *webhookEventRepository) CountByWebhookID(ctx context.Context, webhookID string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.WebhookEvent)(nil)).
		Where("webhook_id = ?", webhookID).
		Where("deleted_at IS NULL").
		Count(ctx)
	return count, err
}

func (r *webhookEventRepository) CountPendingByWebhookID(ctx context.Context, webhookID string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.WebhookEvent)(nil)).
		Where("webhook_id = ?", webhookID).
		Where("delivered = ?", false).
		Where("deleted_at IS NULL").
		Count(ctx)
	return count, err
}

func (r *webhookEventRepository) DeleteOldEvents(ctx context.Context, before time.Time) (int, error) {
	res, err := r.db.NewDelete().
		Model((*models.WebhookEvent)(nil)).
		Where("created_at < ?", before).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	rows, _ := res.RowsAffected()
	return int(rows), nil
}

func (r *webhookEventRepository) ListByEventType(ctx context.Context, eventType string, opts PaginationParams) (*PaginatedOutput[*models.WebhookEvent], error) {
	query := r.db.NewSelect().
		Model((*models.WebhookEvent)(nil)).
		Relation("Webhook").
		Where("event_type = ?", eventType).
		Where("deleted_at IS NULL")

	return Paginate[*models.WebhookEvent](ctx, query, opts)
}

func (r *webhookEventRepository) GetDeliveryStats(ctx context.Context, webhookID string, since time.Time) (*WebhookDeliveryStats, error) {
	stats := &WebhookDeliveryStats{}

	// Count total events
	totalEvents, err := r.db.NewSelect().
		Model((*models.WebhookEvent)(nil)).
		Where("webhook_id = ?", webhookID).
		Where("created_at >= ?", since).
		Where("deleted_at IS NULL").
		Count(ctx)
	if err != nil {
		return nil, err
	}

	// Count delivered events
	deliveredEvents, err := r.db.NewSelect().
		Model((*models.WebhookEvent)(nil)).
		Where("webhook_id = ?", webhookID).
		Where("created_at >= ?", since).
		Where("delivered = ?", true).
		Where("deleted_at IS NULL").
		Count(ctx)
	if err != nil {
		return nil, err
	}

	// Count pending events
	pendingEvents, err := r.db.NewSelect().
		Model((*models.WebhookEvent)(nil)).
		Where("webhook_id = ?", webhookID).
		Where("created_at >= ?", since).
		Where("delivered = ?", false).
		Where("deleted_at IS NULL").
		Count(ctx)
	if err != nil {
		return nil, err
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
