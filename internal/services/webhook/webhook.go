package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// Service defines the interface for webhook operations
type Service interface {
	// Webhook CRUD operations
	CreateWebhook(ctx context.Context, req model.CreateWebhookRequest, orgID xid.ID) (*model.Webhook, error)
	GetWebhook(ctx context.Context, id xid.ID, orgID xid.ID) (*model.Webhook, error)
	UpdateWebhook(ctx context.Context, id xid.ID, req model.UpdateWebhookRequest, orgID xid.ID) (*model.Webhook, error)
	DeleteWebhook(ctx context.Context, id xid.ID, orgID xid.ID) error
	ListWebhooks(ctx context.Context, req model.WebhookListRequest, orgID xid.ID) (*model.WebhookListResponse, error)

	// Webhook management
	ActivateWebhook(ctx context.Context, id xid.ID, orgID xid.ID) error
	DeactivateWebhook(ctx context.Context, id xid.ID, orgID xid.ID) error
	RegenerateSecret(ctx context.Context, id xid.ID, orgID xid.ID) (string, error)

	// Event operations
	ListWebhookEvents(ctx context.Context, req model.WebhookEventListRequest, orgID xid.ID) (*model.WebhookEventListResponse, error)
	GetWebhookEvent(ctx context.Context, id xid.ID, orgID xid.ID) (*model.WebhookEvent, error)
	RetryWebhookEvent(ctx context.Context, req model.RetryWebhookEventRequest, orgID xid.ID) (*model.RetryWebhookEventResponse, error)

	// Testing
	TestWebhook(ctx context.Context, req model.TestWebhookRequest, orgID xid.ID) (*model.TestWebhookResponse, error)
	ValidateWebhookURL(ctx context.Context, url string) error

	// Security
	GetWebhookSecurity(ctx context.Context, id xid.ID, orgID xid.ID) (*model.WebhookSecuritySettings, error)
	UpdateWebhookSecurity(ctx context.Context, id xid.ID, req model.UpdateWebhookSecurityRequest, orgID xid.ID) (*model.WebhookSecuritySettings, error)

	// Analytics and stats
	GetWebhookStats(ctx context.Context, id xid.ID, orgID xid.ID) (*model.WebhookStats, error)
	GetGlobalStats(ctx context.Context, orgID xid.ID) (*model.WebhookGlobalStats, error)

	// Bulk operations
	BulkWebhookOperation(ctx context.Context, req model.BulkWebhookOperationRequest, orgID xid.ID) (*model.BulkWebhookOperationResponse, error)
	BulkRetryEvents(ctx context.Context, req model.WebhookDeliveryRetryRequest, orgID xid.ID) (*model.WebhookDeliveryRetryResponse, error)

	// Export and health
	ExportWebhookData(ctx context.Context, req model.WebhookExportRequest, orgID xid.ID) (*model.WebhookExportResponse, error)
	GetWebhookHealth(ctx context.Context, id xid.ID, orgID xid.ID) (*model.WebhookHealthCheck, error)

	// Event publishing (called by other services)
	PublishEvent(ctx context.Context, eventType string, payload map[string]interface{}, orgID xid.ID) error
}

// webhookService implements the Service interface
type webhookService struct {
	webhookRepo repository.WebhookRepository
	delivery    DeliveryService
	logger      logging.Logger
}

// NewService creates a new webhook service
func NewService(
	webhookRepo repository.WebhookRepository,
	delivery DeliveryService,
	logger logging.Logger,
) Service {
	return &webhookService{
		webhookRepo: webhookRepo,
		delivery:    delivery,
		logger:      logger.Named("webhook.service"),
	}
}

// CreateWebhook creates a new webhook
func (s *webhookService) CreateWebhook(ctx context.Context, req model.CreateWebhookRequest, orgID xid.ID) (*model.Webhook, error) {
	defer logging.Track(ctx, "CreateWebhook")()

	// Validate webhook URL
	if err := s.ValidateWebhookURL(ctx, req.URL); err != nil {
		return nil, errors.Wrap(err, errors.CodeBadRequest, "invalid webhook URL")
	}

	// Generate secret if not provided
	secret := req.Secret
	if secret == "" {
		var err error
		secret, err = s.generateWebhookSecret()
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to generate webhook secret")
		}
	}

	// Set defaults
	if req.Version == "" {
		req.Version = "v1"
	}
	if req.RetryCount == 0 {
		req.RetryCount = 3
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = 5000
	}
	if req.Format == "" {
		req.Format = "json"
	}

	// Create webhook
	input := repository.CreateWebhookInput{
		Name:           req.Name,
		URL:            req.URL,
		OrganizationID: orgID,
		Secret:         secret,
		Active:         true,
		EventTypes:     req.EventTypes,
		Version:        req.Version,
		RetryCount:     req.RetryCount,
		TimeoutMs:      req.TimeoutMs,
		Format:         req.Format,
		Headers:        req.Headers,
		Metadata:       req.Metadata,
	}

	webhook, err := s.webhookRepo.Create(ctx, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create webhook")
	}

	s.logger.Info("Webhook created",
		logging.String("webhook_id", webhook.ID.String()),
		logging.String("organization_id", orgID.String()),
		logging.String("url", req.URL),
	)

	return s.entToModel(webhook), nil
}

// GetWebhook retrieves a webhook by ID
func (s *webhookService) GetWebhook(ctx context.Context, id xid.ID, orgID xid.ID) (*model.Webhook, error) {
	webhook, err := s.webhookRepo.GetByID(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "webhook not found")
	}

	// Ensure webhook belongs to organization
	if webhook.OrganizationID != orgID {
		return nil, errors.New(errors.CodeForbidden, "access denied to webhook")
	}

	return s.entToModel(webhook), nil
}

// UpdateWebhook updates an existing webhook
func (s *webhookService) UpdateWebhook(ctx context.Context, id xid.ID, req model.UpdateWebhookRequest, orgID xid.ID) (*model.Webhook, error) {
	defer logging.Track(ctx, "UpdateWebhook")()

	// Verify webhook exists and belongs to organization
	existing, err := s.GetWebhook(ctx, id, orgID)
	if err != nil {
		return nil, err
	}

	// Validate URL if being updated
	if req.URL != "" && req.URL != existing.URL {
		if err := s.ValidateWebhookURL(ctx, req.URL); err != nil {
			return nil, errors.Wrap(err, errors.CodeBadRequest, "invalid webhook URL")
		}
	}

	// Build update input
	input := repository.UpdateWebhookInput{}
	if req.Name != "" {
		input.Name = &req.Name
	}
	if req.URL != "" {
		input.URL = &req.URL
	}
	if req.Active != existing.Active {
		input.Active = &req.Active
	}
	if len(req.EventTypes) > 0 {
		input.EventTypes = req.EventTypes
	}
	if req.Secret != "" {
		input.Secret = &req.Secret
	}
	if req.RetryCount > 0 {
		input.RetryCount = &req.RetryCount
	}
	if req.TimeoutMs > 0 {
		input.TimeoutMs = &req.TimeoutMs
	}
	if req.Headers != nil {
		input.Headers = req.Headers
	}
	if req.Metadata != nil {
		input.Metadata = req.Metadata
	}

	webhook, err := s.webhookRepo.Update(ctx, id, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update webhook")
	}

	s.logger.Info("Webhook updated",
		logging.String("webhook_id", id.String()),
		logging.String("organization_id", orgID.String()),
	)

	return s.entToModel(webhook), nil
}

// DeleteWebhook deletes a webhook
func (s *webhookService) DeleteWebhook(ctx context.Context, id xid.ID, orgID xid.ID) error {
	defer logging.Track(ctx, "DeleteWebhook")()

	// Verify webhook exists and belongs to organization
	_, err := s.GetWebhook(ctx, id, orgID)
	if err != nil {
		return err
	}

	if err := s.webhookRepo.Delete(ctx, id); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to delete webhook")
	}

	s.logger.Info("Webhook deleted",
		logging.String("webhook_id", id.String()),
		logging.String("organization_id", orgID.String()),
	)

	return nil
}

// ListWebhooks lists webhooks for an organization
func (s *webhookService) ListWebhooks(ctx context.Context, req model.WebhookListRequest, orgID xid.ID) (*model.WebhookListResponse, error) {
	// Set organization ID filter
	req.OrganizationID.Value = orgID
	req.OrganizationID.IsSet = true

	result, err := s.webhookRepo.ListByOrganizationID(ctx, orgID, req.PaginationParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to list webhooks")
	}

	// Convert to summaries
	summaries := make([]model.WebhookSummary, len(result.Data))
	for i, webhook := range result.Data {
		summaries[i] = s.entToSummary(webhook)
	}

	return &model.WebhookListResponse{
		Data:       summaries,
		Pagination: result.Pagination,
	}, nil
}

// ActivateWebhook activates a webhook
func (s *webhookService) ActivateWebhook(ctx context.Context, id xid.ID, orgID xid.ID) error {
	return s.updateWebhookStatus(ctx, id, orgID, true)
}

// DeactivateWebhook deactivates a webhook
func (s *webhookService) DeactivateWebhook(ctx context.Context, id xid.ID, orgID xid.ID) error {
	return s.updateWebhookStatus(ctx, id, orgID, false)
}

// RegenerateSecret generates a new secret for a webhook
func (s *webhookService) RegenerateSecret(ctx context.Context, id xid.ID, orgID xid.ID) (string, error) {
	defer logging.Track(ctx, "RegenerateSecret")()

	// Verify webhook exists and belongs to organization
	_, err := s.GetWebhook(ctx, id, orgID)
	if err != nil {
		return "", err
	}

	// Generate new secret
	secret, err := s.generateWebhookSecret()
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to generate webhook secret")
	}

	// Update webhook
	input := repository.UpdateWebhookInput{
		Secret: &secret,
	}
	_, err = s.webhookRepo.Update(ctx, id, input)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to update webhook secret")
	}

	s.logger.Info("Webhook secret regenerated",
		logging.String("webhook_id", id.String()),
		logging.String("organization_id", orgID.String()),
	)

	return secret, nil
}

// TestWebhook tests a webhook endpoint
func (s *webhookService) TestWebhook(ctx context.Context, req model.TestWebhookRequest, orgID xid.ID) (*model.TestWebhookResponse, error) {
	defer logging.Track(ctx, "TestWebhook")()

	// Get webhook
	webhook, err := s.GetWebhook(ctx, req.WebhookID, orgID)
	if err != nil {
		return nil, err
	}

	// Create test payload
	payload := req.Payload
	if payload == nil {
		payload = map[string]interface{}{
			"event_type": "test",
			"test":       true,
			"timestamp":  time.Now().Unix(),
			"data": map[string]interface{}{
				"message": "This is a test webhook",
			},
		}
	}

	// Set event type if not provided
	eventType := req.EventType
	if eventType == "" {
		eventType = "test"
	}

	// Test delivery
	result, err := s.delivery.DeliverEvent(ctx, DeliveryRequest{
		WebhookID: webhook.ID,
		URL:       webhook.URL,
		Secret:    webhook.Secret,
		EventType: eventType,
		Payload:   payload,
		Headers:   webhook.Headers,
		TimeoutMs: webhook.TimeoutMs,
		IsTest:    true,
	})

	response := &model.TestWebhookResponse{
		Success:      result.Success,
		StatusCode:   result.StatusCode,
		ResponseBody: result.ResponseBody,
		Duration:     result.Duration,
		Error:        result.Error,
		Headers:      result.ResponseHeaders,
	}

	return response, err
}

// ValidateWebhookURL validates a webhook URL
func (s *webhookService) ValidateWebhookURL(ctx context.Context, webhookURL string) error {
	// Parse URL
	u, err := url.Parse(webhookURL)
	if err != nil {
		return errors.New(errors.CodeBadRequest, "invalid URL format")
	}

	// Check scheme
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New(errors.CodeBadRequest, "URL must use HTTP or HTTPS scheme")
	}

	// Check if localhost (only allow in development)
	if strings.Contains(u.Host, "localhost") || strings.Contains(u.Host, "127.0.0.1") {
		// In production, this should be configurable
		s.logger.Warn("Webhook URL uses localhost", logging.String("url", webhookURL))
	}

	// Check if private IP ranges (should be configurable)
	if s.isPrivateIP(u.Host) {
		s.logger.Warn("Webhook URL uses private IP", logging.String("url", webhookURL))
	}

	return nil
}

// PublishEvent publishes an event to all matching webhooks
func (s *webhookService) PublishEvent(ctx context.Context, eventType string, payload map[string]interface{}, orgID xid.ID) error {
	defer logging.Track(ctx, "PublishEvent")()

	// Get active webhooks for this organization and event type
	webhooks, err := s.webhookRepo.GetActiveByOrganizationIDAndEventType(ctx, orgID, eventType)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get webhooks for event")
	}

	if len(webhooks) == 0 {
		s.logger.Debug("No webhooks found for event",
			logging.String("event_type", eventType),
			logging.String("organization_id", orgID.String()),
		)
		return nil
	}

	// Queue events for delivery
	for _, webhook := range webhooks {
		if err := s.delivery.QueueEvent(ctx, DeliveryRequest{
			WebhookID:      webhook.ID,
			OrganizationID: orgID,
			URL:            webhook.URL,
			Secret:         webhook.Secret,
			EventType:      eventType,
			Payload:        payload,
			Headers:        webhook.Headers,
			RetryCount:     webhook.RetryCount,
			TimeoutMs:      webhook.TimeoutMs,
		}); err != nil {
			s.logger.Error("Failed to queue webhook event",
				logging.String("webhook_id", webhook.ID.String()),
				logging.String("event_type", eventType),
				logging.Error(err),
			)
		}
	}

	s.logger.Info("Event published to webhooks",
		logging.String("event_type", eventType),
		logging.String("organization_id", orgID.String()),
		logging.Int("webhook_count", len(webhooks)),
	)

	return nil
}

// Helper methods

func (s *webhookService) updateWebhookStatus(ctx context.Context, id xid.ID, orgID xid.ID, active bool) error {
	// Verify webhook exists and belongs to organization
	_, err := s.GetWebhook(ctx, id, orgID)
	if err != nil {
		return err
	}

	input := repository.UpdateWebhookInput{
		Active: &active,
	}
	_, err = s.webhookRepo.Update(ctx, id, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to update webhook status")
	}

	action := "deactivated"
	if active {
		action = "activated"
	}

	s.logger.Info("Webhook "+action,
		logging.String("webhook_id", id.String()),
		logging.String("organization_id", orgID.String()),
	)

	return nil
}

func (s *webhookService) generateWebhookSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "whsec_" + hex.EncodeToString(bytes), nil
}

func (s *webhookService) isPrivateIP(host string) bool {
	// Simple check for private IP ranges
	// In production, this should be more comprehensive
	return strings.HasPrefix(host, "10.") ||
		strings.HasPrefix(host, "192.168.") ||
		strings.HasPrefix(host, "172.")
}

func (s *webhookService) entToModel(webhook *ent.Webhook) *model.Webhook {
	return &model.Webhook{
		Base: model.Base{
			ID:        webhook.ID,
			CreatedAt: webhook.CreatedAt,
			UpdatedAt: webhook.UpdatedAt,
		},
		Name:           webhook.Name,
		URL:            webhook.URL,
		OrganizationID: webhook.OrganizationID,
		Active:         webhook.Active,
		EventTypes:     webhook.EventTypes,
		Version:        webhook.Version,
		RetryCount:     webhook.RetryCount,
		TimeoutMs:      webhook.TimeoutMs,
		Format:         webhook.Format,
		Headers:        webhook.Headers,
		Metadata:       webhook.Metadata,
	}
}

func (s *webhookService) entToSummary(webhook *ent.Webhook) model.WebhookSummary {
	return model.WebhookSummary{
		ID:         webhook.ID,
		Name:       webhook.Name,
		URL:        webhook.URL,
		Active:     webhook.Active,
		EventTypes: webhook.EventTypes,
		CreatedAt:  webhook.CreatedAt,
	}
}

// Stub implementations for remaining methods (would be fully implemented)

func (s *webhookService) ListWebhookEvents(ctx context.Context, req model.WebhookEventListRequest, orgID xid.ID) (*model.WebhookEventListResponse, error) {
	// Implementation would fetch webhook events with filtering
	return &model.WebhookEventListResponse{}, nil
}

func (s *webhookService) GetWebhookEvent(ctx context.Context, id xid.ID, orgID xid.ID) (*model.WebhookEvent, error) {
	// Implementation would fetch specific webhook event
	return &model.WebhookEvent{}, nil
}

func (s *webhookService) RetryWebhookEvent(ctx context.Context, req model.RetryWebhookEventRequest, orgID xid.ID) (*model.RetryWebhookEventResponse, error) {
	// Implementation would retry specific webhook event
	return &model.RetryWebhookEventResponse{}, nil
}

func (s *webhookService) GetWebhookSecurity(ctx context.Context, id xid.ID, orgID xid.ID) (*model.WebhookSecuritySettings, error) {
	// Implementation would fetch webhook security settings
	return &model.WebhookSecuritySettings{}, nil
}

func (s *webhookService) UpdateWebhookSecurity(ctx context.Context, id xid.ID, req model.UpdateWebhookSecurityRequest, orgID xid.ID) (*model.WebhookSecuritySettings, error) {
	// Implementation would update webhook security settings
	return &model.WebhookSecuritySettings{}, nil
}

func (s *webhookService) GetWebhookStats(ctx context.Context, id xid.ID, orgID xid.ID) (*model.WebhookStats, error) {
	// Implementation would calculate webhook statistics
	return &model.WebhookStats{}, nil
}

func (s *webhookService) GetGlobalStats(ctx context.Context, orgID xid.ID) (*model.WebhookGlobalStats, error) {
	// Implementation would calculate global webhook statistics
	return &model.WebhookGlobalStats{}, nil
}

func (s *webhookService) BulkWebhookOperation(ctx context.Context, req model.BulkWebhookOperationRequest, orgID xid.ID) (*model.BulkWebhookOperationResponse, error) {
	// Implementation would handle bulk webhook operations
	return &model.BulkWebhookOperationResponse{}, nil
}

func (s *webhookService) BulkRetryEvents(ctx context.Context, req model.WebhookDeliveryRetryRequest, orgID xid.ID) (*model.WebhookDeliveryRetryResponse, error) {
	// Implementation would handle bulk retry of webhook events
	return &model.WebhookDeliveryRetryResponse{}, nil
}

func (s *webhookService) ExportWebhookData(ctx context.Context, req model.WebhookExportRequest, orgID xid.ID) (*model.WebhookExportResponse, error) {
	// Implementation would export webhook data
	return &model.WebhookExportResponse{}, nil
}

func (s *webhookService) GetWebhookHealth(ctx context.Context, id xid.ID, orgID xid.ID) (*model.WebhookHealthCheck, error) {
	// Implementation would check webhook health
	return &model.WebhookHealthCheck{}, nil
}

// GenerateSignature generates HMAC signature for webhook payload
func GenerateSignature(secret, payload string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// VerifySignature verifies HMAC signature for webhook payload
func VerifySignature(secret, payload, signature string) bool {
	expectedSignature := GenerateSignature(secret, payload)
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}
