package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/cryptoold"
	"github.com/juicycleff/frank/pkg/logging"
)

// Deliverer handles webhook event delivery
type Deliverer interface {
	// DeliverEvent delivers a webhook event
	DeliverEvent(ctx context.Context, event *ent.WebhookEvent, webhook *ent.Webhook) error

	// RetryPendingEvents retries pending webhook events
	RetryPendingEvents(ctx context.Context) error
}

type deliverer struct {
	eventRepo   EventRepository
	webhookRepo Repository
	httpClient  *http.Client
	config      *config.Config
	logger      logging.Logger
}

// NewDeliverer creates a new webhook event deliverer
func NewDeliverer(
	eventRepo EventRepository,
	webhookRepo Repository,
	cfg *config.Config,
	logger logging.Logger,
) Deliverer {
	// Create HTTP client with default timeout
	httpClient := &http.Client{
		Timeout: cfg.Webhooks.DefaultTimeout,
	}

	return &deliverer{
		eventRepo:   eventRepo,
		webhookRepo: webhookRepo,
		httpClient:  httpClient,
		config:      cfg,
		logger:      logger,
	}
}

// DeliverEvent delivers a webhook event
func (d *deliverer) DeliverEvent(ctx context.Context, event *ent.WebhookEvent, webhook *ent.Webhook) error {
	// Check if webhook is active
	if !webhook.Active {
		d.logger.Warn("Attempted to deliver event to inactive webhook",
			logging.String("webhook_id", webhook.ID.String()),
			logging.String("event_id", event.ID.String()),
			logging.String("event_type", event.EventType),
		)
		return nil
	}

	// Create payload to send
	payload := map[string]interface{}{
		"id":         event.ID,
		"event_type": event.EventType,
		"webhook_id": webhook.ID,
		"data":       event.Payload,
		"created_at": event.CreatedAt.Format(time.RFC3339),
		"attempt":    event.Attempts + 1,
	}

	// Marshal payload to JSON
	var payloadBytes []byte
	var err error

	if webhook.Format == "json" {
		payloadBytes, err = json.Marshal(payload)
	} else if webhook.Format == "form" {
		// Handle form encoding if needed
		payloadBytes = []byte("Not implemented")
		err = fmt.Errorf("form encoding not implemented")
	} else {
		// Default to JSON
		payloadBytes, err = json.Marshal(payload)
	}

	if err != nil {
		d.logger.Error("Failed to marshal webhook payload",
			logging.Error(err),
			logging.String("webhook_id", webhook.ID.String()),
			logging.String("event_id", event.ID.String()),
		)

		// Update event with error
		d.updateEventWithError(ctx, event, err.Error())
		return err
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", webhook.URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		d.logger.Error("Failed to create webhook request",
			logging.Error(err),
			logging.String("webhook_id", webhook.ID.String()),
			logging.String("event_id", event.ID.String()),
		)

		// Update event with error
		d.updateEventWithError(ctx, event, err.Error())
		return err
	}

	// Set headers
	if webhook.Format == "json" {
		req.Header.Set("Content-Type", "application/json")
	} else if webhook.Format == "form" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Set custom headers if present in event
	if event.Headers != nil {
		for key, value := range event.Headers {
			req.Header.Set(key, value)
		}
	}

	// Create signature
	timestamp := time.Now().Unix()
	signature := d.createSignature(webhook.Secret, timestamp, payloadBytes)

	// Set signature headers
	req.Header.Set("X-Webhook-Signature", signature)
	req.Header.Set("X-Webhook-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Webhook-ID", webhook.ID.String())
	req.Header.Set("X-Event-ID", event.ID.String())
	req.Header.Set("X-Event-Type", event.EventType)

	// Create HTTP client with webhook-specific timeout
	client := &http.Client{
		Timeout: time.Duration(webhook.TimeoutMs) * time.Millisecond,
	}

	// Increment attempt count
	attempts := event.Attempts + 1

	// Send request
	resp, err := client.Do(req)

	// Handle response
	if err != nil {
		d.logger.Warn("Webhook delivery failed",
			logging.Error(err),
			logging.String("webhook_id", webhook.ID.String()),
			logging.String("event_id", event.ID.String()),
			logging.Int("attempt", attempts),
		)

		// Check if should retry
		if attempts < webhook.RetryCount {
			// Calculate next retry time with exponential backoff
			nextRetry := calculateNextRetry(attempts, d.config.Webhooks.RetryBackoffFactor, d.config.Webhooks.MaxRetryDelay)

			// Update event with error and next retry time
			d.updateEventWithNextRetry(ctx, event, err.Error(), attempts, nextRetry)
		} else {
			// Max attempts reached, mark as failed
			d.updateEventAsFailed(ctx, event, err.Error(), attempts)
		}

		return err
	}

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	// Check for success status code (2xx)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Success! Mark as delivered
		d.updateEventAsDelivered(ctx, event, resp.StatusCode, string(body), attempts)

		d.logger.Info("Webhook delivered successfully",
			logging.String("webhook_id", webhook.ID.String()),
			logging.String("event_id", event.ID.String()),
			logging.Int("status_code", resp.StatusCode),
			logging.Int("attempt", attempts),
		)

		return nil
	}

	// Non-success status code
	errMsg := fmt.Sprintf("HTTP error %d: %s", resp.StatusCode, string(body))

	d.logger.Warn("Webhook delivery failed with non-success status code",
		logging.String("webhook_id", webhook.ID.String()),
		logging.String("event_id", event.ID.String()),
		logging.Int("status_code", resp.StatusCode),
		logging.Int("attempt", attempts),
		logging.String("response", string(body)),
	)

	// Check if should retry
	if attempts < webhook.RetryCount {
		// Calculate next retry time with exponential backoff
		nextRetry := calculateNextRetry(attempts, d.config.Webhooks.RetryBackoffFactor, d.config.Webhooks.MaxRetryDelay)

		// Update event with error and next retry time
		d.updateEventWithNextRetry(ctx, event, errMsg, attempts, nextRetry)
	} else {
		// Max attempts reached, mark as failed
		d.updateEventAsFailed(ctx, event, errMsg, attempts)
	}

	return fmt.Errorf(errMsg)
}

// RetryPendingEvents retries pending webhook events
func (d *deliverer) RetryPendingEvents(ctx context.Context) error {
	// Get pending events
	events, err := d.eventRepo.GetPendingEvents(ctx, 100)
	if err != nil {
		d.logger.Error("Failed to get pending webhook events", logging.Error(err))
		return err
	}

	d.logger.Info("Processing pending webhook events", logging.Int("count", len(events)))

	// Process each event
	for _, event := range events {
		// Get webhook
		webhook, err := d.webhookRepo.GetByID(ctx, event.WebhookID)
		if err != nil {
			d.logger.Error("Failed to get webhook for pending event",
				logging.Error(err),
				logging.String("webhook_id", event.WebhookID.String()),
				logging.String("event_id", event.ID.String()),
			)
			continue
		}

		// Deliver event in a separate goroutine
		go func(e *ent.WebhookEvent, w *ent.Webhook) {
			deliveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			d.DeliverEvent(deliveryCtx, e, w)
		}(event, webhook)
	}

	return nil
}

// Helper functions for event status updates

func (d *deliverer) updateEventAsDelivered(ctx context.Context, event *ent.WebhookEvent, statusCode int, responseBody string, attempts int) {
	webhookUpdate := d.eventRepo.Client().WebhookEvent.UpdateOne(event).
		SetAttempts(attempts).
		SetResponseBody(responseBody).
		SetStatusCode(statusCode).
		SetDeliveredAt(time.Now()).
		SetDelivered(true)

	_, err := d.eventRepo.Update(ctx, webhookUpdate)

	if err != nil {
		d.logger.Error("Failed to update webhook event as delivered",
			logging.Error(err),
			logging.Any("event_id", event.ID),
		)
	}
}

func (d *deliverer) updateEventWithError(ctx context.Context, event *ent.WebhookEvent, errMsg string) {
	attempts := event.Attempts + 1

	if attempts < d.config.Webhooks.DefaultRetries {
		// Calculate next retry time with exponential backoff
		nextRetry := calculateNextRetry(attempts, d.config.Webhooks.RetryBackoffFactor, d.config.Webhooks.MaxRetryDelay)
		d.updateEventWithNextRetry(ctx, event, errMsg, attempts, nextRetry)
	} else {
		d.updateEventAsFailed(ctx, event, errMsg, attempts)
	}
}

func (d *deliverer) updateEventWithNextRetry(ctx context.Context, event *ent.WebhookEvent, errMsg string, attempts int, nextRetry time.Time) {
	webhookUpdate := d.eventRepo.Client().WebhookEvent.UpdateOne(event).
		SetAttempts(attempts).
		SetNextRetry(nextRetry).
		SetError(errMsg)

	_, err := d.eventRepo.Update(ctx, webhookUpdate)

	if err != nil {
		d.logger.Error("Failed to update webhook event retry information",
			logging.Error(err),
			logging.Any("event_id", event.ID),
		)
	}
}

func (d *deliverer) updateEventAsFailed(ctx context.Context, event *ent.WebhookEvent, errMsg string, attempts int) {
	webhookUpdate := d.eventRepo.Client().WebhookEvent.UpdateOne(event).
		SetAttempts(attempts).
		SetError(errMsg)

	_, err := d.eventRepo.Update(ctx, webhookUpdate)

	if err != nil {
		d.logger.Error("Failed to update webhook event as failed",
			logging.Error(err),
			logging.Any("event_id", event.ID),
		)
	}
}

// createSignature creates an HMAC signature for webhook payload
func (d *deliverer) createSignature(secret string, timestamp int64, payload []byte) string {
	// Create signature string: timestamp + "." + payload
	signatureData := fmt.Sprintf("%d.%s", timestamp, string(payload))

	// Create HMAC signature
	return cryptoold.HMAC(signatureData, []byte(secret))
}

// Helper function to create bool pointer
func boolPtr(b bool) *bool {
	return &b
}

// calculateNextRetry calculates the next retry time with exponential backoff
func calculateNextRetry(attempt int, factor float64, maxDelay time.Duration) time.Time {
	// Calculate delay using exponential backoff
	// delay = min(maxDelay, initialDelay * (factor ^ attempt))
	initialDelay := 30 * time.Second
	delay := time.Duration(float64(initialDelay) * math.Pow(factor, float64(attempt-1)))

	// Cap at maximum delay
	if delay > maxDelay {
		delay = maxDelay
	}

	return time.Now().Add(delay)
}
