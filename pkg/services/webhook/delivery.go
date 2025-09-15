package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// DeliveryService defines the interface for webhook delivery operations
type DeliveryService interface {
	// Event delivery
	QueueEvent(ctx context.Context, req DeliveryRequest) error
	DeliverEvent(ctx context.Context, req DeliveryRequest) (*DeliveryResult, error)
	ProcessQueue(ctx context.Context) error

	// Retry operations
	RetryEvent(ctx context.Context, eventID xid.ID, force bool) (*DeliveryResult, error)
	RetryFailedEvents(ctx context.Context, webhookID xid.ID, maxAge time.Duration) (int, error)

	// Health and monitoring
	GetDeliveryStats(ctx context.Context, webhookID *xid.ID, orgID xid.ID, period string) (*model.WebhookStats, error)
	HealthCheck(ctx context.Context, webhookID xid.ID) (*DeliveryHealthResult, error)

	// Queue management
	GetQueueSize(ctx context.Context) (int, error)
	PurgeQueue(ctx context.Context, webhookID *xid.ID) error

	// Start/OnStop processing
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// DeliveryRequest represents a webhook delivery request
type DeliveryRequest struct {
	WebhookID      xid.ID                 `json:"webhookId"`
	OrganizationID xid.ID                 `json:"organizationId"`
	URL            string                 `json:"url"`
	Secret         string                 `json:"secret"`
	EventType      string                 `json:"eventType"`
	Payload        map[string]interface{} `json:"payload"`
	Headers        map[string]string      `json:"headers"`
	RetryCount     int                    `json:"retryCount"`
	TimeoutMs      int                    `json:"timeoutMs"`
	IsTest         bool                   `json:"isTest"`
	Attempts       int                    `json:"attempts"`
	LastAttempt    *time.Time             `json:"lastAttempt"`
	NextRetry      *time.Time             `json:"nextRetry"`
}

// DeliveryResult represents the result of a webhook delivery attempt
type DeliveryResult struct {
	Success         bool              `json:"success"`
	StatusCode      int               `json:"statusCode"`
	ResponseBody    string            `json:"responseBody"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	Duration        int               `json:"duration"` // milliseconds
	Error           string            `json:"error"`
	Timestamp       time.Time         `json:"timestamp"`
	Attempts        int               `json:"attempts"`
}

// DeliveryHealthResult represents webhook endpoint health check result
type DeliveryHealthResult struct {
	Healthy          bool          `json:"healthy"`
	ResponseTime     time.Duration `json:"responseTime"`
	StatusCode       int           `json:"statusCode"`
	Error            string        `json:"error"`
	LastCheck        time.Time     `json:"lastCheck"`
	ConsecutiveFails int           `json:"consecutiveFails"`
}

// deliveryService implements the DeliveryService interface
type deliveryService struct {
	webhookRepo repository.WebhookRepository
	logger      logging.Logger
	httpClient  *http.Client
	queue       chan DeliveryRequest
	workers     int
	stopChan    chan struct{}
	wg          sync.WaitGroup
	isRunning   bool
	mu          sync.RWMutex
}

// NewDeliveryService creates a new webhook delivery service
func NewDeliveryService(
	webhookRepo repository.WebhookRepository,
	logger logging.Logger,
	workers int,
) DeliveryService {
	if workers <= 0 {
		workers = 10 // Default number of workers
	}

	return &deliveryService{
		webhookRepo: webhookRepo,
		logger:      logger.Named("webhook.delivery"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  false,
				MaxIdleConnsPerHost: 10,
			},
		},
		queue:     make(chan DeliveryRequest, 1000), // Buffered channel
		workers:   workers,
		stopChan:  make(chan struct{}),
		isRunning: false,
	}
}

// Start starts the webhook delivery workers
func (s *deliveryService) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isRunning {
		return errors.New(errors.CodeConflict, "delivery service is already running")
	}

	s.logger.Info("Starting webhook delivery service", logging.Int("workers", s.workers))

	// OnStart worker goroutines
	for i := 0; i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx, i)
	}

	s.isRunning = true
	return nil
}

// Stop stops the webhook delivery workers
func (s *deliveryService) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isRunning {
		return nil
	}

	s.logger.Info("Stopping webhook delivery service")

	// Signal workers to stop
	close(s.stopChan)

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("Webhook delivery service stopped successfully")
	case <-time.After(30 * time.Second):
		s.logger.Warn("Webhook delivery service stop timed out")
	}

	s.isRunning = false
	return nil
}

// QueueEvent queues an event for delivery
func (s *deliveryService) QueueEvent(ctx context.Context, req DeliveryRequest) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.isRunning {
		return errors.New(errors.CodeServiceUnavailable, "delivery service is not running")
	}

	// Set initial values
	if req.Attempts == 0 {
		req.Attempts = 0
	}
	if req.RetryCount == 0 {
		req.RetryCount = 3
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = 5000
	}

	select {
	case s.queue <- req:
		s.logger.Debug("Event queued for delivery",
			logging.String("webhook_id", req.WebhookID.String()),
			logging.String("event_type", req.EventType),
		)
		return nil
	case <-time.After(5 * time.Second):
		return errors.New(errors.CodeServiceUnavailable, "delivery queue is full")
	}
}

// DeliverEvent delivers a webhook event immediately
func (s *deliveryService) DeliverEvent(ctx context.Context, req DeliveryRequest) (*DeliveryResult, error) {
	defer logging.Track(ctx, "DeliverEvent")()

	startTime := time.Now()

	// Prepare payload
	payload, err := s.preparePayload(req)
	if err != nil {
		return &DeliveryResult{
			Success:   false,
			Error:     fmt.Sprintf("Failed to prepare payload: %v", err),
			Timestamp: startTime,
			Attempts:  req.Attempts + 1,
		}, err
	}

	// Create HTTP request
	request, err := s.createRequest(ctx, req, payload)
	if err != nil {
		return &DeliveryResult{
			Success:   false,
			Error:     fmt.Sprintf("Failed to create request: %v", err),
			Timestamp: startTime,
			Attempts:  req.Attempts + 1,
		}, err
	}

	// Set timeout for this specific request
	client := s.httpClient
	if req.TimeoutMs > 0 {
		client = &http.Client{
			Timeout:   time.Duration(req.TimeoutMs) * time.Millisecond,
			Transport: s.httpClient.Transport,
		}
	}

	// Make the request
	response, err := client.Do(request)
	duration := int(time.Since(startTime).Milliseconds())

	result := &DeliveryResult{
		Duration:  duration,
		Timestamp: startTime,
		Attempts:  req.Attempts + 1,
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.logger.Error("Webhook delivery failed",
			logging.String("webhook_id", req.WebhookID.String()),
			logging.String("url", req.URL),
			logging.String("event_type", req.EventType),
			logging.Error(err),
		)
		return result, err
	}
	defer response.Body.Close()

	// Read response
	responseBody, _ := io.ReadAll(response.Body)
	result.StatusCode = response.StatusCode
	result.ResponseBody = string(responseBody)
	result.ResponseHeaders = s.extractHeaders(response.Header)

	// Determine success based on status code
	result.Success = response.StatusCode >= 200 && response.StatusCode < 300

	if !result.Success {
		result.Error = fmt.Sprintf("HTTP %d: %s", response.StatusCode, string(responseBody))
		s.logger.Warn("Webhook delivery returned error status",
			logging.String("webhook_id", req.WebhookID.String()),
			logging.String("url", req.URL),
			logging.String("event_type", req.EventType),
			logging.Int("status_code", response.StatusCode),
		)
	} else {
		s.logger.Debug("Webhook delivered successfully",
			logging.String("webhook_id", req.WebhookID.String()),
			logging.String("event_type", req.EventType),
			logging.Int("duration_ms", duration),
		)
	}

	// Store delivery result if not a test
	if !req.IsTest {
		if err := s.storeDeliveryResult(ctx, req, result); err != nil {
			s.logger.Error("Failed to store delivery result", logging.Error(err))
		}
	}

	return result, nil
}

// ProcessQueue processes the delivery queue (used for manual processing)
func (s *deliveryService) ProcessQueue(ctx context.Context) error {
	processed := 0
	timeout := time.After(30 * time.Second)

	for {
		select {
		case req := <-s.queue:
			if _, err := s.DeliverEvent(ctx, req); err != nil {
				// If delivery failed and retries remain, requeue with backoff
				if req.Attempts < req.RetryCount {
					req.Attempts++
					req.LastAttempt = &time.Time{}
					*req.LastAttempt = time.Now()

					// Calculate next retry time with exponential backoff
					backoff := time.Duration(math.Pow(2, float64(req.Attempts))) * time.Second
					nextRetry := time.Now().Add(backoff)
					req.NextRetry = &nextRetry

					// Requeue for later (in a real implementation, this would go to a delayed queue)
					go func() {
						time.Sleep(backoff)
						s.QueueEvent(ctx, req)
					}()
				}
			}
			processed++
		case <-timeout:
			s.logger.Info("Queue processing timeout", logging.Int("processed", processed))
			return nil
		default:
			if processed == 0 {
				time.Sleep(100 * time.Millisecond) // Small delay to prevent busy waiting
			} else {
				s.logger.Info("Queue processing complete", logging.Int("processed", processed))
				return nil
			}
		}
	}
}

// RetryEvent retries a specific webhook event
func (s *deliveryService) RetryEvent(ctx context.Context, eventID xid.ID, force bool) (*DeliveryResult, error) {
	// In a real implementation, this would:
	// 1. Fetch the event from storage
	// 2. Check if retry is allowed (max attempts, etc.)
	// 3. Recreate the delivery request
	// 4. Deliver the event
	// 5. Update the event record

	return &DeliveryResult{
		Success:   true,
		Timestamp: time.Now(),
	}, nil
}

// RetryFailedEvents retries all failed events for a webhook
func (s *deliveryService) RetryFailedEvents(ctx context.Context, webhookID xid.ID, maxAge time.Duration) (int, error) {
	// In a real implementation, this would:
	// 1. Query failed events for the webhook within the time window
	// 2. Filter events that can be retried
	// 3. Queue them for delivery
	// 4. Return the count of queued events

	return 0, nil
}

// GetDeliveryStats gets delivery statistics
func (s *deliveryService) GetDeliveryStats(ctx context.Context, webhookID *xid.ID, orgID xid.ID, period string) (*model.WebhookStats, error) {
	// In a real implementation, this would calculate statistics from stored delivery results
	return &model.WebhookStats{
		TotalEvents:      100,
		SuccessfulEvents: 95,
		FailedEvents:     5,
		SuccessRate:      95.0,
	}, nil
}

// HealthCheck performs a health check on a webhook endpoint
func (s *deliveryService) HealthCheck(ctx context.Context, webhookID xid.ID) (*DeliveryHealthResult, error) {
	webhook, err := s.webhookRepo.GetByID(ctx, webhookID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "webhook not found")
	}

	startTime := time.Now()

	// Create a simple health check request
	req, err := http.NewRequestWithContext(ctx, "HEAD", webhook.URL, nil)
	if err != nil {
		return &DeliveryHealthResult{
			Healthy:   false,
			Error:     err.Error(),
			LastCheck: startTime,
		}, nil
	}

	// Set timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	responseTime := time.Since(startTime)

	result := &DeliveryHealthResult{
		ResponseTime: responseTime,
		LastCheck:    startTime,
	}

	if err != nil {
		result.Healthy = false
		result.Error = err.Error()
	} else {
		resp.Body.Close()
		result.StatusCode = resp.StatusCode
		result.Healthy = resp.StatusCode >= 200 && resp.StatusCode < 500 // Allow client errors as "healthy"
	}

	return result, nil
}

// GetQueueSize returns the current queue size
func (s *deliveryService) GetQueueSize(ctx context.Context) (int, error) {
	return len(s.queue), nil
}

// PurgeQueue purges the delivery queue
func (s *deliveryService) PurgeQueue(ctx context.Context, webhookID *xid.ID) error {
	if webhookID == nil {
		// Purge entire queue
		for {
			select {
			case <-s.queue:
				// Remove item from queue
			default:
				return nil
			}
		}
	}

	// Purge specific webhook (would require a more sophisticated queue implementation)
	return nil
}

// Worker functions

// worker processes delivery requests from the queue
func (s *deliveryService) worker(ctx context.Context, workerID int) {
	defer s.wg.Done()

	s.logger.Debug("Webhook delivery worker started", logging.Int("worker_id", workerID))

	for {
		select {
		case req := <-s.queue:
			s.processDeliveryRequest(ctx, req, workerID)
		case <-s.stopChan:
			s.logger.Debug("Webhook delivery worker stopping", logging.Int("worker_id", workerID))
			return
		case <-ctx.Done():
			s.logger.Debug("Webhook delivery worker context cancelled", logging.Int("worker_id", workerID))
			return
		}
	}
}

// processDeliveryRequest processes a single delivery request
func (s *deliveryService) processDeliveryRequest(ctx context.Context, req DeliveryRequest, workerID int) {
	logger := s.logger.With(
		logging.Int("worker_id", workerID),
		logging.String("webhook_id", req.WebhookID.String()),
		logging.String("event_type", req.EventType),
	)

	logger.Debug("Processing delivery request")

	result, err := s.DeliverEvent(ctx, req)
	if err != nil || !result.Success {
		// Handle retry logic
		if req.Attempts < req.RetryCount {
			// Calculate backoff
			backoff := s.calculateBackoff(req.Attempts)

			logger.Info("Scheduling retry",
				logging.Int("attempt", req.Attempts+1),
				logging.Int("max_attempts", req.RetryCount),
				logging.Duration("backoff", backoff),
			)

			// Schedule retry (in a real implementation, this would use a delayed queue or scheduler)
			go func() {
				time.Sleep(backoff)
				req.Attempts++
				now := time.Now()
				req.LastAttempt = &now
				s.QueueEvent(ctx, req)
			}()
		} else {
			logger.Warn("Max delivery attempts reached, giving up")
		}
	}
}

// Helper methods

// preparePayload prepares the webhook payload
func (s *deliveryService) preparePayload(req DeliveryRequest) ([]byte, error) {
	// Create the webhook payload structure
	webhookPayload := map[string]interface{}{
		"event_type":   req.EventType,
		"webhook_id":   req.WebhookID.String(),
		"timestamp":    time.Now().Unix(),
		"data":         req.Payload,
		"organization": req.OrganizationID.String(),
	}

	// Add test flag if this is a test delivery
	if req.IsTest {
		webhookPayload["test"] = true
	}

	return json.Marshal(webhookPayload)
}

// createRequest creates an HTTP request for webhook delivery
func (s *deliveryService) createRequest(ctx context.Context, req DeliveryRequest, payload []byte) (*http.Request, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "POST", req.URL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	// Set standard headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "Frank-Webhooks/1.0")
	httpReq.Header.Set("X-Frank-Event", req.EventType)
	httpReq.Header.Set("X-Frank-Webhook-ID", req.WebhookID.String())
	httpReq.Header.Set("X-Frank-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))

	// Add signature if secret is provided
	if req.Secret != "" {
		signature := GenerateSignature(req.Secret, string(payload))
		httpReq.Header.Set("X-Frank-Signature", signature)
	}

	// Add custom headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	return httpReq, nil
}

// extractHeaders extracts relevant headers from HTTP response
func (s *deliveryService) extractHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)

	// Extract common headers
	for _, key := range []string{"Content-Type", "Content-Length", "Server", "Date"} {
		if value := headers.Get(key); value != "" {
			result[key] = value
		}
	}

	return result
}

// storeDeliveryResult stores the delivery result
func (s *deliveryService) storeDeliveryResult(ctx context.Context, req DeliveryRequest, result *DeliveryResult) error {
	// In a real implementation, this would store the delivery result in the database
	// This might involve creating a WebhookEvent record with the delivery details

	s.logger.Debug("Storing delivery result",
		logging.String("webhook_id", req.WebhookID.String()),
		logging.String("event_type", req.EventType),
		logging.Bool("success", result.Success),
		logging.Int("status_code", result.StatusCode),
		logging.Int("duration_ms", result.Duration),
	)

	// Create webhook event record (simplified)
	// In reality, this would use a WebhookEventRepository

	return nil
}

// calculateBackoff calculates exponential backoff duration
func (s *deliveryService) calculateBackoff(attempt int) time.Duration {
	// Exponential backoff with jitter: 2^attempt seconds (max 5 minutes)
	backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second

	// Cap at 5 minutes
	if backoff > 5*time.Minute {
		backoff = 5 * time.Minute
	}

	// Add some jitter (±25%)
	jitter := time.Duration(float64(backoff) * 0.25 * (rand.Float64()*2 - 1))
	backoff += jitter

	return backoff
}

// Utility functions for webhook signature verification

// ValidateWebhookSignature validates a webhook signature
func ValidateWebhookSignature(secret, payload, signature string) bool {
	return VerifySignature(secret, payload, signature)
}

// ExtractSignatureFromHeader extracts signature from webhook header
func ExtractSignatureFromHeader(header string) string {
	// Handle different signature formats
	if strings.HasPrefix(header, "sha256=") {
		return header
	}
	return "sha256=" + header
}

// IsRetryableError determines if an error is retryable
func IsRetryableError(statusCode int, err error) bool {
	if err != nil {
		// Network errors are generally retryable
		return true
	}

	// Retry on server errors and some client errors
	switch statusCode {
	case 408, 409, 429: // Request Timeout, Conflict, Too Many Requests
		return true
	case 500, 502, 503, 504: // Server errors
		return true
	default:
		return false
	}
}

// ShouldRetry determines if a delivery should be retried
func ShouldRetry(result *DeliveryResult, maxAttempts int) bool {
	if result.Attempts >= maxAttempts {
		return false
	}

	if result.Success {
		return false
	}

	return IsRetryableError(result.StatusCode, nil)
}
