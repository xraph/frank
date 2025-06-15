package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// sinchProvider implements the Sinch SMS provider
type sinchProvider struct {
	config    *config.SMSConfig
	logger    logging.Logger
	client    *http.Client
	apiKey    string
	apiSecret string
	serviceID string
}

// NewSinchProvider creates a new Sinch SMS provider
func NewSinchProvider(cfg *config.SMSConfig, logger logging.Logger) Provider {
	return &sinchProvider{
		config:    cfg,
		logger:    logger,
		client:    &http.Client{},
		apiKey:    cfg.Sinch.APIKey,
		apiSecret: cfg.Sinch.APISecret,
		serviceID: cfg.Sinch.ServiceID,
	}
}

// Send sends an SMS via Sinch
func (p *sinchProvider) Send(ctx context.Context, input SMS) error {
	// Validate credentials
	if p.apiKey == "" || p.serviceID == "" {
		return errors.New(errors.CodeConfigurationError, "Sinch API key and service ID are required")
	}

	// Set sender (From) if not provided
	from := input.From
	if from == "" {
		from = p.config.FromNumber
	}

	// Prepare request body
	requestBody := map[string]interface{}{
		"from":    from,
		"to":      []string{input.To},
		"message": input.Message,
	}

	// Add optional parameters from metadata
	if input.Metadata != nil {
		if delivery_report, ok := input.Metadata["delivery_report"].(string); ok {
			requestBody["delivery_report"] = delivery_report
		}
		if expire_at, ok := input.Metadata["expire_at"].(string); ok {
			requestBody["expire_at"] = expire_at
		}
		if callback_url, ok := input.Metadata["callback_url"].(string); ok {
			requestBody["callback_url"] = callback_url
		}
	}

	// Marshal request body to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to marshal Sinch request")
	}

	// Create request URL
	apiURL := fmt.Sprintf("https://eu.sms.api.sinch.com/xms/v1/%s/batches", p.serviceID)
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to create Sinch request")
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to send Sinch request")
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.Warn("Failed to read Sinch response body", logging.Error(err))
	}

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("Sinch API error: %s - %s", resp.Status, string(respBody)))
	}

	return nil
}

// Name returns the name of the provider
func (p *sinchProvider) Name() string {
	return "sinch"
}
