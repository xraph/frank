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

// sendgridProvider implements the SendGrid SMS provider
// Note: SendGrid's SMS service is powered by Twilio
type sendgridProvider struct {
	config *config.Config
	logger logging.Logger
	client *http.Client
	apiKey string
}

// NewSendgridProvider creates a new SendGrid SMS provider
func NewSendgridProvider(cfg *config.Config, logger logging.Logger) Provider {
	return &sendgridProvider{
		config: cfg,
		logger: logger,
		client: &http.Client{},
		apiKey: cfg.SMS.SendGrid.APIKey,
	}
}

// Send sends an SMS via SendGrid
func (p *sendgridProvider) Send(ctx context.Context, input SMS) error {
	// Validate API key
	if p.apiKey == "" {
		return errors.New(errors.CodeConfigurationError, "SendGrid API key is required")
	}

	// Set sender (From) if not provided
	from := input.From
	if from == "" {
		from = p.config.SMS.FromNumber
	}

	// Prepare request body
	requestBody := map[string]interface{}{
		"to":      input.To,
		"from":    from,
		"content": input.Message,
	}

	// Add optional parameters from metadata
	if input.Metadata != nil {
		if scheduleTime, ok := input.Metadata["schedule_time"].(string); ok {
			requestBody["schedule_time"] = scheduleTime
		}
	}

	// Marshal request body to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to marshal SendGrid request")
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.sendgrid.com/v3/sms/send", bytes.NewBuffer(jsonBody))
	if err != nil {
		return errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to create SendGrid request")
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to send SendGrid request")
	}
	defer resp.Body.Close()

	// Read response body for error details if needed
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.Warn("Failed to read SendGrid response body",
			logging.Error(err),
		)
	}

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("SendGrid API error: %s - %s", resp.Status, string(respBody)))
	}

	return nil
}

// Name returns the name of the provider
func (p *sendgridProvider) Name() string {
	return "sendgrid"
}
