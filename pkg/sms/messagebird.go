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

// messagebirdProvider implements the MessageBird SMS provider
type messagebirdProvider struct {
	config *config.SMSConfig
	logger logging.Logger
	client *http.Client
	apiKey string
}

// NewMessageBirdProvider creates a new MessageBird SMS provider
func NewMessageBirdProvider(cfg *config.SMSConfig, logger logging.Logger) Provider {
	return &messagebirdProvider{
		config: cfg,
		logger: logger,
		client: &http.Client{},
		apiKey: cfg.MessageBird.AccessKey,
	}
}

// Send sends an SMS via MessageBird
func (p *messagebirdProvider) Send(ctx context.Context, input SMS) error {
	// Validate API key
	if p.apiKey == "" {
		return errors.New(errors.CodeConfigurationError, "MessageBird access key is required")
	}

	// Set sender (From) if not provided
	from := input.From
	if from == "" {
		from = p.config.FromNumber
	}

	// Prepare request body
	requestBody := map[string]interface{}{
		"recipients": []string{input.To},
		"originator": from,
		"body":       input.Message,
	}

	// Add optional parameters from metadata
	if input.Metadata != nil {
		if reference, ok := input.Metadata["reference"].(string); ok {
			requestBody["reference"] = reference
		}
		if reportUrl, ok := input.Metadata["report_url"].(string); ok {
			requestBody["reportUrl"] = reportUrl
		}
		if type_, ok := input.Metadata["type"].(string); ok {
			requestBody["type"] = type_
		}
	}

	// Marshal request body to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to marshal MessageBird request")
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://rest.messagebird.com/messages", bytes.NewBuffer(jsonBody))
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to create MessageBird request")
	}

	// Set headers
	req.Header.Set("Authorization", "AccessKey "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to send MessageBird request")
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to read MessageBird response")
	}

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("MessageBird API error: %s - %s", resp.Status, string(respBody)))
	}

	return nil
}

// Name returns the name of the provider
func (p *messagebirdProvider) Name() string {
	return "messagebird"
}
