package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/xraph/frank/config"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
)

// telnyxProvider implements the Telnyx SMS provider
type telnyxProvider struct {
	config             *config.SMSConfig
	logger             logging.Logger
	client             *http.Client
	apiKey             string
	messagingProfileID string
}

// NewTelnyxProvider creates a new Telnyx SMS provider
func NewTelnyxProvider(cfg *config.SMSConfig, logger logging.Logger) Provider {
	return &telnyxProvider{
		config:             cfg,
		logger:             logger,
		client:             &http.Client{},
		apiKey:             cfg.Telnyx.APIKey,
		messagingProfileID: cfg.Telnyx.MessagingProfileID,
	}
}

// Send sends an SMS via Telnyx
func (p *telnyxProvider) Send(ctx context.Context, input SMS) error {
	// Validate API key
	if p.apiKey == "" {
		return errors.New(errors.CodeConfigurationError, "Telnyx API key is required")
	}

	// Set sender (From) if not provided
	from := input.From
	if from == "" {
		from = p.config.FromNumber
	}

	// Prepare request body
	requestBody := map[string]interface{}{
		"from": from,
		"to":   input.To,
		"text": input.Message,
		"type": "SMS",
	}

	// Add messaging profile ID if available
	if p.messagingProfileID != "" {
		requestBody["messaging_profile_id"] = p.messagingProfileID
	}

	// Add optional parameters from metadata
	if input.Metadata != nil {
		if webhookURL, ok := input.Metadata["webhook_url"].(string); ok {
			requestBody["webhook_url"] = webhookURL
		}
		if webhookFailoverURL, ok := input.Metadata["webhook_failover_url"].(string); ok {
			requestBody["webhook_failover_url"] = webhookFailoverURL
		}
		if useProfileWebhooks, ok := input.Metadata["use_profile_webhooks"].(bool); ok {
			requestBody["use_profile_webhooks"] = useProfileWebhooks
		}
	}

	// Marshal request body to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to marshal Telnyx request")
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.telnyx.com/v2/messages", bytes.NewBuffer(jsonBody))
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to create Telnyx request")
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to send Telnyx request")
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.Warn("Failed to read Telnyx response body", logging.Error(err))
	}

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("Telnyx API error: %s - %s", resp.Status, string(respBody)))
	}

	// Parse response for potential errors
	var response struct {
		Data struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Errors []struct {
				Code   string `json:"code"`
				Title  string `json:"title"`
				Detail string `json:"detail"`
			} `json:"errors"`
		} `json:"data"`
		Errors []struct {
			Code   string `json:"code"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(respBody, &response); err == nil {
		// Check for errors in the data object
		if len(response.Data.Errors) > 0 {
			errorMsg := response.Data.Errors[0].Detail
			if errorMsg == "" {
				errorMsg = response.Data.Errors[0].Title
			}
			return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("Telnyx API error: %s", errorMsg))
		}

		// Check for top-level errors
		if len(response.Errors) > 0 {
			errorMsg := response.Errors[0].Detail
			if errorMsg == "" {
				errorMsg = response.Errors[0].Title
			}
			return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("Telnyx API error: %s", errorMsg))
		}
	}

	return nil
}

// Name returns the name of the provider
func (p *telnyxProvider) Name() string {
	return "telnyx"
}
