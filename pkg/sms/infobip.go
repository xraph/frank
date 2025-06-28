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

// infobipProvider implements the Infobip SMS provider
type infobipProvider struct {
	config  *config.SMSConfig
	logger  logging.Logger
	client  *http.Client
	apiKey  string
	baseURL string
}

// NewInfobipProvider creates a new Infobip SMS provider
func NewInfobipProvider(cfg *config.SMSConfig, logger logging.Logger) Provider {
	baseURL := cfg.Infobip.BaseURL
	if baseURL == "" {
		baseURL = "https://api.infobip.com"
	}

	return &infobipProvider{
		config:  cfg,
		logger:  logger,
		client:  &http.Client{},
		apiKey:  cfg.Infobip.APIKey,
		baseURL: baseURL,
	}
}

// Send sends an SMS via Infobip
func (p *infobipProvider) Send(ctx context.Context, input SMS) error {
	// Validate API key
	if p.apiKey == "" {
		return errors.New(errors.CodeConfigurationError, "Infobip API key is required")
	}

	// Set sender (From) if not provided
	from := input.From
	if from == "" {
		from = p.config.FromNumber
	}

	// Prepare message
	message := map[string]interface{}{
		"from": from,
		"destinations": []map[string]string{
			{"to": input.To},
		},
		"text": input.Message,
	}

	// Add optional parameters from metadata
	if input.Metadata != nil {
		if callback_data, ok := input.Metadata["callback_data"].(string); ok {
			message["callbackData"] = callback_data
		}
		if notify_url, ok := input.Metadata["notify_url"].(string); ok {
			message["notifyUrl"] = notify_url
		}
		if track, ok := input.Metadata["track"].(string); ok {
			message["track"] = track
		}
	}

	// Create request body with messages array
	requestBody := map[string]interface{}{
		"messages": []interface{}{message},
	}

	// Marshal request body to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to marshal Infobip request")
	}

	// Create request
	apiURL := fmt.Sprintf("%s/sms/2/text/advanced", p.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to create Infobip request")
	}

	// Set headers
	req.Header.Set("Authorization", "App "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to send Infobip request")
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.Warn("Failed to read Infobip response body", logging.Error(err))
	}

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("Infobip API error: %s - %s", resp.Status, string(respBody)))
	}

	// Parse response
	var response struct {
		Messages []struct {
			Status struct {
				GroupID     int    `json:"groupId"`
				GroupName   string `json:"groupName"`
				ID          int    `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"status"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(respBody, &response); err == nil {
		if len(response.Messages) > 0 {
			status := response.Messages[0].Status
			// Check if there was an error sending the message
			if status.GroupID != 1 { // Group ID 1 means "PENDING"
				return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("Infobip API error: %s - %s", status.Name, status.Description))
			}
		}
	}

	return nil
}

// Name returns the name of the provider
func (p *infobipProvider) Name() string {
	return "infobip"
}
