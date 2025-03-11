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

// clickSendProvider implements the ClickSend SMS provider
type clickSendProvider struct {
	config   *config.Config
	logger   logging.Logger
	client   *http.Client
	username string
	apiKey   string
}

// NewClickSendProvider creates a new ClickSend SMS provider
func NewClickSendProvider(cfg *config.Config, logger logging.Logger) Provider {
	return &clickSendProvider{
		config:   cfg,
		logger:   logger,
		client:   &http.Client{},
		username: cfg.SMS.ClickSend.Username,
		apiKey:   cfg.SMS.ClickSend.APIKey,
	}
}

// Send sends an SMS via ClickSend
func (p *clickSendProvider) Send(ctx context.Context, input SMS) error {
	// Validate credentials
	if p.username == "" || p.apiKey == "" {
		return errors.New(errors.CodeConfigurationError, "ClickSend username and API key are required")
	}

	// Set sender (From) if not provided
	from := input.From
	if from == "" {
		from = p.config.SMS.FromNumber
	}

	// Prepare message
	message := map[string]interface{}{
		"source": "sdk",
		"from":   from,
		"body":   input.Message,
		"to":     input.To,
	}

	// Create request body with messages array
	requestBody := map[string]interface{}{
		"messages": []interface{}{message},
	}

	// Marshal request body to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to marshal ClickSend request")
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://rest.clicksend.com/v3/sms/send", bytes.NewBuffer(jsonBody))
	if err != nil {
		return errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to create ClickSend request")
	}

	// Set headers
	req.SetBasicAuth(p.username, p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to send ClickSend request")
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.Warn("Failed to read ClickSend response body", logging.Error(err))
	}

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("ClickSend API error: %s - %s", resp.Status, string(respBody)))
	}

	// Check for API-level errors
	var response struct {
		ResponseCode string `json:"response_code"`
		ResponseMsg  string `json:"response_msg"`
	}
	if err := json.Unmarshal(respBody, &response); err == nil {
		if response.ResponseCode != "SUCCESS" {
			return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("ClickSend API error: %s", response.ResponseMsg))
		}
	}

	return nil
}

// Name returns the name of the provider
func (p *clickSendProvider) Name() string {
	return "clicksend"
}
