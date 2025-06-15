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

// plivoProvider implements the Plivo SMS provider
type plivoProvider struct {
	config    *config.SMSConfig
	logger    logging.Logger
	client    *http.Client
	authID    string
	authToken string
}

// NewPlivoProvider creates a new Plivo SMS provider
func NewPlivoProvider(cfg *config.SMSConfig, logger logging.Logger) Provider {
	return &plivoProvider{
		config:    cfg,
		logger:    logger,
		client:    &http.Client{},
		authID:    cfg.Plivo.AuthID,
		authToken: cfg.Plivo.AuthToken,
	}
}

// Send sends an SMS via Plivo
func (p *plivoProvider) Send(ctx context.Context, input SMS) error {
	// Validate credentials
	if p.authID == "" || p.authToken == "" {
		return errors.New(errors.CodeConfigurationError, "Plivo auth ID and token are required")
	}

	// Set sender (From) if not provided
	from := input.From
	if from == "" {
		from = p.config.FromNumber
	}

	// Prepare request body
	requestBody := map[string]interface{}{
		"src":  from,
		"dst":  input.To,
		"text": input.Message,
	}

	// Add optional parameters from metadata
	if input.Metadata != nil {
		if url, ok := input.Metadata["url"].(string); ok {
			requestBody["url"] = url
		}
		if method, ok := input.Metadata["method"].(string); ok {
			requestBody["method"] = method
		}
		if type_, ok := input.Metadata["type"].(string); ok {
			requestBody["type"] = type_
		}
	}

	// Marshal request body to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to marshal Plivo request")
	}

	// Create request URL
	apiURL := fmt.Sprintf("https://api.plivo.com/v1/Account/%s/Message/", p.authID)
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to create Plivo request")
	}

	// Set headers
	req.SetBasicAuth(p.authID, p.authToken)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to send Plivo request")
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.Warn("Failed to read Plivo response body", logging.Error(err))
	}

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("Plivo API error: %s - %s", resp.Status, string(respBody)))
	}

	return nil
}

// Name returns the name of the provider
func (p *plivoProvider) Name() string {
	return "plivo"
}
