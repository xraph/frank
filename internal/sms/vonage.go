package sms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// vonageProvider implements the Vonage (formerly Nexmo) SMS provider
type vonageProvider struct {
	config    *config.Config
	logger    logging.Logger
	client    *http.Client
	apiKey    string
	apiSecret string
}

// NewVonageProvider creates a new Vonage SMS provider
func NewVonageProvider(cfg *config.Config, logger logging.Logger) Provider {
	return &vonageProvider{
		config:    cfg,
		logger:    logger,
		client:    &http.Client{},
		apiKey:    cfg.SMS.Vonage.APIKey,
		apiSecret: cfg.SMS.Vonage.APISecret,
	}
}

// Send sends an SMS via Vonage
func (p *vonageProvider) Send(ctx context.Context, input SMS) error {
	// Validate credentials
	if p.apiKey == "" || p.apiSecret == "" {
		return errors.New(errors.CodeConfigurationError, "Vonage API key and secret are required")
	}

	// Set sender (From) if not provided
	from := input.From
	if from == "" {
		from = p.config.SMS.FromNumber
	}

	// Prepare request data
	data := url.Values{}
	data.Set("api_key", p.apiKey)
	data.Set("api_secret", p.apiSecret)
	data.Set("to", input.To)
	data.Set("from", from)
	data.Set("text", input.Message)
	data.Set("type", "text")

	// Add optional parameters from metadata
	if input.Metadata != nil {
		if clientRef, ok := input.Metadata["client_ref"].(string); ok {
			data.Set("client-ref", clientRef)
		}
		if ttl, ok := input.Metadata["ttl"].(string); ok {
			data.Set("ttl", ttl)
		}
		if callback, ok := input.Metadata["callback"].(string); ok {
			data.Set("callback", callback)
		}
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://rest.nexmo.com/sms/json", strings.NewReader(data.Encode()))
	if err != nil {
		return errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to create Vonage request")
	}

	// Set headers
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to send Vonage request")
	}
	defer resp.Body.Close()

	// Parse response
	var result struct {
		Messages []struct {
			Status    string `json:"status"`
			ErrorText string `json:"error-text"`
		} `json:"messages"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to parse Vonage response")
	}

	// Check for errors in response
	if len(result.Messages) > 0 {
		status := result.Messages[0].Status
		if status != "0" { // 0 means success
			errorText := result.Messages[0].ErrorText
			return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("Vonage API error: %s", errorText))
		}
	} else {
		return errors.New(errors.CodeSMSDeliveryFail, "Vonage API returned empty response")
	}

	return nil
}

// Name returns the name of the provider
func (p *vonageProvider) Name() string {
	return "vonage"
}
