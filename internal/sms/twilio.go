package sms

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// twilioProvider implements the Twilio SMS provider
type twilioProvider struct {
	config     *config.Config
	logger     logging.Logger
	accountSID string
	authToken  string
	client     *http.Client
}

// NewTwilioProvider creates a new Twilio SMS provider
func NewTwilioProvider(cfg *config.Config, logger logging.Logger) Provider {
	return &twilioProvider{
		config:     cfg,
		logger:     logger,
		accountSID: cfg.SMS.Twilio.AccountSID,
		authToken:  cfg.SMS.Twilio.AuthToken,
		client:     &http.Client{},
	}
}

// Send sends an SMS via Twilio
func (p *twilioProvider) Send(ctx context.Context, input SMS) error {
	// Validate credentials
	if p.accountSID == "" || p.authToken == "" {
		return errors.New(errors.CodeConfigurationError, "Twilio account SID and auth token are required")
	}

	// Set sender (From) if not provided
	from := input.From
	if from == "" {
		from = p.config.SMS.FromPhone
	}

	// Prepare request data
	data := url.Values{}
	data.Set("To", input.To)
	data.Set("From", from)
	data.Set("Body", input.Message)

	// Add optional parameters from metadata
	if input.Metadata != nil {
		if statusCallback, ok := input.Metadata["status_callback"].(string); ok {
			data.Set("StatusCallback", statusCallback)
		}
		if validityPeriod, ok := input.Metadata["validity_period"].(string); ok {
			data.Set("ValidityPeriod", validityPeriod)
		}
	}

	// Create request
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", p.accountSID)
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to create Twilio request")
	}

	// Set headers
	req.SetBasicAuth(p.accountSID, p.authToken)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to send Twilio request")
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New(errors.CodeSMSDeliveryFail, fmt.Sprintf("Twilio API returned error: %s", resp.Status))
	}

	return nil
}

// Name returns the name of the provider
func (p *twilioProvider) Name() string {
	return "twilio"
}
