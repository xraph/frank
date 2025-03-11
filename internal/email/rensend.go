package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// ResendSender sends emails using Resend
type ResendSender struct {
	config *config.Config
	logger logging.Logger
	client *http.Client
}

// NewResendSender creates a new Resend sender
func NewResendSender(cfg *config.Config, logger logging.Logger) *ResendSender {
	return &ResendSender{
		config: cfg,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Send sends an email using Resend
func (s *ResendSender) Send(ctx context.Context, email Email) error {
	// Check if Resend is configured
	if s.config.Email.Resend.APIKey == "" {
		return errors.New(errors.CodeConfigurationError, "Resend API key not configured")
	}

	// Set from email if not provided
	from := email.From
	if from == "" {
		from = s.config.Email.FromEmail
	}

	// Construct payload
	payload := map[string]interface{}{
		"from":    from,
		"to":      email.To,
		"subject": email.Subject,
	}

	// Add CC if present
	if len(email.CC) > 0 {
		payload["cc"] = email.CC
	}

	// Add BCC if present
	if len(email.BCC) > 0 {
		payload["bcc"] = email.BCC
	}

	// Add reply-to if provided
	if email.ReplyTo != "" {
		payload["reply_to"] = email.ReplyTo
	}

	// Handle content
	if email.HTMLContent != "" {
		payload["html"] = email.HTMLContent
	}
	if email.TextContent != "" {
		payload["text"] = email.TextContent
	}

	// Handle attachments if any
	if len(email.Attachments) > 0 {
		attachments := make([]map[string]string, len(email.Attachments))
		for i, attachment := range email.Attachments {
			attachments[i] = map[string]string{
				"filename": attachment.Filename,
				"content":  attachment.Base64Content,
			}
		}
		payload["attachments"] = attachments
	}

	// Handle custom headers
	if len(email.Headers) > 0 {
		payload["headers"] = email.Headers
	}

	// Convert payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to marshal email payload")
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to create HTTP request")
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.config.Email.Resend.APIKey)

	// Execute request
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.Wrap(errors.CodeEmailDeliveryFail, err, "failed to send email via Resend")
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode >= 400 {
		var errorResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return errors.New(errors.CodeEmailDeliveryFail, fmt.Sprintf("Resend API error: %d", resp.StatusCode))
		}
		return errors.New(errors.CodeEmailDeliveryFail, fmt.Sprintf("Resend API error: %v", errorResponse))
	}

	s.logger.Info("Email sent successfully via Resend",
		logging.String("subject", email.Subject),
		logging.Int("recipients", len(email.To)),
	)

	return nil
}
