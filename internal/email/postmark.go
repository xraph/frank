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

// PostmarkSender sends emails using Postmark
type PostmarkSender struct {
	config *config.Config
	logger logging.Logger
	client *http.Client
}

// NewPostmarkSender creates a new Postmark sender
func NewPostmarkSender(cfg *config.Config, logger logging.Logger) *PostmarkSender {
	return &PostmarkSender{
		config: cfg,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Send sends an email using Postmark
func (s *PostmarkSender) Send(ctx context.Context, email Email) error {
	// Check if Postmark is configured
	if s.config.Email.Postmark.ServerToken == "" {
		return errors.New(errors.CodeConfigurationError, "Postmark server token not configured")
	}

	// Set from email if not provided
	from := email.From
	if from == "" {
		from = s.config.Email.FromEmail
	}

	// Construct payload
	payload := map[string]interface{}{
		"From":       from,
		"To":         join(email.To),
		"Subject":    email.Subject,
		"TrackOpens": true,
	}

	// Add CC if present
	if len(email.CC) > 0 {
		payload["Cc"] = join(email.CC)
	}

	// Add BCC if present
	if len(email.BCC) > 0 {
		payload["Bcc"] = join(email.BCC)
	}

	// Add reply-to if provided
	if email.ReplyTo != "" {
		payload["ReplyTo"] = email.ReplyTo
	}

	// Handle content
	if email.HTMLContent != "" {
		payload["HtmlBody"] = email.HTMLContent
	}
	if email.TextContent != "" {
		payload["TextBody"] = email.TextContent
	}

	// Handle custom headers
	if len(email.Headers) > 0 {
		var headers []map[string]string
		for name, value := range email.Headers {
			headers = append(headers, map[string]string{
				"Name":  name,
				"Value": value,
			})
		}
		payload["Header"] = headers
	}

	// Handle attachments if any
	if len(email.Attachments) > 0 {
		attachments := make([]map[string]string, len(email.Attachments))
		for i, attachment := range email.Attachments {
			attachments[i] = map[string]string{
				"Name":        attachment.Filename,
				"Content":     attachment.Base64Content,
				"ContentType": attachment.ContentType,
			}
		}
		payload["Attachments"] = attachments
	}

	// Convert payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to marshal email payload")
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.postmarkapp.com/email", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to create HTTP request")
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Postmark-Server-Token", s.config.Email.Postmark.ServerToken)

	// Execute request
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.Wrap(errors.CodeEmailDeliveryFail, err, "failed to send email via Postmark")
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode >= 400 {
		var errorResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return errors.New(errors.CodeEmailDeliveryFail, fmt.Sprintf("Postmark API error: %d", resp.StatusCode))
		}
		return errors.New(errors.CodeEmailDeliveryFail, fmt.Sprintf("Postmark API error: %v", errorResponse))
	}

	s.logger.Info("Email sent successfully via Postmark",
		logging.String("subject", email.Subject),
		logging.Int("recipients", len(email.To)),
	)

	return nil
}

// join combines a list of email addresses into a comma-separated string
func join(emails []string) string {
	if len(emails) == 0 {
		return ""
	}

	if len(emails) == 1 {
		return emails[0]
	}

	var result string
	for i, email := range emails {
		if i > 0 {
			result += ", "
		}
		result += email
	}
	return result
}
