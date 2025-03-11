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

// MailerSendSender sends emails using MailerSend
type MailerSendSender struct {
	config *config.Config
	logger logging.Logger
	client *http.Client
}

// NewMailerSendSender creates a new MailerSend sender
func NewMailerSendSender(cfg *config.Config, logger logging.Logger) *MailerSendSender {
	return &MailerSendSender{
		config: cfg,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Send sends an email using MailerSend
func (s *MailerSendSender) Send(ctx context.Context, email Email) error {
	// Check if MailerSend is configured
	if s.config.Email.MailerSend.APIKey == "" {
		return errors.New(errors.CodeConfigurationError, "MailerSend API key not configured")
	}

	// Set from email if not provided
	from := email.From
	if from == "" {
		from = s.config.Email.FromEmail
	}

	// Construct recipients
	recipients := make([]map[string]string, len(email.To))
	for i, to := range email.To {
		recipients[i] = map[string]string{
			"email": to,
		}
	}

	// Construct CC recipients if present
	var cc []map[string]string
	if len(email.CC) > 0 {
		cc = make([]map[string]string, len(email.CC))
		for i, c := range email.CC {
			cc[i] = map[string]string{
				"email": c,
			}
		}
	}

	// Construct BCC recipients if present
	var bcc []map[string]string
	if len(email.BCC) > 0 {
		bcc = make([]map[string]string, len(email.BCC))
		for i, b := range email.BCC {
			bcc[i] = map[string]string{
				"email": b,
			}
		}
	}

	// Construct payload
	payload := map[string]interface{}{
		"from": map[string]string{
			"email": from,
		},
		"to":      recipients,
		"subject": email.Subject,
	}

	// Add CC if present
	if len(cc) > 0 {
		payload["cc"] = cc
	}

	// Add BCC if present
	if len(bcc) > 0 {
		payload["bcc"] = bcc
	}

	// Add reply-to if provided
	if email.ReplyTo != "" {
		payload["reply_to"] = map[string]string{
			"email": email.ReplyTo,
		}
	}

	// Handle content
	var content []map[string]string
	if email.HTMLContent != "" {
		content = append(content, map[string]string{
			"type":  "html",
			"value": email.HTMLContent,
		})
	}
	if email.TextContent != "" {
		content = append(content, map[string]string{
			"type":  "text",
			"value": email.TextContent,
		})
	}
	payload["content"] = content

	// Handle attachments if any
	if len(email.Attachments) > 0 {
		attachments := make([]map[string]string, len(email.Attachments))
		for i, attachment := range email.Attachments {
			attachments[i] = map[string]string{
				"filename":    attachment.Filename,
				"content":     attachment.Base64Content,
				"disposition": "attachment",
			}
		}
		payload["attachments"] = attachments
	}

	// Convert payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to marshal email payload")
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.mailersend.com/v1/email", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to create HTTP request")
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.config.Email.MailerSend.APIKey)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	// Execute request
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.Wrap(errors.CodeEmailDeliveryFail, err, "failed to send email via MailerSend")
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode >= 400 {
		var errorResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return errors.New(errors.CodeEmailDeliveryFail, fmt.Sprintf("MailerSend API error: %d", resp.StatusCode))
		}
		return errors.New(errors.CodeEmailDeliveryFail, fmt.Sprintf("MailerSend API error: %v", errorResponse))
	}

	s.logger.Info("Email sent successfully via MailerSend",
		logging.String("subject", email.Subject),
		logging.Int("recipients", len(email.To)),
	)

	return nil
}
