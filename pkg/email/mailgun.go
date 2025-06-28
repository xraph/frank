package email

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xraph/frank/config"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
)

// SendgridSender sends emails using Twilio SendGrid
type SendgridSender struct {
	config *config.EmailConfig
	logger logging.Logger
	client *http.Client
}

// NewSendgridSender creates a new SendGrid sender
func NewSendgridSender(cfg *config.EmailConfig, logger logging.Logger) Sender {
	return &SendgridSender{
		config: cfg,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Send sends an email using SendGrid
func (s *SendgridSender) Send(ctx context.Context, email Email) error {
	// Check if SendGrid is configured
	if s.config.Sendgrid.APIKey == "" {
		return errors.New(errors.CodeConfigurationError, "SendGrid API key not configured")
	}

	// Set from email if not provided
	from := email.From
	if from == "" {
		from = s.config.FromEmail
	}

	// Parse from name and email
	fromName := ""
	fromEmail := from
	if strings.Contains(from, "<") && strings.Contains(from, ">") {
		parts := strings.Split(from, "<")
		fromName = strings.TrimSpace(parts[0])
		fromEmail = strings.TrimSuffix(strings.TrimSpace(parts[1]), ">")
	}

	// Construct recipients
	personalization := map[string]interface{}{
		"to": make([]map[string]string, len(email.To)),
	}

	for i, to := range email.To {
		personalization["to"].([]map[string]string)[i] = map[string]string{
			"email": to,
		}
	}

	// Add CC if present
	if len(email.CC) > 0 {
		cc := make([]map[string]string, len(email.CC))
		for i, c := range email.CC {
			cc[i] = map[string]string{
				"email": c,
			}
		}
		personalization["cc"] = cc
	}

	// Add BCC if present
	if len(email.BCC) > 0 {
		bcc := make([]map[string]string, len(email.BCC))
		for i, b := range email.BCC {
			bcc[i] = map[string]string{
				"email": b,
			}
		}
		personalization["bcc"] = bcc
	}

	// Add subject
	personalization["subject"] = email.Subject

	// Construct payload
	payload := map[string]interface{}{
		"personalizations": []interface{}{personalization},
		"from": map[string]string{
			"email": fromEmail,
		},
		"subject": email.Subject,
	}

	// Add from name if provided
	if fromName != "" {
		payload["from"].(map[string]string)["name"] = fromName
	}

	// Add reply-to if provided
	if email.ReplyTo != "" {
		payload["reply_to"] = map[string]string{
			"email": email.ReplyTo,
		}
	}

	// Add content
	var content []map[string]string
	if email.HTMLContent != "" {
		content = append(content, map[string]string{
			"type":  "text/html",
			"value": email.HTMLContent,
		})
	}
	if email.TextContent != "" {
		content = append(content, map[string]string{
			"type":  "text/plain",
			"value": email.TextContent,
		})
	}

	if len(content) > 0 {
		payload["content"] = content
	}

	// Add attachments if any
	if len(email.Attachments) > 0 {
		attachments := make([]map[string]string, len(email.Attachments))
		for i, attachment := range email.Attachments {
			attachments[i] = map[string]string{
				"filename":    attachment.Filename,
				"content":     attachment.Base64Content,
				"type":        attachment.ContentType,
				"disposition": "attachment",
			}
		}
		payload["attachments"] = attachments
	}

	// Add headers if any
	if len(email.Headers) > 0 {
		payload["headers"] = email.Headers
	}

	// Convert payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to marshal email payload")
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.sendgrid.com/v3/mail/send", strings.NewReader(string(jsonPayload)))
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to create HTTP request")
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.config.Sendgrid.APIKey)

	// Execute request
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.Wrap(err, errors.CodeEmailDeliveryFail, "failed to send email via SendGrid")
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode >= 400 {
		var errorResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return errors.New(errors.CodeEmailDeliveryFail, fmt.Sprintf("SendGrid API error: %d", resp.StatusCode))
		}
		return errors.New(errors.CodeEmailDeliveryFail, fmt.Sprintf("SendGrid API error: %v", errorResponse))
	}

	s.logger.Info("Email sent successfully via SendGrid",
		logging.String("subject", email.Subject),
		logging.Int("recipients", len(email.To)),
	)

	return nil
}

func (s *SendgridSender) SendBulkEmails(ctx context.Context, emails []Email) (*BulkEmailResult, error) {
	// TODO implement me
	panic("implement me")
}

func (s *SendgridSender) TestConnection(ctx context.Context) error {
	// TODO implement me
	panic("implement me")
}

func (s *SendgridSender) GetDeliveryStatus(ctx context.Context, messageID string) (*DeliveryInfo, error) {
	// TODO implement me
	panic("implement me")
}

func (s *SendgridSender) Name() string {
	return "sendgrid"
}
