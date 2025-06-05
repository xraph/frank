package email

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// SMTPSender sends emails using SMTP
type SMTPSender struct {
	config *config.EmailConfig
	logger logging.Logger
}

// NewSMTPSender creates a new SMTP sender
func NewSMTPSender(cfg *config.EmailConfig, logger logging.Logger) *SMTPSender {
	return &SMTPSender{
		config: cfg,
		logger: logger,
	}
}

// Send sends an email using SMTP
func (s *SMTPSender) Send(ctx context.Context, email Email) error {
	smtpConfig := s.config.SMTP

	// SMTP connection string
	addr := fmt.Sprintf("%s:%d", smtpConfig.Host, smtpConfig.Port)

	// Create authentication if username and password are provided
	var auth smtp.Auth
	if smtpConfig.Username != "" && smtpConfig.Password != "" {
		auth = smtp.PlainAuth("", smtpConfig.Username, smtpConfig.Password, smtpConfig.Host)
	}

	// Set from name if provided
	from := email.From
	if strings.TrimSpace(from) == "" {
		from = s.config.FromEmail
	}

	// Build recipients list
	recipients := append([]string{}, email.To...)
	recipients = append(recipients, email.CC...)
	recipients = append(recipients, email.BCC...)

	// Build email message
	var message strings.Builder

	// Add headers
	message.WriteString(fmt.Sprintf("From: %s\r\n", from))
	message.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(email.To, ", ")))
	message.WriteString(fmt.Sprintf("Subject: %s\r\n", email.Subject))

	// Add CC and BCC headers if needed
	if len(email.CC) > 0 {
		message.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(email.CC, ", ")))
	}

	// Set Reply-To if provided
	if email.ReplyTo != "" {
		message.WriteString(fmt.Sprintf("Reply-To: %s\r\n", email.ReplyTo))
	}

	// Set Content-Type for multipart emails
	boundary := "boundary-" + fmt.Sprintf("%x", s.generateBoundary())
	message.WriteString("MIME-Version: 1.0\r\n")
	message.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=%s\r\n", boundary))

	// Add custom headers
	for key, value := range email.Headers {
		message.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	// Add message body
	message.WriteString("\r\n")

	// Add text part if available
	if email.TextContent != "" {
		message.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		message.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		message.WriteString(email.TextContent)
		message.WriteString("\r\n\r\n")
	}

	// Add HTML part if available
	if email.HTMLContent != "" {
		message.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		message.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		message.WriteString(email.HTMLContent)
		message.WriteString("\r\n\r\n")
	}

	// Close boundary
	message.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	// Send email
	err := smtp.SendMail(
		addr,
		auth,
		from,
		recipients,
		[]byte(message.String()),
	)

	if err != nil {
		return errors.Wrap(errors.CodeEmailDeliveryFail, err, "failed to send email via SMTP")
	}

	return nil
}

// generateBoundary generates a random boundary string
func (s *SMTPSender) generateBoundary() []byte {
	// Simple implementation for generating a boundary
	// In a real implementation, you might want to use crypto/rand
	return []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
}
