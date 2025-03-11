package sms

import (
	"context"

	"github.com/juicycleff/frank/pkg/logging"
)

// SMS represents an SMS to be sent
type SMS struct {
	To       string
	From     string
	Message  string
	Metadata map[string]interface{}
}

// Provider interface for sending SMS
type Provider interface {
	// Send sends an SMS
	Send(ctx context.Context, sms SMS) error
}

// NoOpSender is a sender that does nothing (for testing or when no provider is configured)
type NoOpSender struct {
	logger logging.Logger
}

// NewNoOpSender creates a new no-op sender
func NewNoOpSender(logger logging.Logger) *NoOpSender {
	return &NoOpSender{
		logger: logger,
	}
}

// Send logs the SMS but doesn't actually send it
func (s *NoOpSender) Send(ctx context.Context, sms SMS) error {
	s.logger.Warn("SMS not sent (no-op sender)",
		logging.String("to", sms.To),
		logging.String("from", sms.From),
		logging.String("message", sms.Message),
	)

	return nil
}
