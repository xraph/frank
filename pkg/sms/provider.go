package sms

import (
	"context"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/logging"
)

// SMS represents an SMS to be sent
type SMS struct {
	To              string                 `json:"to" example:"+1234567890" doc:"Recipient phone number"`
	Message         string                 `json:"message" example:"Your verification code is 123456" doc:"SMS message content"`
	From            string                 `json:"from,omitempty" example:"+1987654321" doc:"Sender phone number"`
	MessageType     string                 `json:"messageType,omitempty" example:"transactional" doc:"Message type (transactional, promotional, etc.)"`
	Priority        string                 `json:"priority,omitempty" example:"high" doc:"Message priority"`
	ScheduledFor    *time.Time             `json:"scheduledFor,omitempty" doc:"Schedule message for later"`
	Tags            []string               `json:"tags,omitempty" doc:"Message tags for tracking"`
	Metadata        map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
	OrganizationID  *xid.ID                `json:"organizationId" doc:"Organization ID"`
	UserID          *xid.ID                `json:"userId,omitempty" doc:"User ID if applicable"`
	TTL             int                    `json:"ttl,omitempty" doc:"Time to live in seconds"`
	CallbackURL     string                 `json:"callbackUrl,omitempty" doc:"Delivery callback URL"`
	ValidityPeriod  int                    `json:"validityPeriod,omitempty" doc:"Validity period in seconds"`
	RequireDelivery bool                   `json:"requireDelivery" doc:"Require delivery confirmation"`
	AllowOptOut     bool                   `json:"allowOptOut" doc:"Allow opt-out responses"`
}

// Provider interface for sending SMS
type Provider interface {
	// Send sends an SMS
	Send(ctx context.Context, sms SMS) error
	Name() string
}

// NoOpSender is a sender that does nothing (for testing or when no provider is configured)
type NoOpSender struct {
	logger logging.Logger
}

func (s *NoOpSender) Name() string {
	return "noop"
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
