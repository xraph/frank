package sms

import (
	"context"
	"fmt"

	"github.com/xraph/frank/config"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
)

// Service provides SMS operations
type Service interface {
	// Send sends an SMS
	Send(ctx context.Context, input SendSMSInput) error

	// SendVerificationCode sends a verification code
	SendVerificationCode(ctx context.Context, phoneNumber string, code string) error
}

// SendSMSInput represents input for sending an SMS
type SendSMSInput struct {
	To       string                 `json:"to" validate:"required"`
	Message  string                 `json:"message" validate:"required"`
	From     string                 `json:"from,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type service struct {
	config *config.SMSConfig
	sender Provider
	logger logging.Logger
}

// NewService creates a new SMS service
func NewService(cfg *config.SMSConfig, sender Provider, logger logging.Logger) Service {
	return &service{
		config: cfg,
		sender: sender,
		logger: logger,
	}
}

// Send sends an SMS
func (s *service) Send(ctx context.Context, input SendSMSInput) error {
	// Validate input
	if input.To == "" {
		return errors.New(errors.CodeInvalidInput, "recipient phone number is required")
	}

	if input.Message == "" {
		return errors.New(errors.CodeInvalidInput, "message is required")
	}

	// Use default from number if not provided
	from := input.From
	if from == "" {
		from = s.config.FromPhone
	}

	// Create SMS
	sms := SMS{
		To:       input.To,
		From:     from,
		Message:  input.Message,
		Metadata: input.Metadata,
	}

	// Send SMS
	err := s.sender.Send(ctx, sms)
	if err != nil {
		s.logger.Error("Failed to send SMS",
			logging.Error(err),
			logging.String("to", input.To),
		)
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to send SMS")
	}

	return nil
}

// SendVerificationCode sends a verification code
func (s *service) SendVerificationCode(ctx context.Context, phoneNumber string, code string) error {
	// Create message with verification code
	message := fmt.Sprintf("Your verification code is: %s", code)

	// Send SMS
	return s.Send(ctx, SendSMSInput{
		To:      phoneNumber,
		Message: message,
	})
}
