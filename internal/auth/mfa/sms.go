package mfa

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// SMSProviderInterface defines the methods required for an SMS provider
type SMSProviderInterface interface {
	SendSMS(phoneNumber, message string) error
}

// SMSCodeConfig contains configuration for SMS-based MFA
type SMSCodeConfig struct {
	CodeLength       int
	CodeExpiry       time.Duration
	MaxAttempts      int
	ResendCooldown   time.Duration
	MessageTemplate  string
	NumberNormalized bool // Whether phone numbers should be normalized to E.164 format
}

// DefaultSMSCodeConfig returns the default SMS code configuration
func DefaultSMSCodeConfig() SMSCodeConfig {
	return SMSCodeConfig{
		CodeLength:       6,
		CodeExpiry:       time.Minute * 10,
		MaxAttempts:      3,
		ResendCooldown:   time.Minute * 1,
		MessageTemplate:  "Your verification code is: %s. It expires in %d minutes.",
		NumberNormalized: true,
	}
}

// SMSProvider manages SMS-based verification codes
type SMSProvider struct {
	config      SMSCodeConfig
	smsProvider SMSProviderInterface
	logger      logging.Logger
}

// NewSMSProvider creates a new SMS provider
func NewSMSProvider(config SMSCodeConfig, smsProvider SMSProviderInterface, logger logging.Logger) *SMSProvider {
	return &SMSProvider{
		config:      config,
		smsProvider: smsProvider,
		logger:      logger,
	}
}

// GenerateCode generates a new SMS verification code
func (p *SMSProvider) GenerateCode() string {
	rand.Seed(time.Now().UnixNano())

	// Generate a random numeric code of the specified length
	code := ""
	for i := 0; i < p.config.CodeLength; i++ {
		code += strconv.Itoa(rand.Intn(10))
	}
	return code
}

// SendVerificationCode sends a verification code to a phone number
func (p *SMSProvider) SendVerificationCode(ctx context.Context, phoneNumber string) (string, time.Time, error) {
	// Generate code
	code := p.GenerateCode()
	expiresAt := time.Now().Add(p.config.CodeExpiry)

	// Format message
	expiryMinutes := int(p.config.CodeExpiry.Minutes())
	message := fmt.Sprintf(p.config.MessageTemplate, code, expiryMinutes)

	// Send SMS
	err := p.smsProvider.SendSMS(phoneNumber, message)
	if err != nil {
		return "", time.Time{}, errors.Wrap(errors.CodeSMSDeliveryFail, err, "failed to send verification SMS")
	}

	return code, expiresAt, nil
}

// VerifyCode verifies a submitted code against the expected code
func (p *SMSProvider) VerifyCode(submittedCode, expectedCode string, expiresAt time.Time) (bool, error) {
	// Check if the code has expired
	if time.Now().After(expiresAt) {
		return false, errors.New(errors.CodeTokenExpired, "verification code has expired")
	}

	// Compare the codes
	return submittedCode == expectedCode, nil
}

// TwilioSMSProvider is an implementation of SMSProviderInterface that uses Twilio
type TwilioSMSProvider struct {
	config *config.SMSConfig
	logger logging.Logger
}

// NewTwilioSMSProvider creates a new Twilio SMS provider
func NewTwilioSMSProvider(config *config.SMSConfig, logger logging.Logger) *TwilioSMSProvider {
	return &TwilioSMSProvider{
		config: config,
		logger: logger,
	}
}

// SendSMS sends an SMS using Twilio
func (p *TwilioSMSProvider) SendSMS(phoneNumber, message string) error {
	// In a real implementation, this would use the Twilio API
	p.logger.Info("Sending SMS via Twilio",
		logging.String("to", phoneNumber),
		logging.String("message", message),
	)

	// Simulate successful sending
	return nil
}

// AWSSNSProvider is an implementation of SMSProviderInterface that uses SNS SNS
type AWSSNSProvider struct {
	config *config.SMSConfig
	logger logging.Logger
}

// NewAWSSNSProvider creates a new SNS SNS provider
func NewAWSSNSProvider(config *config.SMSConfig, logger logging.Logger) *AWSSNSProvider {
	return &AWSSNSProvider{
		config: config,
		logger: logger,
	}
}

// SendSMS sends an SMS using SNS SNS
func (p *AWSSNSProvider) SendSMS(phoneNumber, message string) error {
	// In a real implementation, this would use the SNS SNS API
	p.logger.Info("Sending SMS via SNS SNS",
		logging.String("to", phoneNumber),
		logging.String("message", message),
	)

	// Simulate successful sending
	return nil
}

// NullSMSProvider is an implementation of SMSProviderInterface that logs messages but doesn't send them
type NullSMSProvider struct {
	logger logging.Logger
}

// NewNullSMSProvider creates a new null SMS provider
func NewNullSMSProvider(logger logging.Logger) *NullSMSProvider {
	return &NullSMSProvider{
		logger: logger,
	}
}

// SendSMS logs the SMS but doesn't actually send it
func (p *NullSMSProvider) SendSMS(phoneNumber, message string) error {
	p.logger.Info("Would send SMS (null provider)",
		logging.String("to", phoneNumber),
		logging.String("message", message),
	)
	return nil
}

// GetSMSProvider returns the appropriate SMS provider based on configuration
func GetSMSProvider(cfg *config.Config, logger logging.Logger) SMSProviderInterface {
	switch cfg.SMS.Provider {
	case "twilio":
		return NewTwilioSMSProvider(&cfg.SMS, logger)
	case "aws_sns":
		return NewAWSSNSProvider(&cfg.SMS, logger)
	default:
		logger.Warn("No SMS provider configured, using null provider")
		return NewNullSMSProvider(logger)
	}
}
