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

// EmailProviderInterface defines the methods required for an email provider
type EmailProviderInterface interface {
	SendEmail(to string, subject string, body string) error
	SendTemplatedEmail(to string, templateName string, data map[string]interface{}) error
}

// EmailCodeConfig contains configuration for email-based MFA
type EmailCodeConfig struct {
	CodeLength      int
	CodeExpiry      time.Duration
	MaxAttempts     int
	ResendCooldown  time.Duration
	Subject         string
	MessageTemplate string
	TemplateID      string
}

// DefaultEmailCodeConfig returns the default email code configuration
func DefaultEmailCodeConfig() EmailCodeConfig {
	return EmailCodeConfig{
		CodeLength:      6,
		CodeExpiry:      time.Minute * 10,
		MaxAttempts:     3,
		ResendCooldown:  time.Minute * 1,
		Subject:         "Your verification code",
		MessageTemplate: "Your verification code is: %s. It expires in %d minutes.",
		TemplateID:      "mfa_code",
	}
}

// EmailProvider manages email-based verification codes
type EmailProvider struct {
	config        EmailCodeConfig
	emailProvider EmailProviderInterface
	logger        logging.Logger
}

// NewEmailProvider creates a new email provider
func NewEmailProvider(config EmailCodeConfig, emailProvider EmailProviderInterface, logger logging.Logger) *EmailProvider {
	return &EmailProvider{
		config:        config,
		emailProvider: emailProvider,
		logger:        logger,
	}
}

// GenerateCode generates a new email verification code
func (p *EmailProvider) GenerateCode() string {
	rand.Seed(time.Now().UnixNano())

	// Generate a random numeric code of the specified length
	code := ""
	for i := 0; i < p.config.CodeLength; i++ {
		code += strconv.Itoa(rand.Intn(10))
	}
	return code
}

// SendVerificationCode sends a verification code to an email address
func (p *EmailProvider) SendVerificationCode(ctx context.Context, email string) (string, time.Time, error) {
	// Generate code
	code := p.GenerateCode()
	expiresAt := time.Now().Add(p.config.CodeExpiry)

	// Format message
	expiryMinutes := int(p.config.CodeExpiry.Minutes())

	// Try to send templated email first
	err := p.sendTemplatedVerificationCode(email, code, expiryMinutes)
	if err != nil {
		// Fall back to plain text
		message := fmt.Sprintf(p.config.MessageTemplate, code, expiryMinutes)
		err = p.emailProvider.SendEmail(email, p.config.Subject, message)
		if err != nil {
			return "", time.Time{}, errors.Wrap(errors.CodeEmailDeliveryFail, err, "failed to send verification email")
		}
	}

	return code, expiresAt, nil
}

// sendTemplatedVerificationCode sends a verification code using a template
func (p *EmailProvider) sendTemplatedVerificationCode(email, code string, expiryMinutes int) error {
	data := map[string]interface{}{
		"code":           code,
		"expiryMinutes":  expiryMinutes,
		"expiryDuration": fmt.Sprintf("%d minutes", expiryMinutes),
	}

	return p.emailProvider.SendTemplatedEmail(email, p.config.TemplateID, data)
}

// VerifyCode verifies a submitted code against the expected code
func (p *EmailProvider) VerifyCode(submittedCode, expectedCode string, expiresAt time.Time) (bool, error) {
	// Check if the code has expired
	if time.Now().After(expiresAt) {
		return false, errors.New(errors.CodeTokenExpired, "verification code has expired")
	}

	// Compare the codes
	return submittedCode == expectedCode, nil
}

// NullEmailProvider is an implementation of EmailProviderInterface that logs messages but doesn't send them
type NullEmailProvider struct {
	logger logging.Logger
}

// NewNullEmailProvider creates a new null email provider
func NewNullEmailProvider(logger logging.Logger) *NullEmailProvider {
	return &NullEmailProvider{
		logger: logger,
	}
}

// SendEmail logs the email but doesn't actually send it
func (p *NullEmailProvider) SendEmail(to string, subject string, body string) error {
	p.logger.Info("Would send email (null provider)",
		logging.String("to", to),
		logging.String("subject", subject),
		logging.String("body", body),
	)
	return nil
}

// SendTemplatedEmail logs the templated email but doesn't actually send it
func (p *NullEmailProvider) SendTemplatedEmail(to string, templateName string, data map[string]interface{}) error {
	p.logger.Info("Would send templated email (null provider)",
		logging.String("to", to),
		logging.String("template", templateName),
		logging.Any("data", data),
	)
	return nil
}

// GetEmailProvider returns the appropriate email provider based on configuration
func GetEmailProvider(cfg *config.Config, logger logging.Logger) EmailProviderInterface {
	// In a real implementation, this would return different implementations based on the config
	// For now, we just return the null provider
	return NewNullEmailProvider(logger)
}

// EmailVerificationResult represents the result of an email verification attempt
type EmailVerificationResult struct {
	Success           bool
	RemainingAttempts int
	IsExpired         bool
	IsRateLimited     bool
	WaitDuration      time.Duration
}

// EmailCodeManager manages the lifecycle of email verification codes
type EmailCodeManager struct {
	provider *EmailProvider
	config   EmailCodeConfig
	logger   logging.Logger
}

// NewEmailCodeManager creates a new email code manager
func NewEmailCodeManager(provider *EmailProvider, config EmailCodeConfig, logger logging.Logger) *EmailCodeManager {
	return &EmailCodeManager{
		provider: provider,
		config:   config,
		logger:   logger,
	}
}

// SendCode sends a verification code to an email address
func (m *EmailCodeManager) SendCode(ctx context.Context, email string) (string, time.Time, error) {
	return m.provider.SendVerificationCode(ctx, email)
}

// VerifyCode verifies a submitted code
func (m *EmailCodeManager) VerifyCode(ctx context.Context, email, submittedCode, expectedCode string, expiresAt time.Time,
	attempts int) EmailVerificationResult {

	result := EmailVerificationResult{
		Success:           false,
		RemainingAttempts: m.config.MaxAttempts - attempts - 1,
		IsExpired:         false,
		IsRateLimited:     false,
	}

	// Check for rate limiting
	if attempts >= m.config.MaxAttempts {
		result.IsRateLimited = true
		result.RemainingAttempts = 0
		return result
	}

	// Check if expired
	if time.Now().After(expiresAt) {
		result.IsExpired = true
		return result
	}

	// Verify the code
	if submittedCode == expectedCode {
		result.Success = true
	}

	return result
}
