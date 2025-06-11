package mfa

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/sms"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// SMSProvider represents an SMS provider interface
type SMSProvider interface {
	SendSMS(ctx context.Context, to, message string) error
	GetProviderName() string
}

// smsService implements the SMSService interface
type smsService struct {
	provider             sms.Provider
	fromNumber           string
	verificationTemplate string
	logger               logging.Logger
}

// NewSMSService creates a new SMS service
func NewSMSService(provider sms.Provider, cfg *config.SMSConfig, logger logging.Logger) SMSService {
	return &smsService{
		provider:             provider,
		fromNumber:           cfg.FromNumber,
		verificationTemplate: "Your verification code is: %s",
		logger:               logger.Named("sms"),
	}
}

// SendVerificationCode sends a verification code via SMS
func (s *smsService) SendVerificationCode(ctx context.Context, phoneNumber string, code string) error {
	s.logger.Debug("Sending SMS verification code",
		logging.String("phoneNumber", s.maskPhoneNumber(phoneNumber)),
		logging.String("provider", s.provider.Name()))

	// Validate phone number format
	if !s.isValidPhoneNumber(phoneNumber) {
		return errors.New(errors.CodeBadRequest, "invalid phone number format")
	}

	// Format the message
	message := fmt.Sprintf(s.verificationTemplate, code)

	// Send SMS
	err := s.provider.Send(ctx, sms.SMS{
		To:      phoneNumber,
		Message: message,
	})
	if err != nil {
		s.logger.Error("Failed to send SMS",
			logging.Error(err),
			logging.String("phoneNumber", s.maskPhoneNumber(phoneNumber)))
		return errors.Wrap(err, errors.CodeInternalServer, "failed to send SMS")
	}

	s.logger.Info("SMS verification code sent successfully",
		logging.String("phoneNumber", s.maskPhoneNumber(phoneNumber)))

	return nil
}

// GenerateCode generates a random verification code
func (s *smsService) GenerateCode(ctx context.Context, length int) (string, error) {
	if length <= 0 || length > 10 {
		return "", errors.New(errors.CodeBadRequest, "invalid code length")
	}

	// Generate random numeric code
	code := ""
	for i := 0; i < length; i++ {
		digit, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", errors.Wrap(err, errors.CodeInternalServer, "failed to generate random digit")
		}
		code += digit.String()
	}

	return code, nil
}

// Helper methods

// isValidPhoneNumber validates phone number format (basic validation)
func (s *smsService) isValidPhoneNumber(phoneNumber string) bool {
	// Remove all non-digit characters except +
	cleaned := regexp.MustCompile(`[^\d+]`).ReplaceAllString(phoneNumber, "")

	// Check if it starts with + and has 10-15 digits
	if strings.HasPrefix(cleaned, "+") {
		digits := cleaned[1:]
		return len(digits) >= 10 && len(digits) <= 15 && regexp.MustCompile(`^\d+$`).MatchString(digits)
	}

	// Check for US format without country code (10 digits)
	return len(cleaned) == 10 && regexp.MustCompile(`^\d+$`).MatchString(cleaned)
}

// maskPhoneNumber masks phone number for logging
func (s *smsService) maskPhoneNumber(phoneNumber string) string {
	if len(phoneNumber) <= 4 {
		return "****"
	}

	return phoneNumber[:2] + strings.Repeat("*", len(phoneNumber)-4) + phoneNumber[len(phoneNumber)-2:]
}
