package passwordless

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/ent/verification"
	"github.com/juicycleff/frank/internal/sms"
	"github.com/juicycleff/frank/pkg/crypto"
	appErrors "github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// SMSProvider handles passwordless authentication via SMS
type SMSProvider struct {
	config     *config.Config
	client     *ent.Client
	logger     logging.Logger
	smsService sms.Service
}

// NewSMSProvider creates a new SMS provider
func NewSMSProvider(
	cfg *config.Config,
	client *ent.Client,
	logger logging.Logger,
	smsService sms.Service,
) *SMSProvider {
	return &SMSProvider{
		config:     cfg,
		client:     client,
		logger:     logger,
		smsService: smsService,
	}
}

// SendVerificationSMS sends a verification SMS with a one-time code
func (p *SMSProvider) SendVerificationSMS(
	ctx context.Context,
	phoneNumber string,
	redirectURL string,
	ipAddress string,
	userAgent string,
) (string, error) {
	// Check if phone number is valid
	if !utils.IsValidPhoneNumber(phoneNumber) {
		return "", appErrors.New(appErrors.CodeInvalidPhone, "invalid phone number")
	}

	// Look up the user
	user, err := p.client.User.Query().
		Where(user.PhoneNumber(phoneNumber)).
		Only(ctx)

	// Handle case where user doesn't exist
	if ent.IsNotFound(err) {
		// If auto-registration is enabled, create a new user
		if p.config.Auth.AutoRegisterUsers {
			user, err = p.client.User.Create().
				SetPhoneNumber(phoneNumber).
				SetPhoneVerified(false).
				SetActive(true).
				Save(ctx)

			if err != nil {
				return "", fmt.Errorf("failed to create user: %w", err)
			}
		} else {
			// Return an obscure error to prevent user enumeration
			p.logger.Info("Passwordless login attempt for non-existent user",
				logging.String("phone_number", phoneNumber),
				logging.String("ip_address", ipAddress))

			return "", appErrors.New(appErrors.CodeInvalidCredentials,
				"if an account with this phone number exists, you will receive a verification code")
		}
	} else if err != nil {
		return "", fmt.Errorf("failed to query user: %w", err)
	}

	// Check if user is active
	if !user.Active {
		p.logger.Warn("Passwordless login attempt for inactive user",
			logging.String("user_id", user.ID),
			logging.String("phone_number", phoneNumber),
			logging.String("ip_address", ipAddress))

		return "", appErrors.New(appErrors.CodeInvalidCredentials,
			"if an account with this phone number exists, you will receive a verification code")
	}

	// Generate a secure OTP code
	code, err := crypto.GenerateNumericCode(6)
	if err != nil {
		return "", fmt.Errorf("failed to generate code: %w", err)
	}

	// Calculate expiration time
	expiresAt := time.Now().Add(p.config.Auth.VerificationTokenDuration)

	// Store the verification token
	_, err = p.client.Verification.Create().
		SetUserID(user.ID).
		SetType("sms_code").
		SetToken(code).
		SetPhoneNumber(phoneNumber).
		SetRedirectURL(redirectURL).
		SetExpiresAt(expiresAt).
		SetIPAddress(ipAddress).
		SetUserAgent(userAgent).
		Save(ctx)

	if err != nil {
		return "", fmt.Errorf("failed to create verification: %w", err)
	}

	// Send the SMS
	message := fmt.Sprintf("Your verification code is %s. It will expire in %d minutes.",
		code, int(p.config.Auth.VerificationTokenDuration.Minutes()))

	err = p.smsService.Send(ctx, sms.SendSMSInput{
		To: phoneNumber, Message: message,
	})
	if err != nil {
		return "", fmt.Errorf("failed to send SMS: %w", err)
	}

	p.logger.Info("Sent verification SMS",
		logging.String("user_id", user.ID),
		logging.String("phone_number", phoneNumber),
		logging.String("ip_address", ipAddress))

	return user.ID, nil
}

// VerifySMS verifies an SMS verification code
func (p *SMSProvider) VerifySMS(
	ctx context.Context,
	phoneNumber string,
	code string,
	ipAddress string,
) (string, string, error) {
	// Find the verification record
	verificationRecord, err := p.client.Verification.Query().
		Where(
			verification.PhoneNumber(phoneNumber),
			verification.Token(code),
			verification.Type("sms_code"),
			verification.Used(false),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			// Increment attempts on any matching records to prevent brute force
			_, err = p.client.Verification.Update().
				Where(
					verification.PhoneNumber(phoneNumber),
					verification.Type("sms_code"),
					verification.Used(false),
				).
				AddAttempts(1).
				Save(ctx)

			if err != nil {
				p.logger.Error("Failed to increment verification attempts",
					logging.String("phone_number", phoneNumber),
					logging.Error(err))
				// Continue despite the error
			}

			return "", "", appErrors.New(appErrors.CodeInvalidOTP, "invalid or expired verification code")
		}
		return "", "", fmt.Errorf("failed to query verification: %w", err)
	}

	// Check if token is expired
	if time.Now().After(verificationRecord.ExpiresAt) {
		return "", "", appErrors.New(appErrors.CodeTokenExpired, "verification code has expired")
	}

	// Check max attempts
	if verificationRecord.Attempts >= p.config.Security.MaxLoginAttempts {
		return "", "", appErrors.New(appErrors.CodeTooManyRequests, "too many verification attempts")
	}

	// Get the user
	user, err := p.client.User.Get(ctx, verificationRecord.UserID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get user: %w", err)
	}

	// Mark token as used
	_, err = p.client.Verification.UpdateOne(verificationRecord).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)

	if err != nil {
		p.logger.Error("Failed to mark verification as used",
			logging.String("verification_id", verificationRecord.ID),
			logging.Error(err))
		// Continue despite the error
	}

	// Set phone as verified if not already
	if !user.PhoneVerified {
		_, err = p.client.User.UpdateOne(user).
			SetPhoneVerified(true).
			Save(ctx)

		if err != nil {
			p.logger.Error("Failed to mark phone as verified",
				logging.String("user_id", user.ID),
				logging.Error(err))
			// Continue despite the error
		}
	}

	p.logger.Info("Successfully verified SMS code",
		logging.String("user_id", user.ID),
		logging.String("phone_number", user.PhoneNumber),
		logging.String("ip_address", ipAddress))

	// Return user ID and redirect URL
	return user.ID, verificationRecord.RedirectURL, nil
}

// VerifyPhoneOTP verifies a phone OTP for TOTP-based authentication
func (p *SMSProvider) VerifyPhoneOTP(
	ctx context.Context,
	phoneNumber string,
	code string,
	ipAddress string,
) (bool, error) {
	// Find the verification record
	verificationRecord, err := p.client.Verification.Query().
		Where(
			verification.PhoneNumber(phoneNumber),
			verification.Token(code),
			verification.Type("sms_code"),
			verification.Used(false),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return false, appErrors.New(appErrors.CodeInvalidOTP, "invalid verification code")
		}
		return false, fmt.Errorf("failed to query verification: %w", err)
	}

	// Check if token is expired
	if time.Now().After(verificationRecord.ExpiresAt) {
		return false, appErrors.New(appErrors.CodeTokenExpired, "verification code has expired")
	}

	// Mark token as used
	_, err = p.client.Verification.UpdateOne(verificationRecord).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)

	if err != nil {
		p.logger.Error("Failed to mark verification as used",
			logging.String("verification_id", verificationRecord.ID),
			logging.Error(err))
		// Continue despite the error
	}

	return true, nil
}
