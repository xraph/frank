package user

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/verification"
	"github.com/juicycleff/frank/pkg/email"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// VerificationManager handles verification-related operations
type VerificationManager interface {
	// CreateVerification creates a new verification token
	CreateVerification(ctx context.Context, input CreateVerificationInput) (*ent.Verification, error)

	// VerifyToken verifies a verification token
	VerifyToken(ctx context.Context, token string) (*ent.Verification, error)

	// VerifyEmailOTP verifies an OTP for a given email and returns the associated verification entity or an error.
	VerifyEmailOTP(ctx context.Context, email, otp string) (*ent.Verification, error)

	// GetVerification retrieves a verification by ID
	GetVerification(ctx context.Context, id xid.ID) (*ent.Verification, error)

	// MarkAsUsed marks a verification as used
	MarkAsUsed(ctx context.Context, id xid.ID) (*ent.Verification, error)

	// DeleteExpired deletes all expired verifications
	DeleteExpired(ctx context.Context) (int, error)

	// GenerateToken generates a random token
	GenerateToken(length int) (string, error)
}

type verificationManager struct {
	client       *ent.Client
	emailService email.Service
	logger       logging.Logger
}

// NewVerificationManager creates a new verification manager
func NewVerificationManager(client *ent.Client, emailService email.Service,
	logger logging.Logger) VerificationManager {
	return &verificationManager{
		client:       client,
		emailService: emailService,
		logger:       logger,
	}
}

// CreateVerification creates a new verification token
func (v *verificationManager) CreateVerification(ctx context.Context, input CreateVerificationInput) (*ent.Verification, error) {
	// Generate token

	// Set default method if not provided
	if input.Method == "" {
		input.Method = VerificationMethodLink // Default to link
	}

	var token string
	var err error

	// Generate token based on verification method
	switch input.Method {
	case VerificationMethodLink:
		// Generate a secure random token for link verification
		token, err = v.GenerateToken(32)
		if err != nil {
			return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate verification token")
		}
	case VerificationMethodOTP:
		// Generate a 6-digit OTP code
		token, err = v.GenerateOTP(6)
		if err != nil {
			return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate OTP code")
		}
	default:
		return nil, errors.New(errors.CodeInvalidInput, "invalid verification method")
	}

	// Create verification
	create := v.client.Verification.
		Create().
		SetUserID(input.UserID).
		SetType(input.Type).
		SetToken(token).
		SetExpiresAt(input.ExpiresAt).
		SetUsed(false).
		SetAttestation(map[string]interface{}{
			"method": string(input.Method),
		})

	// Add optional fields
	if input.Email != "" {
		create = create.SetEmail(input.Email)
	}

	if input.PhoneNumber != "" {
		create = create.SetPhoneNumber(input.PhoneNumber)
	}

	if input.RedirectURL != "" {
		create = create.SetRedirectURL(input.RedirectURL)
	}

	if input.IPAddress != "" {
		create = create.SetIPAddress(input.IPAddress)
	}

	if input.UserAgent != "" {
		create = create.SetUserAgent(input.UserAgent)
	}

	// Save verification
	ver, err := create.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create verification")
	}

	// Handle sending the verification based on method
	if input.Method == VerificationMethodOTP && input.Type == "email" && input.Email != "" {
		// Send OTP via email
		err = v.sendOTPEmail(ctx, input.Email, token, input.ExpiresAt)
		if err != nil {
			v.logger.Error("Failed to send OTP email",
				logging.String("user_id", input.UserID.String()),
				logging.Error(err),
			)
			// Continue despite error
		}
	} else if input.Method == VerificationMethodLink && input.Type == "email" && input.Email != "" {
		// Send verification link via email
		err = v.sendVerificationEmail(ctx, input.Email, token, input.RedirectURL, input.ExpiresAt)
		if err != nil {
			v.logger.Error("Failed to send verification email",
				logging.String("user_id", input.UserID.String()),
				logging.Error(err),
			)
			// Continue despite error
		}
	} else if input.Type == "password_reset" && input.Email != "" {
		// Send verification link via email
		err = v.sendForgotPasswordEmail(ctx, input.Email, token, input.RedirectURL, input.ExpiresAt)
		if err != nil {
			v.logger.Error("Failed to send forgot password email",
				logging.String("user_id", input.UserID.String()),
				logging.Error(err),
			)
			// Continue despite error
		}
	}

	return ver, nil
}

// sendOTPEmail sends an email with OTP code
func (v *verificationManager) sendOTPEmail(ctx context.Context, emailAddr, otp string, expiresAt time.Time) error {
	// Example using the email service:
	data := map[string]interface{}{
		"OTP":       otp,
		"ExpiresAt": expiresAt.Format(time.RFC1123),
	}

	// The actual call would depend on your email service
	return v.emailService.SendTemplate(
		ctx, email.SendTemplateInput{
			To:           []string{emailAddr},
			TemplateType: "email_verification_otp",
			TemplateData: data,
		})
}

// sendVerificationEmail sends an email with verification link
func (v *verificationManager) sendVerificationEmail(ctx context.Context, emailAddr, token, redirectURL string, expiresAt time.Time) error {
	// Construct the verification link
	verificationLink := redirectURL
	if !strings.Contains(redirectURL, "?") {
		verificationLink += "?token=" + token
	} else {
		verificationLink += "&token=" + token
	}

	data := map[string]interface{}{
		"VerificationLink": verificationLink,
		"ExpiresAt":        expiresAt.Format(time.RFC1123),
	}

	return v.emailService.SendTemplate(
		ctx, email.SendTemplateInput{
			To:           []string{emailAddr},
			TemplateType: "email_verification_link",
			TemplateData: data,
		})
}

// sendVerificationEmail sends an email with verification link
func (v *verificationManager) sendForgotPasswordEmail(ctx context.Context, emailAddr, token, redirectURL string, expiresAt time.Time) error {
	// Construct the verification link
	resetLink := redirectURL
	if !strings.Contains(redirectURL, "?") {
		resetLink += "?token=" + token
	} else {
		resetLink += "&token=" + token
	}

	data := map[string]interface{}{
		"ResetURL": resetLink,
	}

	return v.emailService.SendTemplate(
		ctx, email.SendTemplateInput{
			To:           []string{emailAddr},
			TemplateType: "password_reset",
			TemplateData: data,
		})
}

// VerifyToken verifies a verification token
func (v *verificationManager) VerifyToken(ctx context.Context, token string) (*ent.Verification, error) {
	// Find verification by token
	verif, err := v.client.Verification.
		Query().
		Where(verification.Token(token)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeInvalidToken, "invalid or expired verification token")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query verification token")
	}

	// Check if token is expired
	if verif.ExpiresAt.Before(time.Now()) {
		return nil, errors.New(errors.CodeTokenExpired, "verification token has expired")
	}

	// Check if token has already been used
	if verif.Used {
		return nil, errors.New(errors.CodeInvalidToken, "verification token has already been used")
	}

	// Mark verification as used
	verif, err = v.client.Verification.
		UpdateOne(verif).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to mark verification as used")
	}

	return verif, nil
}

// VerifyEmailOTP verifies an email with OTP
func (v *verificationManager) VerifyEmailOTP(ctx context.Context, email, otp string) (*ent.Verification, error) {
	// Find the verification by email and token (OTP)
	verif, err := v.client.Verification.
		Query().
		Where(
			verification.Email(email),
			verification.Token(otp),
		).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeInvalidToken, "invalid or expired OTP")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to verify OTP")
	}

	// Check if token is expired
	if verif.ExpiresAt.Before(time.Now()) {
		return nil, errors.New(errors.CodeTokenExpired, "verification token has expired")
	}

	// Check if token has already been used
	if verif.Used {
		return nil, errors.New(errors.CodeInvalidToken, "verification token has already been used")
	}

	// Mark verification as used
	verif, err = v.client.Verification.
		UpdateOne(verif).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to mark verification as used")
	}

	return verif, nil
}

// GetVerification retrieves a verification by ID
func (v *verificationManager) GetVerification(ctx context.Context, id xid.ID) (*ent.Verification, error) {
	verif, err := v.client.Verification.
		Query().
		Where(verification.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "verification not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get verification")
	}

	return verif, nil
}

// MarkAsUsed marks a verification as used
func (v *verificationManager) MarkAsUsed(ctx context.Context, id xid.ID) (*ent.Verification, error) {
	// Check if verification exists
	ver, err := v.client.Verification.
		Query().
		Where(verification.ID(id)).
		First(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check verification existence")
	}

	if ver == nil {
		return nil, errors.New(errors.CodeNotFound, "verification not found")
	}

	// Mark as used
	verif, err := v.client.Verification.
		UpdateOneID(id).
		SetUsed(true).
		SetUsedAt(time.Now()).
		SetAttempts(ver.Attempts + 1).
		Save(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to mark verification as used")
	}

	return verif, nil
}

// DeleteExpired deletes all expired verifications
func (v *verificationManager) DeleteExpired(ctx context.Context) (int, error) {
	// Delete expired verifications
	deleted, err := v.client.Verification.
		Delete().
		Where(verification.ExpiresAtLT(time.Now())).
		Exec(ctx)

	if err != nil {
		return 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to delete expired verifications")
	}

	return deleted, nil
}

// GenerateOTP Helper function to generate OTP
func (v *verificationManager) GenerateOTP(digits int) (string, error) {
	// Generate a random numeric OTP
	m := int64(math.Pow10(digits))
	n, err := rand.Int(rand.Reader, big.NewInt(m))
	if err != nil {
		return "", err
	}

	// Format the OTP to ensure it has the correct number of digits
	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, n), nil
}

// GenerateToken generates a random token
func (v *verificationManager) GenerateToken(length int) (string, error) {
	if length <= 0 {
		length = 32
	}

	// Generate random bytes
	bytes := make([]byte, length/2) // 2 hex characters per byte
	_, err := rand.Read(bytes)
	if err != nil {
		return "", errors.Wrap(errors.CodeCryptoError, err, "failed to generate random token")
	}

	// Convert to hex string
	return hex.EncodeToString(bytes), nil
}
