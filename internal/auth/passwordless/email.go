package passwordless

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/email"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/ent/verification"
	appErrors "github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// EmailProvider handles passwordless authentication via email
type EmailProvider struct {
	config       *config.Config
	client       *ent.Client
	logger       logging.Logger
	emailService email.Service
}

// NewEmailProvider creates a new email provider
func NewEmailProvider(
	cfg *config.Config,
	client *ent.Client,
	logger logging.Logger,
	emailService email.Service,
) *EmailProvider {
	return &EmailProvider{
		config:       cfg,
		client:       client,
		logger:       logger,
		emailService: emailService,
	}
}

// SendVerificationEmail sends a verification email with a login link
func (p *EmailProvider) SendVerificationEmail(
	ctx context.Context,
	email string,
	redirectURL string,
	ipAddress string,
	userAgent string,
) (string, error) {
	// Check if email is valid
	if !utils.IsValidEmail(email) {
		return "", appErrors.New(appErrors.CodeInvalidEmail, "invalid email address")
	}

	// Look up the user
	user, err := p.client.User.Query().
		Where(user.Email(email)).
		Only(ctx)

	// Handle case where user doesn't exist
	if ent.IsNotFound(err) {
		// If auto-registration is enabled, create a new user
		if p.config.Auth.AutoRegisterUsers {
			user, err = p.client.User.Create().
				SetEmail(email).
				SetEmailVerified(false).
				SetActive(true).
				Save(ctx)

			if err != nil {
				return "", fmt.Errorf("failed to create user: %w", err)
			}
		} else {
			// Return an obscure error to prevent user enumeration
			p.logger.Info("Passwordless login attempt for non-existent user",
				logging.String("email", email),
				logging.String("ip_address", ipAddress))

			return "", appErrors.New(appErrors.CodeInvalidCredentials,
				"if an account with this email exists, you will receive a login link")
		}
	} else if err != nil {
		return "", fmt.Errorf("failed to query user: %w", err)
	}

	// Check if user is active
	if !user.Active {
		p.logger.Warn("Passwordless login attempt for inactive user",
			logging.String("user_id", user.ID),
			logging.String("email", email),
			logging.String("ip_address", ipAddress))

		return "", appErrors.New(appErrors.CodeInvalidCredentials,
			"if an account with this email exists, you will receive a login link")
	}

	// Generate a secure token
	token, err := utils.GenerateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Calculate expiration time
	expiresAt := time.Now().Add(p.config.Auth.MagicLinkDuration)

	// Store the verification token
	_, err = p.client.Verification.Create().
		SetUserID(user.ID).
		SetType("magic_link").
		SetToken(token).
		SetEmail(email).
		SetRedirectURL(redirectURL).
		SetExpiresAt(expiresAt).
		SetIPAddress(ipAddress).
		SetUserAgent(userAgent).
		Save(ctx)

	if err != nil {
		return "", fmt.Errorf("failed to create verification: %w", err)
	}

	// Build the magic link
	baseURL := p.config.Server.BaseURL
	magicLink := fmt.Sprintf("%s/auth/verify?token=%s&type=magic_link", baseURL, token)

	// Send the email
	err = p.emailService.SendMagicLinkEmail(ctx, email, user.FirstName, magicLink, expiresAt, ipAddress, userAgent)
	if err != nil {
		return "", fmt.Errorf("failed to send email: %w", err)
	}

	p.logger.Info("Sent magic link email",
		logging.String("user_id", user.ID),
		logging.String("email", email),
		logging.String("ip_address", ipAddress))

	return user.ID, nil
}

// VerifyEmail verifies an email verification token
func (p *EmailProvider) VerifyEmail(
	ctx context.Context,
	token string,
	ipAddress string,
) (string, string, error) {
	// Find the verification record
	verificationRecord, err := p.client.Verification.Query().
		Where(
			verification.Token(token),
			verification.Type("magic_link"),
			verification.Used(false),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return "", "", appErrors.New(appErrors.CodeInvalidToken, "invalid or expired token")
		}
		return "", "", fmt.Errorf("failed to query verification: %w", err)
	}

	// Check if token is expired
	if time.Now().After(verificationRecord.ExpiresAt) {
		return "", "", appErrors.New(appErrors.CodeTokenExpired, "token has expired")
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

	// Set email as verified if not already
	if !user.EmailVerified {
		_, err = p.client.User.UpdateOne(user).
			SetEmailVerified(true).
			Save(ctx)

		if err != nil {
			p.logger.Error("Failed to mark email as verified",
				logging.String("user_id", user.ID),
				logging.Error(err))
			// Continue despite the error
		}
	}

	p.logger.Info("Successfully verified magic link",
		logging.String("user_id", user.ID),
		logging.String("email", user.Email),
		logging.String("ip_address", ipAddress))

	// Return user ID and redirect URL
	return user.ID, verificationRecord.RedirectURL, nil
}

// GetEmailFromToken retrieves the email associated with a token
func (p *EmailProvider) GetEmailFromToken(ctx context.Context, token string) (string, error) {
	// Find the verification record
	verificationRecord, err := p.client.Verification.Query().
		Where(
			verification.Token(token),
			verification.Type("magic_link"),
			verification.Used(false),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return "", appErrors.New(appErrors.CodeInvalidToken, "invalid or expired token")
		}
		return "", fmt.Errorf("failed to query verification: %w", err)
	}

	// Check if token is expired
	if time.Now().After(verificationRecord.ExpiresAt) {
		return "", appErrors.New(appErrors.CodeTokenExpired, "token has expired")
	}

	return verificationRecord.Email, nil
}
