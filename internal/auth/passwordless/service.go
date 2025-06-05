package passwordless

import (
	"context"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/internal/sms"
	"github.com/juicycleff/frank/pkg/email"
	appErrors "github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// AuthType represents the type of passwordless authentication
type AuthType string

const (
	// AuthTypeEmail represents email-based passwordless authentication
	AuthTypeEmail AuthType = "email"

	// AuthTypeSMS represents SMS-based passwordless authentication
	AuthTypeSMS AuthType = "sms"
)

// LoginRequest contains the information needed for a passwordless login
type LoginRequest struct {
	// Email is the email address for email-based login
	Email string `json:"email,omitempty"`

	// PhoneNumber is the phone number for SMS-based login
	PhoneNumber string `json:"phone_number,omitempty"`

	// RedirectURL is the URL to redirect to after successful authentication
	RedirectURL string `json:"redirect_url,omitempty"`

	// AuthType is the type of passwordless authentication
	AuthType AuthType `json:"auth_type"`

	// OrganizationID is an optional organization ID for scoped authentication
	OrganizationID string `json:"organization_id,omitempty"`

	// IPAddress is the IP address of the login request
	IPAddress string `json:"-"`

	// UserAgent is the user agent of the login request
	UserAgent string `json:"-"`
}

// VerifyRequest contains the information needed to verify a passwordless login
type VerifyRequest struct {
	// Token is the verification token for email-based login
	Token string `json:"token,omitempty"`

	// PhoneNumber is the phone number for SMS-based login
	PhoneNumber string `json:"phone_number,omitempty"`

	// Code is the verification code for SMS-based login
	Code string `json:"code,omitempty"`

	// AuthType is the type of passwordless authentication
	AuthType AuthType `json:"auth_type"`

	// IPAddress is the IP address of the verification request
	IPAddress string `json:"-"`
}

// Service defines the interface for passwordless authentication functionality
type Service interface {
	Login(ctx context.Context, req LoginRequest) (string, error)
	VerifyLogin(ctx context.Context, req VerifyRequest) (string, string, error)
	GenerateMagicLink(ctx context.Context, userID string, email string, redirectURL string, expiresIn time.Duration) (string, error)
	InvalidateUserMagicLinks(ctx context.Context, userID string) error
	GetMagicLinkData(ctx context.Context, token string) (*ent.Verification, error)
	MarkMagicLinkAsUsed(ctx context.Context, verificationID string) error
	VerifyPhoneOTP(ctx context.Context, phoneNumber string, code string, ipAddress string) (bool, error)
	IsConfigured() bool
	GetSupportedMethods() []AuthType
	HandleDeprecatedMethods() error
}

type serviceImpl struct {
	config            *config.Config
	client            *ent.Client
	logger            logging.Logger
	emailProvider     *EmailProvider
	smsProvider       *SMSProvider
	magicLinkProvider *MagicLinkProvider
}

// NewService creates a new instance of the passwordless authentication service
func NewService(
	cfg *config.Config,
	client *ent.Client,
	logger logging.Logger,
	emailService email.Service,
	smsService sms.Service,
) (Service, error) {
	emailProvider := NewEmailProvider(cfg, client, logger, emailService)
	smsProvider := NewSMSProvider(cfg, client, logger, smsService)
	magicLinkProvider := NewMagicLinkProvider(cfg, client, logger)

	return &serviceImpl{
		config:            cfg,
		client:            client,
		logger:            logger,
		emailProvider:     emailProvider,
		smsProvider:       smsProvider,
		magicLinkProvider: magicLinkProvider,
	}, nil
}

// Login initiates a passwordless login flow
func (s *serviceImpl) Login(ctx context.Context, req LoginRequest) (string, error) {
	// Check if feature is enabled
	if !s.config.Features.EnablePasswordless {
		return "", appErrors.New(appErrors.CodeFeatureNotEnabled, "passwordless authentication is not enabled")
	}

	// Validate request
	if err := s.validateLoginRequest(req); err != nil {
		return "", err
	}

	// Process based on auth type
	switch req.AuthType {
	case AuthTypeEmail:
		return s.emailProvider.SendVerificationEmail(
			ctx,
			req.Email,
			req.RedirectURL,
			req.IPAddress,
			req.UserAgent,
		)
	case AuthTypeSMS:
		return s.smsProvider.SendVerificationSMS(
			ctx,
			req.PhoneNumber,
			req.RedirectURL,
			req.IPAddress,
			req.UserAgent,
		)
	default:
		return "", appErrors.New(appErrors.CodeInvalidInput, "invalid authentication type")
	}
}

// VerifyLogin verifies a passwordless login attempt
func (s *serviceImpl) VerifyLogin(ctx context.Context, req VerifyRequest) (string, string, error) {
	// Check if feature is enabled
	if !s.config.Features.EnablePasswordless {
		return "", "", appErrors.New(appErrors.CodeFeatureNotEnabled, "passwordless authentication is not enabled")
	}

	// Validate request
	if err := s.validateVerifyRequest(req); err != nil {
		return "", "", err
	}

	// Process based on auth type
	switch req.AuthType {
	case AuthTypeEmail:
		return s.emailProvider.VerifyEmail(
			ctx,
			req.Token,
			req.IPAddress,
		)
	case AuthTypeSMS:
		return s.smsProvider.VerifySMS(
			ctx,
			req.PhoneNumber,
			req.Code,
			req.IPAddress,
		)
	default:
		return "", "", appErrors.New(appErrors.CodeInvalidInput, "invalid authentication type")
	}
}

// GenerateMagicLink generates a magic link for a user
func (s *serviceImpl) GenerateMagicLink(
	ctx context.Context,
	userID string,
	email string,
	redirectURL string,
	expiresIn time.Duration,
) (string, error) {
	// Check if feature is enabled
	if !s.config.Features.EnablePasswordless {
		return "", appErrors.New(appErrors.CodeFeatureNotEnabled, "passwordless authentication is not enabled")
	}

	if userID == "" {
		u, err := s.client.User.Query().Where(user.Email(email)).Only(ctx)
		if err != nil {
			return "", err
		}
		userID = u.ID
	}

	// Generate magic link
	return s.magicLinkProvider.GenerateMagicLink(
		ctx,
		userID,
		email,
		redirectURL,
		expiresIn,
	)
}

// InvalidateUserMagicLinks invalidates all existing magic links for a user
func (s *serviceImpl) InvalidateUserMagicLinks(ctx context.Context, userID string) error {
	return s.magicLinkProvider.InvalidateMagicLinks(ctx, userID)
}

// GetMagicLinkData retrieves data for a magic link
func (s *serviceImpl) GetMagicLinkData(ctx context.Context, token string) (*ent.Verification, error) {
	return s.magicLinkProvider.GetMagicLinkVerification(ctx, token)
}

// MarkMagicLinkAsUsed marks a magic link as used
func (s *serviceImpl) MarkMagicLinkAsUsed(ctx context.Context, verificationID string) error {
	return s.magicLinkProvider.MarkMagicLinkAsUsed(ctx, verificationID)
}

// VerifyPhoneOTP verifies a phone OTP for MFA
func (s *serviceImpl) VerifyPhoneOTP(
	ctx context.Context,
	phoneNumber string,
	code string,
	ipAddress string,
) (bool, error) {
	return s.smsProvider.VerifyPhoneOTP(ctx, phoneNumber, code, ipAddress)
}

// validateLoginRequest validates a passwordless login request
func (s *serviceImpl) validateLoginRequest(req LoginRequest) error {
	switch req.AuthType {
	case AuthTypeEmail:
		if req.Email == "" {
			return appErrors.New(appErrors.CodeMissingRequiredField, "email is required for email authentication")
		}
	case AuthTypeSMS:
		if req.PhoneNumber == "" {
			return appErrors.New(appErrors.CodeMissingRequiredField, "phone number is required for SMS authentication")
		}
	default:
		return appErrors.New(appErrors.CodeInvalidInput, "invalid authentication type")
	}

	return nil
}

// validateVerifyRequest validates a passwordless verification request
func (s *serviceImpl) validateVerifyRequest(req VerifyRequest) error {
	switch req.AuthType {
	case AuthTypeEmail:
		if req.Token == "" {
			return appErrors.New(appErrors.CodeMissingRequiredField, "token is required for email verification")
		}
	case AuthTypeSMS:
		if req.PhoneNumber == "" {
			return appErrors.New(appErrors.CodeMissingRequiredField, "phone number is required for SMS verification")
		}
		if req.Code == "" {
			return appErrors.New(appErrors.CodeMissingRequiredField, "code is required for SMS verification")
		}
	default:
		return appErrors.New(appErrors.CodeInvalidInput, "invalid authentication type")
	}

	return nil
}

// IsConfigured returns true if the passwordless service is configured
func (s *serviceImpl) IsConfigured() bool {
	return s.config.Features.EnablePasswordless
}

// GetSupportedMethods returns the supported passwordless authentication methods
func (s *serviceImpl) GetSupportedMethods() []AuthType {
	methods := []AuthType{}

	// Check if email is configured
	if s.config.Email.Provider != "" {
		methods = append(methods, AuthTypeEmail)
	}

	// Check if SMS is configured
	if s.config.SMS.Provider != "" {
		methods = append(methods, AuthTypeSMS)
	}

	return methods
}

// HandleDeprecatedMethods provides backward compatibility with deprecated methods
func (s *serviceImpl) HandleDeprecatedMethods() error {
	// For future deprecation handling
	return nil
}
