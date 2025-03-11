package passwordless

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/verification"
	"github.com/juicycleff/frank/pkg/crypto"
	appErrors "github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// MagicLinkProvider handles magic link generation and verification
type MagicLinkProvider struct {
	config *config.Config
	client *ent.Client
	logger logging.Logger
}

// NewMagicLinkProvider creates a new magic link provider
func NewMagicLinkProvider(
	cfg *config.Config,
	client *ent.Client,
	logger logging.Logger,
) *MagicLinkProvider {
	return &MagicLinkProvider{
		config: cfg,
		client: client,
		logger: logger,
	}
}

// GenerateMagicLink generates a secure magic link for authentication
func (p *MagicLinkProvider) GenerateMagicLink(
	ctx context.Context,
	userID string,
	email string,
	redirectURL string,
	expiresIn time.Duration,
) (string, error) {
	// Generate a secure token
	token, err := utils.GenerateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Set expiry time (default to config if not specified)
	if expiresIn == 0 {
		expiresIn = p.config.Auth.MagicLinkDuration
	}
	expiresAt := time.Now().Add(expiresIn)
	fmt.Println(expiresAt)

	// Build the magic link
	baseURL := p.config.Server.BaseURL
	magicLink := fmt.Sprintf("%s/auth/verify?token=%s&type=magic_link", baseURL, token)

	// For security, add signature to verify the link hasn't been tampered with
	signature := crypto.HMAC(token, []byte(p.config.Auth.TokenSecretKey))
	magicLink = fmt.Sprintf("%s&sig=%s", magicLink, signature)

	return magicLink, nil
}

// VerifyMagicLink verifies a magic link token and signature
func (p *MagicLinkProvider) VerifyMagicLink(
	ctx context.Context,
	token string,
	signature string,
) (bool, error) {
	// Verify the signature
	isValid := crypto.VerifyHMAC(token, signature, []byte(p.config.Auth.TokenSecretKey))
	if !isValid {
		return false, appErrors.New(appErrors.CodeInvalidToken, "invalid magic link signature")
	}

	return true, nil
}

// GetMagicLinkVerification gets verification data for a magic link token
func (p *MagicLinkProvider) GetMagicLinkVerification(
	ctx context.Context,
	token string,
) (*ent.Verification, error) {
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
			return nil, appErrors.New(appErrors.CodeInvalidToken, "invalid or expired token")
		}
		return nil, fmt.Errorf("failed to query verification: %w", err)
	}

	// Check if token is expired
	if time.Now().After(verificationRecord.ExpiresAt) {
		return nil, appErrors.New(appErrors.CodeTokenExpired, "token has expired")
	}

	return verificationRecord, nil
}

// MarkMagicLinkAsUsed marks a magic link token as used
func (p *MagicLinkProvider) MarkMagicLinkAsUsed(
	ctx context.Context,
	verificationID string,
) error {
	// Mark token as used
	_, err := p.client.Verification.UpdateOneID(verificationID).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed to mark verification as used: %w", err)
	}

	return nil
}

// InvalidateMagicLinks invalidates all existing magic links for a user
func (p *MagicLinkProvider) InvalidateMagicLinks(
	ctx context.Context,
	userID string,
) error {
	// Mark all magic links for this user as used
	_, err := p.client.Verification.Update().
		Where(
			verification.UserID(userID),
			verification.Type("magic_link"),
			verification.Used(false),
		).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed to invalidate magic links: %w", err)
	}

	return nil
}

// IsValidMagicLinkToken checks if a magic link token is valid
func (p *MagicLinkProvider) IsValidMagicLinkToken(
	ctx context.Context,
	token string,
) (bool, error) {
	// Find the verification record
	count, err := p.client.Verification.Query().
		Where(
			verification.Token(token),
			verification.Type("magic_link"),
			verification.Used(false),
			verification.ExpiresAtGT(time.Now()),
		).
		Count(ctx)

	if err != nil {
		return false, fmt.Errorf("failed to query verification: %w", err)
	}

	return count > 0, nil
}
