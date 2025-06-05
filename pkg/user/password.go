package user

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

// PasswordManager handles password-related operations
type PasswordManager interface {
	// HashPassword hashes a plaintext password
	HashPassword(password string) (string, error)

	// VerifyPassword verifies a password against a hash
	VerifyPassword(hashedPassword, password string) error

	// ValidatePassword validates a password against policy
	ValidatePassword(password string) error

	// GeneratePassword generates a secure random password
	GeneratePassword() (string, error)

	// CreateResetToken creates a password reset token
	CreateResetToken(ctx context.Context, userID xid.ID, expiresIn time.Duration) (*ent.Verification, error)

	// ValidateResetToken validates a password reset token
	ValidateResetToken(ctx context.Context, token string) (*ent.Verification, error)

	// ResetPassword resets a password using a token
	ResetPassword(ctx context.Context, token, newPassword string) error
}

type passwordManager struct {
	config        *config.Config
	client        *ent.Client
	verifyManager VerificationManager
}

// NewPasswordManager creates a new password manager
func NewPasswordManager(config *config.Config, client *ent.Client, verifyManager VerificationManager) PasswordManager {
	return &passwordManager{
		config:        config,
		client:        client,
		verifyManager: verifyManager,
	}
}

// HashPassword hashes a plaintext password
func (p *passwordManager) HashPassword(password string) (string, error) {
	return crypto.HashPassword(password)
}

// VerifyPassword verifies a password against a hash
func (p *passwordManager) VerifyPassword(hashedPassword, password string) error {
	return crypto.VerifyPassword(hashedPassword, password)
}

// ValidatePassword validates a password against policy
func (p *passwordManager) ValidatePassword(password string) error {
	policy := p.config.Auth.PasswordPolicy

	// Check minimum length
	if len(password) < policy.MinLength {
		return errors.New(errors.CodeInvalidPassword, fmt.Sprintf("password must be at least %d characters", policy.MinLength))
	}

	// Check for uppercase
	if policy.RequireUppercase && !containsUppercase(password) {
		return errors.New(errors.CodeInvalidPassword, "password must contain at least one uppercase letter")
	}

	// Check for lowercase
	if policy.RequireLowercase && !containsLowercase(password) {
		return errors.New(errors.CodeInvalidPassword, "password must contain at least one lowercase letter")
	}

	// Check for digits
	if policy.RequireDigit && !containsDigit(password) {
		return errors.New(errors.CodeInvalidPassword, "password must contain at least one digit")
	}

	// Check for special characters
	if policy.RequireSpecial && !containsSpecial(password) {
		return errors.New(errors.CodeInvalidPassword, "password must contain at least one special character")
	}

	return nil
}

// GeneratePassword generates a secure random password
func (p *passwordManager) GeneratePassword() (string, error) {
	policy := p.config.Auth.PasswordPolicy

	// Generate password with appropriate constraints
	password := crypto.GeneratePassword(
		policy.MinLength,
		policy.RequireLowercase,
		policy.RequireUppercase,
		policy.RequireDigit,
		policy.RequireSpecial,
	)
	// if err != nil {
	// 	return "", errors.Wrap(errors.CodeCryptoError, err, "failed to generate password")
	// }

	return password, nil
}

// CreateResetToken creates a password reset token
func (p *passwordManager) CreateResetToken(ctx context.Context, userID xid.ID, expiresIn time.Duration) (*ent.Verification, error) {
	// Use verification manager to create token
	input := CreateVerificationInput{
		UserID:    userID,
		Type:      "password_reset",
		ExpiresAt: time.Now().Add(expiresIn),
	}

	return p.verifyManager.CreateVerification(ctx, input)
}

// ValidateResetToken validates a password reset token
func (p *passwordManager) ValidateResetToken(ctx context.Context, token string) (*ent.Verification, error) {
	verification, err := p.verifyManager.VerifyToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Check verification type
	if verification.Type != "password_reset" {
		return nil, errors.New(errors.CodeInvalidToken, "invalid reset token type")
	}

	return verification, nil
}

// ResetPassword resets a password using a token
func (p *passwordManager) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Validate token
	verification, err := p.ValidateResetToken(ctx, token)
	if err != nil {
		return err
	}

	// Validate new password
	if err := p.ValidatePassword(newPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := p.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Start transaction
	tx, err := p.client.Tx(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to start transaction")
	}

	// Mark verification as used
	_, err = tx.Verification.
		UpdateOneID(verification.ID).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Save(ctx)

	if err != nil {
		_ = tx.Rollback()
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to mark token as used")
	}

	// Update user password
	now := time.Now()
	err = tx.User.
		UpdateOneID(verification.UserID).
		SetPasswordHash(hashedPassword).
		SetLastPasswordChange(now).
		Exec(ctx)

	if err != nil {
		_ = tx.Rollback()
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to update password")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to commit transaction")
	}

	return nil
}

// Helper functions for password validation
func containsUppercase(s string) bool {
	for _, r := range s {
		if 'A' <= r && r <= 'Z' {
			return true
		}
	}
	return false
}

func containsLowercase(s string) bool {
	for _, r := range s {
		if 'a' <= r && r <= 'z' {
			return true
		}
	}
	return false
}

func containsDigit(s string) bool {
	for _, r := range s {
		if '0' <= r && r <= '9' {
			return true
		}
	}
	return false
}

func containsSpecial(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return true
		}
	}
	return false
}
