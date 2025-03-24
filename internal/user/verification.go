package user

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/verification"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/utils"
)

// VerificationManager handles verification-related operations
type VerificationManager interface {
	// CreateVerification creates a new verification token
	CreateVerification(ctx context.Context, input CreateVerificationInput) (*ent.Verification, error)

	// VerifyToken verifies a verification token
	VerifyToken(ctx context.Context, token string) (*ent.Verification, error)

	// GetVerification retrieves a verification by ID
	GetVerification(ctx context.Context, id string) (*ent.Verification, error)

	// MarkAsUsed marks a verification as used
	MarkAsUsed(ctx context.Context, id string) (*ent.Verification, error)

	// DeleteExpired deletes all expired verifications
	DeleteExpired(ctx context.Context) (int, error)

	// GenerateToken generates a random token
	GenerateToken(length int) (string, error)
}

type verificationManager struct {
	client *ent.Client
}

// NewVerificationManager creates a new verification manager
func NewVerificationManager(client *ent.Client) VerificationManager {
	return &verificationManager{
		client: client,
	}
}

// CreateVerification creates a new verification token
func (v *verificationManager) CreateVerification(ctx context.Context, input CreateVerificationInput) (*ent.Verification, error) {
	// Generate UUID
	id := utils.NewID()

	// Generate token
	token, err := v.GenerateToken(32)
	if err != nil {
		return nil, err
	}

	// Create verification
	create := v.client.Verification.
		Create().
		SetID(id.String()).
		SetUserID(input.UserID).
		SetType(input.Type).
		SetToken(token).
		SetExpiresAt(input.ExpiresAt)

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
	verification, err := create.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create verification")
	}

	return verification, nil
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

	return verif, nil
}

// GetVerification retrieves a verification by ID
func (v *verificationManager) GetVerification(ctx context.Context, id string) (*ent.Verification, error) {
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
func (v *verificationManager) MarkAsUsed(ctx context.Context, id string) (*ent.Verification, error) {
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
