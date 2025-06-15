package mfa

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// TOTPService implementation
type totpService struct {
	issuer      string
	secretStore map[string]string   // In production, use persistent storage
	backupCodes map[xid.ID][]string // In production, use persistent storage
	logger      logging.Logger
}

// NewTOTPService creates a new TOTP service
func NewTOTPService(issuer string, logger logging.Logger) TOTPService {
	return &totpService{
		issuer:      issuer,
		secretStore: make(map[string]string),
		backupCodes: make(map[xid.ID][]string),
		logger:      logger.Named("totp"),
	}
}

// GenerateSecret generates a new TOTP secret for a user
func (t *totpService) GenerateSecret(ctx context.Context, userID xid.ID, issuer, accountName string) (*model.TOTPSecret, error) {
	t.logger.Debug("Generating TOTP secret",
		logging.String("userId", userID.String()),
		logging.String("accountName", accountName))

	// Generate random secret (160 bits / 20 bytes)
	secretBytes := make([]byte, 20)
	_, err := rand.Read(secretBytes)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to generate random secret")
	}

	// Encode as base32
	secret := base32.StdEncoding.EncodeToString(secretBytes)
	secret = strings.TrimRight(secret, "=") // Remove padding

	// Create TOTP URL for QR code
	params := url.Values{}
	params.Add("secret", secret)
	params.Add("issuer", issuer)
	params.Add("algorithm", "SHA1")
	params.Add("digits", "6")
	params.Add("period", "30")

	totpURL := fmt.Sprintf("otpauth://totp/%s:%s?%s",
		url.QueryEscape(issuer),
		url.QueryEscape(accountName),
		params.Encode())

	// Store secret (in production, encrypt and store securely)
	secretKey := fmt.Sprintf("totp:%s", userID.String())
	t.secretStore[secretKey] = secret

	t.logger.Info("TOTP secret generated", logging.String("userId", userID.String()))

	return &model.TOTPSecret{
		Secret:      secret,
		URL:         totpURL,
		Issuer:      issuer,
		AccountName: accountName,
		Algorithm:   "SHA1",
		Digits:      6,
		Period:      30,
	}, nil
}

// GenerateQRCode generates a QR code for the TOTP secret
func (t *totpService) GenerateQRCode(ctx context.Context, secret *model.TOTPSecret) ([]byte, error) {
	t.logger.Debug("Generating QR code for TOTP")

	// In production, use a proper QR code library like "github.com/skip2/go-qrcode"
	// For now, return a placeholder
	qrData := fmt.Sprintf("QR Code for: %s", secret.URL)
	return []byte(qrData), nil
}

// ValidateCode validates a TOTP code
func (t *totpService) ValidateCode(ctx context.Context, secret, code string) (bool, error) {
	t.logger.Debug("Validating TOTP code")

	if len(code) != 6 {
		return false, nil
	}

	// Get current time window
	now := time.Now().Unix()
	timeWindow := now / 30

	// Check current window and adjacent windows (for clock skew tolerance)
	for i := -1; i <= 1; i++ {
		window := timeWindow + int64(i)
		expectedCode := t.generateTOTPCode(secret, window)

		if expectedCode == code {
			t.logger.Debug("TOTP code validated successfully")
			return true, nil
		}
	}

	t.logger.Debug("TOTP code validation failed")
	return false, nil
}

// GetBackupCodes gets backup codes for a user
func (t *totpService) GetBackupCodes(ctx context.Context, userID xid.ID) ([]string, error) {
	codes, exists := t.backupCodes[userID]
	if !exists {
		return []string{}, nil
	}
	return codes, nil
}

// GenerateBackupCodes generates backup codes for a user
func (t *totpService) GenerateBackupCodes(ctx context.Context, userID xid.ID, count int) ([]string, error) {
	if count < 1 {
		count = 10
	}

	t.logger.Debug("Generating backup codes",
		logging.String("userId", userID.String()),
		logging.Int("count", count))

	codes := make([]string, count)

	for i := 0; i < count; i++ {
		code, err := t.generateBackupCode()
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}

	// Store backup codes (in production, hash and store securely)
	t.backupCodes[userID] = codes

	t.logger.Info("Backup codes generated",
		logging.String("userId", userID.String()),
		logging.Int("count", count))

	return codes, nil
}

// ValidateBackupCode validates a backup code
func (t *totpService) ValidateBackupCode(ctx context.Context, userID xid.ID, code string) (bool, error) {
	t.logger.Debug("Validating backup code", logging.String("userId", userID.String()))

	codes, exists := t.backupCodes[userID]
	if !exists {
		return false, nil
	}

	// Find and remove the used code
	for i, storedCode := range codes {
		if storedCode == code {
			// Remove the used code from the list
			t.backupCodes[userID] = append(codes[:i], codes[i+1:]...)

			t.logger.Info("Backup code used", logging.String("userId", userID.String()))
			return true, nil
		}
	}

	return false, nil
}

// Helper methods

// generateTOTPCode generates a TOTP code for a given time window
func (t *totpService) generateTOTPCode(secret string, timeWindow int64) string {
	// This is a simplified TOTP implementation
	// In production, use a proper TOTP library like "github.com/pquerna/otp/totp"

	// Decode secret
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}

	// Convert time window to bytes (big endian)
	timeBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		timeBytes[i] = byte(timeWindow & 0xff)
		timeWindow >>= 8
	}

	// Simple hash (in production, use HMAC-SHA1)
	hash := t.simpleHash(key, timeBytes)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0xf
	code := ((int(hash[offset]) & 0x7f) << 24) |
		((int(hash[offset+1]) & 0xff) << 16) |
		((int(hash[offset+2]) & 0xff) << 8) |
		(int(hash[offset+3]) & 0xff)

	// Generate 6-digit code
	code = code % 1000000

	return fmt.Sprintf("%06d", code)
}

// simpleHash is a simplified hash function for demonstration
// In production, use crypto/hmac with SHA1
func (t *totpService) simpleHash(key, data []byte) []byte {
	// This is NOT cryptographically secure - use HMAC-SHA1 in production
	hash := make([]byte, 20)

	for i := 0; i < 20; i++ {
		val := 0
		for j, b := range data {
			keyByte := key[j%len(key)]
			val += int(b) ^ int(keyByte) ^ i
		}
		hash[i] = byte(val % 256)
	}

	return hash
}

// generateBackupCode generates a single backup code
func (t *totpService) generateBackupCode() (string, error) {
	// Generate 8-character alphanumeric code
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const codeLength = 8

	code := make([]byte, codeLength)
	randomBytes := make([]byte, codeLength)

	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to generate random bytes")
	}

	for i, b := range randomBytes {
		code[i] = charset[int(b)%len(charset)]
	}

	return string(code), nil
}
