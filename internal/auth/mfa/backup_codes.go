package mfa

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// BackupCodesConfig contains configuration for backup codes
type BackupCodesConfig struct {
	CodeCount int    // Number of backup codes to generate
	CodeLen   int    // Length of each backup code in bytes (before hex encoding)
	Separator string // Separator for code formatting
}

// DefaultBackupCodesConfig returns the default backup codes configuration
func DefaultBackupCodesConfig() BackupCodesConfig {
	return BackupCodesConfig{
		CodeCount: 10,
		CodeLen:   4, // 4 bytes = 8 hex chars
		Separator: "-",
	}
}

// BackupCodesProvider manages backup codes operations
type BackupCodesProvider struct {
	config BackupCodesConfig
}

// NewBackupCodesProvider creates a new backup codes provider
func NewBackupCodesProvider(config BackupCodesConfig) *BackupCodesProvider {
	return &BackupCodesProvider{
		config: config,
	}
}

// GenerateBackupCodes generates a set of backup codes
func (p *BackupCodesProvider) GenerateBackupCodes() ([]string, []string, error) {
	var plainCodes []string
	var hashedCodes []string

	for i := 0; i < p.config.CodeCount; i++ {
		// Generate random bytes
		codeBytes := make([]byte, p.config.CodeLen)
		_, err := rand.Read(codeBytes)
		if err != nil {
			return nil, nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate backup code")
		}

		// Convert to hex string
		code := hex.EncodeToString(codeBytes)

		// Format the code with separators
		formattedCode := p.formatCode(code)
		plainCodes = append(plainCodes, formattedCode)

		// Hash the code for storage
		hashedCode, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, errors.Wrap(errors.CodeCryptoError, err, "failed to hash backup code")
		}

		hashedCodes = append(hashedCodes, string(hashedCode))
	}

	return plainCodes, hashedCodes, nil
}

// formatCode formats a backup code with separators
func (p *BackupCodesProvider) formatCode(code string) string {
	if p.config.Separator == "" {
		return code
	}

	// Insert separator every 4 characters
	var formatted strings.Builder
	for i, char := range code {
		if i > 0 && i%4 == 0 {
			formatted.WriteString(p.config.Separator)
		}
		formatted.WriteRune(char)
	}
	return formatted.String()
}

// normalizeCode removes separators and spaces from a code
func (p *BackupCodesProvider) normalizeCode(code string) string {
	code = strings.ReplaceAll(code, p.config.Separator, "")
	return strings.ToLower(strings.ReplaceAll(code, " ", ""))
}

// VerifyBackupCode verifies a backup code against a list of hashed codes
func (p *BackupCodesProvider) VerifyBackupCode(code string, hashedCodes []string) (bool, int, error) {
	// Normalize the code
	normalizedCode := p.normalizeCode(code)

	// Check against each hashed code
	for i, hashedCode := range hashedCodes {
		err := bcrypt.CompareHashAndPassword([]byte(hashedCode), []byte(normalizedCode))
		if err == nil {
			// Code matches, return the index for removal
			return true, i, nil
		}
	}

	return false, -1, nil
}

// RemoveUsedCode removes a used backup code from the list
func (p *BackupCodesProvider) RemoveUsedCode(hashedCodes []string, index int) []string {
	if index < 0 || index >= len(hashedCodes) {
		return hashedCodes
	}

	// Remove the used code
	return append(hashedCodes[:index], hashedCodes[index+1:]...)
}

// GetRemainingCount returns the number of remaining backup codes
func (p *BackupCodesProvider) GetRemainingCount(hashedCodes []string) int {
	return len(hashedCodes)
}

// BackupCodeSet represents a set of backup codes with plain and hashed versions
type BackupCodeSet struct {
	PlainCodes  []string // Plain text codes to show to the user
	HashedCodes []string // Hashed codes to store
}

// GenerateBackupCodeSet generates a complete set of backup codes
func (p *BackupCodesProvider) GenerateBackupCodeSet() (*BackupCodeSet, error) {
	plainCodes, hashedCodes, err := p.GenerateBackupCodes()
	if err != nil {
		return nil, err
	}

	return &BackupCodeSet{
		PlainCodes:  plainCodes,
		HashedCodes: hashedCodes,
	}, nil
}

// VerifyCode verifies a code against a list of hashed codes using constant-time comparison
func (p *BackupCodesProvider) VerifyCode(code string, hashedCodes []string) (bool, int) {
	// Normalize the code
	code = p.normalizeCode(code)

	for i, hashedCode := range hashedCodes {
		// Use constant-time comparison to avoid timing attacks
		if crypto.CheckPasswordHash(code, hashedCode) {
			return true, i
		}
	}

	return false, -1
}

// GenerateRecoveryCodes generates a new set of recovery codes
func GenerateRecoveryCodes(count, length int) ([]string, []string, error) {
	var plainCodes []string
	var hashedCodes []string

	for i := 0; i < count; i++ {
		// Generate random code
		codeBytes := make([]byte, length/2) // Each byte becomes 2 hex chars
		_, err := rand.Read(codeBytes)
		if err != nil {
			return nil, nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate recovery code")
		}

		// Convert to hex and format
		code := hex.EncodeToString(codeBytes)
		formattedCode := formatRecoveryCode(code)
		plainCodes = append(plainCodes, formattedCode)

		// Hash for storage
		hashedCode, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, errors.Wrap(errors.CodeCryptoError, err, "failed to hash recovery code")
		}
		hashedCodes = append(hashedCodes, string(hashedCode))
	}

	return plainCodes, hashedCodes, nil
}

// formatRecoveryCode formats a recovery code with dashes for readability
func formatRecoveryCode(code string) string {
	if len(code) <= 4 {
		return code
	}

	var formatted strings.Builder
	for i := 0; i < len(code); i += 4 {
		if i > 0 {
			formatted.WriteString("-")
		}
		end := i + 4
		if end > len(code) {
			end = len(code)
		}
		formatted.WriteString(code[i:end])
	}
	return formatted.String()
}

// VerifyRecoveryCode verifies a recovery code against a list of hashed codes
func VerifyRecoveryCode(inputCode string, hashedCodes []string) (bool, int) {
	// Normalize the input code by removing dashes and spaces
	normalized := strings.ReplaceAll(strings.ReplaceAll(inputCode, "-", ""), " ", "")
	normalized = strings.ToLower(normalized)

	for i, hashedCode := range hashedCodes {
		// Compare the normalized code against the hashed code
		err := bcrypt.CompareHashAndPassword([]byte(hashedCode), []byte(normalized))
		if err == nil {
			return true, i
		}
	}

	return false, -1
}

// ConstantTimeVerifyRecoveryCode verifies a recovery code in constant time to prevent timing attacks
func ConstantTimeVerifyRecoveryCode(inputCode string, plainTextCode string) bool {
	// Normalize both codes
	normalizedInput := strings.ReplaceAll(strings.ReplaceAll(inputCode, "-", ""), " ", "")
	normalizedInput = strings.ToLower(normalizedInput)

	normalizedPlain := strings.ReplaceAll(strings.ReplaceAll(plainTextCode, "-", ""), " ", "")
	normalizedPlain = strings.ToLower(normalizedPlain)

	// Use constant-time comparison
	return subtle.ConstantTimeCompare([]byte(normalizedInput), []byte(normalizedPlain)) == 1
}
