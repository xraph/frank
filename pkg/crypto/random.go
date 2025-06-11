package crypto

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/rs/xid"
)

// Character sets for different types of random strings
const (
	AlphaLower       = "abcdefghijklmnopqrstuvwxyz"
	AlphaUpper       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Alpha            = AlphaLower + AlphaUpper
	Numeric          = "0123456789"
	AlphaNumeric     = Alpha + Numeric
	AlphaNumericSafe = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" // Excludes confusing characters
	Symbols          = "!@#$%&*+-=?_"
	AlphaNumSymbols  = AlphaNumeric + Symbols
	Hex              = "0123456789abcdef"
	Base32Alphabet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	URLSafe          = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// Random string generation options
type RandomStringOptions struct {
	Length      int
	Charset     string
	NoAmbiguous bool // Exclude ambiguous characters like 0/O, 1/I/l
}

// RandomGenerator provides secure random generation functionality
type RandomGenerator interface {
	// String generation
	RandomString(length int) (string, error)
	RandomStringWithCharset(length int, charset string) (string, error)
	RandomStringWithOptions(opts RandomStringOptions) (string, error)

	// Specific string types
	RandomAlphaNumeric(length int) (string, error)
	RandomAlpha(length int) (string, error)
	RandomNumeric(length int) (string, error)
	RandomHex(length int) (string, error)
	RandomBase32(length int) (string, error)
	RandomBase64(length int) (string, error)
	RandomURLSafe(length int) (string, error)

	// Token generation
	GenerateToken(length int) (string, error)
	GenerateSecureToken() (string, error)
	GenerateAPIKey() (string, error)
	GenerateSecrets(count int) ([]string, error)

	// Numeric generation
	RandomInt(max int) (int, error)
	RandomIntRange(min, max int) (int, error)
	RandomInt64(max int64) (int64, error)
	RandomInt64Range(min, max int64) (int64, error)

	// Byte generation
	RandomBytes(length int) ([]byte, error)

	// Specific use cases
	GenerateOTP(digits int) (string, error)
	GeneratePassword(length int, includeSymbols bool) (string, error)
	GenerateInvitationCode() (string, error)
	GenerateVerificationCode() (string, error)
	GenerateSessionID() (string, error)
	GenerateWebhookSecret() (string, error)
}

// randomGenerator implements RandomGenerator interface
type randomGenerator struct{}

// NewRandomGenerator creates a new random generator
func NewRandomGenerator() RandomGenerator {
	return &randomGenerator{}
}

// RandomString generates a random string using alphanumeric characters
func (r *randomGenerator) RandomString(length int) (string, error) {
	return r.RandomStringWithCharset(length, AlphaNumeric)
}

// RandomStringWithCharset generates a random string using the specified charset
func (r *randomGenerator) RandomStringWithCharset(length int, charset string) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive")
	}
	if charset == "" {
		return "", fmt.Errorf("charset cannot be empty")
	}

	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		result[i] = charset[randomIndex.Int64()]
	}

	return string(result), nil
}

// RandomStringWithOptions generates a random string with the specified options
func (r *randomGenerator) RandomStringWithOptions(opts RandomStringOptions) (string, error) {
	charset := opts.Charset
	if charset == "" {
		charset = AlphaNumeric
	}

	if opts.NoAmbiguous {
		charset = removeAmbiguousCharacters(charset)
	}

	return r.RandomStringWithCharset(opts.Length, charset)
}

// RandomAlphaNumeric generates a random alphanumeric string
func (r *randomGenerator) RandomAlphaNumeric(length int) (string, error) {
	return r.RandomStringWithCharset(length, AlphaNumeric)
}

// RandomAlpha generates a random alphabetic string
func (r *randomGenerator) RandomAlpha(length int) (string, error) {
	return r.RandomStringWithCharset(length, Alpha)
}

// RandomNumeric generates a random numeric string
func (r *randomGenerator) RandomNumeric(length int) (string, error) {
	return r.RandomStringWithCharset(length, Numeric)
}

// RandomHex generates a random hexadecimal string
func (r *randomGenerator) RandomHex(length int) (string, error) {
	bytes, err := r.RandomBytes(length / 2)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// RandomBase32 generates a random base32 string
func (r *randomGenerator) RandomBase32(length int) (string, error) {
	// Calculate how many bytes we need
	bytesNeeded := (length*5 + 7) / 8
	bytes, err := r.RandomBytes(bytesNeeded)
	if err != nil {
		return "", err
	}

	encoded := base32.StdEncoding.EncodeToString(bytes)
	// Remove padding and trim to desired length
	encoded = strings.TrimRight(encoded, "=")
	if len(encoded) > length {
		encoded = encoded[:length]
	}

	return encoded, nil
}

// RandomBase64 generates a random base64 string
func (r *randomGenerator) RandomBase64(length int) (string, error) {
	// Calculate how many bytes we need
	bytesNeeded := (length*3 + 3) / 4
	bytes, err := r.RandomBytes(bytesNeeded)
	if err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(bytes)
	// Remove padding and trim to desired length
	encoded = strings.TrimRight(encoded, "=")
	if len(encoded) > length {
		encoded = encoded[:length]
	}

	return encoded, nil
}

// RandomURLSafe generates a random URL-safe string
func (r *randomGenerator) RandomURLSafe(length int) (string, error) {
	return r.RandomStringWithCharset(length, URLSafe)
}

// GenerateToken generates a secure random token
func (r *randomGenerator) GenerateToken(length int) (string, error) {
	if length <= 0 {
		length = 32 // Default length
	}
	return r.RandomURLSafe(length)
}

// GenerateSecureToken generates a cryptographically secure random token
func (r *randomGenerator) GenerateSecureToken() (string, error) {
	bytes, err := r.RandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateAPIKey generates a secure API key
func (r *randomGenerator) GenerateAPIKey() (string, error) {
	// Generate a 32-byte random key and encode as base64
	bytes, err := r.RandomBytes(32)
	if err != nil {
		return "", err
	}

	// Use URL-safe base64 encoding without padding
	key := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)

	// Add a prefix to identify it as an API key
	return fmt.Sprintf("fk_%s", key), nil
}

// GenerateSecrets generates multiple secure secrets
func (r *randomGenerator) GenerateSecrets(count int) ([]string, error) {
	secrets := make([]string, count)
	for i := 0; i < count; i++ {
		secret, err := r.GenerateSecureToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate secret %d: %w", i, err)
		}
		secrets[i] = secret
	}
	return secrets, nil
}

// RandomInt generates a random integer between 0 and max (exclusive)
func (r *randomGenerator) RandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be positive")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random int: %w", err)
	}

	return int(n.Int64()), nil
}

// RandomIntRange generates a random integer between min and max (inclusive)
func (r *randomGenerator) RandomIntRange(min, max int) (int, error) {
	if min >= max {
		return 0, fmt.Errorf("min must be less than max")
	}

	n, err := r.RandomInt(max - min + 1)
	if err != nil {
		return 0, err
	}

	return min + n, nil
}

// RandomInt64 generates a random int64 between 0 and max (exclusive)
func (r *randomGenerator) RandomInt64(max int64) (int64, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be positive")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random int64: %w", err)
	}

	return n.Int64(), nil
}

// RandomInt64Range generates a random int64 between min and max (inclusive)
func (r *randomGenerator) RandomInt64Range(min, max int64) (int64, error) {
	if min >= max {
		return 0, fmt.Errorf("min must be less than max")
	}

	n, err := r.RandomInt64(max - min + 1)
	if err != nil {
		return 0, err
	}

	return min + n, nil
}

// RandomBytes generates cryptographically secure random bytes
func (r *randomGenerator) RandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("length must be positive")
	}

	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return bytes, nil
}

// GenerateOTP generates a One-Time Password with the specified number of digits
func (r *randomGenerator) GenerateOTP(digits int) (string, error) {
	if digits <= 0 {
		digits = 6 // Default to 6 digits
	}

	return r.RandomNumeric(digits)
}

// GeneratePassword generates a secure password
func (r *randomGenerator) GeneratePassword(length int, includeSymbols bool) (string, error) {
	if length <= 0 {
		length = 12 // Default length
	}

	charset := AlphaNumeric
	if includeSymbols {
		charset = AlphaNumSymbols
	}

	// Ensure password has at least one character from each category
	if length >= 4 {
		var password strings.Builder

		// Add at least one lowercase letter
		char, err := r.RandomStringWithCharset(1, AlphaLower)
		if err != nil {
			return "", err
		}
		password.WriteString(char)

		// Add at least one uppercase letter
		char, err = r.RandomStringWithCharset(1, AlphaUpper)
		if err != nil {
			return "", err
		}
		password.WriteString(char)

		// Add at least one digit
		char, err = r.RandomStringWithCharset(1, Numeric)
		if err != nil {
			return "", err
		}
		password.WriteString(char)

		// Add at least one symbol if requested
		if includeSymbols {
			char, err = r.RandomStringWithCharset(1, Symbols)
			if err != nil {
				return "", err
			}
			password.WriteString(char)
		}

		// Fill the rest with random characters
		remaining := length - password.Len()
		if remaining > 0 {
			remainingChars, err := r.RandomStringWithCharset(remaining, charset)
			if err != nil {
				return "", err
			}
			password.WriteString(remainingChars)
		}

		// Shuffle the password to avoid predictable patterns
		return r.shuffleString(password.String())
	}

	// For short passwords, just generate random characters
	return r.RandomStringWithCharset(length, charset)
}

// GenerateInvitationCode generates an invitation code
func (r *randomGenerator) GenerateInvitationCode() (string, error) {
	// Generate a short, user-friendly invitation code
	return r.RandomStringWithCharset(8, AlphaNumericSafe)
}

// GenerateVerificationCode generates a verification code
func (r *randomGenerator) GenerateVerificationCode() (string, error) {
	// Generate a 6-digit numeric verification code
	return r.RandomNumeric(6)
}

// GenerateSessionID generates a session ID
func (r *randomGenerator) GenerateSessionID() (string, error) {
	// Generate a unique session ID using XID
	return xid.New().String(), nil
}

// GenerateWebhookSecret generates a webhook secret
func (r *randomGenerator) GenerateWebhookSecret() (string, error) {
	// Generate a 32-byte secret for webhook signing
	bytes, err := r.RandomBytes(32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Helper functions

// removeAmbiguousCharacters removes ambiguous characters from a charset
func removeAmbiguousCharacters(charset string) string {
	ambiguous := "0O1Il"
	result := charset
	for _, char := range ambiguous {
		result = strings.ReplaceAll(result, string(char), "")
	}
	return result
}

// shuffleString shuffles the characters in a string
func (r *randomGenerator) shuffleString(s string) (string, error) {
	runes := []rune(s)
	n := len(runes)

	for i := n - 1; i > 0; i-- {
		j, err := r.RandomInt(i + 1)
		if err != nil {
			return "", err
		}
		runes[i], runes[j] = runes[j], runes[i]
	}

	return string(runes), nil
}

// Convenience functions for global usage

var globalGenerator = NewRandomGenerator()

// RandomString generates a random alphanumeric string
func RandomString(length int) (string, error) {
	return globalGenerator.RandomString(length)
}

// RandomStringWithCharset generates a random string with custom charset
func RandomStringWithCharset(length int, charset string) (string, error) {
	return globalGenerator.RandomStringWithCharset(length, charset)
}

// RandomBytes generates cryptographically secure random bytes
func RandomBytes(length int) ([]byte, error) {
	return globalGenerator.RandomBytes(length)
}

// GenerateToken generates a secure random token
func GenerateToken(length int) (string, error) {
	return globalGenerator.GenerateToken(length)
}

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken() (string, error) {
	return globalGenerator.GenerateSecureToken()
}

// GenerateAPIKey generates a secure API key
func GenerateAPIKey() (string, error) {
	return globalGenerator.GenerateAPIKey()
}

// GenerateOTP generates a One-Time Password
func GenerateOTP(digits int) (string, error) {
	return globalGenerator.GenerateOTP(digits)
}

// GeneratePassword generates a secure password
func GeneratePassword(length int, includeSymbols bool) (string, error) {
	return globalGenerator.GeneratePassword(length, includeSymbols)
}

// GenerateInvitationCode generates an invitation code
func GenerateInvitationCode() (string, error) {
	return globalGenerator.GenerateInvitationCode()
}

// GenerateVerificationCode generates a verification code
func GenerateVerificationCode() (string, error) {
	return globalGenerator.GenerateVerificationCode()
}

// GenerateSessionID generates a session ID
func GenerateSessionID() (string, error) {
	return globalGenerator.GenerateSessionID()
}

// GenerateWebhookSecret generates a webhook secret
func GenerateWebhookSecret() (string, error) {
	return globalGenerator.GenerateWebhookSecret()
}

// RandomInt generates a random integer
func RandomInt(max int) (int, error) {
	return globalGenerator.RandomInt(max)
}

// RandomIntRange generates a random integer in range
func RandomIntRange(min, max int) (int, error) {
	return globalGenerator.RandomIntRange(min, max)
}

// MustRandomString generates a random string and panics on error
func MustRandomString(length int) string {
	s, err := RandomString(length)
	if err != nil {
		panic(err)
	}
	return s
}

// MustGenerateToken generates a token and panics on error
func MustGenerateToken(length int) string {
	s, err := GenerateToken(length)
	if err != nil {
		panic(err)
	}
	return s
}

// MustGenerateSecureToken generates a secure token and panics on error
func MustGenerateSecureToken() string {
	s, err := GenerateSecureToken()
	if err != nil {
		panic(err)
	}
	return s
}

// Specialized generators for common use cases

// GenerateBackupCodes generates backup codes for MFA
func GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := globalGenerator.RandomStringWithCharset(8, AlphaNumericSafe)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code %d: %w", i, err)
		}
		codes[i] = code
	}
	return codes, nil
}

// GenerateRecoveryCodes generates recovery codes
func GenerateRecoveryCodes(count int) ([]string, error) {
	return GenerateBackupCodes(count)
}

// GenerateCSRFToken generates a CSRF token
func GenerateCSRFToken() (string, error) {
	return GenerateSecureToken()
}

// GenerateNonce generates a cryptographic nonce
func GenerateNonce() (string, error) {
	bytes, err := RandomBytes(16)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateStateToken generates an OAuth state token
func GenerateStateToken() (string, error) {
	return GenerateSecureToken()
}

// GenerateCodeVerifier generates a PKCE code verifier
func GenerateCodeVerifier() (string, error) {
	// PKCE code verifier should be 43-128 characters
	return globalGenerator.RandomURLSafe(64)
}

// TimestampedToken generates a token with embedded timestamp
func TimestampedToken() (string, error) {
	timestamp := time.Now().Unix()
	randomPart, err := GenerateToken(16)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d_%s", timestamp, randomPart), nil
}
