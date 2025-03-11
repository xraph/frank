package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/juicycleff/frank/pkg/errors"
)

const (
	// CharsetAlphanumeric contains all alphanumeric characters
	CharsetAlphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// CharsetAlphabetic contains all alphabetic characters
	CharsetAlphabetic = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// CharsetNumeric contains all numeric characters
	CharsetNumeric = "0123456789"

	// CharsetHex contains all hexadecimal characters
	CharsetHex = "0123456789abcdef"

	// CharsetSymbols contains common symbols
	CharsetSymbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"

	// CharsetURLSafe contains URL-safe characters
	CharsetURLSafe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)

// RandomBytes generates random bytes
func RandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New(errors.CodeInvalidInput, "length must be greater than zero")
	}

	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate random bytes")
	}

	return b, nil
}

// RandomString generates a random string using the specified character set
func RandomString(length int, charsets ...string) string {
	charset := CharsetAlphanumeric
	if len(charsets) > 0 && charsets[0] != "" {
		charset = charsets[0]
	}

	b := make([]byte, length)
	charsetLength := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		n, _ := rand.Int(rand.Reader, charsetLength)
		b[i] = charset[n.Int64()]
	}

	return string(b)
}

// RandomHex generates a random hex string
func RandomHex(length int) string {
	return RandomString(length, CharsetHex)
}

// RandomNumeric generates a random numeric string
func RandomNumeric(length int) string {
	return RandomString(length, CharsetNumeric)
}

// RandomAlphabetic generates a random alphabetic string
func RandomAlphabetic(length int) string {
	return RandomString(length, CharsetAlphabetic)
}

// SecureToken generates a secure token with the given length
func SecureToken(length int) string {
	bytes, _ := RandomBytes(length)
	return hex.EncodeToString(bytes)[:length]
}

// SecureURLToken generates a URL-safe secure token
func SecureURLToken(length int) string {
	bytes, _ := RandomBytes(length)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

// APIKey generates an API key in the format prefix.randomstring
func APIKey(prefix string, length int) string {
	if prefix == "" {
		prefix = "api"
	}

	randomPart := SecureURLToken(length)
	return fmt.Sprintf("%s_%s", prefix, randomPart)
}

// ClientID generates a client ID for OAuth2 clients
func ClientID(length int) string {
	return RandomString(length, CharsetAlphanumeric)
}

// ClientSecret generates a client secret for OAuth2 clients
func ClientSecret(length int) string {
	return SecureToken(length)
}

// GenerateOTP generates a one-time password with the specified length
func GenerateOTP(length int) string {
	return RandomString(length, CharsetNumeric)
}

// GeneratePassword generates a secure password
func GeneratePassword(length int, includeLower, includeUpper, includeNumbers, includeSymbols bool) string {
	var charset strings.Builder

	if includeLower {
		charset.WriteString("abcdefghijklmnopqrstuvwxyz")
	}

	if includeUpper {
		charset.WriteString("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}

	if includeNumbers {
		charset.WriteString(CharsetNumeric)
	}

	if includeSymbols {
		charset.WriteString(CharsetSymbols)
	}

	// Default to alphanumeric if no character sets selected
	if charset.Len() == 0 {
		charset.WriteString(CharsetAlphanumeric)
	}

	return RandomString(length, charset.String())
}

// GenerateWebhookSecret generates a secure webhook secret
func GenerateWebhookSecret() string {
	return SecureToken(32)
}

// GenerateRandomString generates a cryptographically secure random string
// with the specified length. The string is base64url encoded without padding.
func GenerateRandomString(length int) (string, error) {
	if length <= 0 {
		length = 32 // Default to 32 characters if invalid length provided
	}

	// Calculate how many bytes we need to generate
	// Base64 encoding converts every 3 bytes into 4 characters
	// So to get 'length' characters, we need 3/4 * length bytes (rounded up)
	numBytes := (length * 3) / 4
	if (length*3)%4 != 0 {
		numBytes++
	}

	// Generate random bytes
	randomBytes := make([]byte, numBytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to base64url encoding (URL-safe base64 without padding)
	encoded := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Trim to the requested length (in case we generated more characters than needed)
	if len(encoded) > length {
		encoded = encoded[:length]
	}

	return encoded, nil
}

// GenerateHexToken generates a random hex string of specified length
func GenerateHexToken(length int) (string, error) {
	if length <= 0 {
		length = 32 // Default to 32 characters
	}

	// Each byte becomes 2 hex characters, so we need length/2 bytes
	numBytes := length / 2
	if length%2 != 0 {
		numBytes++
	}

	randomBytes := make([]byte, numBytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to hexadecimal
	hexToken := hex.EncodeToString(randomBytes)

	// Ensure it's exactly the right length
	if len(hexToken) > length {
		hexToken = hexToken[:length]
	}

	return hexToken, nil
}

// GenerateNumericCode generates a random numeric code of specified length
func GenerateNumericCode(length int) (string, error) {
	if length <= 0 {
		length = 6 // Default to 6 digits
	}

	// Generate a random number for each position
	var codeBuilder strings.Builder
	for i := 0; i < length; i++ {
		// Generate a number between 0 and 9
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		codeBuilder.WriteString(num.String())
	}

	return codeBuilder.String(), nil
}

// GenerateAPIKey generates an API key with a prefix
func GenerateAPIKey(prefix string) (string, error) {
	if prefix == "" {
		prefix = "key"
	}

	// Generate 32 bytes of random data (will become 43 characters in base64url)
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode as base64url without padding
	encoded := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Combine prefix with underscore and the encoded random bytes
	return fmt.Sprintf("%s_%s", prefix, encoded), nil
}

// GenerateUUID generates a random UUID v4
func GenerateUUID() (string, error) {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Set version to 4 (random) and variant to RFC4122
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant RFC4122

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

// ConstantTimeCompare compares two strings in constant time to prevent timing attacks
func ConstantTimeCompare(a, b string) bool {
	// If lengths are different, return false but still go through the rest
	// of the comparison to maintain constant time
	if len(a) != len(b) {
		// Compare dummy values to ensure constant time
		b = strings.Repeat("0", len(a))
	}

	var result byte = 0
	for i := 0; i < len(a); i++ {
		// XOR the bytes - result will be non-zero if any bytes are different
		result |= a[i] ^ b[i]
	}

	return result == 0
}
