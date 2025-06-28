package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"

	"github.com/xraph/frank/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// HashAlgorithm represents different hashing algorithms
type HashAlgorithm string

const (
	AlgorithmBcrypt HashAlgorithm = "bcrypt"
	AlgorithmScrypt HashAlgorithm = "scrypt"
	AlgorithmSHA256 HashAlgorithm = "sha256"
	AlgorithmSHA512 HashAlgorithm = "sha512"
)

// HashConfig contains configuration for password hashing
type HashConfig struct {
	Algorithm HashAlgorithm
	Cost      int    // For bcrypt
	Salt      []byte // For scrypt
	N         int    // scrypt CPU/memory cost parameter
	R         int    // scrypt block size parameter
	P         int    // scrypt parallelization parameter
	KeyLen    int    // scrypt key length
}

// DefaultHashConfig returns default configuration for password hashing
func DefaultHashConfig() *HashConfig {
	return &HashConfig{
		Algorithm: AlgorithmBcrypt,
		Cost:      bcrypt.DefaultCost,
		N:         16384, // scrypt default
		R:         8,     // scrypt default
		P:         1,     // scrypt default
		KeyLen:    32,    // scrypt key length
	}
}

// PasswordHasher provides password hashing and verification functionality
type PasswordHasher interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password, hash string) error
	NeedsRehash(hash string) bool
}

// Hasher provides general hashing functionality
type Hasher interface {
	Hash(data []byte) []byte
	HashString(data string) string
	HMAC(data []byte, key []byte) []byte
	HMACString(data string, key string) string
	VerifyHMAC(data []byte, key []byte, expectedHMAC []byte) bool
	HashAPIKey(apiKey string) string
	GenerateAPIKey(keyType string) (string, error)
	ValidateAPIKeyFormat(apiKey string) error
}

// passwordHasher implements PasswordHasher interface
type passwordHasher struct {
	config *HashConfig
}

// NewPasswordHasher creates a new password hasher with the given configuration
func NewPasswordHasher(config *HashConfig) PasswordHasher {
	if config == nil {
		config = DefaultHashConfig()
	}
	return &passwordHasher{config: config}
}

// hashes a password using the configured algorithm
func (h *passwordHasher) HashPassword(password string) (string, error) {
	switch h.config.Algorithm {
	case AlgorithmBcrypt:
		return h.hashPasswordBcrypt(password)
	case AlgorithmScrypt:
		return h.hashPasswordScrypt(password)
	default:
		return "", fmt.Errorf("unsupported hashing algorithm: %s", h.config.Algorithm)
	}
}

// VerifyPassword verifies a password against its hash
func (h *passwordHasher) VerifyPassword(password, hash string) error {
	// Try bcrypt first (most common)
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err == nil {
		return nil
	}

	// Try scrypt if bcrypt fails
	return h.verifyPasswordScrypt(password, hash)
}

// NeedsRehash checks if a password hash needs to be rehashed
func (h *passwordHasher) NeedsRehash(hash string) bool {
	switch h.config.Algorithm {
	case AlgorithmBcrypt:
		cost, err := bcrypt.Cost([]byte(hash))
		if err != nil {
			return true // If we can't determine cost, assume rehash needed
		}
		return cost < h.config.Cost
	case AlgorithmScrypt:
		// For scrypt, we'd need to parse the hash to check parameters
		// For simplicity, we'll return false here
		return false
	default:
		return true
	}
}

// hashPasswordBcrypt hashes password using bcrypt
func (h *passwordHasher) hashPasswordBcrypt(password string) (string, error) {
	cost := h.config.Cost
	if cost <= 0 {
		cost = bcrypt.DefaultCost
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password with bcrypt: %w", err)
	}

	return string(hash), nil
}

// hashPasswordScrypt hashes password using scrypt
func (h *passwordHasher) hashPasswordScrypt(password string) (string, error) {
	salt := h.config.Salt
	if len(salt) == 0 {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return "", fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	hash, err := scrypt.Key([]byte(password), salt, h.config.N, h.config.R, h.config.P, h.config.KeyLen)
	if err != nil {
		return "", fmt.Errorf("failed to hash password with scrypt: %w", err)
	}

	// Format: algorithm$N$r$p$salt$hash
	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s",
		h.config.N, h.config.R, h.config.P,
		hex.EncodeToString(salt),
		hex.EncodeToString(hash)), nil
}

// verifyPasswordScrypt verifies password using scrypt
func (h *passwordHasher) verifyPasswordScrypt(password, hashStr string) error {
	// Parse scrypt hash format: scrypt$N$r$p$salt$hash
	var algorithm string
	var N, r, p int
	var saltHex, hashHex string

	n, err := fmt.Sscanf(hashStr, "%s$%d$%d$%d$%s$%s", &algorithm, &N, &r, &p, &saltHex, &hashHex)
	if err != nil || n != 6 || algorithm != "scrypt" {
		return fmt.Errorf("invalid scrypt hash format")
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return fmt.Errorf("invalid salt in hash: %w", err)
	}

	expectedHash, err := hex.DecodeString(hashHex)
	if err != nil {
		return fmt.Errorf("invalid hash in hash string: %w", err)
	}

	derivedKey, err := scrypt.Key([]byte(password), salt, N, r, p, len(expectedHash))
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	if !hmac.Equal(derivedKey, expectedHash) {
		return fmt.Errorf("password verification failed")
	}

	return nil
}

// generalHasher implements Hasher interface
type generalHasher struct {
	algorithm HashAlgorithm
}

// NewHasher creates a new general hasher
func NewHasher(algorithm HashAlgorithm) Hasher {
	return &generalHasher{algorithm: algorithm}
}

// Hash hashes data using the configured algorithm
func (h *generalHasher) Hash(data []byte) []byte {
	var hasher hash.Hash
	switch h.algorithm {
	case AlgorithmSHA256:
		hasher = sha256.New()
	case AlgorithmSHA512:
		hasher = sha512.New()
	default:
		hasher = sha256.New() // Default to SHA256
	}

	hasher.Write(data)
	return hasher.Sum(nil)
}

// HashString hashes a string and returns hex-encoded result
func (h *generalHasher) HashString(data string) string {
	hash := h.Hash([]byte(data))
	return hex.EncodeToString(hash)
}

// HMAC creates an HMAC of the data using the provided key
func (h *generalHasher) HMAC(data []byte, key []byte) []byte {
	var hasher hash.Hash
	switch h.algorithm {
	case AlgorithmSHA256:
		hasher = hmac.New(sha256.New, key)
	case AlgorithmSHA512:
		hasher = hmac.New(sha512.New, key)
	default:
		hasher = hmac.New(sha256.New, key) // Default to SHA256
	}

	hasher.Write(data)
	return hasher.Sum(nil)
}

// HMACString creates an HMAC of the string and returns hex-encoded result
func (h *generalHasher) HMACString(data string, key string) string {
	hmacBytes := h.HMAC([]byte(data), []byte(key))
	return hex.EncodeToString(hmacBytes)
}

// VerifyHMAC verifies an HMAC against expected value
func (h *generalHasher) VerifyHMAC(data []byte, key []byte, expectedHMAC []byte) bool {
	computedHMAC := h.HMAC(data, key)
	return hmac.Equal(computedHMAC, expectedHMAC)
}

// HashAPIKey creates a secure hash of an API key for storage and lookup
func (h *generalHasher) HashAPIKey(apiKey string) string {
	// Use SHA-256 for consistent, secure hashing
	hash := sha256.Sum256([]byte(apiKey))
	return fmt.Sprintf("%x", hash)
}

// GenerateAPIKey generates a new API key with the specified type prefix
func (h *generalHasher) GenerateAPIKey(keyType string) (string, error) {
	// Generate random bytes for the key
	randomBytes, err := h.GenerateRandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 and clean up
	keyData := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Determine prefix based on key type
	var prefix string
	switch keyType {
	case "server", "admin":
		prefix = "frank_sk_" // Secret key
	case "client", "public":
		prefix = "frank_pk_" // Public key
	default:
		prefix = "frank_sk_" // Default to secret key
	}

	return prefix + keyData, nil
}

// ValidateAPIKeyFormat validates the format of an API key
func (h *generalHasher) ValidateAPIKeyFormat(apiKey string) error {
	if apiKey == "" {
		return errors.New(errors.CodeBadRequest, "API key cannot be empty")
	}

	// Check for valid prefixes
	validPrefixes := []string{"frank_sk_", "frank_pk_"}
	hasValidPrefix := false
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(apiKey, prefix) {
			hasValidPrefix = true
			break
		}
	}

	if !hasValidPrefix {
		return errors.New(errors.CodeBadRequest, "invalid API key format")
	}

	// Check minimum length (prefix + base64 encoded 32 bytes)
	minLength := len("frank_sk_") + 43 // 32 bytes base64 encoded without padding
	if len(apiKey) < minLength {
		return errors.New(errors.CodeBadRequest, "API key too short")
	}

	return nil
}

// GenerateRandomBytes generates cryptographically secure random bytes
func (h *generalHasher) GenerateRandomBytes(length int) ([]byte, error) {
	return generateRandomBytes(length)
}

// Utility functions
// generateRandomBytes generates cryptographically secure random bytes
func generateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// HashSHA256 is a convenience function for SHA256 hashing
func HashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// HashSHA256String is a convenience function for SHA256 hashing strings
func HashSHA256String(data string) string {
	hash := HashSHA256([]byte(data))
	return hex.EncodeToString(hash)
}

// HashSHA512 is a convenience function for SHA512 hashing
func HashSHA512(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// HashSHA512String is a convenience function for SHA512 hashing strings
func HashSHA512String(data string) string {
	hash := HashSHA512([]byte(data))
	return hex.EncodeToString(hash)
}

// HMACSHA256 creates an HMAC-SHA256
func HMACSHA256(data []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// HMACSHA256String creates an HMAC-SHA256 and returns hex string
func HMACSHA256String(data string, key string) string {
	hmacBytes := HMACSHA256([]byte(data), []byte(key))
	return hex.EncodeToString(hmacBytes)
}

// VerifyHMACSHA256 verifies an HMAC-SHA256
func VerifyHMACSHA256(data []byte, key []byte, expectedHMAC []byte) bool {
	computedHMAC := HMACSHA256(data, key)
	return hmac.Equal(computedHMAC, expectedHMAC)
}

// SecureCompare performs a constant-time comparison of two byte slices
func SecureCompare(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// SecureCompareString performs a constant-time comparison of two strings
func SecureCompareString(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// DeriveKeyWithPBK derives a key from a password using scrypt
func DeriveKey(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	return scrypt.Key(password, salt, N, r, p, keyLen)
}

// GenerateSalt generates a cryptographically secure random salt
func GenerateSalt(length int) ([]byte, error) {
	if length <= 0 {
		length = 32 // Default salt length
	}

	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	return salt, nil
}
