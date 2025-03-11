package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/juicycleff/frank/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	// Hash password with bcrypt
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), BcryptDefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hashedBytes), nil
}

// // HashPassword hashes a password using bcrypt
// func HashPassword(password string) (string, error) {
// 	if password == "" {
// 		return "", errors.New(errors.CodeInvalidInput, "password cannot be empty")
// 	}
//
// 	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	if err != nil {
// 		return "", errors.Wrap(errors.CodeCryptoError, err, "failed to hash password")
// 	}
//
// 	return string(bytes), nil
// }

// VerifyPassword verifies a password against a hash
func VerifyPassword(hashedPassword, password string) error {
	if hashedPassword == "" || password == "" {
		return errors.New(errors.CodeInvalidInput, "password or hash cannot be empty")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return errors.New(errors.CodeInvalidCredentials, "incorrect password")
		}
		return errors.Wrap(errors.CodeCryptoError, err, "failed to verify password")
	}

	return nil
}

// HashAPIKey hashes an API key using SHA-256
func HashAPIKey(apiKey string) string {
	hash := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(hash[:])
}

// VerifyAPIKey securely compares an API key with its hash
func VerifyAPIKey(apiKey, hashedKey string) bool {
	hash := HashAPIKey(apiKey)
	return subtle.ConstantTimeCompare([]byte(hash), []byte(hashedKey)) == 1
}

// HMAC generates an HMAC signature using SHA-256
func HMAC(message string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMAC verifies an HMAC signature
func VerifyHMAC(message, signature string, key []byte) bool {
	expectedSignature := HMAC(message, key)
	return subtle.ConstantTimeCompare([]byte(expectedSignature), []byte(signature)) == 1
}

// DeriveKey derives a key from a password using PBKDF2
func DeriveKey(password, salt string, iterations, keyLen int) string {
	if salt == "" {
		salt = RandomString(16)
	}

	key := pbkdf2.Key([]byte(password), []byte(salt), iterations, keyLen, sha512.New)
	return fmt.Sprintf("%s$%d$%s$%s", "pbkdf2:sha512", iterations, salt, base64.StdEncoding.EncodeToString(key))
}

// ParseDerivedKey parses a derived key string
func ParseDerivedKey(derivedKey string) (algorithm string, iterations int, salt string, key string, err error) {
	var parsed int
	parsed, err = fmt.Sscanf(derivedKey, "%s$%d$%s$%s", &algorithm, &iterations, &salt, &key)
	if err != nil || parsed != 4 {
		return "", 0, "", "", errors.Wrap(errors.CodeCryptoError, err, "failed to parse derived key")
	}
	return
}

// VerifyDerivedKey verifies a password against a derived key
func VerifyDerivedKey(password, derivedKey string) bool {
	algorithm, iterations, salt, encodedKey, err := ParseDerivedKey(derivedKey)
	if err != nil {
		return false
	}

	if algorithm != "pbkdf2:sha512" {
		return false
	}

	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return false
	}

	newKey := pbkdf2.Key([]byte(password), []byte(salt), iterations, len(key), sha512.New)
	return subtle.ConstantTimeCompare(key, newKey) == 1
}

const (
	// BcryptDefaultCost is the default cost for bcrypt hashing
	BcryptDefaultCost = 12

	// PBKDF2Iterations is the number of iterations for PBKDF2
	PBKDF2Iterations = 10000

	// PBKDF2KeyLength is the length of the derived key for PBKDF2
	PBKDF2KeyLength = 32
)

// CheckPasswordHash compares a password with a hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashPasswordWithPBKDF2 hashes a password with PBKDF2
func HashPasswordWithPBKDF2(password, salt string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	if salt == "" {
		var err error
		salt, err = GenerateRandomString(16)
		if err != nil {
			return "", fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	// Use PBKDF2 with SHA-512
	dk := pbkdf2.Key([]byte(password), []byte(salt), PBKDF2Iterations, PBKDF2KeyLength, sha512.New)

	// Encode the derived key as base64
	encodedHash := base64.StdEncoding.EncodeToString(dk)

	// Format: algorithm$iterations$salt$hash
	return fmt.Sprintf("pbkdf2-sha512$%d$%s$%s", PBKDF2Iterations, salt, encodedHash), nil
}

// CheckPBKDF2Hash verifies a password against a PBKDF2 hash
func CheckPBKDF2Hash(password, hashString string) bool {
	// Parse the hash string
	parts := strings.Split(hashString, "$")
	if len(parts) != 4 || !strings.HasPrefix(parts[0], "pbkdf2-") {
		return false
	}

	// Extract components
	iterations := 0
	_, err := fmt.Sscanf(parts[1], "%d", &iterations)
	if err != nil {
		return false
	}

	salt := parts[2]
	storedHash := parts[3]

	// Decode the stored hash
	decodedHash, err := base64.StdEncoding.DecodeString(storedHash)
	if err != nil {
		return false
	}

	// Compute hash of the provided password
	dk := pbkdf2.Key([]byte(password), []byte(salt), iterations, len(decodedHash), sha512.New)

	// Compare in constant time
	return subtle.ConstantTimeCompare(dk, decodedHash) == 1
}

// SHA256Hash computes the SHA-256 hash of data
func SHA256Hash(data string) []byte {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hash.Sum(nil)
}

// SHA256HashString computes the SHA-256 hash of data as a hex string
func SHA256HashString(data string) string {
	hash := SHA256Hash(data)
	return hex.EncodeToString(hash)
}

// SHA512Hash computes the SHA-512 hash of data
func SHA512Hash(data string) []byte {
	hash := sha512.New()
	hash.Write([]byte(data))
	return hash.Sum(nil)
}

// SHA512HashString computes the SHA-512 hash of data as a hex string
func SHA512HashString(data string) string {
	hash := SHA512Hash(data)
	return hex.EncodeToString(hash)
}

// GenerateHashedAPIKey generates a random API key and its hash
func GenerateHashedAPIKey(prefix string) (string, string, error) {
	// Generate API key
	apiKey, err := GenerateAPIKey(prefix)
	if err != nil {
		return "", "", err
	}

	// Hash the API key with SHA-256
	hashedKey := SHA256HashString(apiKey)

	return apiKey, hashedKey, nil
}

// ValidateAPIKey checks if an API key matches a stored hash
func ValidateAPIKey(apiKey, storedHash string) bool {
	// Hash the provided API key
	computedHash := SHA256HashString(apiKey)

	// Compare with the stored hash in constant time
	return subtle.ConstantTimeCompare([]byte(computedHash), []byte(storedHash)) == 1
}
