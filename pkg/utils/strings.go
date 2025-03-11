package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/gosimple/slug"
)

var (
	// slugifyRegexp is used to remove characters that aren't allowed in slugs
	slugifyRegexp = regexp.MustCompile(`[^a-z0-9\-]`)

	// nonAlphanumericRegexp is used to check if a string contains non-alphanumeric characters
	nonAlphanumericRegexp = regexp.MustCompile(`[^a-zA-Z0-9]`)

	// emailRegexp is used to validate email addresses
	emailRegexp = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

// Slugify converts a string into a URL-friendly slug
func Slugify(s string) string {
	return slug.Make(s)
}

// TruncateString truncates a string to the specified length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	return s[:maxLen]
}

// IsEmpty checks if a string is empty or contains only whitespace
func IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// IsValidEmail checks if a string is a valid email address
func IsValidEmail(email string) bool {
	return emailRegexp.MatchString(email)
}

// RemoveWhitespace removes all whitespace from a string
func RemoveWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// ContainsOnly checks if a string contains only characters from the allowed set
func ContainsOnly(s, allowed string) bool {
	for _, c := range s {
		if !strings.ContainsRune(allowed, c) {
			return false
		}
	}
	return true
}

// Capitalize capitalizes the first letter of a string
func Capitalize(s string) string {
	if s == "" {
		return ""
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// ToSnakeCase converts a string from camelCase or PascalCase to snake_case
func ToSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) {
			result.WriteByte('_')
		}
		result.WriteRune(unicode.ToLower(r))
	}
	return result.String()
}

// ToCamelCase converts a string from snake_case to camelCase
func ToCamelCase(s string) string {
	words := strings.Split(s, "_")
	for i := 1; i < len(words); i++ {
		words[i] = Capitalize(words[i])
	}
	return strings.Join(words, "")
}

// ToPascalCase converts a string from snake_case to PascalCase
func ToPascalCase(s string) string {
	words := strings.Split(s, "_")
	for i := range words {
		words[i] = Capitalize(words[i])
	}
	return strings.Join(words, "")
}

// GenerateRandomString generates a cryptographically secure random string
// with the specified length (defaults to 32 bytes if length is 0)
func GenerateRandomString(length int) (string, error) {
	if length == 0 {
		length = 32
	}

	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Use URL-safe base64 encoding without padding
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateStateToken generates a random state token for CSRF protection
func GenerateStateToken() (string, error) {
	return GenerateRandomString(16)
}

// IsValidPhoneNumber verifies if a string is a valid phone number format
// This is a simple implementation, consider using a more robust library like libphonenumber
func IsValidPhoneNumber(phone string) bool {
	// Remove common separators
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")
	phone = strings.ReplaceAll(phone, "(", "")
	phone = strings.ReplaceAll(phone, ")", "")

	// Check if it starts with + and has 10-15 digits
	if strings.HasPrefix(phone, "+") {
		phone = phone[1:]
	}

	// Check if it's all digits and has a reasonable length
	for _, r := range phone {
		if !unicode.IsDigit(r) {
			return false
		}
	}

	return len(phone) >= 10 && len(phone) <= 15
}

// IsStrongPassword checks if a password meets security requirements
func IsStrongPassword(password string, minLength int, requireUpper, requireLower, requireDigit, requireSpecial bool) bool {
	if len(password) < minLength {
		return false
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	return (!requireUpper || hasUpper) &&
		(!requireLower || hasLower) &&
		(!requireDigit || hasDigit) &&
		(!requireSpecial || hasSpecial)
}

// SanitizeUsername removes invalid characters from username
func SanitizeUsername(username string) string {
	// Replace spaces with underscores
	username = strings.ReplaceAll(username, " ", "_")

	// Remove any characters that aren't alphanumeric, underscore, dot, or hyphen
	re := regexp.MustCompile(`[^a-zA-Z0-9_\.\-]`)
	username = re.ReplaceAllString(username, "")

	return strings.ToLower(username)
}

// GenerateSlug creates a URL-friendly string from input
func GenerateSlug(input string) string {
	// Convert to lowercase
	input = strings.ToLower(input)

	// Replace spaces with hyphens
	input = strings.ReplaceAll(input, " ", "-")

	// Remove characters that aren't alphanumeric or hyphen
	re := regexp.MustCompile(`[^a-z0-9\-]`)
	input = re.ReplaceAllString(input, "")

	// Replace multiple hyphens with a single one
	re = regexp.MustCompile(`[\-]+`)
	input = re.ReplaceAllString(input, "-")

	// Trim hyphens from start and end
	input = strings.Trim(input, "-")

	return input
}

// Truncate shortens a string to the specified length, adding ellipsis if truncated
func Truncate(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}

	return s[:maxLength-3] + "..."
}

// // MaskEmail partially masks an email address for privacy
// func MaskEmail(email string) string {
// 	parts := strings.Split(email, "@")
// 	if len(parts) != 2 {
// 		return email
// 	}
//
// 	username := parts[0]
// 	domain := parts[1]
//
// 	// Keep first and last character of username, mask the rest
// 	if len(username) > 2 {
// 		masked := username[0] + strings.Repeat("*", len(username)-2) + username[len(username)-1]
// 		return masked + "@" + domain
// 	}
//
// 	// For very short usernames, just mask everything
// 	return strings.Repeat("*", len(username)) + "@" + domain
// }

// MaskPhone partially masks a phone number for privacy
func MaskPhone(phone string) string {
	// Remove common separators
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")
	phone = strings.ReplaceAll(phone, "(", "")
	phone = strings.ReplaceAll(phone, ")", "")

	// If it's a reasonable length, mask the middle portion
	if len(phone) >= 7 {
		prefix := phone[:3]
		suffix := phone[len(phone)-4:]
		middle := strings.Repeat("*", len(phone)-7)
		return fmt.Sprintf("%s%s%s", prefix, middle, suffix)
	}

	// For very short numbers, just mask everything except the last 4 digits
	if len(phone) > 4 {
		return strings.Repeat("*", len(phone)-4) + phone[len(phone)-4:]
	}

	// For extremely short numbers, mask everything
	return strings.Repeat("*", len(phone))
}

// FormatBytes converts bytes to a human-readable string (KB, MB, GB, etc.)
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
