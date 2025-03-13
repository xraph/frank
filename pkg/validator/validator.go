package validator

import (
	"context"
	errs2 "errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
	"github.com/juicycleff/frank/pkg/errors"
)

var (
	// emailRegex is the regular expression for validating email addresses
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

	// passwordRegex is the regular expression for validating passwords
	passwordRegex = regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$`)

	// phoneRegex is the regular expression for validating phone numbers
	phoneRegex = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

	// slugRegex is the regular expression for validating slugs
	slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

	// hexRegex is the regular expression for validating hexadecimal strings
	hexRegex = regexp.MustCompile(`^[a-fA-F0-9]+$`)

	// apiKeyRegex validates API key format (prefix_base64urlstring)
	apiKeyRegex = regexp.MustCompile(`^[a-z0-9]+_[A-Za-z0-9\-_]+$`)

	// sessionTokenRegex validates session token format
	sessionTokenRegex = regexp.MustCompile(`^[A-Za-z0-9\-_]{32,}$`)

	// otpRegex validates one-time passwords (typically 6 numeric digits)
	otpRegex = regexp.MustCompile(`^[0-9]{4,8}$`)
)

// Validate validates a struct or field
func Validate(v interface{}) error {
	err := GetInstance().Validate(v)
	if err == nil {
		return nil
	}

	validationErrors := err.(validator.ValidationErrors)
	if len(validationErrors) == 0 {
		return errors.New(errors.CodeInvalidInput, "validation error")
	}

	// Convert validation errors to a map
	errorsMap := make(map[string]string)
	for _, e := range validationErrors {
		fieldName := e.Field()
		// Convert from CamelCase to snake_case
		fieldName = toSnakeCase(fieldName)

		// Get the validation error message
		errorsMap[fieldName] = getErrorMessage(e)
	}

	return errors.New(errors.CodeInvalidInput, "validation failed").
		WithMetadata("errors", errorsMap)
}

// toSnakeCase converts a string from CamelCase to snake_case
func toSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && 'A' <= r && r <= 'Z' {
			result.WriteByte('_')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}

// validateEmail validates an email address
func validateEmail(fl validator.FieldLevel) bool {
	return emailRegex.MatchString(fl.Field().String())
}

// validatePassword validates a password
func validatePassword(fl validator.FieldLevel) bool {
	return passwordRegex.MatchString(fl.Field().String())
}

// validatePhone validates a phone number in E.164 format
func validatePhone(fl validator.FieldLevel) bool {
	return phoneRegex.MatchString(fl.Field().String())
}

// validateURL validates a URL
func validateURL(fl validator.FieldLevel) bool {
	urlStr := fl.Field().String()
	if urlStr == "" {
		return true
	}

	u, err := url.Parse(urlStr)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// validateSlug validates a slug
func validateSlug(fl validator.FieldLevel) bool {
	return slugRegex.MatchString(fl.Field().String())
}

// validateHex validates a hexadecimal string
func validateHex(fl validator.FieldLevel) bool {
	return hexRegex.MatchString(fl.Field().String())
}

// IsValidEmail checks if an email address is valid
func IsValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// IsValidPassword checks if a password is valid
func IsValidPassword(password string) bool {
	return passwordRegex.MatchString(password)
}

// IsValidPhone checks if a phone number is valid
func IsValidPhone(phone string) bool {
	return phoneRegex.MatchString(phone)
}

// IsValidURL checks if a URL is valid
func IsValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// IsValidRedirectURI checks if a redirect URI is valid
func IsValidRedirectURI(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil
}

// IsEmpty checks if a value is empty
func IsEmpty(value interface{}) bool {
	v := reflect.ValueOf(value)

	switch v.Kind() {
	case reflect.String, reflect.Array, reflect.Map, reflect.Slice:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}

	return false
}

// validateAPIKey validates an API key format
func validateAPIKey(fl validator.FieldLevel) bool {
	apiKey := fl.Field().String()
	if apiKey == "" {
		return true // Allow empty for optional fields
	}
	return apiKeyRegex.MatchString(apiKey)
}

// validateSessionToken validates a session token format
func validateSessionToken(fl validator.FieldLevel) bool {
	token := fl.Field().String()
	if token == "" {
		return true // Allow empty for optional fields
	}
	return sessionTokenRegex.MatchString(token)
}

// validateOTP validates a one-time password format
func validateOTP(fl validator.FieldLevel) bool {
	otp := fl.Field().String()
	if otp == "" {
		return true // Allow empty for optional fields
	}
	return otpRegex.MatchString(otp)
}

// validatePasswordStrength validates that a password meets strength requirements
func validatePasswordStrength(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	// Skip validation if password is empty (for optional fields)
	if password == "" {
		return true
	}

	// Password must be at least 8 characters
	if len(password) < 8 {
		return false
	}

	// Check for various character classes
	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	// Require at least 3 character types
	score := 0
	if hasUpper {
		score++
	}
	if hasLower {
		score++
	}
	if hasDigit {
		score++
	}
	if hasSpecial {
		score++
	}

	return score >= 3
}

// validateRedirectURI validates an OAuth2 redirect URI
func validateRedirectURI(fl validator.FieldLevel) bool {
	uri := fl.Field().String()
	if uri == "" {
		return true // Allow empty for optional fields
	}

	// Parse the URI
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return false
	}

	// Validate scheme (must be http or https)
	if parsedURI.Scheme != "http" && parsedURI.Scheme != "https" {
		return false
	}

	// Must have a host
	if parsedURI.Host == "" {
		return false
	}

	// Cannot have user info
	if parsedURI.User != nil {
		return false
	}

	return true
}

// validateWebhookURL validates a webhook URL
// Webhooks require HTTPS for security
func validateWebhookURL(fl validator.FieldLevel) bool {
	uri := fl.Field().String()
	if uri == "" {
		return true // Allow empty for optional fields
	}

	// Parse the URI
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return false
	}

	// Validate scheme (must be https)
	if parsedURI.Scheme != "https" {
		return false
	}

	// Must have a host
	if parsedURI.Host == "" {
		return false
	}

	// Cannot have user info
	if parsedURI.User != nil {
		return false
	}

	return true
}

// validateCSRFToken validates a CSRF token format
func validateCSRFToken(fl validator.FieldLevel) bool {
	token := fl.Field().String()
	if token == "" {
		return true // Allow empty for optional fields
	}

	// CSRF tokens should be at least 32 characters with no spaces
	return len(token) >= 32 && !strings.Contains(token, " ")
}

// validateAuthCode validates an OAuth2 authorization code format
func validateAuthCode(fl validator.FieldLevel) bool {
	code := fl.Field().String()
	if code == "" {
		return true // Allow empty for optional fields
	}

	// Authorization codes should be at least 20 characters
	return len(code) >= 20 && !strings.Contains(code, " ")
}

// Validate validates a struct and returns structured validation errors
func (v *FrankValidator) Validate(s interface{}) error {
	if err := v.validator.Struct(s); err != nil {
		validationErrors, ok := err.(validator.ValidationErrors)
		if !ok {
			fmt.Println("validationErrors", validationErrors, ok)
			return errors.New(errors.CodeInvalidInput, "Invalid input format")
		}

		// Build structured error map
		fieldErrors := make(map[string]string)
		for _, e := range validationErrors {
			fieldName := e.Field()
			fieldErrors[fieldName] = getErrorMessage(e)
		}

		return errors.New(errors.CodeInvalidInput, "Validation failed").
			WithMetadata("fields", fieldErrors)
	}

	return nil
}

// ValidateWithContext validates a struct with context
func (v *FrankValidator) ValidateWithContext(ctx context.Context, s interface{}) error {
	if err := v.validator.StructCtx(ctx, s); err != nil {
		var validationErrors validator.ValidationErrors
		ok := errs2.As(err, &validationErrors)
		if !ok {
			return errors.New(errors.CodeInvalidInput, "Invalid input format")
		}

		// Build structured error map
		fieldErrors := make(map[string]string)
		for _, e := range validationErrors {
			fieldName := e.Field()
			fieldErrors[fieldName] = getErrorMessage(e)
		}

		return errors.New(errors.CodeInvalidInput, "Validation failed").
			WithMetadata("fields", fieldErrors)
	}

	return nil
}

// ValidateVar validates a single variable
func (v *FrankValidator) ValidateVar(field interface{}, tag string) error {
	if err := v.validator.Var(field, tag); err != nil {
		validationErrors, ok := err.(validator.ValidationErrors)
		if !ok || len(validationErrors) == 0 {
			return errors.New(errors.CodeInvalidInput, "Invalid input")
		}

		return errors.New(errors.CodeInvalidInput, getErrorMessage(validationErrors[0]))
	}

	return nil
}

// getErrorMessage returns a human-readable message for validation errors
func getErrorMessage(e validator.FieldError) string {
	switch e.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Must be a valid email address"
	case "min":
		return "Must be at least " + e.Param() + " characters"
	case "max":
		return "Must be no more than " + e.Param() + " characters"
	case "api_key":
		return "Invalid API key format"
	case "session_token":
		return "Invalid session token"
	case "otp":
		return "Must be a numeric code (4-8 digits)"
	case "password_strength":
		return "Password must be at least 8 characters and contain 3 of: uppercase, lowercase, numbers, and special characters"
	case "redirect_uri":
		return "Must be a valid http or https URL"
	case "webhook_url":
		return "Must be a valid https URL"
	case "csrf_token":
		return "Invalid CSRF token format"
	case "auth_code":
		return "Invalid authorization code format"
	case "url":
		return "Must be a valid URL"
	case "uuid":
		return "Must be a valid UUID"
	case "alphanum":
		return "Must contain only letters and numbers"
	case "oneof":
		return "Must be one of: " + e.Param()
	case "password":
		return "Password must be at least 8 characters"
	case "phone":
		return "Invalid phone number, must be in E.164 format"
	case "slug":
		return "Invalid slug format"
	case "hex":
		return "Invalid hexadecimal string"
	case "len":
		return "Length is invalid"
	default:
		return "Invalid value for field"
	}
}
