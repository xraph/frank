package validator

import (
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/juicycleff/frank/pkg/errors"
)

var (
	// validate is the global validator instance
	validate *validator.Validate

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
)

// Init initializes the validator
func Init() {
	validate = validator.New()

	// Register custom validators
	_ = validate.RegisterValidation("email", validateEmail)
	_ = validate.RegisterValidation("password", validatePassword)
	_ = validate.RegisterValidation("phone", validatePhone)
	_ = validate.RegisterValidation("url", validateURL)
	_ = validate.RegisterValidation("slug", validateSlug)
	_ = validate.RegisterValidation("hex", validateHex)
	_ = validate.RegisterValidation("redirect_uri", validateRedirectURI)
	_ = validate.RegisterValidation("webhook_url", validateWebhookURL)
}

// Validate validates a struct or field
func Validate(v interface{}) error {
	if validate == nil {
		Init()
	}

	err := validate.Struct(v)
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

// getErrorMessage returns a human-readable error message for a validation error
func getErrorMessage(e validator.FieldError) string {
	switch e.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email address"
	case "password":
		return "Password must be at least 8 characters"
	case "phone":
		return "Invalid phone number, must be in E.164 format"
	case "url":
		return "Invalid URL"
	case "slug":
		return "Invalid slug format"
	case "hex":
		return "Invalid hexadecimal string"
	case "redirect_uri":
		return "Invalid redirect URI"
	case "webhook_url":
		return "Invalid webhook URL"
	case "min":
		return "Value is less than minimum allowed"
	case "max":
		return "Value is greater than maximum allowed"
	case "len":
		return "Length is invalid"
	case "oneof":
		return "Must be one of the allowed values"
	default:
		return "Invalid value"
	}
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

// validateRedirectURI validates a redirect URI for OAuth2
func validateRedirectURI(fl validator.FieldLevel) bool {
	urlStr := fl.Field().String()
	if urlStr == "" {
		return true
	}

	// Parse URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Verify scheme is http or https
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// Verify host is present
	if u.Host == "" {
		return false
	}

	// Disallow credentials in URL
	if u.User != nil {
		return false
	}

	return true
}

// validateWebhookURL validates a webhook URL
func validateWebhookURL(fl validator.FieldLevel) bool {
	urlStr := fl.Field().String()
	if urlStr == "" {
		return true
	}

	// Parse URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Verify scheme is https
	if u.Scheme != "https" {
		return false
	}

	// Verify host is present
	if u.Host == "" {
		return false
	}

	// Disallow credentials in URL
	if u.User != nil {
		return false
	}

	return true
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
