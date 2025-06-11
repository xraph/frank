package validation

import (
	"fmt"
	"net/mail"
	"reflect"
	"regexp"
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
	"github.com/rs/xid"
)

// Validator provides validation functionality
type Validator interface {
	Validate(s interface{}) error
	ValidateStruct(s interface{}) error
	ValidateVar(field interface{}, tag string) error
	ValidateEmail(email string) error
	ValidatePassword(password string, policy *PasswordPolicy) error
	ValidateUsername(username string) error
	ValidatePhone(phone string) error
	ValidateURL(url string) error
	ValidateXID(id string) error
	RegisterCustomValidation(tag string, fn validator.Func) error
}

// PasswordPolicy defines password validation requirements
type PasswordPolicy struct {
	MinLength          int  `json:"min_length" validate:"min=1"`
	MaxLength          int  `json:"max_length" validate:"min=1"`
	RequireUppercase   bool `json:"require_uppercase"`
	RequireLowercase   bool `json:"require_lowercase"`
	RequireDigit       bool `json:"require_digit"`
	RequireSpecial     bool `json:"require_special"`
	MaxReusedPasswords int  `json:"max_reused_passwords"`
	PreventReuse       bool `json:"prevent_reuse"`
	ExpiryDays         int  `json:"expiry_days"`
}

// DefaultPasswordPolicy returns a default password policy
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:          8,
		MaxLength:          100,
		RequireUppercase:   true,
		RequireLowercase:   true,
		RequireDigit:       true,
		RequireSpecial:     false,
		MaxReusedPasswords: 3,
		PreventReuse:       true,
		ExpiryDays:         90,
	}
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value,omitempty"`
	Message string `json:"message"`
}

// Error implements the error interface
func (e ValidationError) Error() string {
	return e.Message
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

// Error implements the error interface
func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "validation failed"
	}
	if len(e) == 1 {
		return e[0].Message
	}
	var messages []string
	for _, err := range e {
		messages = append(messages, err.Message)
	}
	return strings.Join(messages, "; ")
}

// customValidator implements the Validator interface
type customValidator struct {
	validator *validator.Validate
}

// New creates a new validator instance
func New() Validator {
	validate := validator.New()

	v := &customValidator{
		validator: validate,
	}

	// Register custom validations
	v.registerCustomValidations()

	return v
}

// GetInstance returns the singleton instance of FrankValidator
func GetInstance() Validator {
	if valInstance == nil {
		valInstance = New()
	}
	return valInstance
}

// registerCustomValidations registers custom validation functions
func (v *customValidator) registerCustomValidations() {
	// XID validation
	v.validator.RegisterValidation("xid", func(fl validator.FieldLevel) bool {
		_, err := xid.FromString(fl.Field().String())
		return err == nil
	})

	// Strong password validation
	v.validator.RegisterValidation("strong_password", func(fl validator.FieldLevel) bool {
		password := fl.Field().String()
		return v.isStrongPassword(password)
	})

	// Username validation
	v.validator.RegisterValidation("username", func(fl validator.FieldLevel) bool {
		username := fl.Field().String()
		return v.isValidUsername(username)
	})

	// Phone number validation
	v.validator.RegisterValidation("phone", func(fl validator.FieldLevel) bool {
		phone := fl.Field().String()
		return v.isValidPhone(phone)
	})

	// Organization name validation
	v.validator.RegisterValidation("org_name", func(fl validator.FieldLevel) bool {
		name := fl.Field().String()
		return v.isValidOrganizationName(name)
	})

	// Role name validation
	v.validator.RegisterValidation("role_name", func(fl validator.FieldLevel) bool {
		name := fl.Field().String()
		return v.isValidRoleName(name)
	})

	// Permission name validation
	v.validator.RegisterValidation("permission", func(fl validator.FieldLevel) bool {
		permission := fl.Field().String()
		return v.isValidPermission(permission)
	})

	// Webhook URL validation
	v.validator.RegisterValidation("webhook_url", func(fl validator.FieldLevel) bool {
		url := fl.Field().String()
		return v.isValidWebhookURL(url)
	})

	// OAuth redirect URI validation
	v.validator.RegisterValidation("redirect_uri", func(fl validator.FieldLevel) bool {
		uri := fl.Field().String()
		return v.isValidRedirectURI(uri)
	})

	// Scope validation
	v.validator.RegisterValidation("scope", func(fl validator.FieldLevel) bool {
		scope := fl.Field().String()
		return v.isValidScope(scope)
	})

	// Password confirmation validation
	v.validator.RegisterValidation("password_confirm", func(fl validator.FieldLevel) bool {
		return fl.Field().String() == fl.Parent().FieldByName("Password").String()
	})

	// Use JSON field names for error reporting
	v.validator.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return fld.Name
		}
		return name
	})

	// Register custom validators
	_ = v.validator.RegisterValidation("email", validateEmail)
	_ = v.validator.RegisterValidation("password", validatePassword)
	_ = v.validator.RegisterValidation("phone", validatePhone)
	_ = v.validator.RegisterValidation("url", validateURL)
	_ = v.validator.RegisterValidation("slug", validateSlug)
	_ = v.validator.RegisterValidation("hex", validateHex)
	_ = v.validator.RegisterValidation("redirect_uri", validateRedirectURI)
	_ = v.validator.RegisterValidation("webhook_url", validateWebhookURL)
	_ = v.validator.RegisterValidation("password_strength", validatePasswordStrength)

	// Register custom validators
	_ = v.validator.RegisterValidation("api_key", validateAPIKey)
	_ = v.validator.RegisterValidation("session_token", validateSessionToken)
	_ = v.validator.RegisterValidation("otp", validateOTP)
	_ = v.validator.RegisterValidation("password_strength", validatePasswordStrength)
	_ = v.validator.RegisterValidation("redirect_uri", validateRedirectURI)
	_ = v.validator.RegisterValidation("webhook_url", validateWebhookURL)
	_ = v.validator.RegisterValidation("csrf_token", validateCSRFToken)
	_ = v.validator.RegisterValidation("auth_code", validateAuthCode)
}

// Validate validates a struct
func (v *customValidator) Validate(s interface{}) error {
	return v.ValidateStruct(s)
}

// ValidateStruct validates a struct and returns formatted errors
func (v *customValidator) ValidateStruct(s interface{}) error {
	err := v.validator.Struct(s)
	if err == nil {
		return nil
	}

	var validationErrors ValidationErrors

	for _, err := range err.(validator.ValidationErrors) {
		validationError := ValidationError{
			Field: err.Field(),
			Tag:   err.Tag(),
			Value: fmt.Sprintf("%v", err.Value()),
		}

		// Generate human-readable error messages
		validationError.Message = v.generateErrorMessage(err)

		validationErrors = append(validationErrors, validationError)
	}

	return validationErrors
}

// ValidateVar validates a single variable
func (v *customValidator) ValidateVar(field interface{}, tag string) error {
	err := v.validator.Var(field, tag)
	if err == nil {
		return nil
	}

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		var errors ValidationErrors
		for _, err := range validationErrors {
			errors = append(errors, ValidationError{
				Field:   err.Field(),
				Tag:     err.Tag(),
				Value:   fmt.Sprintf("%v", err.Value()),
				Message: v.generateErrorMessage(err),
			})
		}
		return errors
	}

	return err
}

// ValidateEmail validates an email address
func (v *customValidator) ValidateEmail(email string) error {
	if email == "" {
		return ValidationError{
			Field:   "email",
			Tag:     "required",
			Message: "Email is required",
		}
	}

	// Use Go's mail package for basic validation
	_, err := mail.ParseAddress(email)
	if err != nil {
		return ValidationError{
			Field:   "email",
			Tag:     "email",
			Value:   email,
			Message: "Invalid email format",
		}
	}

	// Additional email validation rules
	if len(email) > 254 { // RFC 5321 limit
		return ValidationError{
			Field:   "email",
			Tag:     "max",
			Value:   email,
			Message: "Email address is too long",
		}
	}

	// Check for disposable email domains (basic check)
	if v.isDisposableEmail(email) {
		return ValidationError{
			Field:   "email",
			Tag:     "email",
			Value:   email,
			Message: "Disposable email addresses are not allowed",
		}
	}

	return nil
}

// ValidatePassword validates a password against a policy
func (v *customValidator) ValidatePassword(password string, policy *PasswordPolicy) error {
	if policy == nil {
		policy = DefaultPasswordPolicy()
	}

	var errors ValidationErrors

	// Check length
	if len(password) < policy.MinLength {
		errors = append(errors, ValidationError{
			Field:   "password",
			Tag:     "min",
			Value:   password,
			Message: fmt.Sprintf("Password must be at least %d characters long", policy.MinLength),
		})
	}

	if len(password) > policy.MaxLength {
		errors = append(errors, ValidationError{
			Field:   "password",
			Tag:     "max",
			Value:   password,
			Message: fmt.Sprintf("Password must be no more than %d characters long", policy.MaxLength),
		})
	}

	// Check character requirements
	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if policy.RequireUppercase && !hasUpper {
		errors = append(errors, ValidationError{
			Field:   "password",
			Tag:     "uppercase",
			Message: "Password must contain at least one uppercase letter",
		})
	}

	if policy.RequireLowercase && !hasLower {
		errors = append(errors, ValidationError{
			Field:   "password",
			Tag:     "lowercase",
			Message: "Password must contain at least one lowercase letter",
		})
	}

	if policy.RequireDigit && !hasDigit {
		errors = append(errors, ValidationError{
			Field:   "password",
			Tag:     "digit",
			Message: "Password must contain at least one digit",
		})
	}

	if policy.RequireSpecial && !hasSpecial {
		errors = append(errors, ValidationError{
			Field:   "password",
			Tag:     "special",
			Message: "Password must contain at least one special character",
		})
	}

	// Check for common weak passwords
	if v.isCommonPassword(password) {
		errors = append(errors, ValidationError{
			Field:   "password",
			Tag:     "weak",
			Message: "Password is too common and easily guessable",
		})
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// ValidateUsername validates a username
func (v *customValidator) ValidateUsername(username string) error {
	if !v.isValidUsername(username) {
		return ValidationError{
			Field:   "username",
			Tag:     "username",
			Value:   username,
			Message: "Username must be 3-30 characters long and contain only letters, numbers, hyphens, and underscores",
		}
	}
	return nil
}

// ValidatePhone validates a phone number
func (v *customValidator) ValidatePhone(phone string) error {
	if !v.isValidPhone(phone) {
		return ValidationError{
			Field:   "phone",
			Tag:     "phone",
			Value:   phone,
			Message: "Invalid phone number format",
		}
	}
	return nil
}

// ValidateURL validates a URL
func (v *customValidator) ValidateURL(url string) error {
	err := v.validator.Var(url, "url")
	if err != nil {
		return ValidationError{
			Field:   "url",
			Tag:     "url",
			Value:   url,
			Message: "Invalid URL format",
		}
	}
	return nil
}

// ValidateXID validates an XID
func (v *customValidator) ValidateXID(id string) error {
	_, err := xid.FromString(id)
	if err != nil {
		return ValidationError{
			Field:   "id",
			Tag:     "xid",
			Value:   id,
			Message: "Invalid ID format",
		}
	}
	return nil
}

// RegisterCustomValidation registers a custom validation function
func (v *customValidator) RegisterCustomValidation(tag string, fn validator.Func) error {
	return v.validator.RegisterValidation(tag, fn)
}

// Helper methods

// generateErrorMessage generates human-readable error messages
func (v *customValidator) generateErrorMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", err.Field())
	case "email":
		return "Invalid email format"
	case "min":
		return fmt.Sprintf("%s must be at least %s characters", err.Field(), err.Param())
	case "max":
		return fmt.Sprintf("%s must be no more than %s characters", err.Field(), err.Param())
	case "len":
		return fmt.Sprintf("%s must be exactly %s characters", err.Field(), err.Param())
	case "url":
		return "Invalid URL format"
	case "uuid":
		return "Invalid UUID format"
	case "xid":
		return "Invalid ID format"
	case "strong_password":
		return "Password does not meet strength requirements"
	case "username":
		return "Invalid username format"
	case "phone":
		return "Invalid phone number format"
	case "password_confirm":
		return "Password confirmation does not match"
	default:
		return fmt.Sprintf("%s is invalid", err.Field())
	}
}

// isStrongPassword checks if a password meets strength requirements
func (v *customValidator) isStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	var hasUpper, hasLower, hasDigit bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}

	return hasUpper && hasLower && hasDigit
}

// isValidUsername checks if a username is valid
func (v *customValidator) isValidUsername(username string) bool {
	if len(username) < 3 || len(username) > 30 {
		return false
	}

	// Username should start with a letter or number
	if !unicode.IsLetter(rune(username[0])) && !unicode.IsDigit(rune(username[0])) {
		return false
	}

	// Check allowed characters
	for _, r := range username {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return false
		}
	}

	// Username should not end with a hyphen or underscore
	lastChar := rune(username[len(username)-1])
	if lastChar == '-' || lastChar == '_' {
		return false
	}

	return true
}

// isValidPhone checks if a phone number is valid
func (v *customValidator) isValidPhone(phone string) bool {
	// Basic phone number validation
	// Remove spaces, hyphens, and parentheses for validation
	cleaned := strings.ReplaceAll(phone, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "(", "")
	cleaned = strings.ReplaceAll(cleaned, ")", "")
	cleaned = strings.ReplaceAll(cleaned, "+", "")

	// Check if it contains only digits after cleaning
	for _, r := range cleaned {
		if !unicode.IsDigit(r) {
			return false
		}
	}

	// Check length (7-15 digits is generally acceptable)
	return len(cleaned) >= 7 && len(cleaned) <= 15
}

// isValidOrganizationName checks if an organization name is valid
func (v *customValidator) isValidOrganizationName(name string) bool {
	if len(name) < 2 || len(name) > 100 {
		return false
	}

	// Organization name should not be empty or contain only whitespace
	if strings.TrimSpace(name) == "" {
		return false
	}

	return true
}

// isValidRoleName checks if a role name is valid
func (v *customValidator) isValidRoleName(name string) bool {
	if len(name) < 2 || len(name) > 50 {
		return false
	}

	// Role name should contain only letters, numbers, spaces, hyphens, and underscores
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' && r != '-' && r != '_' {
			return false
		}
	}

	return true
}

// isValidPermission checks if a permission string is valid
func (v *customValidator) isValidPermission(permission string) bool {
	// Permission format: resource:action (e.g., "users:read", "organizations:write")
	parts := strings.Split(permission, ":")
	if len(parts) != 2 {
		return false
	}

	resource, action := parts[0], parts[1]

	// Both resource and action should be non-empty and contain only letters, numbers, and underscores
	if resource == "" || action == "" {
		return false
	}

	resourcePattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)
	actionPattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)

	return resourcePattern.MatchString(resource) && actionPattern.MatchString(action)
}

// isValidWebhookURL checks if a webhook URL is valid
func (v *customValidator) isValidWebhookURL(url string) bool {
	// Basic URL validation
	if err := v.validator.Var(url, "url"); err != nil {
		return false
	}

	// Must be HTTPS for security
	return strings.HasPrefix(url, "https://")
}

// isValidRedirectURI checks if an OAuth redirect URI is valid
func (v *customValidator) isValidRedirectURI(uri string) bool {
	// Allow both HTTP (for development) and HTTPS
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		return false
	}

	// Basic URL validation
	return v.validator.Var(uri, "url") == nil
}

// isValidScope checks if an OAuth scope is valid
func (v *customValidator) isValidScope(scope string) bool {
	// Scope should contain only letters, numbers, colons, and spaces
	scopePattern := regexp.MustCompile(`^[a-zA-Z0-9:_ ]+$`)
	return scopePattern.MatchString(scope)
}

// isDisposableEmail checks if an email is from a disposable email provider
func (v *customValidator) isDisposableEmail(email string) bool {
	// Basic check for common disposable email domains
	disposableDomains := []string{
		"10minutemail.com",
		"guerrillamail.com",
		"mailinator.com",
		"tempmail.org",
		"throwaway.email",
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	domain := strings.ToLower(parts[1])
	for _, disposable := range disposableDomains {
		if domain == disposable {
			return true
		}
	}

	return false
}

// isCommonPassword checks if a password is commonly used
func (v *customValidator) isCommonPassword(password string) bool {
	// List of common weak passwords
	commonPasswords := []string{
		"password", "123456", "password123", "admin", "qwerty",
		"letmein", "welcome", "monkey", "1234567890", "abc123",
		"password1", "123456789", "welcome123", "admin123",
	}

	lowerPassword := strings.ToLower(password)
	for _, common := range commonPasswords {
		if lowerPassword == common {
			return true
		}
	}

	return false
}

// Convenience functions for common validations

// ValidateEmail validates an email address using the default validator
func ValidateEmail(email string) error {
	validator := New()
	return validator.ValidateEmail(email)
}

// ValidatePassword validates a password using the default policy
func ValidatePassword(password string) error {
	validator := New()
	return validator.ValidatePassword(password, DefaultPasswordPolicy())
}

// ValidatePasswordWithPolicy validates a password with a custom policy
func ValidatePasswordWithPolicy(password string, policy *PasswordPolicy) error {
	validator := New()
	return validator.ValidatePassword(password, policy)
}

// ValidateUsername validates a username
func ValidateUsername(username string) error {
	validator := New()
	return validator.ValidateUsername(username)
}

// ValidatePhone validates a phone number
func ValidatePhone(phone string) error {
	validator := New()
	return validator.ValidatePhone(phone)
}

// ValidateXID validates an XID
func ValidateXID(id string) error {
	validator := New()
	return validator.ValidateXID(id)
}

// IsValidXID checks if a string is a valid XID
func IsValidXID(id string) bool {
	_, err := xid.FromString(id)
	return err == nil
}

// IsValidEmail checks if a string is a valid email
func IsValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// IsStrongPassword checks if a password meets basic strength requirements
func IsStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	var hasUpper, hasLower, hasDigit bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}

	return hasUpper && hasLower && hasDigit
}
