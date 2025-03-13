package validator

import (
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

// FrankValidator handles validation for authentication-related operations
type FrankValidator struct {
	validator *validator.Validate
}

var (
	// Instance of the validator for singleton use
	valInstance *FrankValidator
)

func New() *FrankValidator {
	validate := validator.New()

	// Use JSON field names for error reporting
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return fld.Name
		}
		return name
	})

	// Register custom validators
	_ = validate.RegisterValidation("email", validateEmail)
	_ = validate.RegisterValidation("password", validatePassword)
	_ = validate.RegisterValidation("phone", validatePhone)
	_ = validate.RegisterValidation("url", validateURL)
	_ = validate.RegisterValidation("slug", validateSlug)
	_ = validate.RegisterValidation("hex", validateHex)
	_ = validate.RegisterValidation("redirect_uri", validateRedirectURI)
	_ = validate.RegisterValidation("webhook_url", validateWebhookURL)
	_ = validate.RegisterValidation("password_strength", validatePasswordStrength)

	// Register custom validators
	_ = validate.RegisterValidation("api_key", validateAPIKey)
	_ = validate.RegisterValidation("session_token", validateSessionToken)
	_ = validate.RegisterValidation("otp", validateOTP)
	_ = validate.RegisterValidation("password_strength", validatePasswordStrength)
	_ = validate.RegisterValidation("redirect_uri", validateRedirectURI)
	_ = validate.RegisterValidation("webhook_url", validateWebhookURL)
	_ = validate.RegisterValidation("csrf_token", validateCSRFToken)
	_ = validate.RegisterValidation("auth_code", validateAuthCode)

	return &FrankValidator{validator: validate}
}

// GetInstance returns the singleton instance of FrankValidator
func GetInstance() *FrankValidator {
	if valInstance == nil {
		valInstance = New()
	}
	return valInstance
}
