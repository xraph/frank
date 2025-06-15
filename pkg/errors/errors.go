package errors

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// Error represents a custom error with context information
type Error struct {
	Code       string                 `json:"code"`
	ID         string                 `json:"id,omitempty"`
	StatusCode int                    `json:"status_code"`
	Message    string                 `json:"message"`
	Err        error                  `json:"error,omitempty"`
	Details    []string               `json:"details,omitempty"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// Error returns the error message
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap returns the wrapped error
func (e *Error) Unwrap() error {
	return e.Err
}

// Is implements the interface to work with errors.Is
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// WithMetadata adds metadata to the error
func (e *Error) WithMetadata(key string, value interface{}) *Error {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}

// WithDetails adds details to the error
func (e *Error) WithDetails(value interface{}) *Error {
	if e.Details == nil {
		e.Details = []string{}
	}
	e.Details = append(e.Details, fmt.Sprintf("%v", value))
	return e
}

func (e *Error) GetStatus() int {
	return e.StatusCode
}

// New creates a new error with a message
func New(code string, message string, a ...any) *Error {
	return &Error{
		Code:       code,
		StatusCode: GetStatusCode(code),
		Message:    fmt.Sprintf(message, a),
	}
}

// Newf creates a new error with a message
func Newf(code string, message string, a ...any) *Error {
	return &Error{
		Code:       code,
		StatusCode: GetStatusCode(code),
		Message:    fmt.Sprintf(message, a),
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, code string, message string) *Error {
	return &Error{
		Code:       code,
		StatusCode: GetStatusCode(code),
		Message:    message,
		Err:        err,
	}
}

// Wrapf wraps an existing error with additional context
func Wrapf(err error, code string, message string, a ...any) *Error {
	return &Error{
		Code:       code,
		StatusCode: GetStatusCode(code),
		Message:    fmt.Sprintf(message, a),
		Err:        err,
	}
}

// GetStatusCode maps error codes to HTTP status codes
func GetStatusCode(code string) int {
	// switch {
	// case code == CodeBadRequest:
	// 	return http.StatusBadRequest
	// case code == CodeUnauthorized:
	// 	return http.StatusUnauthorized
	// case code == CodeForbidden:
	// 	return http.StatusForbidden
	// case code == CodeNotFound:
	// 	return http.StatusNotFound
	// case code == CodeInternalServer:
	// 	return http.StatusInternalServerError
	// case code == CodeConflict:
	// 	return http.StatusConflict
	// case code == CodeTooManyRequests:
	// 	return http.StatusTooManyRequests
	// case code == CodeUnprocessableEntity:
	// 	return http.StatusUnprocessableEntity
	// case code == CodeMethodNotAllowed:
	// 	return http.StatusMethodNotAllowed
	// default:
	// 	return http.StatusInternalServerError
	// }

	// Authentication errors
	switch code {
	case CodeUnauthorized, CodeInvalidCredentials, CodeInvalidToken, CodeTokenExpired,
		CodeInvalidRefreshToken, CodeSessionExpired, CodeMFARequired, CodeMFAFailed,
		CodeEmailNotVerified, CodeInvalidAPIKey, CodeInvalidOAuthState, CodeOAuthFailed,
		CodeSSOMismatch, CodeInvalidPasskey, CodePasskeyRegistration, CodePasskeyAuthentication,
		CodePasswordlessLinkFailed:
		return http.StatusUnauthorized

	// Authorization errors
	case CodeForbidden, CodeFeatureNotEnabled:
		return http.StatusForbidden

	// Resource errors
	case CodeNotFound, CodeUserNotFound, CodeOrganizationNotFound,
		CodeResourceNotFound, CodeRoleNotFound, CodePermissionNotFound,
		CodeClientNotFound, CodeWebhookNotFound, CodeFeatureFlagNotFound,
		CodeScopeNotFound, CodeTemplateNotFound, CodeProviderNotFound:
		return http.StatusNotFound

	case CodeAlreadyExists, CodeConflict:
		return http.StatusConflict

	// Validation errors
	case CodeBadRequest, CodeInvalidInput, CodeInvalidFormat,
		CodeInvalidEmail, CodeInvalidPhone, CodeInvalidPassword,
		CodeInvalidOTP, CodePasswordTooWeak, CodeInvalidRedirectURI,
		CodeInvalidScope, CodeInvalidWebhookURL, CodeInvalidCallbackURL,
		CodeMissingRequiredField, CodeInvalidMetadata, CodeInvalidHeader,
		CodeInvalidCallback:
		return http.StatusBadRequest

	case CodeUnprocessableEntity:
		return http.StatusUnprocessableEntity

	// Server errors
	case CodeInternalServer, CodeDatabaseError, CodeCryptoError,
		CodeStorageError, CodeNetworkError, CodeWebhookDeliveryFail,
		CodeEmailDeliveryFail, CodeSMSDeliveryFail, CodeConfigurationError,
		CodeThirdPartyAPIError, CodeUnexpectedError, CodeIdentityProviderError,
		CodeProviderInitError, CodeProviderCommunicationError, CodeMissingUserInfo:
		return http.StatusInternalServerError

	case CodeServiceUnavailable:
		return http.StatusServiceUnavailable

	// Request handling errors
	case CodeMethodNotAllowed:
		return http.StatusMethodNotAllowed

	case CodeTooManyRequests, CodeRateLimited:
		return http.StatusTooManyRequests

	case CodeRequestTimeout:
		return http.StatusRequestTimeout

	case CodeUnsupportedOperation, CodeNotImplemented, CodeUnsupportedProvider:
		return http.StatusNotImplemented

	// SSO specific errors
	case CodeProviderDisabled, CodeDomainNotAllowed:
		return http.StatusForbidden

	// Default case for any unhandled error codes
	default:
		return http.StatusInternalServerError
	}
}

// IsNotFound checks if the error is a not found error
func IsNotFound(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Code == CodeNotFound
}

// IsUnauthorized checks if the error is an unauthorized error
func IsUnauthorized(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Code == CodeUnauthorized
}

// IsForbidden checks if the error is a forbidden error
func IsForbidden(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Code == CodeForbidden
}

// IsConflict checks if the error is a conflict error
func IsConflict(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Code == CodeConflict
}

// IsInternalServer checks if the error is an internal server error
func IsInternalServer(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Code == CodeInternalServer
}

// IsBadRequest checks if the error is a bad request error
func IsBadRequest(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Code == CodeBadRequest
}

// CustomErrorFormatter is a goa HTTP error formatter that formats errors according to our API standards
func CustomErrorFormatter(ctx context.Context, err error) goahttp.Statuser {
	// Check if it's already our custom error type
	if e, ok := err.(*ErrorResponse); ok {
		return e
	}

	// Check if it's already our custom error type
	if e, ok := err.(*Error); ok {
		return NewErrorResponse(e)
	}

	// Handle Goa's built-in ServiceError type (used for validation errors)
	if serr, ok := err.(*goa.ServiceError); ok {
		var code string
		var message string
		metadata := make(map[string]interface{})

		switch serr.Name {
		case "missing_field", "required":
			code = CodeMissingRequiredField
			if serr.Field != nil {
				message = fmt.Sprintf("The field '%s' is required", *serr.Field)
				metadata["field"] = *serr.Field
			} else {
				message = "A required field is missing"
			}

		case "invalid_field_type":
			code = CodeInvalidFormat
			message = serr.Message
			if serr.Field != nil {
				metadata["field"] = *serr.Field
			}

		case "invalid_format":
			code = CodeInvalidFormat
			message = serr.Message
			if serr.Field != nil {
				metadata["field"] = *serr.Field
				metadata["format_error"] = serr.Message
			}

		case "invalid_pattern":
			code = CodeInvalidFormat
			message = serr.Message
			if serr.Field != nil {
				metadata["field"] = *serr.Field
				metadata["pattern_error"] = serr.Message
			}

		case "invalid_range":
			code = CodeInvalidInput
			message = serr.Message
			if serr.Field != nil {
				metadata["field"] = *serr.Field
				metadata["range_error"] = serr.Message
			}

		case "invalid_length":
			code = CodeInvalidInput
			message = serr.Message
			if serr.Field != nil {
				metadata["field"] = *serr.Field
				metadata["length_error"] = serr.Message
			}

		case "enum":
			code = CodeInvalidInput
			message = serr.Message
			if serr.Field != nil {
				metadata["field"] = *serr.Field
				metadata["enum_error"] = serr.Message
			}

		default:
			code = CodeInvalidInput
			message = serr.Message
			if serr.ID != "" {
				metadata["error_id"] = serr.ID
			}
			if serr.Field != nil {
				metadata["field"] = *serr.Field
			}
		}

		return &ErrorResponse{
			Code:    code,
			Message: message,
			Details: metadata,
		}
	}

	// Check if it's another type of goa error with an HTTP status
	if statuser, ok := err.(goahttp.Statuser); ok {
		status := statuser.StatusCode()

		// Convert goa errors to our error format based on status code
		var code string
		switch status {
		case http.StatusBadRequest:
			code = CodeBadRequest
		case http.StatusUnauthorized:
			code = CodeUnauthorized
		case http.StatusForbidden:
			code = CodeForbidden
		case http.StatusNotFound:
			code = CodeNotFound
		case http.StatusMethodNotAllowed:
			code = CodeMethodNotAllowed
		case http.StatusConflict:
			code = CodeConflict
		case http.StatusUnprocessableEntity:
			code = CodeUnprocessableEntity
		case http.StatusTooManyRequests:
			code = CodeTooManyRequests
		case http.StatusInternalServerError:
			code = CodeInternalServer
		case http.StatusServiceUnavailable:
			code = CodeServiceUnavailable
		default:
			code = CodeInternalServer
		}
		return &ErrorResponse{
			Code:      toUpperSnakeCase(code),
			StatsCode: code,
			Message:   err.Error(),
		}
	}

	// Default to internal server error for unknown error types
	return &ErrorResponse{
		Code:      CodeInternalServer,
		StatsCode: CodeInternalServer,
		Message:   err.Error(),
	}
}

// ErrorResponse formats an error for HTTP response
type ErrorResponse struct {
	Code      string                 `json:"code"`
	StatsCode string                 `json:"_"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
} // @name FrankError

// NewErrorResponse creates a new error response from an error
func NewErrorResponse(err error) *ErrorResponse {
	if e, ok := err.(*Error); ok {
		return &ErrorResponse{
			Code:      toUpperSnakeCase(e.Code),
			StatsCode: e.Code,
			Message:   e.Message,
			Details:   e.Metadata,
		}
	}
	return &ErrorResponse{
		Code:      CodeInternalServer,
		StatsCode: CodeInternalServer,
		Message:   err.Error(),
	}
}

func (e *ErrorResponse) StatusCode() int {
	if GetStatusCode(e.StatsCode) == http.StatusInternalServerError {
		return GetStatusCode(e.Code)
	}

	return GetStatusCode(e.StatsCode)
}

// Error returns the error message
func (e *ErrorResponse) Error() string {
	return e.Message
}

func toUpperSnakeCase(s string) string {
	if s == "" {
		return ""
	}

	// First, handle camelCase and PascalCase by adding underscores
	var result strings.Builder
	result.WriteRune(unicode.ToUpper(rune(s[0])))

	for i := 1; i < len(s); i++ {
		if unicode.IsUpper(rune(s[i])) &&
			((i+1 < len(s) && unicode.IsLower(rune(s[i+1]))) ||
				(i-1 >= 0 && unicode.IsLower(rune(s[i-1])))) {
			result.WriteRune('_')
		}
		result.WriteRune(unicode.ToUpper(rune(s[i])))
	}

	// Then handle spaces, hyphens, and other separators
	processed := result.String()
	processed = strings.ReplaceAll(processed, " ", "_")
	processed = strings.ReplaceAll(processed, "-", "_")
	processed = strings.ReplaceAll(processed, ".", "_")

	// Remove consecutive underscores
	for strings.Contains(processed, "__") {
		processed = strings.ReplaceAll(processed, "__", "_")
	}

	return strings.ToUpper(processed)
}

// Is implements the interface to work with errors.Is
func Is(target error, code string) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return code == t.Code
}
