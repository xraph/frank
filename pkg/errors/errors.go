package errors

import (
	"fmt"
	"net/http"
)

// Error represents a custom error with context information
type Error struct {
	Code       string
	StatusCode int
	Message    string
	Err        error
	Metadata   map[string]interface{}
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

// WithMetadata adds metadata to the error
func (e *Error) WithMetadata(key string, value interface{}) *Error {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}

// New creates a new error with a message
func New(code string, message string) *Error {
	return &Error{
		Code:       code,
		StatusCode: GetStatusCode(code),
		Message:    message,
	}
}

// Wrap wraps an existing error with additional context
func Wrap(code string, err error, message string) *Error {
	return &Error{
		Code:       code,
		StatusCode: GetStatusCode(code),
		Message:    message,
		Err:        err,
	}
}

// GetStatusCode maps error codes to HTTP status codes
func GetStatusCode(code string) int {
	switch {
	case code == CodeBadRequest:
		return http.StatusBadRequest
	case code == CodeUnauthorized:
		return http.StatusUnauthorized
	case code == CodeForbidden:
		return http.StatusForbidden
	case code == CodeNotFound:
		return http.StatusNotFound
	case code == CodeInternalServer:
		return http.StatusInternalServerError
	case code == CodeConflict:
		return http.StatusConflict
	case code == CodeTooManyRequests:
		return http.StatusTooManyRequests
	case code == CodeUnprocessableEntity:
		return http.StatusUnprocessableEntity
	case code == CodeMethodNotAllowed:
		return http.StatusMethodNotAllowed
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

// ErrorResponse formats an error for HTTP response
type ErrorResponse struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data,omitempty"`
} // @name FrankError

// NewErrorResponse creates a new error response from an error
func NewErrorResponse(err error) *ErrorResponse {
	if e, ok := err.(*Error); ok {
		return &ErrorResponse{
			Code:    e.Code,
			Message: e.Message,
			Data:    e.Metadata,
		}
	}
	return &ErrorResponse{
		Code:    CodeInternalServer,
		Message: err.Error(),
	}
}
