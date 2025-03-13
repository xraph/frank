package validator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// ValidationMiddleware handles request validation
type ValidationMiddleware struct {
	logger    logging.Logger
	validator *FrankValidator
}

// NewValidationMiddleware creates a new validation middleware
func NewValidationMiddleware(logger logging.Logger) *ValidationMiddleware {
	return &ValidationMiddleware{
		logger:    logger,
		validator: GetInstance(),
	}
}

// ValidateRequest is a middleware that validates request bodies against a provided struct type
func (m *ValidationMiddleware) ValidateRequest(structPtr interface{}) func(http.Handler) http.Handler {
	// Get the type of the struct
	structType := reflect.TypeOf(structPtr)
	if structType.Kind() == reflect.Ptr {
		structType = structType.Elem()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only process POST, PUT, and PATCH requests
			if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
				next.ServeHTTP(w, r)
				return
			}

			// Check content type
			contentType := r.Header.Get("Content-Type")
			if !strings.HasPrefix(contentType, "application/json") {
				utils.RespondError(w, errors.New(errors.CodeInvalidInput, "Content-Type must be application/json"))
				return
			}

			// Create a new instance of the struct
			val := reflect.New(structType).Interface()

			// Read body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				utils.RespondError(w, errors.Wrap(errors.CodeInvalidInput, err, "Failed to read request body"))
				return
			}

			// Close and restore body for later use
			r.Body.Close()
			r.Body = io.NopCloser(strings.NewReader(string(body)))

			// Parse JSON
			if err := json.Unmarshal(body, val); err != nil {
				utils.RespondError(w, errors.Wrap(errors.CodeInvalidInput, err, "Invalid JSON format"))
				return
			}

			// Validate struct
			if err := m.validator.Validate(val); err != nil {
				utils.RespondError(w, err)
				return
			}

			// Store validated struct in request context
			ctx := r.Context()
			ctx = context.WithValue(ctx, validatedDataKey, val)

			// Continue with the valid request
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ValidationFunc is a function that performs validation
type ValidationFunc func(r *http.Request) error

// ValidateRequestFunc validates a request using a custom validation function
func (m *ValidationMiddleware) ValidateRequestFunc(validationFunc ValidationFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := validationFunc(r); err != nil {
				utils.RespondError(w, err)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// contextKey is a private type for context keys
type contextKey string

const (
	// validatedDataKey is the key for validated data in the request context
	validatedDataKey contextKey = "validated_data"
)

// GetValidatedData retrieves the validated data from the request context
func GetValidatedData(r *http.Request) interface{} {
	return r.Context().Value(validatedDataKey)
}

// GetValidatedDataAs retrieves and casts the validated data to the provided type
func GetValidatedDataAs[T any](r *http.Request) (T, bool) {
	data := r.Context().Value(validatedDataKey)
	if data == nil {
		var zero T
		return zero, false
	}

	typed, ok := data.(*T)
	if !ok {
		var zero T
		return zero, false
	}

	return *typed, true
}

// ValidateInput is a generic function to validate and return any input type
func ValidateInput[T any](r *http.Request) (*T, error) {
	var input T

	// Decode JSON
	if err := utils.DecodeJSON(r, &input); err != nil {
		return nil, err
	}

	// Validate struct
	if err := GetInstance().Validate(&input); err != nil {
		return nil, err
	}

	return &input, nil
}

// ValidateDecodeJSON is a generic function to validate and return any input type
func ValidateDecodeJSON[T any](r *http.Request, input T) error {
	// Decode JSON
	if err := utils.DecodeJSON(r, input); err != nil {
		return err
	}

	// Validate struct
	if err := GetInstance().Validate(input); err != nil {
		return err
	}

	return nil
}
