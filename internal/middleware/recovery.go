package middleware

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/xraph/frank/config"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/utils"
)

// Recovery is a middleware that recovers from panics and returns a 500 response
func Recovery(logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use request-specific logger if available
			reqLogger := logging.FromContext(r.Context())

			defer func() {
				if rec := recover(); rec != nil {
					// Log the panic with stack trace
					stack := debug.Stack()
					requestID := logging.RequestIDFromContext(r.Context())

					// Format error with stacktrace
					errMsg := fmt.Sprintf("PANIC: %v\n%s", rec, string(stack))

					reqLogger.Error("Panic recovery",
						logging.Any("error", rec),
						logging.String("stack", string(stack)),
						logging.String("request_id", requestID),
						logging.String("uri", r.RequestURI),
						logging.String("method", r.Method),
					)

					// Return a generic error to the client
					err := errors.New(errors.CodeInternalServer, "An unexpected error occurred")

					// Only include detailed error in development mode
					if config.IsDevelopment() {
						err = errors.New(errors.CodeInternalServer, errMsg)
					}

					// Return error response
					utils.RespondError(w, err)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// ErrorHandler middleware catches errors returned from handlers and standardizes responses
func ErrorHandler(logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqLogger := logging.FromContext(r.Context())

			// Create a response writer that captures errors
			rw := NewErrorCaptureResponseWriter(w)

			// Process the request
			next.ServeHTTP(rw, r)

			// If an error was captured, handle it appropriately
			if rw.Err != nil {
				requestID := logging.RequestIDFromContext(r.Context())

				// Log the error
				reqLogger.Error("Request error",
					logging.Error(rw.Err),
					logging.String("request_id", requestID),
					logging.String("uri", r.RequestURI),
					logging.String("method", r.Method),
				)

				// Return standardized error response
				utils.RespondError(w, rw.Err)
			}
		})
	}
}

// ErrorCaptureResponseWriter captures errors from handlers
type ErrorCaptureResponseWriter struct {
	http.ResponseWriter
	Err error
}

// NewErrorCaptureResponseWriter creates a new error capturing response writer
func NewErrorCaptureResponseWriter(w http.ResponseWriter) *ErrorCaptureResponseWriter {
	return &ErrorCaptureResponseWriter{ResponseWriter: w}
}

// CaptureError captures an error
func (w *ErrorCaptureResponseWriter) CaptureError(err error) {
	w.Err = err
}

// Write writes the response
func (w *ErrorCaptureResponseWriter) Write(b []byte) (int, error) {
	if w.Err != nil {
		return 0, nil
	}
	return w.ResponseWriter.Write(b)
}

// WriteHeader writes the header
func (w *ErrorCaptureResponseWriter) WriteHeader(statusCode int) {
	if w.Err != nil {
		return
	}
	w.ResponseWriter.WriteHeader(statusCode)
}
