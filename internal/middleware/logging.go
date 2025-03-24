package middleware

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/juicycleff/frank/pkg/logging"
)

// Logging middleware enhances the built-in logging middleware
func Logging(logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Generate or extract request ID
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = uuid.New().String()
				r.Header.Set("X-Request-ID", requestID)
			}

			// Set request ID header in response
			w.Header().Set("X-Request-ID", requestID)

			// Create new context with request ID
			ctx := logging.WithRequestID(r.Context(), requestID)

			// Create logger with request context
			reqLogger := logger.WithContext(ctx).With(
				logging.String("method", r.Method),
				logging.String("path", r.URL.Path),
				logging.String("remote_addr", logging.GetIPAddress(r)),
				logging.String("user_agent", r.UserAgent()),
				logging.String("request_id", requestID),
			)

			// Add logger to context
			ctx = logging.WithContext(ctx, reqLogger)
			r = r.WithContext(ctx)

			// Create wrapper response writer to capture status code
			ww := logging.NewResponseWriter(w)

			// Log request
			reqLogger.Info("Request started")

			// Call next handler
			next.ServeHTTP(ww, r)

			// Calculate and log response time
			duration := time.Since(start)
			reqLogger.With(
				logging.Int("status", ww.Status()),
				logging.Int("size", ww.Size()),
				logging.Duration("duration", duration),
			).Info("Request completed")
		})
	}
}

// RequestLogging logs detailed information about requests and responses
func RequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get logger from context
		logger := logging.FromContext(r.Context())

		// Log details about the incoming request
		logger.Debug("Request details",
			logging.String("method", r.Method),
			logging.String("path", r.URL.Path),
			logging.String("query", r.URL.RawQuery),
			logging.String("protocol", r.Proto),
			logging.String("remote_addr", r.RemoteAddr),
			logging.String("user_agent", r.UserAgent()),
			logging.String("referer", r.Referer()),
			logging.String("content_type", r.Header.Get("Content-Type")),
			logging.String("content_length", r.Header.Get("Content-Length")),
		)

		// Create a response writer wrapper
		ww := logging.NewResponseWriter(w)

		// Process the request
		start := time.Now()
		next.ServeHTTP(ww, r)
		duration := time.Since(start)

		// Log additional details about the response
		logger.Debug("Response details",
			logging.Int("status", ww.Status()),
			logging.Int("size", ww.Size()),
			logging.Duration("duration", duration),
			logging.String("content_type", ww.Header().Get("Content-Type")),
		)

		// Extract authentication information if available
		userID, hasUserID := GetUserIDReq(r)
		orgID, hasOrgID := GetOrganizationID(r)

		if hasUserID {
			logger.With(logging.String("user_id", userID)).Debug("Authenticated request")
		}

		if hasOrgID {
			logger.With(logging.String("organization_id", orgID)).Debug("Organization context")
		}
	})
}
