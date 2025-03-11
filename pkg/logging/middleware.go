package logging

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Middleware creates a middleware that logs HTTP requests
func Middleware(next http.Handler) http.Handler {
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
		ctx := WithRequestID(r.Context(), requestID)

		// Create logger with request context
		logger := GetLogger().WithContext(ctx).With(
			String("method", r.Method),
			String("path", r.URL.Path),
			String("remote_addr", GetIPAddress(r)),
			String("user_agent", r.UserAgent()),
			String("request_id", requestID),
		)

		// Add logger to context
		ctx = WithContext(ctx, logger)
		r = r.WithContext(ctx)

		// Create wrapper response writer to capture status code
		ww := NewResponseWriter(w)

		// Log request
		logger.Info("Request started")

		// Call next handler
		next.ServeHTTP(ww, r)

		// Log response
		duration := time.Since(start)
		logger.With(
			Int("status", ww.Status()),
			Int("size", ww.Size()),
			Duration("duration", duration),
		).Info("Request completed")
	})
}

// ResponseWriter is a wrapper around http.ResponseWriter that captures the status code
type ResponseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

// NewResponseWriter creates a new response writer
func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
}

// WriteHeader captures the status code
func (rw *ResponseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

// Write captures the size of the response
func (rw *ResponseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// Status returns the status code
func (rw *ResponseWriter) Status() int {
	return rw.status
}

// Size returns the size of the response
func (rw *ResponseWriter) Size() int {
	return rw.size
}

// Flush implements http.Flusher
func (rw *ResponseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker
func (rw *ResponseWriter) Hijack() (interface{}, interface{}, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// GetIPAddress extracts the client IP address from a request
func GetIPAddress(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// X-Forwarded-For can be a comma-separated list; use the first address
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header next
	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		return xRealIP
	}

	// Fall back to remote address
	return strings.Split(r.RemoteAddr, ":")[0]
}
