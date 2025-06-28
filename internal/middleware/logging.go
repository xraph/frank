package middleware

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/juicycleff/frank/pkg/contexts"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// LoggingConfig represents logging middleware configuration
type LoggingConfig struct {
	SkipPaths            []string      // Paths to skip logging
	SkipUserAgents       []string      // User agents to skip logging
	RequestHeaders       []string      // Request headers to log
	ResponseHeaders      []string      // Response headers to log
	LogRequestBody       bool          // Whether to log request body
	LogResponseBody      bool          // Whether to log response body
	MaxBodySize          int           // Maximum body size to log
	SensitiveHeaders     []string      // Headers to redact
	SensitiveParams      []string      // Query parameters to redact
	LogSlowRequests      bool          // Log slow requests
	SlowRequestThreshold time.Duration // Threshold for slow requests
	StructuredLogging    bool          // Use structured logging
	IncludeUserContext   bool          // Include user context in logs
	Environment          string        // Environment (dev, prod, etc.)
}

// DefaultLoggingConfig returns default logging configuration
func DefaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		SkipPaths: []string{
			"/health",
			"/ready",
			"/metrics",
			"/favicon.ico",
			"/robots.txt",
		},
		SkipUserAgents: []string{
			"kube-probe",
			"GoogleHC",
			"ELB-HealthChecker",
		},
		RequestHeaders: []string{
			"Content-Type",
			"Accept",
			"User-Agent",
			"Referer",
			"X-Forwarded-For",
			"X-Real-IP",
			"X-Request-ID",
			"X-Correlation-ID",
		},
		ResponseHeaders: []string{
			"Content-Type",
			"Content-Length",
			"X-Request-ID",
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
		},
		SensitiveHeaders: []string{
			"Authorization",
			"Cookie",
			"Set-Cookie",
			"X-API-Key",
			"X-Auth-Token",
		},
		SensitiveParams: []string{
			"password",
			"token",
			"secret",
			"key",
			"api_key",
		},
		LogRequestBody:       false,
		LogResponseBody:      false,
		MaxBodySize:          1024 * 10, // 10KB
		LogSlowRequests:      true,
		SlowRequestThreshold: 2 * time.Second,
		StructuredLogging:    true,
		IncludeUserContext:   true,
		Environment:          "development",
	}
}

// responseWriter is a wrapper around http.ResponseWriter to capture response data
type responseWriter struct {
	http.ResponseWriter
	status      int
	size        int
	body        *bytes.Buffer
	captureBody bool
}

func newResponseWriter(w http.ResponseWriter, captureBody bool) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
		body:           &bytes.Buffer{},
		captureBody:    captureBody,
	}
}

func (w *responseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	size, err := w.ResponseWriter.Write(b)
	w.size += size

	if w.captureBody && w.body.Len() < 10*1024 { // Limit captured body size
		w.body.Write(b)
	}

	return size, err
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseWriter does not support hijacking")
}

func (w *responseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return fmt.Errorf("ResponseWriter does not support server push")
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp       time.Time         `json:"timestamp"`
	RequestID       string            `json:"request_id,omitempty"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Path            string            `json:"path"`
	Query           string            `json:"query,omitempty"`
	Protocol        string            `json:"protocol"`
	Status          int               `json:"status"`
	ResponseSize    int               `json:"response_size"`
	Duration        time.Duration     `json:"duration"`
	DurationMs      float64           `json:"duration_ms"`
	RemoteAddr      string            `json:"remote_addr"`
	RealIP          string            `json:"real_ip,omitempty"`
	UserAgent       string            `json:"user_agent,omitempty"`
	Referer         string            `json:"referer,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`

	// User context
	UserID         *xid.ID `json:"user_id,omitempty"`
	UserType       string  `json:"user_type,omitempty"`
	OrganizationID *xid.ID `json:"organization_id,omitempty"`
	SessionID      *xid.ID `json:"session_id,omitempty"`
	APIKeyID       *xid.ID `json:"api_key_id,omitempty"`
	AuthMethod     string  `json:"auth_method,omitempty"`

	// Error information
	Error     string `json:"error,omitempty"`
	ErrorType string `json:"error_type,omitempty"`

	// Additional metadata
	IsSlowRequest bool `json:"is_slow_request,omitempty"`
	IsError       bool `json:"is_error,omitempty"`
	IsClientError bool `json:"is_client_error,omitempty"`
	IsServerError bool `json:"is_server_error,omitempty"`

	// Tracing
	TraceID string `json:"trace_id,omitempty"`
	SpanID  string `json:"span_id,omitempty"`
}

// Logging creates a structured logging middleware
func Logging(logger logging.Logger) func(http.Handler) http.Handler {
	config := DefaultLoggingConfig()
	return LoggingWithConfig(logger, config)
}

// LoggingWithConfig creates a logging middleware with custom configuration
func LoggingWithConfig(logger logging.Logger, config *LoggingConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Skip logging for certain paths
			if shouldSkipLogging(r, config) {
				next.ServeHTTP(w, r)
				return
			}

			// Generate request ID if not present
			requestID := middleware.GetReqID(r.Context())
			if requestID == "" {
				requestID = xid.New().String()
				r = r.WithContext(context.WithValue(r.Context(), middleware.RequestIDKey, requestID))
			}

			// Capture request body if configured
			var requestBody string
			if config.LogRequestBody && r.Body != nil {
				bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, int64(config.MaxBodySize)))
				if err == nil {
					requestBody = string(bodyBytes)
					r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				}
			}

			// Wrap response writer
			wrapped := newResponseWriter(w, config.LogResponseBody)

			// Process request
			next.ServeHTTP(wrapped, r)

			// Calculate duration
			duration := time.Since(start)

			// Create log entry
			entry := createLogEntry(r, wrapped, duration, requestID, requestBody, config)

			// Add user context if available
			if config.IncludeUserContext {
				addUserContextToLogEntry(r.Context(), entry)
			}

			// Log the entry
			logEntry(logger, entry, config)
		})
	}
}

// DevelopmentLogging creates a development-friendly logging middleware
func DevelopmentLogging(logger logging.Logger) func(http.Handler) http.Handler {
	config := DefaultLoggingConfig()
	config.Environment = "development"
	config.LogRequestBody = true
	config.LogResponseBody = true
	config.MaxBodySize = 1024 * 50 // 50KB for development

	return LoggingWithConfig(logger, config)
}

// ProductionLogging creates a production-optimized logging middleware
func ProductionLogging(logger logging.Logger) func(http.Handler) http.Handler {
	config := DefaultLoggingConfig()
	config.Environment = "production"
	config.LogRequestBody = false
	config.LogResponseBody = false
	config.SkipPaths = append(config.SkipPaths,
		"/debug/",
		"/assets/",
		"/static/",
	)

	return LoggingWithConfig(logger, config)
}

// SecurityLogging creates a security-focused logging middleware
func SecurityLogging(logger logging.Logger) func(http.Handler) http.Handler {
	config := DefaultLoggingConfig()
	config.LogRequestBody = true
	config.LogResponseBody = false
	config.RequestHeaders = append(config.RequestHeaders,
		"X-Forwarded-Proto",
		"X-Forwarded-Host",
		"X-Forwarded-Port",
		"CF-Connecting-IP",
		"CF-Ray",
	)
	config.IncludeUserContext = true
	config.SlowRequestThreshold = 1 * time.Second

	return LoggingWithConfig(logger, config)
}

// APILogging creates an API-specific logging middleware
func APILogging(logger logging.Logger) func(http.Handler) http.Handler {
	config := DefaultLoggingConfig()
	config.RequestHeaders = append(config.RequestHeaders,
		"Accept-Encoding",
		"Content-Length",
		"X-Org-ID",
		"X-Client-Version",
	)
	config.ResponseHeaders = append(config.ResponseHeaders,
		"X-Total-Count",
		"X-Page-Count",
		"Cache-Control",
		"ETag",
	)
	config.LogSlowRequests = true
	config.SlowRequestThreshold = 500 * time.Millisecond

	return LoggingWithConfig(logger, config)
}

// Helper functions

func shouldSkipLogging(r *http.Request, config *LoggingConfig) bool {
	// Skip based on path
	for _, skipPath := range config.SkipPaths {
		if strings.HasPrefix(r.URL.Path, skipPath) {
			return true
		}
	}

	// Skip based on user agent
	userAgent := r.UserAgent()
	for _, skipUA := range config.SkipUserAgents {
		if strings.Contains(userAgent, skipUA) {
			return true
		}
	}

	return false
}

func createLogEntry(r *http.Request, w *responseWriter, duration time.Duration, requestID, requestBody string, config *LoggingConfig) *LogEntry {
	entry := &LogEntry{
		Timestamp:    time.Now(),
		RequestID:    requestID,
		Method:       r.Method,
		URL:          r.URL.String(),
		Path:         r.URL.Path,
		Query:        redactSensitiveParams(r.URL.RawQuery, config.SensitiveParams),
		Protocol:     r.Proto,
		Status:       w.status,
		ResponseSize: w.size,
		Duration:     duration,
		DurationMs:   float64(duration.Nanoseconds()) / 1e6,
		RemoteAddr:   r.RemoteAddr,
		RealIP:       getRealIP(r),
		UserAgent:    r.UserAgent(),
		Referer:      r.Referer(),
	}

	// Add request headers
	if len(config.RequestHeaders) > 0 {
		entry.RequestHeaders = extractHeaders(r.Header, config.RequestHeaders, config.SensitiveHeaders)
	}

	// Add response headers
	if len(config.ResponseHeaders) > 0 {
		entry.ResponseHeaders = extractHeaders(w.Header(), config.ResponseHeaders, config.SensitiveHeaders)
	}

	// Add request body
	if config.LogRequestBody && requestBody != "" {
		entry.RequestBody = truncateString(requestBody, config.MaxBodySize)
	}

	// Add response body
	if config.LogResponseBody && w.body.Len() > 0 {
		entry.ResponseBody = truncateString(w.body.String(), config.MaxBodySize)
	}

	// Add flags
	entry.IsSlowRequest = config.LogSlowRequests && duration > config.SlowRequestThreshold
	entry.IsError = w.status >= 400
	entry.IsClientError = w.status >= 400 && w.status < 500
	entry.IsServerError = w.status >= 500

	return entry
}

func addUserContextToLogEntry(ctx context.Context, entry *LogEntry) {
	if user := GetUserFromContext(ctx); user != nil {
		entry.UserID = &user.ID
		entry.UserType = string(user.UserType)
		entry.OrganizationID = user.OrganizationID
	}

	if session := GetSessionFromContext(ctx); session != nil {
		entry.SessionID = &session.ID
	}

	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil {
		entry.APIKeyID = &apiKey.ID
	}

	if authMethod := GetAuthMethodFromContext(ctx); authMethod != contexts.AuthMethodNone {
		entry.AuthMethod = string(authMethod)
	}
}

func logEntry(logger logging.Logger, entry *LogEntry, config *LoggingConfig) {
	fields := []logging.Field{
		logging.String("method", entry.Method),
		logging.String("path", entry.Path),
		logging.Int("status", entry.Status),
		logging.Duration("duration", entry.Duration),
		logging.Float64("duration_ms", entry.DurationMs),
		logging.String("remote_addr", entry.RemoteAddr),
		logging.Int("response_size", entry.ResponseSize),
	}

	// Add request ID
	if entry.RequestID != "" {
		fields = append(fields, logging.String("request_id", entry.RequestID))
	}

	// Add real IP
	if entry.RealIP != "" {
		fields = append(fields, logging.String("real_ip", entry.RealIP))
	}

	// Add user agent
	if entry.UserAgent != "" {
		fields = append(fields, logging.String("user_agent", entry.UserAgent))
	}

	// Add user context
	if entry.UserID != nil {
		fields = append(fields, logging.String("user_id", entry.UserID.String()))
	}

	if entry.UserType != "" {
		fields = append(fields, logging.String("user_type", entry.UserType))
	}

	if entry.OrganizationID != nil {
		fields = append(fields, logging.String("organization_id", entry.OrganizationID.String()))
	}

	if entry.AuthMethod != "" {
		fields = append(fields, logging.String("auth_method", entry.AuthMethod))
	}

	// Add query if present
	if entry.Query != "" {
		fields = append(fields, logging.String("query", entry.Query))
	}

	// Add slow request flag
	if entry.IsSlowRequest {
		fields = append(fields, logging.Bool("slow_request", true))
	}

	// Create log message
	message := fmt.Sprintf("%s %s", entry.Method, entry.Path)

	// Log at appropriate level
	switch {
	case entry.IsServerError:
		logger.Error(message, fields...)
	case entry.IsClientError:
		logger.Warn(message, fields...)
	case entry.IsSlowRequest:
		logger.Warn(message, fields...)
	case config.Environment == "development":
		logger.Info(message, fields...)
	default:
		logger.Debug(message, fields...)
	}
}

func extractHeaders(headers http.Header, includeHeaders, sensitiveHeaders []string) map[string]string {
	result := make(map[string]string)

	for _, header := range includeHeaders {
		if value := headers.Get(header); value != "" {
			// Check if header is sensitive
			if isSensitiveHeader(header, sensitiveHeaders) {
				result[header] = "[REDACTED]"
			} else {
				result[header] = value
			}
		}
	}

	return result
}

func isSensitiveHeader(header string, sensitiveHeaders []string) bool {
	headerLower := strings.ToLower(header)
	for _, sensitive := range sensitiveHeaders {
		if strings.ToLower(sensitive) == headerLower {
			return true
		}
	}
	return false
}

func redactSensitiveParams(query string, sensitiveParams []string) string {
	if query == "" {
		return ""
	}

	// Simple redaction - in production you might want more sophisticated parsing
	result := query
	for _, param := range sensitiveParams {
		// Redact parameter values
		paramLower := strings.ToLower(param)
		if strings.Contains(strings.ToLower(result), paramLower+"=") {
			// This is a simple approach - you might want to use url.ParseQuery for proper handling
			result = strings.ReplaceAll(result, param+"=", param+"=[REDACTED]")
		}
	}

	return result
}

func getRealIP(r *http.Request) string {
	// Check various forwarded headers
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP if there are multiple
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return cfip
	}

	// Extract IP from RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}

	return r.RemoteAddr
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// IsWebSocketRequest checks if the request is a WebSocket upgrade request
func IsWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// IsSSERequest checks if the request expects Server-Sent Events
func IsSSERequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/event-stream")
}

// RequestLogger creates a request-scoped logger with context
func RequestLogger(ctx context.Context, baseLogger logging.Logger) logging.Logger {
	fields := []logging.Field{}

	// Add request ID
	if requestID := middleware.GetReqID(ctx); requestID != "" {
		fields = append(fields, logging.String("request_id", requestID))
	}

	// Add user context
	if user := GetUserFromContext(ctx); user != nil {
		fields = append(fields, logging.String("user_id", user.ID.String()))
		fields = append(fields, logging.String("user_type", string(user.UserType)))

		if user.OrganizationID != nil {
			fields = append(fields, logging.String("organization_id", user.OrganizationID.String()))
		}
	}

	if len(fields) > 0 {
		return baseLogger.With(fields...)
	}

	return baseLogger
}
