package logging

import (
	"bufio"
	"net"
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

		// Check if this is a WebSocket request
		isWebSocket := strings.ToLower(r.Header.Get("Upgrade")) == "websocket"

		isSSE := IsSSERequest(r)

		if isWebSocket {
			// For WebSocket connections, don't wrap the ResponseWriter
			logger.Info("WebSocket connection started")
			next.ServeHTTP(w, r)
			logger.Info("WebSocket connection handling complete")
			return
		} else if isSSE {
			// For SSE connections, use a minimal wrapper that preserves flusher
			logger.Info("SSE connection started")
			sseWrapper := &SSEResponseWriter{
				ResponseWriter: w,
				start:          start,
			}
			next.ServeHTTP(sseWrapper, r)
			return
		}

		// For regular HTTP requests, use the full wrapper
		ww := NewResponseWriter(w)
		logger.Info("Request started")
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

// IsSSERequest checks if the request is for Server-Sent Events
func IsSSERequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return accept == "text/event-stream" ||
		r.Header.Get("Cache-Control") == "no-cache" ||
		r.URL.Query().Get("stream") == "true"
}

// ResponseWriter is a wrapper around http.ResponseWriter that captures the status code
type ResponseWriter struct {
	http.ResponseWriter
	status        int
	size          int
	headerWritten bool
}

// NewResponseWriter creates a new response writer
func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
		headerWritten:  false,
	}
}

// WriteHeader captures the status code
func (rw *ResponseWriter) WriteHeader(status int) {
	if rw.headerWritten {
		return // Prevent multiple calls
	}
	rw.status = status
	rw.headerWritten = true
	rw.ResponseWriter.WriteHeader(status)
}

// Write captures the size of the response
func (rw *ResponseWriter) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		rw.WriteHeader(http.StatusOK)
	}
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
func (rw *ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// SSEResponseWriter is a minimal wrapper for SSE that preserves all interfaces
type SSEResponseWriter struct {
	http.ResponseWriter
	start time.Time
}

// Write tracks the response for SSE
func (w *SSEResponseWriter) Write(b []byte) (int, error) {
	return w.ResponseWriter.Write(b)
}

// Flush ensures flushing is available for SSE
func (w *SSEResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker for SSE
func (w *SSEResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// CloseNotify implements http.CloseNotifier for SSE
func (w *SSEResponseWriter) CloseNotify() <-chan bool {
	if cn, ok := w.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	// Return a channel that never sends if CloseNotifier is not available
	ch := make(chan bool)
	return ch
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
