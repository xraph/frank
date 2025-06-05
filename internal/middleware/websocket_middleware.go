// Add this to a new file websocket_middleware.go
package middleware

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// IsWebSocketRequest checks if the request is a WebSocket upgrade request
func IsWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// WebSocketSafeResponseWriter is a ResponseWriter wrapper that preserves the http.Hijacker interface
type WebSocketSafeResponseWriter struct {
	http.ResponseWriter
}

// These methods ensure all ResponseWriter interfaces are implemented
func (w *WebSocketSafeResponseWriter) WriteHeader(code int) {
	w.ResponseWriter.WriteHeader(code)
}

func (w *WebSocketSafeResponseWriter) Write(b []byte) (int, error) {
	return w.ResponseWriter.Write(b)
}

func (w *WebSocketSafeResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

// Hijack calls the underlying ResponseWriter's Hijack method if it implements http.Hijacker
func (w *WebSocketSafeResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

// WebSocketMiddlewareGate provides middleware that skips certain middleware for WebSocket requests
func WebSocketMiddlewareGate(wsHandler http.Handler, regularHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsWebSocketRequest(r) {
			wsHandler.ServeHTTP(w, r)
			return
		}
		regularHandler.ServeHTTP(w, r)
	})
}

// WebSocketSafeMiddleware wraps a middleware to make it WebSocket-compatible
func WebSocketSafeMiddleware(middleware func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsWebSocketRequest(r) {
				// For WebSocket requests, preserve the original response writer
				next.ServeHTTP(w, r)
				return
			}

			// For regular requests, apply the middleware
			wrappedHandler := middleware(next)
			wrappedHandler.ServeHTTP(w, r)
		})
	}
}

// IsSSERequest checks if the request is for Server-Sent Events
func IsSSERequest(r *http.Request) bool {
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "text/event-stream") ||
		strings.HasSuffix(r.URL.Path, "/events") ||
		strings.Contains(r.URL.Path, "/event") ||
		strings.Contains(r.URL.Path, "-events") ||
		r.Header.Get("Cache-Control") == "no-cache"
}

// IsStreamingRequest checks if the request is for any streaming protocol
func IsStreamingRequest(r *http.Request) bool {
	return IsWebSocketRequest(r) || IsSSERequest(r)
}

// ShouldSkipMiddleware determines if certain middleware should be skipped for this request
func ShouldSkipMiddleware(r *http.Request) bool {
	return IsStreamingRequest(r)
}
