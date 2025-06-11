package contexts

import (
	"context"
	"net/http"
)

// GetIPAddressFromContext retrieves the client IP address from the context.
func GetIPAddressFromContext(ctx context.Context) (string, bool) {
	ip, ok := ctx.Value(IPAddressContextKey).(string)
	return ip, ok
}

// GetUserAgentFromContext retrieves the User-Agent from the context.
func GetUserAgentFromContext(ctx context.Context) (string, bool) {
	ua, ok := ctx.Value(UserAgentContextKey).(string)
	return ua, ok
}

// GetHeadersFromContext retrieves the headers from the context.
func GetHeadersFromContext(ctx context.Context) (http.Header, bool) {
	h, ok := ctx.Value(HeadersContextKKey).(http.Header)
	return h, ok
}
