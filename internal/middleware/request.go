package middleware

import (
	"context"
	"net/http"
	"net/url"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/contexts"
)

// AddHeader is a middleware that attaches request headers to the context using the specified permission.
func AddHeader() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), contexts.HeadersContextKKey, r.Header))
			// Try header first
			keyValue := r.Header.Get("X-Org-ID")
			if keyValue != "" {
				id, err := xid.FromString(keyValue)
				if err == nil {
					r = r.WithContext(context.WithValue(r.Context(), contexts.OrganizationIDContextKey, id))
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetHeaders retrieves the HTTP headers from the provided context associated with the UserIDKey.
// Returns the headers and a boolean indicating success or failure of the retrieval.
func GetHeaders(ctx context.Context) (*http.Header, bool) {
	h, ok := ctx.Value(contexts.HeadersContextKKey).(*http.Header)
	return h, ok
}

type RequestInfo struct {
	Header     http.Header
	RemoteAddr string
	URL        *url.URL
	Req        *http.Request
	Res        http.ResponseWriter
}

// AddRequestToContextHuma is a middleware that adds request headers to the request context using the RequestInfoKey constant.
func AddRequestToContextHuma() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, w := humachi.Unwrap(ctx)

		info := &RequestInfo{
			Header:     r.Header,
			URL:        r.URL,
			RemoteAddr: r.RemoteAddr,
			Req:        r,
			Res:        w,
		}

		// Add IP address
		ctx = huma.WithValue(ctx, contexts.IPAddressContextKey, GetClientIP(r))

		// Add HTTP Request
		ctx = huma.WithValue(ctx, contexts.HTTPRequestContextKey, r)

		// Add HTTP Writer
		ctx = huma.WithValue(ctx, contexts.HTTPResponseWriterKey, w)

		// Add User Agent
		ctx = huma.WithValue(ctx, contexts.UserAgentContextKey, r.UserAgent())

		// Add Headers
		ctx = huma.WithValue(ctx, contexts.HeadersContextKKey, r.Header)

		// Add request info
		ctx = huma.WithValue(ctx, contexts.RequestInfoContextKey, info)

		next(ctx)
	}
}

// AddRequestInfo is a middleware that adds request headers to the request context using the RequestInfoKey constant.
func AddRequestInfo() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := &RequestInfo{
				Header:     r.Header,
				URL:        r.URL,
				RemoteAddr: r.RemoteAddr,
				Req:        r,
				Res:        w,
			}

			ctx := r.Context()

			// Add IP address
			ctx = context.WithValue(ctx, contexts.IPAddressContextKey, GetClientIP(r))

			// Add HTTP Request
			ctx = context.WithValue(ctx, contexts.HTTPRequestContextKey, r)

			// Add HTTP Writer
			ctx = context.WithValue(ctx, contexts.HTTPResponseWriterKey, w)

			// Add User Agent
			ctx = context.WithValue(ctx, contexts.UserAgentContextKey, r.UserAgent())

			// Add Headers
			ctx = context.WithValue(ctx, contexts.HeadersContextKKey, r.Header)

			// Add request info
			ctx = context.WithValue(r.Context(), contexts.RequestInfoContextKey, info)

			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// GetRequestInfoFromContext retrieves the RequestInfo object from the provided context.
// Returns the RequestInfo and true if successful, otherwise nil and false.
func GetRequestInfoFromContext(ctx context.Context) (*RequestInfo, bool) {
	h, ok := ctx.Value(contexts.RequestInfoContextKey).(*RequestInfo)
	return h, ok
}

// GetIPAddressFromContext retrieves the client IP address from the context.
func GetIPAddressFromContext(ctx context.Context) (string, bool) {
	ip, ok := ctx.Value(contexts.IPAddressContextKey).(string)
	return ip, ok
}

// GetUserAgentFromContext retrieves the User-Agent from the context.
func GetUserAgentFromContext(ctx context.Context) (string, bool) {
	ua, ok := ctx.Value(contexts.UserAgentContextKey).(string)
	return ua, ok
}

// GetHeadersFromContext retrieves the headers from the context.
func GetHeadersFromContext(ctx context.Context) (http.Header, bool) {
	h, ok := ctx.Value(contexts.HeadersContextKKey).(http.Header)
	return h, ok
}

// GetHeaderFromContext retrieves the headers from the context.
func GetHeaderFromContext(ctx context.Context, header string) string {
	h, ok := GetHeadersFromContext(ctx)
	if !ok {
		return ""
	}

	return h.Get(header)
}

// GetCookieFromContext retrieves the cookies from the context.
func GetCookieFromContext(ctx context.Context, cookie string) string {
	h, ok := ctx.Value(contexts.HTTPRequestContextKey).(*http.Request)
	if !ok {
		return ""
	}

	c, err := h.Cookie(cookie)
	if err != nil {
		return ""
	}

	return c.Value
}
