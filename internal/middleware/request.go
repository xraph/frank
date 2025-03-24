package middleware

import (
	"context"
	"net/http"
	"net/url"
)

// AddHeader is a middleware that attaches request headers to the context using the specified permission.
func AddHeader() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), HeadersKey, r.Header))
			next.ServeHTTP(w, r)
		})
	}
}

// GetHeaders retrieves the HTTP headers from the provided context associated with the UserIDKey.
// Returns the headers and a boolean indicating success or failure of the retrieval.
func GetHeaders(ctx context.Context) (*http.Header, bool) {
	h, ok := ctx.Value(HeadersKey).(*http.Header)
	return h, ok
}

type RequestInfo struct {
	Header     http.Header
	RemoteAddr string
	URL        *url.URL
	Req        *http.Request
	Res        http.ResponseWriter
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
			r = r.WithContext(context.WithValue(r.Context(), RequestInfoKey, info))
			next.ServeHTTP(w, r)
		})
	}
}

// GetRequestInfo retrieves the RequestInfo object from the provided context.
// Returns the RequestInfo and true if successful, otherwise nil and false.
func GetRequestInfo(ctx context.Context) (*RequestInfo, bool) {
	h, ok := ctx.Value(RequestInfoKey).(*RequestInfo)
	return h, ok
}
