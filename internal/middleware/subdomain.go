package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/organization"
	"github.com/juicycleff/frank/pkg/logging"
)

// SubdomainMiddleware Middleware to handle subdomain extraction
type SubdomainMiddleware struct {
	config     *config.Config
	orgService organization.Service
	logger     logging.Logger
}

func (s *SubdomainMiddleware) RequireSubdomain(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subdomain := extractSubdomain(r.Host)
		// Store the subdomain in the request context for later use
		ctx := r.Context()
		ctx = context.WithValue(ctx, SubdomainKey, subdomain)
		r = r.WithContext(ctx)

		// Pass the request to the next handler
		next.ServeHTTP(w, r)
	})
}

// Helper function to extract subdomain
func extractSubdomain(host string) string {
	// Remove port if present
	if i := strings.Index(host, ":"); i != -1 {
		host = host[:i]
	}

	parts := strings.Split(host, ".")
	if len(parts) >= 3 {
		return parts[0]
	}

	return ""
}

// GetSubdomain gets the organization ID from the request context
func GetSubdomain(r *http.Request) (string, bool) {
	orgID, ok := r.Context().Value(SubdomainKey).(string)
	return orgID, ok
}
