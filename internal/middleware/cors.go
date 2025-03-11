package middleware

import (
	"net/http"
	"strings"

	"github.com/juicycleff/frank/config"
)

// CORSConfig defines configuration options for CORS
type CORSConfig struct {
	// AllowedOrigins is a list of origins a cross-domain request can be executed from
	AllowedOrigins []string

	// AllowedMethods is a list of methods the client is allowed to use
	AllowedMethods []string

	// AllowedHeaders is a list of headers the client is allowed to use
	AllowedHeaders []string

	// ExposedHeaders is a list of headers that are safe to expose
	ExposedHeaders []string

	// AllowCredentials indicates whether the request can include user credentials
	AllowCredentials bool

	// MaxAge indicates how long (in seconds) the results of a preflight request can be cached
	MaxAge int
}

// DefaultCORSConfig returns a default CORS configuration
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With", "X-API-Key"},
		ExposedHeaders:   []string{"Content-Length", "Content-Type", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours
	}
}

// CORS middleware handles Cross-Origin Resource Sharing
func CORS(cfg *config.Config) func(http.Handler) http.Handler {
	corsConfig := DefaultCORSConfig()

	// Override with config values if provided
	if len(cfg.Security.AllowedOrigins) > 0 {
		corsConfig.AllowedOrigins = cfg.Security.AllowedOrigins
	}
	if len(cfg.Security.AllowedMethods) > 0 {
		corsConfig.AllowedMethods = cfg.Security.AllowedMethods
	}
	if len(cfg.Security.AllowedHeaders) > 0 {
		corsConfig.AllowedHeaders = cfg.Security.AllowedHeaders
	}
	if len(cfg.Security.ExposedHeaders) > 0 {
		corsConfig.ExposedHeaders = cfg.Security.ExposedHeaders
	}
	corsConfig.AllowCredentials = cfg.Security.AllowCredentials

	return CORSWithConfig(corsConfig)
}

// CORSWithConfig implements CORS with custom configuration
func CORSWithConfig(config CORSConfig) func(http.Handler) http.Handler {
	// Convert methods and headers to uppercase for consistency
	methods := normalize(config.AllowedMethods)
	headers := normalize(config.AllowedHeaders)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Skip if no Origin header is present
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if the origin is allowed
			allowed := isOriginAllowed(origin, config.AllowedOrigins)

			if allowed {
				// Set CORS headers
				w.Header().Set("Access-Control-Allow-Origin", origin)

				if config.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				if len(config.ExposedHeaders) > 0 {
					w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				// Set preflight headers
				if allowed {
					w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
					w.Header().Set("Access-Control-Allow-Headers", strings.Join(headers, ", "))

					if config.MaxAge > 0 {
						w.Header().Set("Access-Control-Max-Age", string(config.MaxAge))
					}
				}

				// Return 204 No Content for preflight requests
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Process actual request
			next.ServeHTTP(w, r)
		})
	}
}

// normalize converts all entries in the slice to uppercase
func normalize(values []string) []string {
	normalized := make([]string, len(values))
	for i, v := range values {
		normalized[i] = strings.ToUpper(v)
	}
	return normalized
}

// isOriginAllowed checks if the origin is allowed based on the allowed origins
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}

		// Handle wildcard subdomains, e.g., "*.example.com"
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:] // Remove the "*"
			if strings.HasSuffix(origin, suffix) {
				return true
			}
		}
	}

	return false
}
