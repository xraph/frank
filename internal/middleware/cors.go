package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/pkg/contexts"
	"github.com/xraph/frank/pkg/logging"
)

// CORSConfig represents CORS configuration options
type CORSConfig struct {
	AllowedOrigins     []string
	AllowedMethods     []string
	AllowedHeaders     []string
	ExposedHeaders     []string
	AllowCredentials   bool
	MaxAge             int
	OptionsPassthrough bool
	Debug              bool
	Logger             logging.Logger
}

// DefaultCORSConfig returns default CORS configuration
func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodHead,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Accept-Language",
			"Content-Type",
			"Content-Language",
			"Authorization",
			"X-API-Key",
			"X-Publishable-Key",
			"X-Org-ID",
			"X-User-Type",
			"X-Requested-With",
			"X-Request-ID",
			"X-Correlation-ID",
			"Cache-Control",
			"Pragma",
		},
		ExposedHeaders: []string{
			"X-Request-ID",
			"X-Correlation-ID",
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
			"X-RateLimit-Reset",
		},
		AllowCredentials:   true,
		MaxAge:             86400, // 24 hours
		OptionsPassthrough: false,
		Debug:              false,
	}
}

// NewCORSConfig creates CORS configuration from app config
func NewCORSConfig(cfg *config.Config) *CORSConfig {
	corsConfig := DefaultCORSConfig()

	// Override with configuration values if provided
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
	corsConfig.Debug = cfg.App.Environment == "development"

	return corsConfig
}

// CORS returns a CORS middleware handler
func CORS(cfg *config.Config) func(http.Handler) http.Handler {
	corsConfig := NewCORSConfig(cfg)
	logger := logging.GetLogger().Named("cors-middleware")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				if corsConfig.Debug {
					logger.Debug("Handling CORS preflight request",
						logging.String("origin", origin),
						logging.String("method", r.Header.Get("Access-Control-Request-Method")),
						logging.String("headers", r.Header.Get("Access-Control-Request-Headers")))
				}

				// Set preflight headers
				if isOriginAllowed(origin, corsConfig.AllowedOrigins) {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}

				if corsConfig.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				if len(corsConfig.AllowedMethods) > 0 {
					w.Header().Set("Access-Control-Allow-Methods", strings.Join(corsConfig.AllowedMethods, ", "))
				}

				if len(corsConfig.AllowedHeaders) > 0 {
					w.Header().Set("Access-Control-Allow-Headers", strings.Join(corsConfig.AllowedHeaders, ", "))
				}

				if corsConfig.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", strconv.Itoa(corsConfig.MaxAge))
				}

				// Handle preflight request
				if !corsConfig.OptionsPassthrough {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}

			// Set CORS headers for actual requests
			if origin != "" && isOriginAllowed(origin, corsConfig.AllowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)

				if corsConfig.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				if len(corsConfig.ExposedHeaders) > 0 {
					w.Header().Set("Access-Control-Expose-Headers", strings.Join(corsConfig.ExposedHeaders, ", "))
				}

				if corsConfig.Debug {
					logger.Debug("Applied CORS headers",
						logging.String("origin", origin),
						logging.String("method", r.Method),
						logging.Bool("credentials", corsConfig.AllowCredentials))
				}
			}

			// Vary header for caching
			w.Header().Add("Vary", "Origin")
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")

			next.ServeHTTP(w, r)
		})
	}
}

// isOriginAllowed checks if an origin is allowed
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	if origin == "" {
		return false
	}

	for _, allowedOrigin := range allowedOrigins {
		if allowedOrigin == "*" {
			return true
		}

		if allowedOrigin == origin {
			return true
		}

		// Check for wildcard patterns
		if strings.HasPrefix(allowedOrigin, "*.") {
			domain := strings.TrimPrefix(allowedOrigin, "*.")
			if strings.HasSuffix(origin, domain) {
				return true
			}
		}

		// Check for protocol-relative patterns
		if strings.HasPrefix(allowedOrigin, "//") {
			pattern := strings.TrimPrefix(allowedOrigin, "//")
			if strings.Contains(origin, "://"+pattern) {
				return true
			}
		}
	}

	return false
}

// CORSWithConfig returns a CORS middleware with custom configuration
func CORSWithConfig(corsConfig *CORSConfig) func(http.Handler) http.Handler {
	logger := logging.GetLogger().Named("cors-middleware")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				if corsConfig.Debug {
					logger.Debug("Handling CORS preflight request",
						logging.String("origin", origin),
						logging.String("method", r.Header.Get("Access-Control-Request-Method")),
						logging.String("headers", r.Header.Get("Access-Control-Request-Headers")))
				}

				// Set preflight headers
				if isOriginAllowed(origin, corsConfig.AllowedOrigins) {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}

				if corsConfig.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				if len(corsConfig.AllowedMethods) > 0 {
					w.Header().Set("Access-Control-Allow-Methods", strings.Join(corsConfig.AllowedMethods, ", "))
				}

				if len(corsConfig.AllowedHeaders) > 0 {
					w.Header().Set("Access-Control-Allow-Headers", strings.Join(corsConfig.AllowedHeaders, ", "))
				}

				if corsConfig.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", strconv.Itoa(corsConfig.MaxAge))
				}

				// Handle preflight request
				if !corsConfig.OptionsPassthrough {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}

			// Set CORS headers for actual requests
			if origin != "" && isOriginAllowed(origin, corsConfig.AllowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)

				if corsConfig.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				if len(corsConfig.ExposedHeaders) > 0 {
					w.Header().Set("Access-Control-Expose-Headers", strings.Join(corsConfig.ExposedHeaders, ", "))
				}

				if corsConfig.Debug {
					logger.Debug("Applied CORS headers",
						logging.String("origin", origin),
						logging.String("method", r.Method),
						logging.Bool("credentials", corsConfig.AllowCredentials))
				}
			}

			// Vary header for caching
			w.Header().Add("Vary", "Origin")
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds security headers to responses
func SecurityHeaders(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// X-Content-Type-Options
			if cfg.Security.ContentTypeOptions != "" {
				w.Header().Set("X-Content-Type-Options", cfg.Security.ContentTypeOptions)
			}

			// X-Frame-Options
			if cfg.Security.XFrameOptions != "" {
				w.Header().Set("X-Frame-Options", cfg.Security.XFrameOptions)
			}

			// X-XSS-Protection
			if cfg.Security.XSSProtection != "" {
				w.Header().Set("X-XSS-Protection", cfg.Security.XSSProtection)
			}

			// Referrer-Policy
			if cfg.Security.ReferrerPolicy != "" {
				w.Header().Set("Referrer-Policy", cfg.Security.ReferrerPolicy)
			}

			// Strict-Transport-Security
			if cfg.Server.TLS.Enabled && cfg.Security.HSTSMaxAge > 0 {
				hstsValue := "max-age=" + strconv.Itoa(cfg.Security.HSTSMaxAge)
				if cfg.Security.HSTSIncludeSubdomains {
					hstsValue += "; includeSubDomains"
				}
				w.Header().Set("Strict-Transport-Security", hstsValue)
			}

			// Content-Security-Policy
			if cfg.Security.ContentSecurityPolicy != "" {
				w.Header().Set("Content-Security-Policy", cfg.Security.ContentSecurityPolicy)
			}

			// Remove server identification
			w.Header().Set("Server", "")

			next.ServeHTTP(w, r)
		})
	}
}

// DevelopmentCORS returns a permissive CORS middleware for development
func DevelopmentCORS() func(http.Handler) http.Handler {
	corsConfig := &CORSConfig{
		AllowedOrigins: []string{
			"http://localhost:3000",
			"http://localhost:3001",
			"http://localhost:8080",
			"http://localhost:8998",
			"http://localhost:4000",
			"http://127.0.0.1:3000",
			"http://127.0.0.1:3001",
			"http://127.0.0.1:8080",
			"http://127.0.0.1:8998",
			"http://127.0.0.1:4000",
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodHead,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Accept-Language",
			"Content-Type",
			"Content-Language",
			"Authorization",
			"X-API-Key",
			"X-Publishable-Key",
			"X-Org-ID",
			"X-User-Type",
			"X-Requested-With",
			"X-Request-ID",
			"X-Correlation-ID",
			"Cache-Control",
			"Pragma",
		},
		ExposedHeaders: []string{
			"X-Request-ID",
			"X-Correlation-ID",
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
			"X-RateLimit-Reset",
		},
		AllowCredentials:   true,
		MaxAge:             86400,
		OptionsPassthrough: false,
		Debug:              true,
	}

	return CORSWithConfig(corsConfig)
}

// ProductionCORS returns a restrictive CORS middleware for production
func ProductionCORS(allowedOrigins []string) func(http.Handler) http.Handler {
	corsConfig := &CORSConfig{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodHead,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Accept-Language",
			"Content-Type",
			"Authorization",
			"X-API-Key",
			"X-Publishable-Key",
			"X-Org-ID",
			"X-User-Type",
			"X-Requested-With",
			"X-Request-ID",
			"Cache-Control",
		},
		ExposedHeaders: []string{
			"X-Request-ID",
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
			"X-RateLimit-Reset",
		},
		AllowCredentials:   true,
		MaxAge:             86400,
		OptionsPassthrough: false,
		Debug:              false,
	}

	return CORSWithConfig(corsConfig)
}

// APICORSMiddleware provides CORS specifically for API endpoints
func APICORSMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	corsConfig := &CORSConfig{
		AllowedOrigins: cfg.Security.AllowedOrigins,
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodHead,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Accept-Language",
			"Content-Type",
			"Authorization",
			"X-API-Key",
			"X-Publishable-Key",
			"X-Org-ID",
			"X-User-Type",
			"X-Requested-With",
			"X-Request-ID",
			"Cache-Control",
		},
		ExposedHeaders: []string{
			"X-Request-ID",
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
			"X-RateLimit-Reset",
			"X-Total-Count",
			"X-Page-Count",
		},
		AllowCredentials:   cfg.Security.AllowCredentials,
		MaxAge:             3600, // 1 hour for API endpoints
		OptionsPassthrough: false,
		Debug:              cfg.App.Environment == "development",
	}

	// Use wildcard for development
	if cfg.App.Environment == "development" {
		corsConfig.AllowedOrigins = []string{"*"}
		corsConfig.AllowCredentials = false // Can't use credentials with wildcard
	}

	return CORSWithConfig(corsConfig)
}

// WebhookCORSMiddleware provides CORS for webhook endpoints (usually more restrictive)
func WebhookCORSMiddleware() func(http.Handler) http.Handler {
	corsConfig := &CORSConfig{
		AllowedOrigins: []string{}, // Webhooks typically don't need CORS
		AllowedMethods: []string{
			http.MethodPost,
			http.MethodPut,
			http.MethodHead,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Content-Type",
			"X-Webhook-Signature",
			"X-Hub-Signature",
			"X-Hub-Signature-256",
		},
		ExposedHeaders:     []string{},
		AllowCredentials:   false,
		MaxAge:             0,
		OptionsPassthrough: false,
		Debug:              false,
	}

	return CORSWithConfig(corsConfig)
}

// HumaWebhookCORSMiddleware creates a Huma-compatible webhook CORS middleware
func HumaWebhookCORSMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	config := DefaultCORSConfig()
	config.Logger = logging.GetLogger().Named("webhook-cors-middleware")
	return HumaWebhookCORSMiddlewareWithConfig(api, config)
}

// HumaWebhookCORSMiddlewareWithConfig creates a Huma webhook CORS middleware with custom config
func HumaWebhookCORSMiddlewareWithConfig(api huma.API, config *CORSConfig) func(huma.Context, func(huma.Context)) {
	if config.Logger == nil {
		config.Logger = logging.GetLogger().Named("webhook-cors-middleware")
	}

	return func(ctx huma.Context, next func(huma.Context)) {
		// Get the underlying HTTP request and response writer
		r := ctx.Context().Value(contexts.HTTPRequestContextKey).(*http.Request)
		w := ctx.Context().Value(contexts.HTTPResponseWriterKey).(http.ResponseWriter)

		origin := r.Header.Get("Origin")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			if config.Debug {
				config.Logger.Debug("Handling webhook CORS preflight request",
					logging.String("origin", origin),
					logging.String("method", r.Header.Get("Access-Control-Request-Method")),
					logging.String("headers", r.Header.Get("Access-Control-Request-Headers")),
					logging.String("path", r.URL.Path))
			}

			// Set preflight headers
			if origin != "" && isOriginAllowed(origin, config.AllowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else if len(config.AllowedOrigins) == 0 {
				// If no origins specified, allow any origin for webhooks
				// This is common for webhook endpoints that need to accept from various services
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}

			if config.AllowCredentials && origin != "" {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if len(config.AllowedMethods) > 0 {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
			}

			if len(config.AllowedHeaders) > 0 {
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
			}

			if config.MaxAge > 0 {
				w.Header().Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
			}

			// Handle preflight request
			if !config.OptionsPassthrough {
				ctx.SetStatus(http.StatusNoContent)
				return
			}
		}

		// Set CORS headers for actual requests
		if origin != "" {
			if isOriginAllowed(origin, config.AllowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else if len(config.AllowedOrigins) == 0 {
				// Allow any origin if none specified
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}

			if config.AllowCredentials && origin != "" {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if len(config.ExposedHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
			}

			if config.Debug {
				config.Logger.Debug("Applied webhook CORS headers",
					logging.String("origin", origin),
					logging.String("method", r.Method),
					logging.String("path", r.URL.Path),
					logging.Bool("credentials", config.AllowCredentials))
			}
		}

		// Vary header for caching
		w.Header().Add("Vary", "Origin")
		w.Header().Add("Vary", "Access-Control-Request-Method")
		w.Header().Add("Vary", "Access-Control-Request-Headers")

		// Add webhook-specific security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		next(ctx)
	}
}

// AuthCORSMiddleware provides CORS specifically for authentication endpoints
func AuthCORSMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	corsConfig := &CORSConfig{
		AllowedOrigins: cfg.Security.AllowedOrigins,
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodHead,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Accept-Language",
			"Content-Type",
			"Authorization",
			"X-Requested-With",
			"X-Request-ID",
			"X-CSRF-Token",
			"Cache-Control",
			"X-Publishable-Key",
			"X-Org-ID",
			"X-User-Type",
		},
		ExposedHeaders: []string{
			"X-Request-ID",
			"Set-Cookie",
		},
		AllowCredentials:   true, // Required for cookies
		MaxAge:             3600,
		OptionsPassthrough: false,
		Debug:              cfg.App.Environment == "development",
	}

	return CORSWithConfig(corsConfig)
}

// DocsCORSMiddleware Documentation-specific middleware that relaxes CSP for docs routes
func DocsCORSMiddleware(openAPIURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set permissive CSP headers for documentation routes only
			csp := "default-src 'self'; " +
				"script-src 'self' 'unsafe-inline' 'unsafe-eval' " +
				"https://unpkg.com " +
				"https://cdn.jsdelivr.net " +
				"https://cdn.redoc.ly " +
				"https://cdnjs.cloudflare.com; " +
				"script-src-elem 'self' 'unsafe-inline' " +
				"https://unpkg.com " +
				"https://cdn.jsdelivr.net " +
				"https://cdn.redoc.ly " +
				"https://cdnjs.cloudflare.com; " +
				"worker-src 'self' blob: data:; " +
				"child-src 'self' blob: data:; " +
				"style-src 'self' 'unsafe-inline' " +
				"https://unpkg.com " +
				"https://cdn.jsdelivr.net " +
				"https://fonts.googleapis.com; " +
				"style-src-elem 'self' 'unsafe-inline' " +
				"https://unpkg.com " +
				"https://cdn.jsdelivr.net " +
				"https://fonts.googleapis.com; " +
				"font-src 'self' " +
				"https://fonts.gstatic.com " +
				"https://unpkg.com; " +
				"img-src 'self' data: https:; " +
				"connect-src 'self' " + openAPIURL + " https:; " +
				"frame-src 'none'; " +
				"object-src 'none';"

			w.Header().Set("Content-Security-Policy", csp)

			// Also set CORS headers for documentation
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			next.ServeHTTP(w, r)
		})
	}
}

// TrustedWebhookCORSMiddleware creates a webhook CORS middleware for trusted origins only
func TrustedWebhookCORSMiddleware(api huma.API, trustedOrigins []string) func(huma.Context, func(huma.Context)) {
	config := DefaultCORSConfig()
	config.AllowedOrigins = trustedOrigins
	config.AllowCredentials = true
	config.Debug = true
	config.Logger = logging.GetLogger().Named("trusted-webhook-cors")

	return HumaWebhookCORSMiddlewareWithConfig(api, config)
}

// RestrictiveWebhookCORSMiddleware creates a very restrictive webhook CORS middleware
func RestrictiveWebhookCORSMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	config := DefaultCORSConfig()
	config.AllowedOrigins = []string{} // No browser origins allowed
	config.AllowedMethods = []string{http.MethodPost, http.MethodPut}
	config.AllowCredentials = false
	config.MaxAge = 0
	config.Logger = logging.GetLogger().Named("restrictive-webhook-cors")

	return HumaWebhookCORSMiddlewareWithConfig(api, config)
}

// DevelopmentWebhookCORSMiddleware creates a permissive webhook CORS middleware for development
func DevelopmentWebhookCORSMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	config := DefaultCORSConfig()
	config.AllowedOrigins = []string{
		"http://localhost:3000",
		"http://localhost:3001",
		"http://localhost:8080",
		"http://localhost:8998",
		"http://localhost:4000",
		"http://127.0.0.1:3000",
		"http://127.0.0.1:3001",
		"http://127.0.0.1:8080",
		"http://127.0.0.1:8998",
		"http://0.0.0.0:3000",
		"http://0.0.0.0:3001",
		"http://0.0.0.0:8080",
		"http://0.0.0.0:8998",
	}
	config.AllowedMethods = append(config.AllowedMethods, http.MethodGet, http.MethodDelete)
	config.AllowCredentials = true
	config.Debug = true
	config.Logger = logging.GetLogger().Named("dev-webhook-cors")

	return HumaWebhookCORSMiddlewareWithConfig(api, config)
}

// ServiceSpecificWebhookCORSMiddleware creates CORS middleware for specific webhook services
func ServiceSpecificWebhookCORSMiddleware(api huma.API, service string) func(huma.Context, func(huma.Context)) {
	config := DefaultCORSConfig()
	config.Logger = logging.GetLogger().Named("webhook-cors-" + service)

	switch strings.ToLower(service) {
	case "github":
		config.AllowedOrigins = []string{
			"https://github.com",
			"https://api.github.com",
		}
		config.AllowedHeaders = append(config.AllowedHeaders,
			"X-GitHub-Delivery",
			"X-GitHub-Event",
			"X-GitHub-Hook-ID",
		)
	case "stripe":
		config.AllowedOrigins = []string{
			"https://api.stripe.com",
		}
		config.AllowedHeaders = append(config.AllowedHeaders,
			"Stripe-Signature",
		)
	case "paypal":
		config.AllowedOrigins = []string{
			"https://api.paypal.com",
			"https://api.sandbox.paypal.com",
		}
		config.AllowedHeaders = append(config.AllowedHeaders,
			"PAYPAL-AUTH-ALGO",
			"PAYPAL-AUTH-VERSION",
			"PAYPAL-CERT-ID",
			"PAYPAL-TRANSMISSION-ID",
			"PAYPAL-TRANSMISSION-SIG",
			"PAYPAL-TRANSMISSION-TIME",
		)
	case "slack":
		config.AllowedOrigins = []string{
			"https://hooks.slack.com",
			"https://api.slack.com",
		}
	case "discord":
		config.AllowedOrigins = []string{
			"https://discord.com",
			"https://discordapp.com",
		}
	case "twilio":
		config.AllowedOrigins = []string{
			"https://api.twilio.com",
		}
		config.AllowedHeaders = append(config.AllowedHeaders,
			"X-Twilio-Signature",
		)
	default:
		// Generic webhook service
		config.AllowedOrigins = []string{} // Allow any origin for unknown services
	}

	return HumaWebhookCORSMiddlewareWithConfig(api, config)
}

// ApplyWebhookCORS applies webhook CORS middleware to a Huma group
func ApplyWebhookCORS(group huma.API, middleware func(huma.Context, func(huma.Context))) {
	group.UseMiddleware(middleware)
}
