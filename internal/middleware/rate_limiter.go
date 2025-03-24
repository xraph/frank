package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
	"golang.org/x/time/rate"
)

// RateLimiterConfig defines rate limiting configuration
type RateLimiterConfig struct {
	// Enabled determines if rate limiting is enabled
	Enabled bool

	// RequestsPerSecond is the number of requests allowed per second
	RequestsPerSecond float64

	// Burst is the maximum number of requests allowed in a burst
	Burst int

	// IPRateLimiting enables rate limiting by IP address
	IPRateLimiting bool

	// UserRateLimiting enables rate limiting by user ID
	UserRateLimiting bool

	// APIKeyRateLimiting enables rate limiting by API key
	APIKeyRateLimiting bool

	// CustomKeyFunc provides a custom function to determine the rate limit key
	CustomKeyFunc func(r *http.Request) string
}

// DefaultRateLimiterConfig returns the default rate limiter configuration
func DefaultRateLimiterConfig(cfg *config.Config) RateLimiterConfig {
	return RateLimiterConfig{
		Enabled:            cfg.Security.RateLimitEnabled,
		RequestsPerSecond:  cfg.Security.RateLimitPerSecond,
		Burst:              cfg.Security.RateLimitBurst,
		IPRateLimiting:     true,
		UserRateLimiting:   true,
		APIKeyRateLimiting: true,
	}
}

// visitor represents a client being rate limited
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimiterStore manages the rate limiters for different clients
type rateLimiterStore struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	config   RateLimiterConfig
}

// newRateLimiterStore creates a new rate limiter store
func newRateLimiterStore(config RateLimiterConfig) *rateLimiterStore {
	store := &rateLimiterStore{
		visitors: make(map[string]*visitor),
		config:   config,
	}

	// Start a background cleanup process
	go store.cleanupVisitors()

	return store
}

// getLimiter gets or creates a rate limiter for a client
func (s *rateLimiterStore) getLimiter(key string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, exists := s.visitors[key]
	if !exists {
		limiter := rate.NewLimiter(rate.Limit(s.config.RequestsPerSecond), s.config.Burst)
		s.visitors[key] = &visitor{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}

	// Update last seen time
	v.lastSeen = time.Now()
	return v.limiter
}

// cleanupVisitors periodically removes old entries from the store
func (s *rateLimiterStore) cleanupVisitors() {
	for {
		time.Sleep(time.Hour) // Clean up once per hour

		s.mu.Lock()
		for key, v := range s.visitors {
			// Remove entries that haven't been seen in the last hour
			if time.Since(v.lastSeen) > time.Hour {
				delete(s.visitors, key)
			}
		}
		s.mu.Unlock()
	}
}

// RateLimiter middleware limits request rates based on client identity
func RateLimiter(rps float64, burst int) func(http.Handler) http.Handler {
	config := RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: rps,
		Burst:             burst,
		IPRateLimiting:    true,
	}

	return RateLimiterWithConfig(config)
}

// RateLimiterWithConfig returns a rate limiter middleware with custom configuration
func RateLimiterWithConfig(config RateLimiterConfig) func(http.Handler) http.Handler {
	store := newRateLimiterStore(config)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting if disabled
			if !config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Determine the rate limit key
			var key string
			if config.CustomKeyFunc != nil {
				key = config.CustomKeyFunc(r)
			} else {
				// Try different identification methods based on configuration
				if config.UserRateLimiting {
					userID, ok := GetUserIDReq(r)
					if ok && userID != "" {
						key = "user:" + userID
					}
				}

				if key == "" && config.APIKeyRateLimiting {
					apiKey := r.Header.Get("X-API-Key")
					if apiKey != "" {
						key = "apikey:" + apiKey
					}
				}

				// Fall back to IP address
				if key == "" && config.IPRateLimiting {
					key = "ip:" + utils.GetRealIP(r)
				}

				// If no key could be determined, allow the request
				if key == "" {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Get limiter for this key
			limiter := store.getLimiter(key)

			// Check if request is allowed
			if !limiter.Allow() {
				// Get logger from context
				logger := logging.FromContext(r.Context())
				logger.Warn("Rate limit exceeded",
					logging.String("key", key),
					logging.String("path", r.URL.RequestURI()),
					logging.String("method", r.Method),
				)

				// Set rate limit headers
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(config.Burst))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Second).Unix(), 10))
				w.Header().Set("Retry-After", "1")

				// Return rate limit exceeded error
				utils.RespondError(w, errors.New(errors.CodeRateLimited, "rate limit exceeded"))
				return
			}

			// Request is allowed, process it
			next.ServeHTTP(w, r)
		})
	}
}

// CustomRateLimiter returns a rate limiter with custom key extraction
func CustomRateLimiter(cfg *config.Config, keyFunc func(r *http.Request) string) func(http.Handler) http.Handler {
	config := DefaultRateLimiterConfig(cfg)
	config.CustomKeyFunc = keyFunc

	return RateLimiterWithConfig(config)
}

// APIPathRateLimiter creates a rate limiter specific to API paths
func APIPathRateLimiter(cfg *config.Config) func(http.Handler) http.Handler {
	return CustomRateLimiter(cfg, func(r *http.Request) string {
		// Get identity (user ID, API key, or IP)
		identity := ""

		// Try to get user ID first
		if userID, ok := GetUserIDReq(r); ok && userID != "" {
			identity = "user:" + userID
		} else {
			// Try to get API key
			apiKey := r.Header.Get("X-API-Key")
			if apiKey != "" {
				identity = "apikey:" + apiKey
			} else {
				// Fall back to IP
				identity = "ip:" + utils.GetRealIP(r)
			}
		}

		// Combine identity with path for path-specific rate limiting
		return identity + ":" + r.URL.Path
	})
}
