package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"golang.org/x/time/rate"
)

// RateLimitStrategy defines different rate limiting strategies
type RateLimitStrategy string

const (
	StrategyIP           RateLimitStrategy = "ip"
	StrategyUser         RateLimitStrategy = "user"
	StrategyAPIKey       RateLimitStrategy = "api_key"
	StrategyOrganization RateLimitStrategy = "organization"
	StrategyGlobal       RateLimitStrategy = "global"
	StrategyEnvironment  RateLimitStrategy = "environment" // New strategy for environment-based limiting
)

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Strategy          RateLimitStrategy
	RequestsPerSecond float64
	BurstSize         int
	WindowSize        time.Duration
	SkipPaths         []string
	TrustedIPs        []string

	// Headers to include in response
	IncludeHeaders bool
	HeaderPrefix   string

	// Advanced options
	EnableBucketKeys   bool
	BucketKeyGenerator func(*http.Request) string
	OnLimitExceeded    func(*http.Request, *RateLimitInfo)
	Logger             logging.Logger

	// Plan-based limits
	PlanLimits map[string]*PlanRateLimit

	// Environment-based limits
	EnvironmentLimits map[model.Environment]*EnvironmentRateLimit

	// Storage backend
	Store RateLimitStore
}

// PlanRateLimit defines rate limits for different subscription plans
type PlanRateLimit struct {
	RequestsPerSecond float64
	RequestsPerMinute int
	RequestsPerHour   int
	RequestsPerDay    int
	BurstSize         int
}

// EnvironmentRateLimit defines rate limits for different environments
type EnvironmentRateLimit struct {
	RequestsPerSecond float64
	RequestsPerMinute int
	RequestsPerHour   int
	RequestsPerDay    int
	BurstSize         int
	// Different limits for public vs secret keys
	PublicKeyLimits *PlanRateLimit
	SecretKeyLimits *PlanRateLimit
}

// RateLimitInfo contains information about current rate limit status
type RateLimitInfo struct {
	Limit       int
	Remaining   int
	Reset       int64
	ResetTime   time.Time
	RetryAfter  int
	Strategy    RateLimitStrategy
	Key         string
	Blocked     bool
	BlockReason string
	Environment model.Environment `json:"environment,omitempty"`
	KeyType     string            `json:"keyType,omitempty"`
}

// RateLimitStore defines the interface for rate limit storage
type RateLimitStore interface {
	Get(ctx context.Context, key string) (*RateLimitEntry, error)
	Set(ctx context.Context, key string, entry *RateLimitEntry, ttl time.Duration) error
	Increment(ctx context.Context, key string, window time.Duration) (int, error)
	Delete(ctx context.Context, key string) error
	Reset(ctx context.Context, key string) error
}

// RateLimitEntry represents a rate limit entry in storage
type RateLimitEntry struct {
	Count        int        `json:"count"`
	WindowStart  time.Time  `json:"window_start"`
	LastReset    time.Time  `json:"last_reset"`
	Blocked      bool       `json:"blocked"`
	BlockedUntil *time.Time `json:"blocked_until,omitempty"`
}

// InMemoryStore implements RateLimitStore using in-memory storage
type InMemoryStore struct {
	mu              sync.RWMutex
	entries         map[string]*RateLimitEntry
	cleanupInterval time.Duration
	logger          logging.Logger
}

// NewInMemoryStore creates a new in-memory rate limit store
func NewInMemoryStore(logger logging.Logger) *InMemoryStore {
	store := &InMemoryStore{
		entries:         make(map[string]*RateLimitEntry),
		cleanupInterval: 5 * time.Minute,
		logger:          logger,
	}

	// OnStart cleanup goroutine
	go store.cleanup()

	return store
}

func (s *InMemoryStore) Get(ctx context.Context, key string) (*RateLimitEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.entries[key]
	if !exists {
		return &RateLimitEntry{
			Count:       0,
			WindowStart: time.Now(),
			LastReset:   time.Now(),
		}, nil
	}

	return entry, nil
}

func (s *InMemoryStore) Set(ctx context.Context, key string, entry *RateLimitEntry, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[key] = entry
	return nil
}

func (s *InMemoryStore) Increment(ctx context.Context, key string, window time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	entry, exists := s.entries[key]

	if !exists || now.Sub(entry.WindowStart) >= window {
		// Create new window
		entry = &RateLimitEntry{
			Count:       1,
			WindowStart: now,
			LastReset:   now,
		}
	} else {
		// Increment existing window
		entry.Count++
	}

	s.entries[key] = entry
	return entry.Count, nil
}

func (s *InMemoryStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key)
	return nil
}

func (s *InMemoryStore) Reset(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.entries[key]; exists {
		entry.Count = 0
		entry.WindowStart = time.Now()
		entry.LastReset = time.Now()
	}

	return nil
}

func (s *InMemoryStore) cleanup() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()

		for key, entry := range s.entries {
			// Remove entries older than 1 hour
			if now.Sub(entry.WindowStart) > time.Hour {
				delete(s.entries, key)
			}
		}

		s.mu.Unlock()
	}
}

// TokenBucketLimiter implements token bucket rate limiting
type TokenBucketLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
	logger   logging.Logger
}

// NewTokenBucketLimiter creates a new token bucket rate limiter
func NewTokenBucketLimiter(requestsPerSecond float64, burstSize int, logger logging.Logger) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Limit(requestsPerSecond),
		burst:    burstSize,
		logger:   logger,
	}
}

func (tbl *TokenBucketLimiter) GetLimiter(key string) *rate.Limiter {
	tbl.mu.RLock()
	limiter, exists := tbl.limiters[key]
	tbl.mu.RUnlock()

	if exists {
		return limiter
	}

	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := tbl.limiters[key]; exists {
		return limiter
	}

	limiter = rate.NewLimiter(tbl.rate, tbl.burst)
	tbl.limiters[key] = limiter

	return limiter
}

func (tbl *TokenBucketLimiter) Allow(key string) bool {
	limiter := tbl.GetLimiter(key)
	return limiter.Allow()
}

func (tbl *TokenBucketLimiter) AllowN(key string, n int) bool {
	limiter := tbl.GetLimiter(key)
	return limiter.AllowN(time.Now(), n)
}

// DefaultRateLimitConfig returns default rate limiting configuration
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Strategy:          StrategyIP,
		RequestsPerSecond: 10.0,
		BurstSize:         30,
		WindowSize:        time.Minute,
		IncludeHeaders:    true,
		HeaderPrefix:      "X-RateLimit",
		EnableBucketKeys:  false,
		SkipPaths: []string{
			"/_health",
			"/_ready",
			"/metrics",
			"/favicon.ico",
		},
		PlanLimits: map[string]*PlanRateLimit{
			"free": {
				RequestsPerSecond: 1.0,
				RequestsPerMinute: 60,
				RequestsPerHour:   1000,
				RequestsPerDay:    10000,
				BurstSize:         10,
			},
			"starter": {
				RequestsPerSecond: 5.0,
				RequestsPerMinute: 300,
				RequestsPerHour:   10000,
				RequestsPerDay:    100000,
				BurstSize:         20,
			},
			"pro": {
				RequestsPerSecond: 20.0,
				RequestsPerMinute: 1200,
				RequestsPerHour:   50000,
				RequestsPerDay:    1000000,
				BurstSize:         50,
			},
			"enterprise": {
				RequestsPerSecond: 100.0,
				RequestsPerMinute: 6000,
				RequestsPerHour:   500000,
				RequestsPerDay:    10000000,
				BurstSize:         200,
			},
		},
		EnvironmentLimits: map[model.Environment]*EnvironmentRateLimit{
			model.EnvironmentTest: {
				RequestsPerSecond: 50.0,
				RequestsPerMinute: 3000,
				RequestsPerHour:   100000,
				RequestsPerDay:    1000000,
				BurstSize:         100,
				PublicKeyLimits: &PlanRateLimit{
					RequestsPerSecond: 10.0,
					RequestsPerMinute: 600,
					RequestsPerHour:   10000,
					RequestsPerDay:    100000,
					BurstSize:         20,
				},
				SecretKeyLimits: &PlanRateLimit{
					RequestsPerSecond: 50.0,
					RequestsPerMinute: 3000,
					RequestsPerHour:   100000,
					RequestsPerDay:    1000000,
					BurstSize:         100,
				},
			},
			model.EnvironmentLive: {
				RequestsPerSecond: 25.0,
				RequestsPerMinute: 1500,
				RequestsPerHour:   50000,
				RequestsPerDay:    500000,
				BurstSize:         50,
				PublicKeyLimits: &PlanRateLimit{
					RequestsPerSecond: 5.0,
					RequestsPerMinute: 300,
					RequestsPerHour:   5000,
					RequestsPerDay:    50000,
					BurstSize:         10,
				},
				SecretKeyLimits: &PlanRateLimit{
					RequestsPerSecond: 25.0,
					RequestsPerMinute: 1500,
					RequestsPerHour:   50000,
					RequestsPerDay:    500000,
					BurstSize:         50,
				},
			},
			model.EnvironmentDevelopment: {
				RequestsPerSecond: 100.0,
				RequestsPerMinute: 6000,
				RequestsPerHour:   200000,
				RequestsPerDay:    2000000,
				BurstSize:         200,
				PublicKeyLimits: &PlanRateLimit{
					RequestsPerSecond: 20.0,
					RequestsPerMinute: 1200,
					RequestsPerHour:   20000,
					RequestsPerDay:    200000,
					BurstSize:         40,
				},
				SecretKeyLimits: &PlanRateLimit{
					RequestsPerSecond: 100.0,
					RequestsPerMinute: 6000,
					RequestsPerHour:   200000,
					RequestsPerDay:    2000000,
					BurstSize:         200,
				},
			},
		},
	}
}

// RateLimiter creates a rate limiting middleware
func RateLimiter(requestsPerSecond float64, burstSize int) func(http.Handler) http.Handler {
	config := DefaultRateLimitConfig()
	config.RequestsPerSecond = requestsPerSecond
	config.BurstSize = burstSize
	config.Store = NewInMemoryStore(logging.GetLogger().Named("rate-limiter"))

	return RateLimiterWithConfig(config)
}

// RateLimiterWithConfig creates a rate limiting middleware with custom configuration
func RateLimiterWithConfig(config *RateLimitConfig) func(http.Handler) http.Handler {
	if config.Logger == nil {
		config.Logger = logging.GetLogger().Named("rate-limiter")
	}

	if config.Store == nil {
		config.Store = NewInMemoryStore(config.Logger)
	}

	limiter := NewTokenBucketLimiter(config.RequestsPerSecond, config.BurstSize, config.Logger)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting for certain paths
			if shouldSkipPath(r.URL.Path, config.SkipPaths) {
				next.ServeHTTP(w, r)
				return
			}

			// Skip for trusted IPs
			if isTrustedIP(GetClientIP(r), config.TrustedIPs) {
				next.ServeHTTP(w, r)
				return
			}

			// Generate rate limit key
			key := generateRateLimitKey(r, config)

			// Get rate limit info
			limitInfo := getRateLimitInfo(r.Context(), key, config)

			// Check if request is allowed
			allowed := limiter.Allow(key)

			// Update rate limit info
			if allowed {
				limitInfo.Remaining--
			} else {
				limitInfo.Blocked = true
				limitInfo.BlockReason = "rate limit exceeded"
			}

			// Add headers if enabled
			if config.IncludeHeaders {
				addRateLimitHeaders(w, limitInfo, config)
			}

			// Block request if not allowed
			if !allowed {
				if config.OnLimitExceeded != nil {
					config.OnLimitExceeded(r, limitInfo)
				}

				respondRateLimited(w, r, limitInfo, config)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// IPRateLimiter creates an IP-based rate limiter
func IPRateLimiter(requestsPerSecond float64, burstSize int) func(http.Handler) http.Handler {
	config := DefaultRateLimitConfig()
	config.Strategy = StrategyIP
	config.RequestsPerSecond = requestsPerSecond
	config.BurstSize = burstSize

	return RateLimiterWithConfig(config)
}

// UserRateLimiter creates a user-based rate limiter
func UserRateLimiter(requestsPerSecond float64, burstSize int) func(http.Handler) http.Handler {
	config := DefaultRateLimitConfig()
	config.Strategy = StrategyUser
	config.RequestsPerSecond = requestsPerSecond
	config.BurstSize = burstSize

	return RateLimiterWithConfig(config)
}

// APIKeyRateLimiter creates an API key-based rate limiter with environment support
func APIKeyRateLimiter() func(http.Handler) http.Handler {
	config := DefaultRateLimitConfig()
	config.Strategy = StrategyAPIKey

	return func(next http.Handler) http.Handler {
		return RateLimiterWithConfig(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get API key context from middleware
			apiKey := GetAPIKeyFromContext(r.Context())
			if apiKey == nil {
				// No API key context, allow request (will be handled by auth middleware)
				next.ServeHTTP(w, r)
				return
			}

			// Check API key specific rate limits
			key := fmt.Sprintf("api_key:%s", apiKey.ID.String())

			// Apply environment-specific limits
			if !checkAPIKeyEnvironmentRateLimit(r.Context(), key, apiKey, config) {
				limitInfo := &RateLimitInfo{
					Blocked:     true,
					BlockReason: fmt.Sprintf("API key rate limit exceeded for %s environment", apiKey.Environment),
					Strategy:    StrategyAPIKey,
					Key:         key,
					Environment: apiKey.Environment,
					KeyType:     apiKey.KeyType,
				}

				addRateLimitHeaders(w, limitInfo, config)
				respondRateLimited(w, r, limitInfo, config)
				return
			}

			// Check custom API key rate limits if available
			if apiKey.RateLimits != nil {
				if !checkAPIKeyCustomRateLimit(r.Context(), key, apiKey.RateLimits, config) {
					limitInfo := &RateLimitInfo{
						Blocked:     true,
						BlockReason: "API key custom rate limit exceeded",
						Strategy:    StrategyAPIKey,
						Key:         key,
						Environment: apiKey.Environment,
						KeyType:     apiKey.KeyType,
					}

					addRateLimitHeaders(w, limitInfo, config)
					respondRateLimited(w, r, limitInfo, config)
					return
				}
			}

			next.ServeHTTP(w, r)
		}))
	}
}

// EnvironmentBasedRateLimiter creates an environment-based rate limiter
func EnvironmentBasedRateLimiter() func(http.Handler) http.Handler {
	config := DefaultRateLimitConfig()
	config.Strategy = StrategyEnvironment

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get API key context to determine environment
			apiKey := GetAPIKeyFromContext(r.Context())
			if apiKey == nil {
				// No API key context, use default limits
				next.ServeHTTP(w, r)
				return
			}

			// Get environment-specific limits
			envLimits, exists := config.EnvironmentLimits[apiKey.Environment]
			if !exists {
				// No specific limits for this environment, use default
				next.ServeHTTP(w, r)
				return
			}

			// Choose limits based on key type
			var limits *PlanRateLimit
			switch apiKey.KeyType {
			case "public":
				limits = envLimits.PublicKeyLimits
			case "secret":
				limits = envLimits.SecretKeyLimits
			default:
				limits = &PlanRateLimit{
					RequestsPerSecond: envLimits.RequestsPerSecond,
					RequestsPerMinute: envLimits.RequestsPerMinute,
					RequestsPerHour:   envLimits.RequestsPerHour,
					RequestsPerDay:    envLimits.RequestsPerDay,
					BurstSize:         envLimits.BurstSize,
				}
			}

			if limits == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Apply environment-specific rate limiting
			key := fmt.Sprintf("env:%s:key_type:%s:key:%s",
				apiKey.Environment, apiKey.KeyType, apiKey.ID.String())

			limiter := NewTokenBucketLimiter(limits.RequestsPerSecond, limits.BurstSize, config.Logger)

			if !limiter.Allow(key) {
				limitInfo := &RateLimitInfo{
					Limit:       int(limits.RequestsPerSecond * 60), // Per minute
					Remaining:   0,
					Reset:       time.Now().Add(time.Minute).Unix(),
					ResetTime:   time.Now().Add(time.Minute),
					RetryAfter:  60,
					Strategy:    StrategyEnvironment,
					Key:         key,
					Blocked:     true,
					BlockReason: fmt.Sprintf("environment rate limit exceeded: %s (%s key)", apiKey.Environment, apiKey.KeyType),
					Environment: apiKey.Environment,
					KeyType:     apiKey.KeyType,
				}

				addRateLimitHeaders(w, limitInfo, config)
				respondRateLimited(w, r, limitInfo, config)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// OrganizationRateLimiter creates an organization-based rate limiter
func OrganizationRateLimiter() func(http.Handler) http.Handler {
	config := DefaultRateLimitConfig()
	config.Strategy = StrategyOrganization

	return func(next http.Handler) http.Handler {
		return RateLimiterWithConfig(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get organization plan and apply appropriate limits
			if orgID := GetOrganizationIDFromContext(r.Context()); orgID != nil {
				// TODO: Get organization plan from database
				plan := "free" // Default plan

				if planLimit, exists := config.PlanLimits[plan]; exists {
					key := fmt.Sprintf("org:%s", orgID.String())

					limiter := NewTokenBucketLimiter(planLimit.RequestsPerSecond, planLimit.BurstSize, config.Logger)

					if !limiter.Allow(key) {
						limitInfo := &RateLimitInfo{
							Blocked:     true,
							BlockReason: fmt.Sprintf("organization rate limit exceeded for plan: %s", plan),
							Strategy:    StrategyOrganization,
							Key:         key,
						}

						addRateLimitHeaders(w, limitInfo, config)
						respondRateLimited(w, r, limitInfo, config)
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		}))
	}
}

// PlanBasedRateLimiter creates a plan-based rate limiter
func PlanBasedRateLimiter(getPlan func(context.Context) string) func(http.Handler) http.Handler {
	config := DefaultRateLimitConfig()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plan := getPlan(r.Context())
			if plan == "" {
				plan = "free" // Default to free plan
			}

			planLimit, exists := config.PlanLimits[plan]
			if !exists {
				planLimit = config.PlanLimits["free"] // Fallback to free
			}

			// Generate key based on strategy
			var key string
			switch config.Strategy {
			case StrategyUser:
				if userID := GetUserIDFromContext(r.Context()); userID != nil {
					key = fmt.Sprintf("user:%s:plan:%s", userID.String(), plan)
				}
			case StrategyOrganization:
				if orgID := GetOrganizationIDFromContext(r.Context()); orgID != nil {
					key = fmt.Sprintf("org:%s:plan:%s", orgID.String(), plan)
				}
			default:
				key = fmt.Sprintf("ip:%s:plan:%s", GetClientIP(r), plan)
			}

			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			limiter := NewTokenBucketLimiter(planLimit.RequestsPerSecond, planLimit.BurstSize, config.Logger)

			if !limiter.Allow(key) {
				limitInfo := &RateLimitInfo{
					Limit:       int(planLimit.RequestsPerSecond * 60), // Per minute
					Remaining:   0,
					Reset:       time.Now().Add(time.Minute).Unix(),
					ResetTime:   time.Now().Add(time.Minute),
					RetryAfter:  60,
					Strategy:    config.Strategy,
					Key:         key,
					Blocked:     true,
					BlockReason: fmt.Sprintf("plan rate limit exceeded: %s", plan),
				}

				addRateLimitHeaders(w, limitInfo, config)
				respondRateLimited(w, r, limitInfo, config)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper functions

func generateRateLimitKey(r *http.Request, config *RateLimitConfig) string {
	if config.EnableBucketKeys && config.BucketKeyGenerator != nil {
		return config.BucketKeyGenerator(r)
	}

	switch config.Strategy {
	case StrategyIP:
		return fmt.Sprintf("ip:%s", GetClientIP(r))
	case StrategyUser:
		if userID := GetUserIDFromContext(r.Context()); userID != nil {
			return fmt.Sprintf("user:%s", userID.String())
		}
		// Fallback to IP if no user context
		return fmt.Sprintf("ip:%s", GetClientIP(r))
	case StrategyAPIKey:
		if apiKey := GetAPIKeyFromContext(r.Context()); apiKey != nil {
			return fmt.Sprintf("api_key:%s:env:%s:type:%s",
				apiKey.ID.String(), apiKey.Environment, apiKey.KeyType)
		}
		// Fallback to IP if no API key context
		return fmt.Sprintf("ip:%s", GetClientIP(r))
	case StrategyEnvironment:
		if apiKey := GetAPIKeyFromContext(r.Context()); apiKey != nil {
			return fmt.Sprintf("env:%s:type:%s", apiKey.Environment, apiKey.KeyType)
		}
		// Fallback to IP if no API key context
		return fmt.Sprintf("ip:%s", GetClientIP(r))
	case StrategyOrganization:
		if orgID := GetOrganizationIDFromContext(r.Context()); orgID != nil {
			return fmt.Sprintf("org:%s", orgID.String())
		}
		// Fallback to IP if no organization context
		return fmt.Sprintf("ip:%s", GetClientIP(r))
	case StrategyGlobal:
		return "global"
	default:
		return fmt.Sprintf("ip:%s", GetClientIP(r))
	}
}

func getRateLimitInfo(ctx context.Context, key string, config *RateLimitConfig) *RateLimitInfo {
	info := &RateLimitInfo{
		Limit:     int(config.RequestsPerSecond * 60), // Per minute
		Remaining: int(config.RequestsPerSecond * 60), // OnStart with full limit
		Reset:     time.Now().Add(time.Minute).Unix(),
		ResetTime: time.Now().Add(time.Minute),
		Strategy:  config.Strategy,
		Key:       key,
	}

	// Add environment and key type info if available
	if apiKey := GetAPIKeyFromContext(ctx); apiKey != nil {
		info.Environment = apiKey.Environment
		info.KeyType = apiKey.KeyType
	}

	return info
}

func checkAPIKeyEnvironmentRateLimit(ctx context.Context, key string, apiKey *APIKeyContext, config *RateLimitConfig) bool {
	envLimits, exists := config.EnvironmentLimits[apiKey.Environment]
	if !exists {
		return true // No limits defined for this environment
	}

	// Choose limits based on key type
	var limits *PlanRateLimit
	switch apiKey.KeyType {
	case "public":
		limits = envLimits.PublicKeyLimits
	case "secret":
		limits = envLimits.SecretKeyLimits
	default:
		limits = &PlanRateLimit{
			RequestsPerSecond: envLimits.RequestsPerSecond,
			RequestsPerMinute: envLimits.RequestsPerMinute,
			RequestsPerHour:   envLimits.RequestsPerHour,
			RequestsPerDay:    envLimits.RequestsPerDay,
			BurstSize:         envLimits.BurstSize,
		}
	}

	if limits == nil {
		return true
	}

	// Check per-minute limit
	if limits.RequestsPerMinute > 0 {
		count, err := config.Store.Increment(ctx, key+":minute", time.Minute)
		if err == nil && count > limits.RequestsPerMinute {
			return false
		}
	}

	// Check per-hour limit
	if limits.RequestsPerHour > 0 {
		count, err := config.Store.Increment(ctx, key+":hour", time.Hour)
		if err == nil && count > limits.RequestsPerHour {
			return false
		}
	}

	// Check per-day limit
	if limits.RequestsPerDay > 0 {
		count, err := config.Store.Increment(ctx, key+":day", 24*time.Hour)
		if err == nil && count > limits.RequestsPerDay {
			return false
		}
	}

	return true
}

func checkAPIKeyCustomRateLimit(ctx context.Context, key string, limits *model.APIKeyRateLimits, config *RateLimitConfig) bool {
	// Check per-minute limit
	if limits.RequestsPerMinute > 0 {
		count, err := config.Store.Increment(ctx, key+":minute", time.Minute)
		if err == nil && count > limits.RequestsPerMinute {
			return false
		}
	}

	// Check per-hour limit
	if limits.RequestsPerHour > 0 {
		count, err := config.Store.Increment(ctx, key+":hour", time.Hour)
		if err == nil && count > limits.RequestsPerHour {
			return false
		}
	}

	// Check per-day limit
	if limits.RequestsPerDay > 0 {
		count, err := config.Store.Increment(ctx, key+":day", 24*time.Hour)
		if err == nil && count > limits.RequestsPerDay {
			return false
		}
	}

	return true
}

func addRateLimitHeaders(w http.ResponseWriter, info *RateLimitInfo, config *RateLimitConfig) {
	prefix := config.HeaderPrefix

	w.Header().Set(prefix+"-Limit", strconv.Itoa(info.Limit))
	w.Header().Set(prefix+"-Remaining", strconv.Itoa(info.Remaining))
	w.Header().Set(prefix+"-Reset", strconv.FormatInt(info.Reset, 10))

	// Add environment and key type headers for API keys
	if info.Environment != "" {
		w.Header().Set(prefix+"-Environment", string(info.Environment))
	}
	if info.KeyType != "" {
		w.Header().Set(prefix+"-KeyType", info.KeyType)
	}

	if info.Blocked && info.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(info.RetryAfter))
	}
}

func respondRateLimited(w http.ResponseWriter, r *http.Request, info *RateLimitInfo, config *RateLimitConfig) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)

	errResp := errors.NewErrorResponse(errors.New(errors.CodeTooManyRequests, info.BlockReason))

	// Enhanced error response with environment and key type info
	jsonResp := fmt.Sprintf(`{"code":"%s","message":"%s","retry_after":%d,"environment":"%s","key_type":"%s"}`,
		errResp.Code, errResp.Message, info.RetryAfter, info.Environment, info.KeyType)

	_, _ = w.Write([]byte(jsonResp))

	if config.Logger != nil {
		config.Logger.Warn("Rate limit exceeded",
			logging.String("key", info.Key),
			logging.String("strategy", string(info.Strategy)),
			logging.String("reason", info.BlockReason),
			logging.String("environment", string(info.Environment)),
			logging.String("key_type", info.KeyType),
			logging.String("ip", GetClientIP(r)),
			logging.String("user_agent", r.UserAgent()),
		)
	}
}

func shouldSkipPath(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func isTrustedIP(ip string, trustedIPs []string) bool {
	for _, trustedIP := range trustedIPs {
		if ip == trustedIP {
			return true
		}
		// TODO: Add CIDR range checking
	}
	return false
}

// AdaptiveRateLimiter Adaptive rate limiter that adjusts based on load
func AdaptiveRateLimiter(baseRate float64, maxRate float64) func(http.Handler) http.Handler {
	var (
		currentRate  = baseRate
		lastAdjust   = time.Now()
		errorCount   = 0
		requestCount = 0
		mu           sync.RWMutex
	)

	config := DefaultRateLimitConfig()
	config.RequestsPerSecond = currentRate

	return func(next http.Handler) http.Handler {
		limiter := RateLimiterWithConfig(config)

		return limiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			next.ServeHTTP(w, r)

			// Adjust rate based on response time and error rate
			go func() {
				mu.Lock()
				defer mu.Unlock()

				requestCount++
				duration := time.Since(start)

				// Count errors
				if w.Header().Get("Content-Type") == "application/json" {
					// Simple heuristic - this would be more sophisticated in practice
					if duration > 2*time.Second {
						errorCount++
					}
				}

				// Adjust rate every 100 requests or every minute
				if requestCount%100 == 0 || time.Since(lastAdjust) > time.Minute {
					errorRate := float64(errorCount) / float64(requestCount)

					if errorRate > 0.1 { // More than 10% errors
						// Decrease rate
						currentRate = currentRate * 0.8
						if currentRate < baseRate/10 {
							currentRate = baseRate / 10
						}
					} else if errorRate < 0.01 { // Less than 1% errors
						// Increase rate
						currentRate = currentRate * 1.2
						if currentRate > maxRate {
							currentRate = maxRate
						}
					}

					config.RequestsPerSecond = currentRate
					lastAdjust = time.Now()
					errorCount = 0
					requestCount = 0
				}
			}()
		}))
	}
}

// PublicKeyRateLimiter creates a rate limiter specifically for public keys
func PublicKeyRateLimiter() func(http.Handler) http.Handler {
	config := DefaultRateLimitConfig()
	config.Strategy = StrategyAPIKey

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := GetAPIKeyFromContext(r.Context())
			if apiKey == nil || apiKey.KeyType != "public" {
				// Not a public key request, skip this limiter
				next.ServeHTTP(w, r)
				return
			}

			// Apply stricter limits for public keys
			envLimits, exists := config.EnvironmentLimits[apiKey.Environment]
			if !exists || envLimits.PublicKeyLimits == nil {
				// No specific limits, use default
				next.ServeHTTP(w, r)
				return
			}

			key := fmt.Sprintf("public_key:%s:env:%s", apiKey.ID.String(), apiKey.Environment)
			limits := envLimits.PublicKeyLimits

			limiter := NewTokenBucketLimiter(limits.RequestsPerSecond, limits.BurstSize, config.Logger)

			if !limiter.Allow(key) {
				limitInfo := &RateLimitInfo{
					Limit:       int(limits.RequestsPerSecond * 60),
					Remaining:   0,
					Reset:       time.Now().Add(time.Minute).Unix(),
					ResetTime:   time.Now().Add(time.Minute),
					RetryAfter:  60,
					Strategy:    StrategyAPIKey,
					Key:         key,
					Blocked:     true,
					BlockReason: "public key rate limit exceeded",
					Environment: apiKey.Environment,
					KeyType:     "public",
				}

				addRateLimitHeaders(w, limitInfo, config)
				respondRateLimited(w, r, limitInfo, config)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
