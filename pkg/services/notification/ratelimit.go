package notification

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
	"go.uber.org/zap"
)

// RateLimiter defines the interface for rate limiting SMS sending
type RateLimiter interface {
	CheckLimits(ctx context.Context, organizationID xid.ID, phoneNumber string) (*SendingLimits, error)
	IncrementUsage(ctx context.Context, organizationID xid.ID, phoneNumber string, count int) error
	ResetUsage(ctx context.Context, organizationID xid.ID, phoneNumber string, window string) error
	GetUsage(ctx context.Context, organizationID xid.ID, phoneNumber string) (*UsageInfo, error)
	SetLimits(ctx context.Context, organizationID xid.ID, limits OrganizationLimits) error
	GetLimits(ctx context.Context, organizationID xid.ID) (*OrganizationLimits, error)
}

// RateLimiterConfig represents rate limiter configuration
type RateLimiterConfig struct {
	DefaultLimits   DefaultLimits                 `json:"defaultLimits"`
	RedisURL        string                        `json:"redisUrl,omitempty"`
	KeyPrefix       string                        `json:"keyPrefix"`
	CleanupInterval time.Duration                 `json:"cleanupInterval"`
	EnableMetrics   bool                          `json:"enableMetrics"`
	CustomLimits    map[string]OrganizationLimits `json:"customLimits,omitempty"`
}

// DefaultLimits represents default rate limits
type DefaultLimits struct {
	HourlyLimit          int `json:"hourlyLimit"`
	DailyLimit           int `json:"dailyLimit"`
	MonthlyLimit         int `json:"monthlyLimit"`
	PerNumberHourlyLimit int `json:"perNumberHourlyLimit"`
	PerNumberDailyLimit  int `json:"perNumberDailyLimit"`
}

// OrganizationLimits represents organization-specific limits
type OrganizationLimits struct {
	OrganizationID       xid.ID          `json:"organizationId"`
	HourlyLimit          int             `json:"hourlyLimit"`
	DailyLimit           int             `json:"dailyLimit"`
	MonthlyLimit         int             `json:"monthlyLimit"`
	PerNumberHourlyLimit int             `json:"perNumberHourlyLimit"`
	PerNumberDailyLimit  int             `json:"perNumberDailyLimit"`
	BurstLimit           int             `json:"burstLimit,omitempty"`
	CustomRules          []RateLimitRule `json:"customRules,omitempty"`
	Enabled              bool            `json:"enabled"`
	CreatedAt            time.Time       `json:"createdAt"`
	UpdatedAt            time.Time       `json:"updatedAt"`
}

// RateLimitRule represents a custom rate limiting rule
type RateLimitRule struct {
	Name        string        `json:"name"`
	Pattern     string        `json:"pattern"` // Phone number pattern or country code
	Limit       int           `json:"limit"`
	Window      time.Duration `json:"window"`
	Description string        `json:"description,omitempty"`
	Enabled     bool          `json:"enabled"`
}

// UsageInfo represents current usage information
type UsageInfo struct {
	OrganizationID xid.ID     `json:"organizationId"`
	PhoneNumber    string     `json:"phoneNumber,omitempty"`
	HourlyUsage    int        `json:"hourlyUsage"`
	DailyUsage     int        `json:"dailyUsage"`
	MonthlyUsage   int        `json:"monthlyUsage"`
	LastUsed       time.Time  `json:"lastUsed"`
	ResetTimes     ResetTimes `json:"resetTimes"`
}

// ResetTimes represents when usage counters reset
type ResetTimes struct {
	HourlyReset  time.Time `json:"hourlyReset"`
	DailyReset   time.Time `json:"dailyReset"`
	MonthlyReset time.Time `json:"monthlyReset"`
}

// rateLimiter implements the RateLimiter interface
type rateLimiter struct {
	config       RateLimiterConfig
	storage      RateLimitStorage
	logger       logging.Logger
	orgLimits    map[string]*OrganizationLimits
	orgLimitsMux sync.RWMutex
	metrics      *RateLimitMetrics
}

// RateLimitStorage defines the interface for rate limit storage
type RateLimitStorage interface {
	GetUsage(ctx context.Context, key string) (int, error)
	SetUsage(ctx context.Context, key string, value int, expiration time.Duration) error
	IncrementUsage(ctx context.Context, key string, expiration time.Duration) (int, error)
	DeleteUsage(ctx context.Context, key string) error
	GetMultipleUsage(ctx context.Context, keys []string) (map[string]int, error)
}

// RateLimitMetrics represents rate limiting metrics
type RateLimitMetrics struct {
	TotalRequests     int64                  `json:"totalRequests"`
	AllowedRequests   int64                  `json:"allowedRequests"`
	BlockedRequests   int64                  `json:"blockedRequests"`
	OrganizationStats map[string]*OrgMetrics `json:"organizationStats"`
	mutex             sync.RWMutex
}

// OrgMetrics represents organization-specific metrics
type OrgMetrics struct {
	Requests     int64     `json:"requests"`
	Allowed      int64     `json:"allowed"`
	Blocked      int64     `json:"blocked"`
	LastActivity time.Time `json:"lastActivity"`
	HourlyPeak   int       `json:"hourlyPeak"`
	DailyPeak    int       `json:"dailyPeak"`
}

// NewRateLimiter creates a new rate limiter instance
func NewRateLimiter(config RateLimiterConfig, storage RateLimitStorage, logger logging.Logger) (RateLimiter, error) {
	if storage == nil {
		// Use in-memory storage as fallback
		storage = NewInMemoryRateLimitStorage()
	}

	rl := &rateLimiter{
		config:    config,
		storage:   storage,
		logger:    logger,
		orgLimits: make(map[string]*OrganizationLimits),
		metrics: &RateLimitMetrics{
			OrganizationStats: make(map[string]*OrgMetrics),
		},
	}

	// Load custom limits
	for orgID, limits := range config.CustomLimits {
		rl.orgLimits[orgID] = &limits
	}

	// Start cleanup routine if configured
	if config.CleanupInterval > 0 {
		go rl.cleanupRoutine()
	}

	return rl, nil
}

// CheckLimits checks if sending is allowed within rate limits
func (rl *rateLimiter) CheckLimits(ctx context.Context, organizationID xid.ID, phoneNumber string) (*SendingLimits, error) {
	if rl.metrics.OrganizationStats == nil {
		rl.metrics.OrganizationStats = make(map[string]*OrgMetrics)
	}

	rl.updateMetrics(organizationID.String(), false)

	// Get organization limits
	limits := rl.getOrganizationLimits(organizationID)

	// Get current usage
	usage, err := rl.getCurrentUsage(ctx, organizationID, phoneNumber)
	if err != nil {
		rl.logger.Error("failed to get current usage", zap.String("organizationID", organizationID.String()), zap.Error(err))
		return nil, fmt.Errorf("failed to check rate limits: %w", err)
	}

	now := time.Now()

	// Calculate remaining limits
	remainingHourly := max(0, limits.HourlyLimit-usage.HourlyUsage)
	remainingDaily := max(0, limits.DailyLimit-usage.DailyUsage)
	remainingMonthly := max(0, limits.MonthlyLimit-usage.MonthlyUsage)

	// Check if sending is allowed
	canSend := usage.HourlyUsage < limits.HourlyLimit &&
		usage.DailyUsage < limits.DailyLimit &&
		usage.MonthlyUsage < limits.MonthlyLimit

	// Check phone number specific limits if configured
	if limits.PerNumberHourlyLimit > 0 || limits.PerNumberDailyLimit > 0 {
		phoneUsage, err := rl.getPhoneNumberUsage(ctx, organizationID, phoneNumber)
		if err != nil {
			rl.logger.Warn("failed to get phone number usage", zap.String("phoneNumber", phoneNumber), zap.Error(err))
		} else {
			if limits.PerNumberHourlyLimit > 0 && phoneUsage.HourlyUsage >= limits.PerNumberHourlyLimit {
				canSend = false
			}
			if limits.PerNumberDailyLimit > 0 && phoneUsage.DailyUsage >= limits.PerNumberDailyLimit {
				canSend = false
			}
		}
	}

	// Apply custom rules
	if canSend && len(limits.CustomRules) > 0 {
		canSend = rl.checkCustomRules(ctx, organizationID, phoneNumber, limits.CustomRules)
	}

	// Update metrics
	if canSend {
		rl.updateMetrics(organizationID.String(), true)
	} else {
		rl.updateMetrics(organizationID.String(), false)
	}

	result := &SendingLimits{
		OrganizationID:   organizationID,
		PhoneNumber:      phoneNumber,
		HourlyLimit:      limits.HourlyLimit,
		DailyLimit:       limits.DailyLimit,
		MonthlyLimit:     limits.MonthlyLimit,
		HourlyUsed:       usage.HourlyUsage,
		DailyUsed:        usage.DailyUsage,
		MonthlyUsed:      usage.MonthlyUsage,
		CanSend:          canSend,
		RemainingHourly:  remainingHourly,
		RemainingDaily:   remainingDaily,
		RemainingMonthly: remainingMonthly,
		NextResetAt:      rl.getNextResetTime(now),
	}

	return result, nil
}

// IncrementUsage increments usage counters
func (rl *rateLimiter) IncrementUsage(ctx context.Context, organizationID xid.ID, phoneNumber string, count int) error {
	now := time.Now()

	// Increment organization usage
	keys := []string{
		rl.getUsageKey(organizationID, "hourly", now),
		rl.getUsageKey(organizationID, "daily", now),
		rl.getUsageKey(organizationID, "monthly", now),
	}

	expirations := []time.Duration{
		time.Hour,
		24 * time.Hour,
		31 * 24 * time.Hour,
	}

	for i, key := range keys {
		for j := 0; j < count; j++ {
			_, err := rl.storage.IncrementUsage(ctx, key, expirations[i])
			if err != nil {
				rl.logger.Error("failed to increment usage", zap.String("key", key), zap.Error(err))
				return fmt.Errorf("failed to increment usage: %w", err)
			}
		}
	}

	// Increment phone number specific usage if needed
	if phoneNumber != "" {
		phoneKeys := []string{
			rl.getPhoneUsageKey(organizationID, phoneNumber, "hourly", now),
			rl.getPhoneUsageKey(organizationID, phoneNumber, "daily", now),
		}

		phoneExpirations := []time.Duration{
			time.Hour,
			24 * time.Hour,
		}

		for i, key := range phoneKeys {
			for j := 0; j < count; j++ {
				_, err := rl.storage.IncrementUsage(ctx, key, phoneExpirations[i])
				if err != nil {
					rl.logger.Warn("failed to increment phone usage", zap.String("key", key), zap.Error(err))
				}
			}
		}
	}

	return nil
}

// ResetUsage resets usage for a specific window
func (rl *rateLimiter) ResetUsage(ctx context.Context, organizationID xid.ID, phoneNumber string, window string) error {
	now := time.Now()
	key := rl.getUsageKey(organizationID, window, now)

	return rl.storage.DeleteUsage(ctx, key)
}

// GetUsage returns current usage information
func (rl *rateLimiter) GetUsage(ctx context.Context, organizationID xid.ID, phoneNumber string) (*UsageInfo, error) {
	usage, err := rl.getCurrentUsage(ctx, organizationID, phoneNumber)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	return &UsageInfo{
		OrganizationID: organizationID,
		PhoneNumber:    phoneNumber,
		HourlyUsage:    usage.HourlyUsage,
		DailyUsage:     usage.DailyUsage,
		MonthlyUsage:   usage.MonthlyUsage,
		LastUsed:       now,
		ResetTimes: ResetTimes{
			HourlyReset:  rl.getNextHourReset(now),
			DailyReset:   rl.getNextDayReset(now),
			MonthlyReset: rl.getNextMonthReset(now),
		},
	}, nil
}

// SetLimits sets organization-specific limits
func (rl *rateLimiter) SetLimits(ctx context.Context, organizationID xid.ID, limits OrganizationLimits) error {
	rl.orgLimitsMux.Lock()
	defer rl.orgLimitsMux.Unlock()

	limits.OrganizationID = organizationID
	limits.UpdatedAt = time.Now()
	if limits.CreatedAt.IsZero() {
		limits.CreatedAt = time.Now()
	}

	rl.orgLimits[organizationID.String()] = &limits

	rl.logger.Info("updated rate limits for organization", zap.String("organizationID", organizationID.String()))

	return nil
}

// GetLimits returns organization-specific limits
func (rl *rateLimiter) GetLimits(ctx context.Context, organizationID xid.ID) (*OrganizationLimits, error) {
	limits := rl.getOrganizationLimits(organizationID)
	return &limits, nil
}

// Helper methods

func (rl *rateLimiter) getOrganizationLimits(organizationID xid.ID) OrganizationLimits {
	rl.orgLimitsMux.RLock()
	defer rl.orgLimitsMux.RUnlock()

	if limits, exists := rl.orgLimits[organizationID.String()]; exists && limits.Enabled {
		return *limits
	}

	// Return default limits
	return OrganizationLimits{
		OrganizationID:       organizationID,
		HourlyLimit:          rl.config.DefaultLimits.HourlyLimit,
		DailyLimit:           rl.config.DefaultLimits.DailyLimit,
		MonthlyLimit:         rl.config.DefaultLimits.MonthlyLimit,
		PerNumberHourlyLimit: rl.config.DefaultLimits.PerNumberHourlyLimit,
		PerNumberDailyLimit:  rl.config.DefaultLimits.PerNumberDailyLimit,
		Enabled:              true,
	}
}

func (rl *rateLimiter) getCurrentUsage(ctx context.Context, organizationID xid.ID, phoneNumber string) (*UsageInfo, error) {
	now := time.Now()

	keys := []string{
		rl.getUsageKey(organizationID, "hourly", now),
		rl.getUsageKey(organizationID, "daily", now),
		rl.getUsageKey(organizationID, "monthly", now),
	}

	usage, err := rl.storage.GetMultipleUsage(ctx, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage: %w", err)
	}

	return &UsageInfo{
		OrganizationID: organizationID,
		PhoneNumber:    phoneNumber,
		HourlyUsage:    usage[keys[0]],
		DailyUsage:     usage[keys[1]],
		MonthlyUsage:   usage[keys[2]],
		LastUsed:       now,
	}, nil
}

func (rl *rateLimiter) getPhoneNumberUsage(ctx context.Context, organizationID xid.ID, phoneNumber string) (*UsageInfo, error) {
	now := time.Now()

	keys := []string{
		rl.getPhoneUsageKey(organizationID, phoneNumber, "hourly", now),
		rl.getPhoneUsageKey(organizationID, phoneNumber, "daily", now),
	}

	usage, err := rl.storage.GetMultipleUsage(ctx, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to get phone usage: %w", err)
	}

	return &UsageInfo{
		OrganizationID: organizationID,
		PhoneNumber:    phoneNumber,
		HourlyUsage:    usage[keys[0]],
		DailyUsage:     usage[keys[1]],
		LastUsed:       now,
	}, nil
}

func (rl *rateLimiter) checkCustomRules(ctx context.Context, organizationID xid.ID, phoneNumber string, rules []RateLimitRule) bool {
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Check if phone number matches rule pattern
		if rl.matchesPattern(phoneNumber, rule.Pattern) {
			// Check rule-specific usage
			key := fmt.Sprintf("%s:rule:%s:%s", rl.config.KeyPrefix, organizationID.String(), rule.Name)
			usage, err := rl.storage.GetUsage(ctx, key)
			if err != nil {
				rl.logger.Warn("failed to get rule usage", zap.String("key", key), zap.Error(err))
				continue
			}

			if usage >= rule.Limit {
				rl.logger.Info("custom rule limit exceeded",
					zap.String("rule", rule.Name),
					zap.Int("limit", rule.Limit),
					zap.Any("organizationId", organizationID),
					zap.String("phoneNumber", phoneNumber),
					zap.Int("usage", usage),
					zap.Int("limit", rule.Limit),
				)
				return false
			}
		}
	}

	return true
}

func (rl *rateLimiter) matchesPattern(phoneNumber, pattern string) bool {
	// Simple pattern matching - could be enhanced with regex
	if pattern == "*" {
		return true
	}

	// Country code matching
	if strings.HasPrefix(pattern, "+") {
		return strings.HasPrefix(phoneNumber, pattern)
	}

	return false
}

func (rl *rateLimiter) getUsageKey(organizationID xid.ID, window string, now time.Time) string {
	var suffix string
	switch window {
	case "hourly":
		suffix = fmt.Sprintf("%d-%d-%d-%d", now.Year(), now.Month(), now.Day(), now.Hour())
	case "daily":
		suffix = fmt.Sprintf("%d-%d-%d", now.Year(), now.Month(), now.Day())
	case "monthly":
		suffix = fmt.Sprintf("%d-%d", now.Year(), now.Month())
	default:
		suffix = "default"
	}

	return fmt.Sprintf("%s:org:%s:%s:%s", rl.config.KeyPrefix, organizationID.String(), window, suffix)
}

func (rl *rateLimiter) getPhoneUsageKey(organizationID xid.ID, phoneNumber, window string, now time.Time) string {
	var suffix string
	switch window {
	case "hourly":
		suffix = fmt.Sprintf("%d-%d-%d-%d", now.Year(), now.Month(), now.Day(), now.Hour())
	case "daily":
		suffix = fmt.Sprintf("%d-%d-%d", now.Year(), now.Month(), now.Day())
	default:
		suffix = "default"
	}

	// Hash phone number for privacy
	phoneHash := fmt.Sprintf("%x", []byte(phoneNumber))[:8]
	return fmt.Sprintf("%s:phone:%s:%s:%s:%s", rl.config.KeyPrefix, organizationID.String(), phoneHash, window, suffix)
}

func (rl *rateLimiter) getNextResetTime(now time.Time) time.Time {
	// Return next hour reset as it's the most frequent
	return rl.getNextHourReset(now)
}

func (rl *rateLimiter) getNextHourReset(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day(), now.Hour()+1, 0, 0, 0, now.Location())
}

func (rl *rateLimiter) getNextDayReset(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
}

func (rl *rateLimiter) getNextMonthReset(now time.Time) time.Time {
	if now.Month() == 12 {
		return time.Date(now.Year()+1, 1, 1, 0, 0, 0, 0, now.Location())
	}
	return time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, now.Location())
}

func (rl *rateLimiter) updateMetrics(orgID string, allowed bool) {
	if !rl.config.EnableMetrics {
		return
	}

	rl.metrics.mutex.Lock()
	defer rl.metrics.mutex.Unlock()

	rl.metrics.TotalRequests++

	if allowed {
		rl.metrics.AllowedRequests++
	} else {
		rl.metrics.BlockedRequests++
	}

	// Update organization-specific metrics
	orgMetrics, exists := rl.metrics.OrganizationStats[orgID]
	if !exists {
		orgMetrics = &OrgMetrics{}
		rl.metrics.OrganizationStats[orgID] = orgMetrics
	}

	orgMetrics.Requests++
	orgMetrics.LastActivity = time.Now()

	if allowed {
		orgMetrics.Allowed++
	} else {
		orgMetrics.Blocked++
	}
}

func (rl *rateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.logger.Debug("running rate limiter cleanup")
		// Cleanup would remove expired keys, could be implemented based on storage type
	}
}

// Helper function
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// In-memory storage implementation for testing/fallback

type inMemoryRateLimitStorage struct {
	data  map[string]entry
	mutex sync.RWMutex
}

type entry struct {
	value      int
	expiration time.Time
}

// NewInMemoryRateLimitStorage creates a new in-memory storage
func NewInMemoryRateLimitStorage() RateLimitStorage {
	return &inMemoryRateLimitStorage{
		data: make(map[string]entry),
	}
}

func (s *inMemoryRateLimitStorage) GetUsage(ctx context.Context, key string) (int, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, exists := s.data[key]
	if !exists || time.Now().After(entry.expiration) {
		return 0, nil
	}

	return entry.value, nil
}

func (s *inMemoryRateLimitStorage) SetUsage(ctx context.Context, key string, value int, expiration time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.data[key] = entry{
		value:      value,
		expiration: time.Now().Add(expiration),
	}

	return nil
}

func (s *inMemoryRateLimitStorage) IncrementUsage(ctx context.Context, key string, expiration time.Duration) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	ent, exists := s.data[key]
	if !exists || time.Now().After(ent.expiration) {
		ent = entry{value: 0}
	}

	ent.value++
	ent.expiration = time.Now().Add(expiration)
	s.data[key] = ent

	return ent.value, nil
}

func (s *inMemoryRateLimitStorage) DeleteUsage(ctx context.Context, key string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.data, key)
	return nil
}

func (s *inMemoryRateLimitStorage) GetMultipleUsage(ctx context.Context, keys []string) (map[string]int, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	result := make(map[string]int)
	now := time.Now()

	for _, key := range keys {
		entry, exists := s.data[key]
		if exists && now.Before(entry.expiration) {
			result[key] = entry.value
		} else {
			result[key] = 0
		}
	}

	return result, nil
}
