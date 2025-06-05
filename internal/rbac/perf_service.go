package rbac

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// PerformanceOptimizedRBACService wraps the standard RBAC service with caching and optimization
type PerformanceOptimizedRBACService struct {
	baseService      Service
	permissionCache  PermissionCache
	userRoleCache    UserRoleCache
	hierarchyService *RoleHierarchyService
	logger           logging.Logger
	metrics          *PerformanceMetrics
	config           *CacheConfig
}

// CacheConfig defines caching behavior
type CacheConfig struct {
	PermissionCacheTTL     time.Duration `json:"permission_cache_ttl"`
	UserRoleCacheTTL       time.Duration `json:"user_role_cache_ttl"`
	HierarchyCacheTTL      time.Duration `json:"hierarchy_cache_ttl"`
	MaxCacheSize           int           `json:"max_cache_size"`
	EnableCompression      bool          `json:"enable_compression"`
	EnableDistributedCache bool          `json:"enable_distributed_cache"`
	CacheKeyPrefix         string        `json:"cache_key_prefix"`
}

// PermissionCache interface for caching user permissions
type PermissionCache interface {
	GetUserPermissions(userID xid.ID, orgID *xid.ID) ([]*Permission, bool)
	SetUserPermissions(userID xid.ID, orgID *xid.ID, permissions []*Permission, ttl time.Duration)
	InvalidateUserPermissions(userID xid.ID, orgID *xid.ID)
	GetPermissionCheck(userID xid.ID, resource, action string, orgID *xid.ID) (bool, bool)
	SetPermissionCheck(userID xid.ID, resource, action string, orgID *xid.ID, allowed bool, ttl time.Duration)
	InvalidateAll()
	GetStats() CacheStats
}

// UserRoleCache interface for caching user role assignments
type UserRoleCache interface {
	GetUserRoles(userID xid.ID, contextType string, contextID *xid.ID) ([]*ent.Role, bool)
	SetUserRoles(userID xid.ID, contextType string, contextID *xid.ID, roles []*ent.Role, ttl time.Duration)
	InvalidateUserRoles(userID xid.ID)
	InvalidateAll()
	GetStats() CacheStats
}

// CacheStats provides cache performance metrics
type CacheStats struct {
	Hits        int64     `json:"hits"`
	Misses      int64     `json:"misses"`
	HitRate     float64   `json:"hit_rate"`
	Size        int       `json:"size"`
	MaxSize     int       `json:"max_size"`
	Evictions   int64     `json:"evictions"`
	LastEvicted time.Time `json:"last_evicted"`
}

// PerformanceMetrics tracks RBAC performance
type PerformanceMetrics struct {
	mu                   sync.RWMutex
	PermissionCheckCount int64            `json:"permission_check_count"`
	CacheHits            int64            `json:"cache_hits"`
	CacheMisses          int64            `json:"cache_misses"`
	AverageCheckTime     time.Duration    `json:"average_check_time"`
	SlowChecks           int64            `json:"slow_checks"`
	ErrorCount           int64            `json:"error_count"`
	CheckTimes           []time.Duration  `json:"-"` // For calculating averages
	HotPermissions       map[string]int64 `json:"hot_permissions"`
	HotUsers             map[string]int64 `json:"hot_users"`
}

// PermissionCheckRequest represents a batched permission check
type PermissionCheckRequest struct {
	UserID   xid.ID  `json:"user_id"`
	Resource string  `json:"resource"`
	Action   string  `json:"action"`
	OrgID    *xid.ID `json:"org_id,omitempty"`
}

// PermissionCheckResult represents the result of a permission check
type PermissionCheckResult struct {
	Request  PermissionCheckRequest `json:"request"`
	Allowed  bool                   `json:"allowed"`
	Cached   bool                   `json:"cached"`
	Duration time.Duration          `json:"duration"`
	Error    error                  `json:"error,omitempty"`
}

// BatchPermissionResult represents results of batch permission checking
type BatchPermissionResult struct {
	Results     []*PermissionCheckResult `json:"results"`
	TotalTime   time.Duration            `json:"total_time"`
	CacheHits   int                      `json:"cache_hits"`
	CacheMisses int                      `json:"cache_misses"`
}

// NewPerformanceOptimizedRBACService creates a new performance-optimized RBAC service
func NewPerformanceOptimizedRBACService(
	baseService Service,
	hierarchyService *RoleHierarchyService,
	permissionCache PermissionCache,
	userRoleCache UserRoleCache,
	config *CacheConfig,
	logger logging.Logger,
) *PerformanceOptimizedRBACService {
	if config == nil {
		config = &CacheConfig{
			PermissionCacheTTL:     15 * time.Minute,
			UserRoleCacheTTL:       5 * time.Minute,
			HierarchyCacheTTL:      30 * time.Minute,
			MaxCacheSize:           10000,
			EnableCompression:      true,
			EnableDistributedCache: false,
			CacheKeyPrefix:         "rbac:",
		}
	}

	return &PerformanceOptimizedRBACService{
		baseService:      baseService,
		permissionCache:  permissionCache,
		userRoleCache:    userRoleCache,
		hierarchyService: hierarchyService,
		logger:           logger,
		config:           config,
		metrics: &PerformanceMetrics{
			HotPermissions: make(map[string]int64),
			HotUsers:       make(map[string]int64),
		},
	}
}

// HasPermission checks if a user has permission with caching optimization
func (pos *PerformanceOptimizedRBACService) HasPermission(ctx context.Context, userID xid.ID, resource, action string, orgID *xid.ID) (bool, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		pos.updateMetrics(userID, resource, action, duration)
	}()

	// Check cache first
	if allowed, found := pos.permissionCache.GetPermissionCheck(userID, resource, action, orgID); found {
		pos.incrementCacheHits()
		return allowed, nil
	}

	pos.incrementCacheMisses()

	// Cache miss - compute permission
	allowed, err := pos.computePermission(ctx, userID, resource, action, orgID)
	if err != nil {
		pos.incrementErrors()
		return false, err
	}

	// Cache the result
	pos.permissionCache.SetPermissionCheck(userID, resource, action, orgID, allowed, pos.config.PermissionCacheTTL)

	return allowed, nil
}

// BatchCheckPermissions checks multiple permissions efficiently
func (pos *PerformanceOptimizedRBACService) BatchCheckPermissions(ctx context.Context, requests []*PermissionCheckRequest) (*BatchPermissionResult, error) {
	start := time.Now()
	result := &BatchPermissionResult{
		Results: make([]*PermissionCheckResult, len(requests)),
	}

	// Group requests by user to optimize cache lookups
	userRequests := make(map[string][]*PermissionCheckRequest)
	for i, req := range requests {
		userKey := req.UserID.String()
		userRequests[userKey] = append(userRequests[userKey], req)
		result.Results[i] = &PermissionCheckResult{Request: *req}
	}

	// Process each user's requests
	for userKey, userReqs := range userRequests {
		userID, _ := xid.FromString(userKey)

		// Get user permissions once for all requests
		permissions, err := pos.GetUserPermissionsOptimized(ctx, userID, userReqs[0].OrgID)
		if err != nil {
			// Mark all requests for this user as errors
			for _, req := range userReqs {
				for _, result := range result.Results {
					if result.Request.UserID == req.UserID {
						// Results[i].Error
						result.Error = err
					}
				}
			}
			continue
		}

		// Build permission map for quick lookup
		permMap := make(map[string]bool)
		for _, perm := range permissions {
			key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
			permMap[key] = true

			// Also add wildcard permissions
			if perm.Action == "*" {
				wildcardKey := fmt.Sprintf("%s:*", perm.Resource)
				permMap[wildcardKey] = true
			}
			if perm.Resource == "*" {
				wildcardKey := fmt.Sprintf("*:%s", perm.Action)
				permMap[wildcardKey] = true
			}
		}

		// Check each request for this user
		for _, req := range userReqs {
			reqStart := time.Now()

			// Find the result index
			var resultIndex int
			for i, r := range result.Results {
				if r.Request.UserID == req.UserID &&
					r.Request.Resource == req.Resource &&
					r.Request.Action == req.Action {
					resultIndex = i
					break
				}
			}

			// Check permission
			key := fmt.Sprintf("%s:%s", req.Resource, req.Action)
			allowed := permMap[key] || permMap[fmt.Sprintf("%s:*", req.Resource)] || permMap["*:*"]

			result.Results[resultIndex].Allowed = allowed
			result.Results[resultIndex].Duration = time.Since(reqStart)
			result.Results[resultIndex].Cached = false // Computed from cached permissions
		}
	}

	result.TotalTime = time.Since(start)
	return result, nil
}

// GetUserPermissionsOptimized gets user permissions with caching
func (pos *PerformanceOptimizedRBACService) GetUserPermissionsOptimized(ctx context.Context, userID xid.ID, orgID *xid.ID) ([]*Permission, error) {
	// Check cache first
	if permissions, found := pos.permissionCache.GetUserPermissions(userID, orgID); found {
		pos.incrementCacheHits()
		return permissions, nil
	}

	pos.incrementCacheMisses()

	// Cache miss - compute permissions
	permissions, err := pos.computeUserPermissions(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}

	// Cache the result
	pos.permissionCache.SetUserPermissions(userID, orgID, permissions, pos.config.PermissionCacheTTL)

	return permissions, nil
}

// PrewarmCache preloads cache with frequently accessed data
func (pos *PerformanceOptimizedRBACService) PrewarmCache(ctx context.Context, userIDs []xid.ID, orgID *xid.ID) error {
	pos.logger.Info("Prewarming RBAC cache",
		logging.Int("user_count", len(userIDs)),
		logging.String("org_id", func() string {
			if orgID != nil {
				return orgID.String()
			}
			return "system"
		}()))

	for _, userID := range userIDs {
		// Prewarm user permissions
		_, err := pos.GetUserPermissionsOptimized(ctx, userID, orgID)
		if err != nil {
			pos.logger.Warn("Failed to prewarm user permissions",
				logging.String("user_id", userID.String()),
				logging.Error(err))
			continue
		}

		// Prewarm common permission checks
		commonPermissions := []string{
			"user:read", "user:create", "user:update",
			"role:read", "permission:read",
			"organization:read",
		}

		for _, perm := range commonPermissions {
			parts := strings.Split(perm, ":")
			if len(parts) == 2 {
				_, _ = pos.HasPermission(ctx, userID, parts[0], parts[1], orgID)
			}
		}
	}

	return nil
}

// InvalidateUserCache invalidates all cache entries for a user
func (pos *PerformanceOptimizedRBACService) InvalidateUserCache(userID xid.ID, orgID *xid.ID) {
	pos.permissionCache.InvalidateUserPermissions(userID, orgID)
	pos.userRoleCache.InvalidateUserRoles(userID)

	pos.logger.Debug("Invalidated user cache",
		logging.String("user_id", userID.String()))
}

// InvalidateOrganizationCache invalidates all cache entries for an organization
func (pos *PerformanceOptimizedRBACService) InvalidateOrganizationCache(orgID xid.ID) {
	// This would require more sophisticated cache implementation that tracks org associations
	// For now, invalidate all caches
	pos.permissionCache.InvalidateAll()
	pos.userRoleCache.InvalidateAll()

	pos.logger.Info("Invalidated organization cache",
		logging.String("org_id", orgID.String()))
}

// GetPerformanceMetrics returns current performance metrics
func (pos *PerformanceOptimizedRBACService) GetPerformanceMetrics() *PerformanceMetrics {
	pos.metrics.mu.RLock()
	defer pos.metrics.mu.RUnlock()

	// Calculate averages
	if len(pos.metrics.CheckTimes) > 0 {
		var total time.Duration
		for _, duration := range pos.metrics.CheckTimes {
			total += duration
		}
		pos.metrics.AverageCheckTime = total / time.Duration(len(pos.metrics.CheckTimes))
	}

	// Create a copy to avoid race conditions
	metrics := &PerformanceMetrics{
		PermissionCheckCount: pos.metrics.PermissionCheckCount,
		CacheHits:            pos.metrics.CacheHits,
		CacheMisses:          pos.metrics.CacheMisses,
		AverageCheckTime:     pos.metrics.AverageCheckTime,
		SlowChecks:           pos.metrics.SlowChecks,
		ErrorCount:           pos.metrics.ErrorCount,
		HotPermissions:       make(map[string]int64),
		HotUsers:             make(map[string]int64),
	}

	// Copy maps
	for k, v := range pos.metrics.HotPermissions {
		metrics.HotPermissions[k] = v
	}
	for k, v := range pos.metrics.HotUsers {
		metrics.HotUsers[k] = v
	}

	return metrics
}

// GetCacheStats returns cache statistics
func (pos *PerformanceOptimizedRBACService) GetCacheStats() map[string]CacheStats {
	return map[string]CacheStats{
		"permissions": pos.permissionCache.GetStats(),
		"user_roles":  pos.userRoleCache.GetStats(),
	}
}

// OptimizeCache performs cache optimization tasks
func (pos *PerformanceOptimizedRBACService) OptimizeCache(ctx context.Context) error {
	pos.logger.Info("Starting cache optimization")

	// Get hot users for prewarming
	hotUsers := pos.getHotUsers(10) // Top 10 most active users

	// Prewarm cache for hot users
	if len(hotUsers) > 0 {
		err := pos.PrewarmCache(ctx, hotUsers, nil)
		if err != nil {
			pos.logger.Warn("Failed to prewarm cache for hot users", logging.Error(err))
		}
	}

	// Clean up cold cache entries (this would depend on cache implementation)
	// For now, just log the action
	pos.logger.Info("Cache optimization completed",
		logging.Int("hot_users_prewarmed", len(hotUsers)))

	return nil
}

// Helper methods

func (pos *PerformanceOptimizedRBACService) computePermission(ctx context.Context, userID xid.ID, resource, action string, orgID *xid.ID) (bool, error) {
	// Use the base service to compute permission
	return pos.baseService.HasPermission(ctx, userID, resource, action)
}

func (pos *PerformanceOptimizedRBACService) computeUserPermissions(ctx context.Context, userID xid.ID, orgID *xid.ID) ([]*Permission, error) {
	// Get user roles
	systemRoles, err := pos.baseService.GetUserSystemRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	var allPermissions []*Permission
	permissionMap := make(map[string]*Permission)

	// Get permissions from system roles
	for _, role := range systemRoles {
		rolePermissions, err := pos.baseService.ListRolePermissions(ctx, role.ID)
		if err != nil {
			continue
		}

		for _, perm := range rolePermissions {
			key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
			if _, exists := permissionMap[key]; !exists {
				permissionMap[key] = perm
				allPermissions = append(allPermissions, perm)
			}
		}
	}

	// Get organization-specific roles if orgID is provided
	if orgID != nil {
		orgRoles, err := pos.baseService.GetUserOrganizationRoles(ctx, userID, *orgID)
		if err == nil {
			for _, role := range orgRoles {
				rolePermissions, err := pos.baseService.ListRolePermissions(ctx, role.ID)
				if err != nil {
					continue
				}

				for _, perm := range rolePermissions {
					key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
					if _, exists := permissionMap[key]; !exists {
						permissionMap[key] = perm
						allPermissions = append(allPermissions, perm)
					}
				}
			}
		}
	}

	// Sort permissions for consistency
	sort.Slice(allPermissions, func(i, j int) bool {
		if allPermissions[i].Resource != allPermissions[j].Resource {
			return allPermissions[i].Resource < allPermissions[j].Resource
		}
		return allPermissions[i].Action < allPermissions[j].Action
	})

	return allPermissions, nil
}

func (pos *PerformanceOptimizedRBACService) updateMetrics(userID xid.ID, resource, action string, duration time.Duration) {
	pos.metrics.mu.Lock()
	defer pos.metrics.mu.Unlock()

	pos.metrics.PermissionCheckCount++

	// Track check times for average calculation
	pos.metrics.CheckTimes = append(pos.metrics.CheckTimes, duration)

	// Keep only last 1000 check times to prevent memory growth
	if len(pos.metrics.CheckTimes) > 1000 {
		pos.metrics.CheckTimes = pos.metrics.CheckTimes[len(pos.metrics.CheckTimes)-1000:]
	}

	// Track slow checks (>100ms)
	if duration > 100*time.Millisecond {
		pos.metrics.SlowChecks++
	}

	// Track hot permissions
	permissionKey := fmt.Sprintf("%s:%s", resource, action)
	pos.metrics.HotPermissions[permissionKey]++

	// Track hot users
	userKey := userID.String()
	pos.metrics.HotUsers[userKey]++
}

func (pos *PerformanceOptimizedRBACService) incrementCacheHits() {
	pos.metrics.mu.Lock()
	pos.metrics.CacheHits++
	pos.metrics.mu.Unlock()
}

func (pos *PerformanceOptimizedRBACService) incrementCacheMisses() {
	pos.metrics.mu.Lock()
	pos.metrics.CacheMisses++
	pos.metrics.mu.Unlock()
}

func (pos *PerformanceOptimizedRBACService) incrementErrors() {
	pos.metrics.mu.Lock()
	pos.metrics.ErrorCount++
	pos.metrics.mu.Unlock()
}

func (pos *PerformanceOptimizedRBACService) getHotUsers(limit int) []xid.ID {
	pos.metrics.mu.RLock()
	defer pos.metrics.mu.RUnlock()

	// Convert map to slice for sorting
	type userCount struct {
		userID string
		count  int64
	}

	var users []userCount
	for userID, count := range pos.metrics.HotUsers {
		users = append(users, userCount{userID, count})
	}

	// Sort by count descending
	sort.Slice(users, func(i, j int) bool {
		return users[i].count > users[j].count
	})

	// Convert back to xid.ID slice
	var result []xid.ID
	for i, user := range users {
		if i >= limit {
			break
		}
		if userID, err := xid.FromString(user.userID); err == nil {
			result = append(result, userID)
		}
	}

	return result
}

// Simple in-memory cache implementations

// MemoryPermissionCache provides in-memory caching for permissions
type MemoryPermissionCache struct {
	mu          sync.RWMutex
	permissions map[string]*cachedPermissions
	checks      map[string]*cachedCheck
	stats       CacheStats
	maxSize     int
}

type cachedPermissions struct {
	permissions []*Permission
	expiry      time.Time
}

type cachedCheck struct {
	allowed bool
	expiry  time.Time
}

func NewMemoryPermissionCache(maxSize int) *MemoryPermissionCache {
	return &MemoryPermissionCache{
		permissions: make(map[string]*cachedPermissions),
		checks:      make(map[string]*cachedCheck),
		maxSize:     maxSize,
		stats:       CacheStats{MaxSize: maxSize},
	}
}

func (mpc *MemoryPermissionCache) GetUserPermissions(userID xid.ID, orgID *xid.ID) ([]*Permission, bool) {
	mpc.mu.RLock()
	defer mpc.mu.RUnlock()

	key := mpc.buildUserKey(userID, orgID)
	if cached, exists := mpc.permissions[key]; exists {
		if time.Now().Before(cached.expiry) {
			mpc.stats.Hits++
			return cached.permissions, true
		}
		// Expired
		delete(mpc.permissions, key)
	}

	mpc.stats.Misses++
	return nil, false
}

func (mpc *MemoryPermissionCache) SetUserPermissions(userID xid.ID, orgID *xid.ID, permissions []*Permission, ttl time.Duration) {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	key := mpc.buildUserKey(userID, orgID)
	mpc.permissions[key] = &cachedPermissions{
		permissions: permissions,
		expiry:      time.Now().Add(ttl),
	}

	mpc.stats.Size = len(mpc.permissions) + len(mpc.checks)
	mpc.evictIfNeeded()
}

func (mpc *MemoryPermissionCache) GetPermissionCheck(userID xid.ID, resource, action string, orgID *xid.ID) (bool, bool) {
	mpc.mu.RLock()
	defer mpc.mu.RUnlock()

	key := mpc.buildCheckKey(userID, resource, action, orgID)
	if cached, exists := mpc.checks[key]; exists {
		if time.Now().Before(cached.expiry) {
			mpc.stats.Hits++
			return cached.allowed, true
		}
		// Expired
		delete(mpc.checks, key)
	}

	mpc.stats.Misses++
	return false, false
}

func (mpc *MemoryPermissionCache) SetPermissionCheck(userID xid.ID, resource, action string, orgID *xid.ID, allowed bool, ttl time.Duration) {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	key := mpc.buildCheckKey(userID, resource, action, orgID)
	mpc.checks[key] = &cachedCheck{
		allowed: allowed,
		expiry:  time.Now().Add(ttl),
	}

	mpc.stats.Size = len(mpc.permissions) + len(mpc.checks)
	mpc.evictIfNeeded()
}

func (mpc *MemoryPermissionCache) InvalidateUserPermissions(userID xid.ID, orgID *xid.ID) {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	userKey := mpc.buildUserKey(userID, orgID)
	delete(mpc.permissions, userKey)

	// Also remove permission checks for this user
	prefix := userID.String() + ":"
	for key := range mpc.checks {
		if strings.HasPrefix(key, prefix) {
			delete(mpc.checks, key)
		}
	}

	mpc.stats.Size = len(mpc.permissions) + len(mpc.checks)
}

func (mpc *MemoryPermissionCache) InvalidateAll() {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	mpc.permissions = make(map[string]*cachedPermissions)
	mpc.checks = make(map[string]*cachedCheck)
	mpc.stats.Size = 0
	mpc.stats.Evictions++
	mpc.stats.LastEvicted = time.Now()
}

func (mpc *MemoryPermissionCache) GetStats() CacheStats {
	mpc.mu.RLock()
	defer mpc.mu.RUnlock()

	stats := mpc.stats
	total := stats.Hits + stats.Misses
	if total > 0 {
		stats.HitRate = float64(stats.Hits) / float64(total)
	}

	return stats
}

func (mpc *MemoryPermissionCache) buildUserKey(userID xid.ID, orgID *xid.ID) string {
	if orgID != nil {
		return fmt.Sprintf("user:%s:org:%s", userID.String(), orgID.String())
	}
	return fmt.Sprintf("user:%s:system", userID.String())
}

func (mpc *MemoryPermissionCache) buildCheckKey(userID xid.ID, resource, action string, orgID *xid.ID) string {
	base := fmt.Sprintf("%s:%s:%s", userID.String(), resource, action)
	if orgID != nil {
		return fmt.Sprintf("%s:org:%s", base, orgID.String())
	}
	return fmt.Sprintf("%s:system", base)
}

func (mpc *MemoryPermissionCache) evictIfNeeded() {
	if mpc.stats.Size > mpc.maxSize {
		// Simple LRU-like eviction - remove oldest entries
		// In a production system, you'd want a proper LRU implementation

		// Remove expired entries first
		now := time.Now()
		for key, cached := range mpc.permissions {
			if now.After(cached.expiry) {
				delete(mpc.permissions, key)
				mpc.stats.Evictions++
			}
		}

		for key, cached := range mpc.checks {
			if now.After(cached.expiry) {
				delete(mpc.checks, key)
				mpc.stats.Evictions++
			}
		}

		mpc.stats.Size = len(mpc.permissions) + len(mpc.checks)
		mpc.stats.LastEvicted = now
	}
}

// MemoryUserRoleCache provides in-memory caching for user roles
type MemoryUserRoleCache struct {
	mu      sync.RWMutex
	roles   map[string]*cachedUserRoles
	stats   CacheStats
	maxSize int
}

type cachedUserRoles struct {
	roles  []*ent.Role
	expiry time.Time
}

func NewMemoryUserRoleCache(maxSize int) *MemoryUserRoleCache {
	return &MemoryUserRoleCache{
		roles:   make(map[string]*cachedUserRoles),
		maxSize: maxSize,
		stats:   CacheStats{MaxSize: maxSize},
	}
}

func (murc *MemoryUserRoleCache) GetUserRoles(userID xid.ID, contextType string, contextID *xid.ID) ([]*ent.Role, bool) {
	murc.mu.RLock()
	defer murc.mu.RUnlock()

	key := murc.buildKey(userID, contextType, contextID)
	if cached, exists := murc.roles[key]; exists {
		if time.Now().Before(cached.expiry) {
			murc.stats.Hits++
			return cached.roles, true
		}
		// Expired
		delete(murc.roles, key)
	}

	murc.stats.Misses++
	return nil, false
}

func (murc *MemoryUserRoleCache) SetUserRoles(userID xid.ID, contextType string, contextID *xid.ID, roles []*ent.Role, ttl time.Duration) {
	murc.mu.Lock()
	defer murc.mu.Unlock()

	key := murc.buildKey(userID, contextType, contextID)
	murc.roles[key] = &cachedUserRoles{
		roles:  roles,
		expiry: time.Now().Add(ttl),
	}

	murc.stats.Size = len(murc.roles)
	murc.evictIfNeeded()
}

func (murc *MemoryUserRoleCache) InvalidateUserRoles(userID xid.ID) {
	murc.mu.Lock()
	defer murc.mu.Unlock()

	prefix := userID.String() + ":"
	for key := range murc.roles {
		if strings.HasPrefix(key, prefix) {
			delete(murc.roles, key)
		}
	}

	murc.stats.Size = len(murc.roles)
}

func (murc *MemoryUserRoleCache) InvalidateAll() {
	murc.mu.Lock()
	defer murc.mu.Unlock()

	murc.roles = make(map[string]*cachedUserRoles)
	murc.stats.Size = 0
	murc.stats.Evictions++
	murc.stats.LastEvicted = time.Now()
}

func (murc *MemoryUserRoleCache) GetStats() CacheStats {
	murc.mu.RLock()
	defer murc.mu.RUnlock()

	stats := murc.stats
	total := stats.Hits + stats.Misses
	if total > 0 {
		stats.HitRate = float64(stats.Hits) / float64(total)
	}

	return stats
}

func (murc *MemoryUserRoleCache) buildKey(userID xid.ID, contextType string, contextID *xid.ID) string {
	base := fmt.Sprintf("%s:%s", userID.String(), contextType)
	if contextID != nil {
		return fmt.Sprintf("%s:%s", base, contextID.String())
	}
	return base
}

func (murc *MemoryUserRoleCache) evictIfNeeded() {
	if murc.stats.Size > murc.maxSize {
		// Remove expired entries
		now := time.Now()
		for key, cached := range murc.roles {
			if now.After(cached.expiry) {
				delete(murc.roles, key)
				murc.stats.Evictions++
			}
		}

		murc.stats.Size = len(murc.roles)
		murc.stats.LastEvicted = now
	}
}
