package rbac

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gin-gonic/gin"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// MiddlewareConfig configures RBAC middleware behavior
type MiddlewareConfig struct {
	// Permission extraction
	ResourceExtractor ResourceExtractor `json:"-"`
	ActionExtractor   ActionExtractor   `json:"-"`
	UserExtractor     UserExtractor     `json:"-"`
	OrgExtractor      OrgExtractor      `json:"-"`

	// Response behavior
	UnauthorizedHandler http.HandlerFunc `json:"-"`
	ForbiddenHandler    http.HandlerFunc `json:"-"`
	ErrorHandler        ErrorHandlerFunc `json:"-"`

	// Caching
	EnableCaching bool          `json:"enable_caching"`
	CacheTTL      time.Duration `json:"cache_ttl"`

	// Logging
	LogPermissionChecks bool   `json:"log_permission_checks"`
	LogLevel            string `json:"log_level"`

	// Performance
	EnableAsync     bool          `json:"enable_async"`
	TimeoutDuration time.Duration `json:"timeout_duration"`

	// Security
	RequireAuthentication bool     `json:"require_authentication"`
	AllowBypass           []string `json:"allow_bypass"` // Paths that bypass RBAC

	// Context enrichment
	EnrichContext bool     `json:"enrich_context"`
	ContextFields []string `json:"context_fields"`
}

// Extractor functions for middleware
type ResourceExtractor func(*http.Request) string
type ActionExtractor func(*http.Request) string
type UserExtractor func(*http.Request) (xid.ID, error)
type OrgExtractor func(*http.Request) (*xid.ID, error)
type ErrorHandlerFunc func(http.ResponseWriter, *http.Request, error)

// RBACMiddleware provides HTTP middleware for permission checking
type RBACMiddleware struct {
	rbacService        Service
	performanceService *PerformanceOptimizedRBACService
	auditService       *AuditTrailService
	config             *MiddlewareConfig
	logger             logging.Logger
}

// GinMiddleware provides Gin-specific middleware
type GinMiddleware struct {
	*RBACMiddleware
}

// HumaMiddleware provides Huma-specific middleware
type HumaMiddleware struct {
	*RBACMiddleware
}

// PermissionAnnotation for declarative permissions
type PermissionAnnotation struct {
	Resource   string            `json:"resource"`
	Action     string            `json:"action"`
	Conditions map[string]string `json:"conditions,omitempty"`
	Optional   bool              `json:"optional"`  // If true, missing permission doesn't block access
	Async      bool              `json:"async"`     // If true, check permission asynchronously
	CacheTTL   time.Duration     `json:"cache_ttl"` // Override default cache TTL
}

// PermissionDecorator for function-level permissions
type PermissionDecorator struct {
	middleware *RBACMiddleware
}

// NewRBACMiddleware creates a new RBAC middleware
func NewRBACMiddleware(
	rbacService Service,
	performanceService *PerformanceOptimizedRBACService,
	auditService *AuditTrailService,
	config *MiddlewareConfig,
	logger logging.Logger,
) *RBACMiddleware {
	if config == nil {
		config = &MiddlewareConfig{
			EnableCaching:         true,
			CacheTTL:              5 * time.Minute,
			LogPermissionChecks:   true,
			LogLevel:              "info",
			EnableAsync:           false,
			TimeoutDuration:       30 * time.Second,
			RequireAuthentication: true,
			EnrichContext:         true,
			ContextFields:         []string{"user_id", "org_id", "permissions"},
		}
	}

	// Set default extractors if not provided
	if config.ResourceExtractor == nil {
		config.ResourceExtractor = DefaultResourceExtractor
	}
	if config.ActionExtractor == nil {
		config.ActionExtractor = DefaultActionExtractor
	}
	if config.UserExtractor == nil {
		config.UserExtractor = DefaultUserExtractor
	}
	if config.OrgExtractor == nil {
		config.OrgExtractor = DefaultOrgExtractor
	}

	// Set default error handlers
	if config.UnauthorizedHandler == nil {
		config.UnauthorizedHandler = DefaultUnauthorizedHandler
	}
	if config.ForbiddenHandler == nil {
		config.ForbiddenHandler = DefaultForbiddenHandler
	}
	if config.ErrorHandler == nil {
		config.ErrorHandler = DefaultErrorHandler
	}

	return &RBACMiddleware{
		rbacService:        rbacService,
		performanceService: performanceService,
		auditService:       auditService,
		config:             config,
		logger:             logger,
	}
}

// HTTPMiddleware returns standard HTTP middleware
func (rm *RBACMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this path should bypass RBAC
		if rm.shouldBypass(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract required information
		userID, err := rm.config.UserExtractor(r)
		if err != nil {
			if rm.config.RequireAuthentication {
				rm.config.UnauthorizedHandler(w, r)
				return
			}
			// Continue without permission check if authentication not required
			next.ServeHTTP(w, r)
			return
		}

		resource := rm.config.ResourceExtractor(r)
		action := rm.config.ActionExtractor(r)
		orgID, _ := rm.config.OrgExtractor(r)

		// Check permission
		ctx := r.Context()
		if rm.config.TimeoutDuration > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, rm.config.TimeoutDuration)
			defer cancel()
		}

		hasPermission, err := rm.checkPermission(ctx, userID, resource, action, orgID)
		if err != nil {
			rm.config.ErrorHandler(w, r, err)
			return
		}

		if !hasPermission {
			rm.config.ForbiddenHandler(w, r)
			return
		}

		// Enrich context if enabled
		if rm.config.EnrichContext {
			r = rm.enrichRequest(r, userID, orgID, resource, action)
		}

		// Log permission check if enabled
		if rm.config.LogPermissionChecks {
			rm.logger.Info("Permission check passed",
				logging.String("user_id", userID.String()),
				logging.String("resource", resource),
				logging.String("action", action),
				logging.String("path", r.URL.Path))
		}

		next.ServeHTTP(w, r)
	})
}

// RequirePermission creates middleware for specific permission requirements
func (rm *RBACMiddleware) RequirePermission(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, err := rm.config.UserExtractor(r)
			if err != nil {
				rm.config.UnauthorizedHandler(w, r)
				return
			}

			orgID, _ := rm.config.OrgExtractor(r)

			hasPermission, err := rm.checkPermission(r.Context(), userID, resource, action, orgID)
			if err != nil {
				rm.config.ErrorHandler(w, r, err)
				return
			}

			if !hasPermission {
				rm.config.ForbiddenHandler(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission creates middleware that allows access if user has any of the specified permissions
func (rm *RBACMiddleware) RequireAnyPermission(permissions []PermissionAnnotation) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, err := rm.config.UserExtractor(r)
			if err != nil {
				rm.config.UnauthorizedHandler(w, r)
				return
			}

			orgID, _ := rm.config.OrgExtractor(r)
			ctx := r.Context()

			// Check each permission until one passes
			hasPermission := false
			for _, perm := range permissions {
				allowed, err := rm.checkPermission(ctx, userID, perm.Resource, perm.Action, orgID)
				if err != nil && !perm.Optional {
					rm.config.ErrorHandler(w, r, err)
					return
				}

				if allowed {
					hasPermission = true
					break
				}
			}

			if !hasPermission {
				rm.config.ForbiddenHandler(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GinMiddleware creates Gin-compatible middleware
func (rm *RBACMiddleware) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if this path should bypass RBAC
		if rm.shouldBypass(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Extract required information
		userID, err := rm.config.UserExtractor(c.Request)
		if err != nil {
			if rm.config.RequireAuthentication {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
				c.Abort()
				return
			}
			c.Next()
			return
		}

		resource := rm.config.ResourceExtractor(c.Request)
		action := rm.config.ActionExtractor(c.Request)
		orgID, _ := rm.config.OrgExtractor(c.Request)

		// Check permission
		hasPermission, err := rm.checkPermission(c.Request.Context(), userID, resource, action, orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		// Add permission info to context
		c.Set("user_id", userID)
		c.Set("org_id", orgID)
		c.Set("resource", resource)
		c.Set("action", action)

		c.Next()
	}
}

// GinRequirePermission creates Gin middleware for specific permissions
func (rm *RBACMiddleware) GinRequirePermission(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := rm.config.UserExtractor(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		orgID, _ := rm.config.OrgExtractor(c.Request)

		hasPermission, err := rm.checkPermission(c.Request.Context(), userID, resource, action, orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// HumaPermissionMiddleware creates Huma-compatible middleware
func (rm *RBACMiddleware) HumaPermissionMiddleware(api huma.API, resource, action string, pathParam ...string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		// Extract user ID from context (assumes JWT middleware has run)
		userIDStr := ctx.Header("user-id")
		if userIDStr == "" {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "Authentication required")
			return
		}

		userID, err := xid.FromString(userIDStr)
		if err != nil {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "Invalid user ID")
			return
		}

		// Extract organization ID from path or header
		var orgID *xid.ID
		if len(pathParam) > 0 {
			if orgIDStr := ctx.Param(pathParam[0]); orgIDStr != "" {
				if parsed, err := xid.FromString(orgIDStr); err == nil {
					orgID = &parsed
				}
			}
		}

		// Check permission
		hasPermission, err := rm.checkPermission(ctx.Context(), userID, resource, action, orgID)
		if err != nil {
			huma.WriteErr(api, ctx, http.StatusInternalServerError, err.Error())
			return
		}

		if !hasPermission {
			huma.WriteErr(api, ctx, http.StatusForbidden, "Insufficient permissions")
			return
		}

		next(ctx)
	}
}

// PermissionDecorator provides function-level permission checking
func (rm *RBACMiddleware) PermissionDecorator() *PermissionDecorator {
	return &PermissionDecorator{middleware: rm}
}

// CheckPermission decorator function
func (pd *PermissionDecorator) CheckPermission(resource, action string) func(func(context.Context, xid.ID, *xid.ID) error) func(context.Context, xid.ID, *xid.ID) error {
	return func(fn func(context.Context, xid.ID, *xid.ID) error) func(context.Context, xid.ID, *xid.ID) error {
		return func(ctx context.Context, userID xid.ID, orgID *xid.ID) error {
			hasPermission, err := pd.middleware.checkPermission(ctx, userID, resource, action, orgID)
			if err != nil {
				return err
			}

			if !hasPermission {
				return errors.New(errors.CodeForbidden, "Insufficient permissions")
			}

			return fn(ctx, userID, orgID)
		}
	}
}

// Helper methods

func (rm *RBACMiddleware) checkPermission(ctx context.Context, userID xid.ID, resource, action string, orgID *xid.ID) (bool, error) {
	start := time.Now()

	var hasPermission bool
	var err error

	// Use performance service if available for caching
	if rm.performanceService != nil {
		hasPermission, err = rm.performanceService.HasPermission(ctx, userID, resource, action, orgID)
	} else {
		hasPermission, err = rm.rbacService.HasPermission(ctx, userID, resource, action)
	}

	// Log to audit trail
	if rm.auditService != nil {
		auditErr := rm.auditService.LogPermissionChecked(ctx, userID, resource, action, hasPermission, orgID)
		if auditErr != nil {
			rm.logger.Warn("Failed to log permission check", logging.Error(auditErr))
		}
	}

	// Log performance metrics
	duration := time.Since(start)
	rm.logger.Debug("Permission check completed",
		logging.String("user_id", userID.String()),
		logging.String("resource", resource),
		logging.String("action", action),
		logging.Bool("granted", hasPermission),
		logging.Duration("duration", duration))

	return hasPermission, err
}

func (rm *RBACMiddleware) shouldBypass(path string) bool {
	for _, bypassPath := range rm.config.AllowBypass {
		if strings.HasPrefix(path, bypassPath) {
			return true
		}
	}
	return false
}

func (rm *RBACMiddleware) enrichRequest(r *http.Request, userID xid.ID, orgID *xid.ID, resource, action string) *http.Request {
	ctx := r.Context()

	// Add RBAC context information
	ctx = context.WithValue(ctx, "rbac_user_id", userID)
	ctx = context.WithValue(ctx, "rbac_org_id", orgID)
	ctx = context.WithValue(ctx, "rbac_resource", resource)
	ctx = context.WithValue(ctx, "rbac_action", action)
	ctx = context.WithValue(ctx, "rbac_checked", true)

	// Add user permissions if requested
	if contains(rm.config.ContextFields, "permissions") && rm.performanceService != nil {
		permissions, err := rm.performanceService.GetUserPermissionsOptimized(ctx, userID, orgID)
		if err == nil {
			ctx = context.WithValue(ctx, "rbac_permissions", permissions)
		}
	}

	return r.WithContext(ctx)
}

// Default extractors

func DefaultResourceExtractor(r *http.Request) string {
	// Extract resource from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

	// Common patterns:
	// /api/v1/users -> users
	// /organizations/{id}/roles -> roles
	// /users/{id} -> users

	for i, part := range pathParts {
		// Skip common prefixes
		if part == "api" || part == "v1" || part == "v2" {
			continue
		}

		// Skip organization prefix
		if part == "organizations" && i+1 < len(pathParts) {
			// Skip org ID and get next resource
			if i+2 < len(pathParts) {
				return pathParts[i+2]
			}
		}

		// Return first non-prefix part
		if part != "" && !isUUID(part) {
			return part
		}
	}

	return "unknown"
}

func DefaultActionExtractor(r *http.Request) string {
	// Map HTTP methods to actions
	actionMap := map[string]string{
		"GET":    "read",
		"POST":   "create",
		"PUT":    "update",
		"PATCH":  "update",
		"DELETE": "delete",
	}

	if action, exists := actionMap[r.Method]; exists {
		return action
	}

	return "access"
}

func DefaultUserExtractor(r *http.Request) (xid.ID, error) {
	// Try to get user ID from various sources

	// 1. From JWT token in Authorization header
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			// Parse JWT token to extract user ID
			// This would require JWT parsing logic
			// For now, return error to indicate implementation needed
		}
	}

	// 2. From custom header
	if userIDStr := r.Header.Get("X-User-ID"); userIDStr != "" {
		return xid.FromString(userIDStr)
	}

	// 3. From context (if set by previous middleware)
	if userID := r.Context().Value("user_id"); userID != nil {
		if uid, ok := userID.(xid.ID); ok {
			return uid, nil
		}
		if uidStr, ok := userID.(string); ok {
			return xid.FromString(uidStr)
		}
	}

	return xid.ID{}, errors.New(errors.CodeUnauthorized, "user not authenticated")
}

func DefaultOrgExtractor(r *http.Request) (*xid.ID, error) {
	// Try to get org ID from various sources

	// 1. From URL path parameter
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	for i, part := range pathParts {
		if part == "organizations" && i+1 < len(pathParts) {
			if orgID, err := xid.FromString(pathParts[i+1]); err == nil {
				return &orgID, nil
			}
		}
	}

	// 2. From custom header
	if orgIDStr := r.Header.Get("X-Organization-ID"); orgIDStr != "" {
		if orgID, err := xid.FromString(orgIDStr); err == nil {
			return &orgID, nil
		}
	}

	// 3. From context
	if orgID := r.Context().Value("org_id"); orgID != nil {
		if oid, ok := orgID.(xid.ID); ok {
			return &oid, nil
		}
		if oidStr, ok := orgID.(string); ok {
			if parsed, err := xid.FromString(oidStr); err == nil {
				return &parsed, nil
			}
		}
	}

	// Return nil if no org ID found (system-level access)
	return nil, nil
}

// Default error handlers

func DefaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"Authentication required","code":"unauthorized"}`))
}

func DefaultForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"Insufficient permissions","code":"forbidden"}`))
}

func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(fmt.Sprintf(`{"error":"Internal server error","code":"internal_error","details":"%s"}`, err.Error())))
}

// Helper functions

func isUUID(s string) bool {
	// Simple UUID pattern check
	return len(s) == 20 || len(s) == 36 // XID length or UUID length
}

// Integration helpers

// RBACChecker provides a simple interface for permission checking
type RBACChecker struct {
	service Service
	logger  logging.Logger
}

// NewRBACChecker creates a new RBAC checker
func NewRBACChecker(service Service, logger logging.Logger) *RBACChecker {
	return &RBACChecker{
		service: service,
		logger:  logger,
	}
}

// CheckPermission checks if a user has a specific permission
func (rc *RBACChecker) CheckPermission(ctx context.Context, userID xid.ID, resource, action string) (bool, error) {
	return rc.service.HasPermission(ctx, userID, resource, action)
}

// CheckPermissions checks multiple permissions at once
func (rc *RBACChecker) CheckPermissions(ctx context.Context, userID xid.ID, permissions []string) (map[string]bool, error) {
	results := make(map[string]bool)

	for _, perm := range permissions {
		parts := strings.Split(perm, ":")
		if len(parts) != 2 {
			continue
		}

		hasPermission, err := rc.service.HasPermission(ctx, userID, parts[0], parts[1])
		if err != nil {
			return nil, err
		}

		results[perm] = hasPermission
	}

	return results, nil
}

// GetUserPermissions returns all permissions for a user
func (rc *RBACChecker) GetUserPermissions(ctx context.Context, userID xid.ID) ([]*Permission, error) {
	// Get user permissions through roles
	systemRoles, err := rc.service.GetUserSystemRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	var allPermissions []*Permission
	permissionMap := make(map[string]*Permission)

	for _, role := range systemRoles {
		rolePermissions, err := rc.service.ListRolePermissions(ctx, role.ID)
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

	return allPermissions, nil
}

// ConditionalChecker provides conditional permission checking
type ConditionalChecker struct {
	checker *RBACChecker
	engine  *ConditionalPermissionEngine
	logger  logging.Logger
}

// NewConditionalChecker creates a new conditional checker
func NewConditionalChecker(checker *RBACChecker, engine *ConditionalPermissionEngine, logger logging.Logger) *ConditionalChecker {
	return &ConditionalChecker{
		checker: checker,
		engine:  engine,
		logger:  logger,
	}
}

// CheckWithContext checks permission with additional context
func (cc *ConditionalChecker) CheckWithContext(ctx context.Context, userID xid.ID, resource, action string, permContext *PermissionContext) (bool, error) {
	if cc.engine != nil {
		decision, err := cc.engine.EvaluatePermission(ctx, userID, resource, action, permContext)
		if err != nil {
			return false, err
		}
		return decision.Decision == PolicyEffectPermit, nil
	}

	// Fall back to basic permission check
	return cc.checker.CheckPermission(ctx, userID, resource, action)
}

// Utility functions for common integration patterns

// RequirePermissionFunc is a utility function for protecting functions
func RequirePermissionFunc(checker *RBACChecker, resource, action string) func(context.Context, xid.ID, func() error) error {
	return func(ctx context.Context, userID xid.ID, fn func() error) error {
		hasPermission, err := checker.CheckPermission(ctx, userID, resource, action)
		if err != nil {
			return err
		}

		if !hasPermission {
			return errors.New(errors.CodeForbidden, "Insufficient permissions")
		}

		return fn()
	}
}

// WithPermissionCheck wraps a function with permission checking
func WithPermissionCheck(checker *RBACChecker, resource, action string, fn func(context.Context, xid.ID) error) func(context.Context, xid.ID) error {
	return func(ctx context.Context, userID xid.ID) error {
		hasPermission, err := checker.CheckPermission(ctx, userID, resource, action)
		if err != nil {
			return err
		}

		if !hasPermission {
			return errors.New(errors.CodeForbidden, "Insufficient permissions")
		}

		return fn(ctx, userID)
	}
}

// PermissionGuard provides a fluent interface for permission checking
type PermissionGuard struct {
	checker *RBACChecker
	ctx     context.Context
	userID  xid.ID
}

// NewPermissionGuard creates a new permission guard
func NewPermissionGuard(checker *RBACChecker, ctx context.Context, userID xid.ID) *PermissionGuard {
	return &PermissionGuard{
		checker: checker,
		ctx:     ctx,
		userID:  userID,
	}
}

// Can checks if the user can perform an action on a resource
func (pg *PermissionGuard) Can(resource, action string) (bool, error) {
	return pg.checker.CheckPermission(pg.ctx, pg.userID, resource, action)
}

// Cannot checks if the user cannot perform an action on a resource
func (pg *PermissionGuard) Cannot(resource, action string) (bool, error) {
	can, err := pg.Can(resource, action)
	return !can, err
}

// Allow executes a function only if the user has permission
func (pg *PermissionGuard) Allow(resource, action string, fn func() error) error {
	can, err := pg.Can(resource, action)
	if err != nil {
		return err
	}

	if !can {
		return errors.New(errors.CodeForbidden, "Insufficient permissions")
	}

	return fn()
}

// Deny executes a function only if the user doesn't have permission
func (pg *PermissionGuard) Deny(resource, action string, fn func() error) error {
	cannot, err := pg.Cannot(resource, action)
	if err != nil {
		return err
	}

	if !cannot {
		return errors.New(errors.CodeForbidden, "User has permission but should not")
	}

	return fn()
}
