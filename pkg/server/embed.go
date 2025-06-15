package server

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// MountOptions provides configuration options for mounting the authentication framework
type MountOptions struct {
	// BasePath is the base path where the auth system will be mounted (e.g., "/auth", "/v1/auth")
	BasePath string

	// IncludeRoutes specifies which route groups to include in the mount
	IncludeRoutes RouteGroups

	// ExcludeRoutes specifies which route groups to exclude from the mount
	ExcludeRoutes RouteGroups

	// CustomMiddleware allows injection of additional middleware for the mounted routes
	CustomMiddleware []func(http.Handler) http.Handler

	// SkipBuiltinMiddleware controls whether to skip the built-in middleware stack
	SkipBuiltinMiddleware bool

	// OpenAPIBasePath overrides the base path in OpenAPI documentation
	OpenAPIBasePath string

	// EnableDocs controls whether to mount API documentation endpoints
	EnableDocs bool

	// CustomAPIInfo allows overriding API information for embedded scenarios
	CustomAPIInfo *huma.Info

	// TenantAware controls whether tenant middleware should be applied
	TenantAware bool
}

// RouteGroups defines which route groups to include/exclude
type RouteGroups struct {
	Public    bool // Authentication, OAuth, SSO, Passkey public endpoints
	Protected bool // Authenticated user management, organization management
	Internal  bool // Platform administration endpoints
	Webhooks  bool // Webhook management and endpoints
	Health    bool // Health check and monitoring
	Docs      bool // API documentation endpoints
}

// DefaultMountOptions returns sensible default options for mounting
func DefaultMountOptions() *MountOptions {
	return &MountOptions{
		BasePath: "/auth",
		IncludeRoutes: RouteGroups{
			Public:    true,
			Protected: true,
			Internal:  false, // Usually not needed in embedded scenarios
			Webhooks:  true,
			Health:    true,
			Docs:      true,
		},
		CustomMiddleware:      []func(http.Handler) http.Handler{},
		SkipBuiltinMiddleware: false,
		EnableDocs:            true,
		TenantAware:           true,
	}
}

// EmbeddedMountOptions returns options optimized for embedding in larger applications
func EmbeddedMountOptions(basePath string) *MountOptions {
	return &MountOptions{
		BasePath: basePath,
		IncludeRoutes: RouteGroups{
			Public:    true,
			Protected: true,
			Internal:  false,
			Webhooks:  false, // Usually handled by parent app
			Health:    false, // Parent app usually has its own health checks
			Docs:      false, // Avoid conflicts with parent app docs
		},
		CustomMiddleware:      []func(http.Handler) http.Handler{},
		SkipBuiltinMiddleware: true, // Parent app handles most middleware
		EnableDocs:            false,
		TenantAware:           true,
	}
}
