package middleware

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/pkg/logging"
)

// FrontendRouteOptions configures how the frontend route protection middleware behaves
type FrontendRouteOptions struct {
	// PublicPaths defines routes that are accessible without authentication
	PublicPaths []string

	// ProtectedPaths defines routes that require authentication
	ProtectedPaths []string

	// LoginPath is the path to redirect to when authentication is required
	LoginPath string

	// StaticFilePrefixes defines prefixes for static files that bypass protection
	StaticFilePrefixes []string
}

// DefaultFrontendRouteOptions returns the default frontend route options
func DefaultFrontendRouteOptions(cfg *config.Config) FrontendRouteOptions {
	return FrontendRouteOptions{
		PublicPaths: []string{
			"/",
			"/login",
			"/signup",
			"/register",
			"/forgot-password",
			"/reset-password",
			"/verify-email",
			"/privacy",
			"/terms",
			"/about",
			"/contact",
		},
		ProtectedPaths: []string{
			"/dashboard",
			"/profile",
			"/settings",
			"/projects",
			"/reports",
			"/admin",
		},
		LoginPath: "/login",
		StaticFilePrefixes: []string{
			"/_astro/",
			"/assets/",
		},
	}
}

// FrontendRouteProtection protects frontend routes and redirects to login when needed
type FrontendRouteProtection struct {
	config         *config.Config
	logger         logging.Logger
	sessionManager *session.Manager
	cookieHandler  *session.CookieHandler
	options        FrontendRouteOptions
	publicPaths    map[string]bool
	protectedPaths map[string]bool
}

// NewFrontendRouteProtection creates a new frontend route protection middleware
func NewFrontendRouteProtection(
	cfg *config.Config,
	logger logging.Logger,
	sessionManager *session.Manager,
	cookieHandler *session.CookieHandler,
) *FrontendRouteProtection {
	options := DefaultFrontendRouteOptions(cfg)

	// Convert paths to maps for faster lookup
	publicPaths := make(map[string]bool)
	for _, path := range options.PublicPaths {
		publicPaths[path] = true
	}

	protectedPaths := make(map[string]bool)
	for _, path := range options.ProtectedPaths {
		protectedPaths[path] = true
	}

	return &FrontendRouteProtection{
		config:         cfg,
		logger:         logger,
		sessionManager: sessionManager,
		cookieHandler:  cookieHandler,
		options:        options,
		publicPaths:    publicPaths,
		protectedPaths: protectedPaths,
	}
}

// WithOptions sets custom options for the middleware
func (f *FrontendRouteProtection) WithOptions(options FrontendRouteOptions) *FrontendRouteProtection {
	f.options = options

	// Update maps from options
	f.publicPaths = make(map[string]bool)
	for _, path := range options.PublicPaths {
		f.publicPaths[path] = true
	}

	f.protectedPaths = make(map[string]bool)
	for _, path := range options.ProtectedPaths {
		f.protectedPaths[path] = true
	}

	return f
}

// SetPublicPaths sets the public paths
func (f *FrontendRouteProtection) SetPublicPaths(paths ...string) *FrontendRouteProtection {
	f.options.PublicPaths = paths
	f.publicPaths = make(map[string]bool)
	for _, path := range paths {
		f.publicPaths[path] = true
	}
	return f
}

// SetProtectedPaths sets the protected paths
func (f *FrontendRouteProtection) SetProtectedPaths(paths ...string) *FrontendRouteProtection {
	f.options.ProtectedPaths = paths
	f.protectedPaths = make(map[string]bool)
	for _, path := range paths {
		f.protectedPaths[path] = true
	}
	return f
}

// SetLoginPath sets the login path
func (f *FrontendRouteProtection) SetLoginPath(path string) *FrontendRouteProtection {
	f.options.LoginPath = path
	return f
}

// SetStaticFilePrefixes sets the static file prefixes
func (f *FrontendRouteProtection) SetStaticFilePrefixes(prefixes ...string) *FrontendRouteProtection {
	f.options.StaticFilePrefixes = prefixes
	return f
}

// ProtectFrontendRoutes returns a middleware that protects frontend routes
func (f *FrontendRouteProtection) ProtectFrontendRoutes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Skip protection for API routes (let the API handle its own auth)
		if strings.HasPrefix(path, "/v1/") {
			next.ServeHTTP(w, r)
			return
		}

		// Skip protection for static files
		for _, prefix := range f.options.StaticFilePrefixes {
			if strings.HasPrefix(path, prefix) {

				// Check if the request ends with a .js file
				if strings.HasSuffix(path, ".js") {
					w.Header().Set("Content-Type", "application/javascript")
				}
				next.ServeHTTP(w, r)
				return
			}
		}

		// Allow public paths
		if f.IsPublicPath(path) {
			// Check if user is authenticated
			userId, ok := GetUserIDReq(r)
			if ok && userId != "" {
				// User is authenticated and on a public path, redirect them

				// Check for returnUrl in query parameters
				returnURL := r.URL.Query().Get("returnUrl")

				if returnURL != "" {
					// Make sure returnUrl is relative for security
					if !strings.HasPrefix(returnURL, "/") {
						returnURL = "/" + returnURL
					}

					// Redirect to the return URL
					http.Redirect(w, r, returnURL, http.StatusSeeOther)
					return
				}

				// No returnUrl, redirect to index page
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// For protected paths or any non-public path, check authentication
		if f.IsProtectedPath(path) || !f.IsPublicPath(path) {
			// Check if user is authenticated via session
			authenticated := false
			userId, ok := GetUserIDReq(r)
			if ok && userId != "" {
				authenticated = true
			}

			if !authenticated {
				// Redirect to login page with return URL
				returnURL := r.URL.String()
				loginURL := f.options.LoginPath

				// Add return URL as query parameter if it's not the login page itself
				if returnURL != loginURL && returnURL != "/" {
					loginURL += "?returnUrl=" + returnURL
				}

				http.Redirect(w, r, loginURL, http.StatusFound)
				return
			}
		}

		// User is authenticated or path doesn't require authentication
		next.ServeHTTP(w, r)
	})
}

// IsPublicPath checks if a path is public
func (f *FrontendRouteProtection) IsPublicPath(path string) bool {
	// Check for exact match
	if f.publicPaths[path] {
		return true
	}

	// Check for path prefix matches
	for publicPath := range f.publicPaths {
		if strings.HasSuffix(publicPath, "*") {
			prefix := strings.TrimSuffix(publicPath, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}

	return false
}

func (f *FrontendRouteProtection) LoginPath() string {
	return f.options.LoginPath
}

func (f *FrontendRouteProtection) Config() *config.Config {
	return f.config
}

func (f *FrontendRouteProtection) GetStaticFilePrefixes() []string {
	return f.options.StaticFilePrefixes
}

// IsProtectedPath checks if a path is protected
func (f *FrontendRouteProtection) IsProtectedPath(path string) bool {
	// Check for exact match
	if f.protectedPaths[path] {
		return true
	}

	// Check for path prefix matches
	for protectedPath := range f.protectedPaths {
		if strings.HasSuffix(protectedPath, "*") {
			prefix := strings.TrimSuffix(protectedPath, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}

	return false
}

// RegisterWithRouter registers the frontend route protection with a router
func (f *FrontendRouteProtection) RegisterWithRouter(router chi.Router) {
	router.Use(f.ProtectFrontendRoutes)
}
