package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/handlers"
	customMiddleware "github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/pkg/logging"
)

// Router manages HTTP routing
type Router struct {
	router chi.Router
	config *config.Config
	logger logging.Logger
}

// NewRouter creates a new router
func NewRouter(cfg *config.Config, logger logging.Logger) *Router {
	r := chi.NewRouter()

	// Basic middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(logging.Middleware)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// CORS middleware
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.Security.AllowedOrigins,
		AllowedMethods:   cfg.Security.AllowedMethods,
		AllowedHeaders:   cfg.Security.AllowedHeaders,
		ExposedHeaders:   cfg.Security.ExposedHeaders,
		AllowCredentials: cfg.Security.AllowCredentials,
		MaxAge:           300, // Maximum value not caught in preflight requests
	}))

	// Rate limiting middleware if enabled
	if cfg.Security.RateLimitEnabled {
		r.Use(customMiddleware.RateLimiter(cfg.Security.RateLimitPerSecond, cfg.Security.RateLimitBurst))
	}

	// Security headers middleware
	if cfg.Security.SecHeadersEnabled {
		r.Use(customMiddleware.SecurityHeaders(cfg.Security))
	}

	return &Router{
		router: r,
		config: cfg,
		logger: logger,
	}
}

// RegisterRoutes registers all API routes
func (r *Router) RegisterRoutes() {
	// Health check routes
	r.router.Get("/health", handlers.HealthCheck)
	r.router.Get("/ready", handlers.ReadyCheck)

	// API routes
	r.router.Route("/api", func(r chi.Router) {
		// Version-specific routes
		r.Route("/v1", func(r chi.Router) {
			// Auth routes
			r.Route("/auth", func(r chi.Router) {
				// These routes will be implemented in handlers package
				r.Post("/login", handlers.Login)
				r.Post("/register", handlers.Register)
				r.Post("/logout", handlers.Logout)
				r.Post("/refresh", handlers.RefreshToken)
				r.Post("/forgot-password", handlers.ForgotPassword)
				r.Post("/reset-password", handlers.ResetPassword)
				r.Post("/verify-email", handlers.VerifyEmail)

				// MFA routes
				r.Route("/mfa", func(r chi.Router) {
					r.Post("/enroll", handlers.MFAEnroll)
					r.Post("/verify", handlers.MFAVerify)
					r.Delete("/unenroll", handlers.MFAUnenroll)
				})

				// Passwordless routes
				r.Route("/passwordless", func(r chi.Router) {
					r.Post("/email", handlers.PasswordlessEmail)
					r.Post("/sms", handlers.PasswordlessSMS)
					r.Post("/verify", handlers.PasswordlessVerify)
				})

				// Passkeys routes
				r.Route("/passkeys", func(r chi.Router) {
					r.Post("/register/begin", handlers.PasskeyRegisterBegin)
					r.Post("/register/complete", handlers.PasskeyRegisterComplete)
					r.Post("/login/begin", handlers.PasskeyLoginBegin)
					r.Post("/login/complete", handlers.PasskeyLoginComplete)
				})

				// OAuth routes
				r.Route("/oauth", func(r chi.Router) {
					r.Get("/authorize", handlers.OAuthAuthorize)
					r.Post("/token", handlers.OAuthToken)
					r.Post("/introspect", handlers.OAuthIntrospect)
					r.Post("/revoke", handlers.OAuthRevoke)

					// Provider-specific auth routes
					r.Get("/providers", handlers.OAuthProvidersList)
					r.Get("/providers/{provider}", handlers.OAuthProviderAuth)
					r.Get("/callback/{provider}", handlers.OAuthProviderCallback)
				})

				// SSO routes
				r.Route("/sso", func(r chi.Router) {
					r.Get("/providers", handlers.SSOProvidersList)
					r.Get("/providers/{provider}", handlers.SSOProviderAuth)
					r.Get("/callback/{provider}", handlers.SSOProviderCallback)
				})
			})

			// Protected routes (require authentication)
			r.Group(func(r chi.Router) {
				r.Use(customMiddleware.Auth)

				// User routes
				r.Route("/users", func(r chi.Router) {
					r.Get("/me", handlers.GetCurrentUser)
					r.Put("/me", handlers.UpdateCurrentUser)
					r.Get("/me/sessions", handlers.GetUserSessions)
					r.Delete("/me/sessions/{id}", handlers.DeleteUserSession)

					// Admin only routes
					r.Group(func(r chi.Router) {
						r.Use(customMiddleware.RequirePermission("users:admin"))

						r.Get("/", handlers.ListUsers)
						r.Post("/", handlers.CreateUser)
						r.Get("/{id}", handlers.GetUser)
						r.Put("/{id}", handlers.UpdateUser)
						r.Delete("/{id}", handlers.DeleteUser)
					})
				})

				// Organization routes
				r.Route("/organizations", func(r chi.Router) {
					r.Get("/", handlers.ListOrganizations)
					r.Post("/", handlers.CreateOrganization)
					r.Get("/{id}", handlers.GetOrganization)
					r.Put("/{id}", handlers.UpdateOrganization)
					r.Delete("/{id}", handlers.DeleteOrganization)

					// Organization members
					r.Get("/{id}/members", handlers.ListOrganizationMembers)
					r.Post("/{id}/members", handlers.AddOrganizationMember)
					r.Delete("/{id}/members/{userId}", handlers.RemoveOrganizationMember)
					r.Put("/{id}/members/{userId}", handlers.UpdateOrganizationMember)

					// Organization features
					r.Get("/{id}/features", handlers.ListOrganizationFeatures)
					r.Post("/{id}/features", handlers.EnableOrganizationFeature)
					r.Delete("/{id}/features/{featureKey}", handlers.DisableOrganizationFeature)
				})

				// API key routes
				r.Route("/api-keys", func(r chi.Router) {
					r.Get("/", handlers.ListAPIKeys)
					r.Post("/", handlers.CreateAPIKey)
					r.Get("/{id}", handlers.GetAPIKey)
					r.Put("/{id}", handlers.UpdateAPIKey)
					r.Delete("/{id}", handlers.DeleteAPIKey)
				})

				// Webhook routes
				r.Route("/webhooks", func(r chi.Router) {
					r.Get("/", handlers.ListWebhooks)
					r.Post("/", handlers.CreateWebhook)
					r.Get("/{id}", handlers.GetWebhook)
					r.Put("/{id}", handlers.UpdateWebhook)
					r.Get("/{id}", handlers.GetWebhook)
					r.Put("/{id}", handlers.UpdateWebhook)
					r.Delete("/{id}", handlers.DeleteWebhook)

					// Webhook events
					r.Get("/{id}/events", handlers.ListWebhookEvents)
					r.Post("/{id}/events/{eventId}/replay", handlers.ReplayWebhookEvent)
				})

				// Email template routes
				r.Route("/email-templates", func(r chi.Router) {
					r.Get("/", handlers.ListEmailTemplates)
					r.Post("/", handlers.CreateEmailTemplate)
					r.Get("/{id}", handlers.GetEmailTemplate)
					r.Put("/{id}", handlers.UpdateEmailTemplate)
					r.Delete("/{id}", handlers.DeleteEmailTemplate)
				})

				// RBAC routes
				r.Route("/roles", func(r chi.Router) {
					r.Get("/", handlers.ListRoles)
					r.Post("/", handlers.CreateRole)
					r.Get("/{id}", handlers.GetRole)
					r.Put("/{id}", handlers.UpdateRole)
					r.Delete("/{id}", handlers.DeleteRole)

					// Role permissions
					r.Get("/{id}/permissions", handlers.ListRolePermissions)
					r.Post("/{id}/permissions", handlers.AddRolePermission)
					r.Delete("/{id}/permissions/{permissionId}", handlers.RemoveRolePermission)
				})

				r.Route("/permissions", func(r chi.Router) {
					r.Get("/", handlers.ListPermissions)
					r.Post("/", handlers.CreatePermission)
					r.Get("/{id}", handlers.GetPermission)
					r.Put("/{id}", handlers.UpdatePermission)
					r.Delete("/{id}", handlers.DeletePermission)
				})
			})
		})
	})

	// OAuth provider endpoints
	r.router.Route("/oauth", func(r chi.Router) {
		r.Get("/authorize", handlers.OAuthAuthorize)
		r.Post("/token", handlers.OAuthToken)
		r.Get("/userinfo", handlers.OAuthUserInfo)
		r.Get("/.well-known/openid-configuration", handlers.OAuthConfiguration)
		r.Get("/.well-known/jwks.json", handlers.OAuthJWKS)
	})

	// SAML endpoints
	r.router.Route("/saml", func(r chi.Router) {
		r.Post("/acs", handlers.SAMLAssertionConsumerService)
		r.Get("/metadata", handlers.SAMLMetadata)
	})

	// Webhook endpoints (for receiving notifications)
	r.router.Post("/webhooks/{id}", handlers.ReceiveWebhook)

	// Static assets (if needed)
	fileServer := http.FileServer(http.Dir("./web/static"))
	r.router.Handle("/static/*", http.StripPrefix("/static", fileServer))
}

// Handler returns the HTTP handler
func (r *Router) Handler() http.Handler {
	return r.router
}

// Group adds a new route group
func (r *Router) Group(fn func(r chi.Router)) {
	r.router.Group(fn)
}

// Route adds a new route group with a pattern
func (r *Router) Route(pattern string, fn func(r chi.Router)) {
	r.router.Route(pattern, fn)
}

// Use appends a middleware to the chain
func (r *Router) Use(middleware ...func(http.Handler) http.Handler) {
	r.router.Use(middleware...)
}

// Method adds a method-specific route
func (r *Router) Method(method, pattern string, handler http.HandlerFunc) {
	r.router.Method(method, pattern, handler)
}

// NotFound sets the not found handler
func (r *Router) NotFound(handler http.HandlerFunc) {
	r.router.NotFound(handler)
}

// MethodNotAllowed sets the method not allowed handler
func (r *Router) MethodNotAllowed(handler http.HandlerFunc) {
	r.router.MethodNotAllowed(handler)
}
