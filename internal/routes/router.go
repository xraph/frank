package routes

import (
	"net/http"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/juicycleff/frank/api/swagger"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/handlers"
	customMiddleware "github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/internal/swaggergen"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
	httpSwagger "github.com/swaggo/http-swagger"
	_ "github.com/swaggo/swag"
)

// Router manages HTTP routing
type Router struct {
	svcs    *services.Services
	router  chi.Router
	config  *config.Config
	logger  logging.Logger
	faktory *Factory
}

// NewRouter creates a new router
func NewRouter(clients *data.Clients, svcs *services.Services, cfg *config.Config, logger logging.Logger) *Router {
	// Create Chi r
	r := chi.NewRouter()

	// Add built-in Chi middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Add custom middleware
	r.Use(customMiddleware.Logging(logger))
	r.Use(logging.Middleware)
	r.Use(customMiddleware.RequestLogging)

	// Add rate limiter if enabled
	if cfg.Security.RateLimitEnabled {
		r.Use(customMiddleware.RateLimiter(cfg.Security.RateLimitPerSecond, cfg.Security.RateLimitBurst))
	}

	// Add recovery middleware
	r.Use(customMiddleware.Recovery(logger))
	r.Use(customMiddleware.ErrorHandler(logger))

	// CORS middleware
	r.Use(customMiddleware.CORS(cfg))

	// Rate limiting middleware if enabled
	if cfg.Security.RateLimitEnabled {
		r.Use(customMiddleware.RateLimiter(cfg.Security.RateLimitPerSecond, cfg.Security.RateLimitBurst))
	}

	// Security headers middleware
	if cfg.Security.SecHeadersEnabled {
		// r.Use(customMiddleware.SecurityHeaders(cfg.Security))
	}

	faktory := NewFactory(svcs, clients, cfg, logger)

	return &Router{
		router:  r,
		config:  cfg,
		logger:  logger,
		svcs:    svcs,
		faktory: faktory,
	}
}

// RegisterRoutes registers all API routes
func (r *Router) RegisterRoutes() {
	faktory := r.faktory

	// Health check routes
	faktory.Health.RegisterPublicRoutes(r.router)

	// Apply Auth middleware - you might need to modify your Auth middleware to work with Chi
	// Since Chi uses middleware differently, the Auth middleware should be adapted
	authMw := customMiddleware.Auth(r.config, r.logger, r.svcs.Session, r.svcs.APIKey)

	// Organization middleware (for routes that need organization context)
	orgMiddleware := customMiddleware.NewOrganizationMiddleware(r.config, r.svcs.Organization, r.logger)

	// API routes
	r.router.Route("/api", func(r chi.Router) {
		// Version-specific routes
		r.Route("/v1", func(r chi.Router) {
			// Public routes (no auth required)
			r.Group(func(r chi.Router) {
				// Auth routes (login, register, etc.)
				faktory.Auth.RegisterPublicRoutes(r)

				// OAuth2 provider endpoints (authorize, token, etc.)
				faktory.OAuth.RegisterProviderRoutes(r)

				// Passwordless auth endpoints
				faktory.Passwordless.RegisterPublicRoutes(r)

				// Passkey auth endpoints
				faktory.Passkey.RegisterPublicRoutes(r)

				// SSO endpoints
				faktory.SSO.RegisterPublicRoutes(r)
			})

			// Protected routes (auth required)
			r.Group(func(r chi.Router) {
				// Apply auth middleware
				r.Use(authMw)
				r.Use(customMiddleware.RequireAuthentication)

				// Auth routes
				faktory.Auth.RegisterRoutes(r)

				// User routes
				faktory.User.RegisterRoutes(r)

				// MFA routes
				faktory.MFA.RegisterRoutes(r)

				// API Key routes
				faktory.APIKey.RegisterRoutes(r)

				// Organization routes (basic routes)
				faktory.Organization.RegisterRoutes(r)

				// Webhooks routes
				faktory.Webhook.RegisterRoutes(r)

				// OAuth client routes
				faktory.OAuth.RegisterClientRoutes(r)

				// Passkey routes
				faktory.Passkey.RegisterRoutes(r)

				// Passwordless routes
				faktory.Passwordless.RegisterRoutes(r)

				// SSO routes
				faktory.SSO.RegisterRoutes(r)

				// Roles routes
				faktory.RBAC.RegisterRolesRoutes(r)

				// Permissions routes
				faktory.RBAC.RegisterPermissionsRoutes(r)

				// Email template routes
				faktory.Email.RegisterRoutes(r)
			})

			// Organization-specific routes (require org context)
			r.Group(func(r chi.Router) {
				// Apply auth middleware plus organization middleware
				r.Use(authMw)
				r.Use(customMiddleware.RequireAuthentication)
				r.Use(orgMiddleware.RequireOrganization)
				r.Use(orgMiddleware.RequireOrganizationMember)

				// Organization management routes
				faktory.Organization.RegisterOrganizationRoutes(r)

				// Feature-specific routes that require organization context
				r.Group(func(r chi.Router) {
					r.Use(orgMiddleware.RequireFeatureEnabled("webhooks"))
					faktory.Webhook.RegisterOrganizationRoutes(r)
				})

				r.Group(func(r chi.Router) {
					r.Use(orgMiddleware.RequireFeatureEnabled("sso"))
					faktory.SSO.RegisterOrganizationRoutes(r)
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

	// Swagger endpoint
	r.router.Get("/docs/*", httpSwagger.WrapHandler)

	// OIDC discovery endpoints
	r.router.Get("/.well-known/openid-configuration", faktory.OAuth.OAuthConfiguration)
	r.router.Get("/.well-known/jwks.json", faktory.OAuth.OAuthJWKS)

	// Webhook endpoints (for receiving notifications)
	r.router.Post("/webhooks/{id}", handlers.ReceiveWebhook)

	// Static assets (if needed)
	fileServer := http.FileServer(http.Dir("./web/static"))
	r.router.Handle("/static/*", http.StripPrefix("/static", fileServer))

	r.router.Handle("/*", handlers.FileServer("./web/client/dist", r.router))

	// Create a new Swagger generator
	info := &openapi3.Info{
		Title:       "User API",
		Description: "API for managing users",
		Version:     "1.0.0",
		Contact: &openapi3.Contact{
			Name:  "API Support",
			Email: "support@example.com",
		},
	}
	swaggerGen := swaggergen.NewSwaggerGen(r.router, info)

	if r.config.GenerateSwagger {
		// Extract all routes
		if err := swaggerGen.ExtractRoutes(); err != nil {
			panic(err)
		}

		// Save the OpenAPI specification
		if err := swaggerGen.SaveJSON("api/swagger/openapi.json"); err != nil {
			panic(err)
		}

		// if err := swaggerGen.SaveYAML("../../api/swagger/openapi.yaml"); err != nil {
		// 	panic(err)
		// }
	}
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
