package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	openmw "github.com/go-openapi/runtime/middleware"
	"github.com/juicycleff/frank/config"
	customMiddleware "github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/router"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/mvrilo/go-redoc"
	goahttp "goa.design/goa/v3/http"
	"goa.design/goa/v3/middleware"
)

type Controllers struct {
	svcs              *services.Services
	router            chi.Router
	config            *config.Config
	logger            logging.Logger
	clients           *data.Clients
	auther            *AutherService
	webRouteProtector *customMiddleware.FrontendRouteProtection
}

func NewControllers(
	clients *data.Clients,
	svcs *services.Services,
	cfg *config.Config,
	logger logging.Logger,
) router.FrankRouter {
	// Create Chi r
	r := chi.NewRouter()

	// Add built-in Chi middleware
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	// Add custom middleware
	r.Use(customMiddleware.Logging(logger))
	r.Use(logging.Middleware)

	r.Use(customMiddleware.AddRequestInfo())
	r.Use(customMiddleware.AddHeader())
	// r.Use(svcs.Session.Middleware())

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

	// Create route protection middleware
	routeProtector := customMiddleware.NewFrontendRouteProtection(
		cfg,
		logger,
		svcs.Session,
		svcs.CookieHandler,
		// svcs.APIKey,
		// svcs.Organization,
	)

	return &Controllers{
		svcs:              svcs,
		router:            r,
		config:            cfg,
		logger:            logger,
		clients:           clients,
		auther:            NewAuther(cfg, logger, svcs.Session, svcs.CookieHandler, svcs.APIKey),
		webRouteProtector: routeProtector,
	}
}

func (c *Controllers) RegisterRoutes() {
	// Set up CSRF configuration
	csrfConfig := customMiddleware.DefaultCSRFConfig()
	csrfConfig.RegenerateOnRequest = false // Set to true to regenerate token on every request
	csrfConfig.CookieExpiry = 8 * time.Hour

	// Initialize the services
	mux := goahttp.NewMuxer()

	mux.Use(customMiddleware.AddHeader())
	mux.Use(customMiddleware.AddRequestInfo())
	mux.Use(customMiddleware.CSRFProtectionWithConfig(c.config, c.logger, csrfConfig))

	RegisterHealthHTTPService(mux, c.clients, c.svcs, c.config, c.logger, c.auther) // Register Health Service
	RegisterAuthHTTPService(mux, c.svcs, c.config, c.logger, c.auther)              // Register Auth Service
	RegisterUserHTTPService(mux, c.svcs, c.config, c.logger, c.auther)              // Register User Service

	doc := redoc.Redoc{
		Title:       "Example API",
		Description: "Example API Description",
		SpecFile:    "./gen/http/openapi3.json", // "./openapi.yaml"
		DocsPath:    "/redoc",
	}
	c.router.Handle("/redoc", http.StripPrefix("/redoc", doc.Handler()))

	// Serve Swagger UI
	opts := openmw.SwaggerUIOpts{
		SpecURL: "/swagger.json",
	}

	sh := openmw.SwaggerUI(opts, nil)
	c.router.Handle("/docs", sh)

	// Serve the OpenAPI spec
	c.router.Get("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./gen/http/openapi3.json")
	})

	// Configure the route protector

	c.router.Handle("/v1/*", mux)
	c.router.Handle("/__health", mux)
	c.router.Handle("/__version", mux)
	c.router.Handle("/__debug", mux)
	c.router.Handle("/__metrics", mux)
	c.router.Handle("/__ready", mux)

	// c.router.Handle("/*", FileServer("./web/client/dist", c.router))
	RegisterFrontendRoutes(
		c.router,
		"web/client/dist",
		c.svcs,
		c.config,
		c.logger,
		// "/*",
	)
}

// Handler returns the HTTP handler
func (c *Controllers) Handler() http.Handler {
	return c.router
}

// Group adds a new route group
func (c *Controllers) Group(fn func(r chi.Router)) {
	c.router.Group(fn)
}

// Route adds a new route group with a pattern
func (c *Controllers) Route(pattern string, fn func(r chi.Router)) {
	c.router.Route(pattern, fn)
}

// Use appends a middleware to the chain
func (c *Controllers) Use(middleware ...func(http.Handler) http.Handler) {
	c.router.Use(middleware...)
}

// Method adds a method-specific route
func (c *Controllers) Method(method, pattern string, handler http.HandlerFunc) {
	c.router.Method(method, pattern, handler)
}

// NotFound sets the not found handler
func (c *Controllers) NotFound(handler http.HandlerFunc) {
	c.router.NotFound(handler)
}

// MethodNotAllowed sets the method not allowed handler
func (c *Controllers) MethodNotAllowed(handler http.HandlerFunc) {
	c.router.MethodNotAllowed(handler)
}

// Helper functions
func decoder(r *http.Request) goahttp.Decoder {
	return goahttp.RequestDecoder(r)
}

func encoder(ctx context.Context, w http.ResponseWriter) goahttp.Encoder {
	return goahttp.ResponseEncoder(ctx, w)
}

func errorHandler(logger logging.Logger) func(context.Context, http.ResponseWriter, error) {
	return func(ctx context.Context, w http.ResponseWriter, err error) {
		id := ctx.Value(middleware.RequestIDKey)
		logger.Errorf("[%s] ERROR: %s", id, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
}
