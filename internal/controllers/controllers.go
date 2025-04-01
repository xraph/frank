package controllers

import (
	"context"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	openmw "github.com/go-openapi/runtime/middleware"
	"github.com/juicycleff/frank/config"
	genht "github.com/juicycleff/frank/gen/http"
	"github.com/juicycleff/frank/internal/hooks"
	customMiddleware "github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/router"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
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
	hooks             *hooks.Hooks
	pathPrefix        string
	webRouteProtector *customMiddleware.FrontendRouteProtection
}

func NewControllers(
	clients *data.Clients,
	svcs *services.Services,
	cfg *config.Config,
	hooks *hooks.Hooks,
	logger logging.Logger,
	router *chi.Mux,
) router.FrankRouter {
	// Create Chi r
	var r *chi.Mux
	if router != nil {
		r = router
	} else {
		r = chi.NewRouter()
	}

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

	c := &Controllers{
		svcs:              svcs,
		router:            r,
		config:            cfg,
		logger:            logger,
		clients:           clients,
		auther:            NewAuther(cfg, logger, svcs.Session, svcs.CookieHandler, svcs.APIKey),
		webRouteProtector: routeProtector,
		pathPrefix:        cfg.BasePath,
		hooks:             hooks,
	}

	c.router.Use(c.MiddlewarePathRewriter())

	return c
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

	// Register controllers
	RegisterHealthHTTPService(mux, c.clients, c.svcs, c.config, c.logger, c.auther) // Register Health Service
	RegisterAuthHTTPService(mux, c.svcs, c.config, c.logger, c.auther, c.hooks)     // Register Auth Service
	RegisterUserHTTPService(mux, c.svcs, c.config, c.logger, c.auther)              // Register User Service
	RegisterRBACHTTPService(mux, c.svcs, c.config, c.logger, c.auther)              // Register RBAC Service
	RegisterOauthProviderHTTPService(mux, c.svcs, c.config, c.logger, c.auther)     // Register Oauth Provider Service
	RegisterOauthClientHTTPService(mux, c.svcs, c.config, c.logger, c.auther)       // Register Oauth Client Service
	RegisterSSOHTTPService(mux, c.svcs, c.config, c.logger, c.auther)               // Register SSO Service

	// doc := redoc.Redoc{
	// 	Title:       "Example API",
	// 	Description: "Example API Description",
	// 	SpecFile:    "./gen/http/openapi3.json", // "./openapi.yaml"
	// 	DocsPath:    "/redoc",
	// }
	// c.router.Handle("/redoc", http.StripPrefix("/redoc", doc.Handler()))

	// Serve Swagger UI
	opts := openmw.SwaggerUIOpts{
		SpecURL: "/swagger.json",
	}

	sh := openmw.SwaggerUI(opts, nil)
	c.router.Handle("/docs", sh)

	// Serve the OpenAPI spec
	c.router.Get("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		// Open the embedded file
		file, err := genht.DocsFs.Open("openapi3.yaml")
		if err != nil {
			http.Error(w, "Could not open OpenAPI spec", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		// Get file info for content type and modification time
		stat, err := file.Stat()
		if err != nil {
			http.Error(w, "Could not stat OpenAPI spec", http.StatusInternalServerError)
			return
		}

		// Set content type
		w.Header().Set("Content-Type", "application/json")

		// Serve the file content
		http.ServeContent(w, r, "/swagger.json", stat.ModTime(), file.(io.ReadSeeker))
	})

	// Configure the route protector

	c.router.Handle("/v1/*", mux)
	c.router.Handle("/__health", mux)
	c.router.Handle("/__version", mux)
	c.router.Handle("/__debug", mux)
	c.router.Handle("/__metrics", mux)
	c.router.Handle("/__ready", mux)

	RegisterFrontendRoutes(
		c,
		c.svcs,
		c.config,
		c.logger,
	)
}

// Handler returns the HTTP handler
func (c *Controllers) Handler() http.Handler {
	return c.router
}

func (c *Controllers) HandleFunc(pattern string, handler http.HandlerFunc) {
	c.router.HandleFunc(pattern, handler)
}

// Group adds a new route group
func (c *Controllers) Group(fn func(r chi.Router)) {
	c.router.Group(fn)
}

// Mount mounts this router on a parent router with a given path prefix
func (c *Controllers) Mount(parent chi.Router, mountPath string) {
	// Set the path prefix for URL generation
	c.pathPrefix = path.Join(mountPath, c.config.BasePath)

	// Mount the router
	parent.Mount(mountPath, c.router)
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

// Handle adds a method-specific route
func (c *Controllers) Handle(pattern string, h http.Handler) {
	c.router.Handle(pattern, h)
}

// NotFound sets the not found handler
func (c *Controllers) NotFound(handler http.HandlerFunc) {
	c.router.NotFound(handler)
}

// MethodNotAllowed sets the method not allowed handler
func (c *Controllers) MethodNotAllowed(handler http.HandlerFunc) {
	c.router.MethodNotAllowed(handler)
}

// BuildPath builds an absolute path from the given relative path
// This will work whether the router is standalone or mounted
func (c *Controllers) BuildPath(relativePath string) string {
	return path.Join(c.pathPrefix, relativePath)
}

// MiddlewarePathRewriter rewrites request paths to work correctly when mounted
func (c *Controllers) MiddlewarePathRewriter() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if c.pathPrefix == "" || c.pathPrefix == "/" {
				next.ServeHTTP(w, req)
				return
			}

			// Store the original path for later reference if needed
			ctx := req.Context()
			originalPath := req.URL.Path

			// Now trim the path prefix
			if c.pathPrefix != "" && strings.HasPrefix(req.URL.Path, c.pathPrefix) {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, c.pathPrefix)
				if req.URL.Path == "" {
					req.URL.Path = "/"
				}
			}

			// You could store the original path in the context if needed
			ctx = context.WithValue(ctx, "contextKeyOriginalPath", originalPath)
			req = req.WithContext(ctx)

			next.ServeHTTP(w, req)
		})
	}
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
