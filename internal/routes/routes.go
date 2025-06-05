package routes

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/juicycleff/frank/internal/di"
	customMiddleware "github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/server"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	goahttp "goa.design/goa/v3/http"
	"goa.design/goa/v3/middleware"
)

type routes struct {
	di     di.Container
	router chi.Router
	api    huma.API
}

func NewRoutes(di di.Container, rin chi.Router) server.Router {
	// Create Chi r
	var r chi.Router
	if rin == nil {
		r = chi.NewRouter()

		// Add built-in Chi middleware that's WebSocket and SSE compatible
		r.Use(chimw.RequestID)
		r.Use(chimw.RealIP)
		r.Use(chimw.Recoverer)

		// Make timeout middleware WebSocket and SSE-safe
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if customMiddleware.IsWebSocketRequest(r) || customMiddleware.IsSSERequest(r) {
					// Skip timeout for WebSockets and SSE
					next.ServeHTTP(w, r)
					return
				}
				chimw.Timeout(60*time.Second)(next).ServeHTTP(w, r)
			})
		})

		r.Use(chimw.Heartbeat("/"))
		r.Use(chimw.StripSlashes)

		// Skip throttling for WebSockets and SSE
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if customMiddleware.IsWebSocketRequest(r) || customMiddleware.IsSSERequest(r) {
					next.ServeHTTP(w, r)
					return
				}
				chimw.Throttle(5000)(next).ServeHTTP(w, r)
			})
		})

		// Skip backlog throttling for WebSockets and SSE
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if customMiddleware.IsWebSocketRequest(r) || customMiddleware.IsSSERequest(r) {
					next.ServeHTTP(w, r)
					return
				}
				chimw.ThrottleBacklog(10, 50, time.Second*10)(next).ServeHTTP(w, r)
			})
		})

		// SINGLE UNIFIED LOGGING MIDDLEWARE (replaces both logging middlewares)
		r.Use(customMiddleware.Logging(di.Logger()))

		// These middleware are safe for WebSockets and SSE since they only modify the request context
		r.Use(customMiddleware.AddRequestInfo())
		r.Use(customMiddleware.AddHeader())

		// Skip rate limiter for WebSockets and SSE
		if di.Config().Security.RateLimitEnabled {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if customMiddleware.IsWebSocketRequest(r) || customMiddleware.IsSSERequest(r) {
						next.ServeHTTP(w, r)
						return
					}
					customMiddleware.RateLimiter(di.Config().Security.RateLimitPerSecond, di.Config().Security.RateLimitBurst)(next).ServeHTTP(w, r)
				})
			})
		}

		// Recovery middleware (now SSE and WebSocket-aware)
		r.Use(customMiddleware.Recovery(di.Logger()))

		// Error handler middleware (now SSE and WebSocket-aware)
		r.Use(customMiddleware.ErrorHandler(di.Logger()))

		// CORS is usually compatible with WebSockets and SSE
		r.Use(customMiddleware.CORS(di.Config()))

		// Security headers middleware
		if di.Config().Security.SecHeadersEnabled {
			// r.Use(customMiddleware.SecurityHeaders(di.cfg.Security))
		}
	} else {
		r = rin
	}

	apicfg := huma.DefaultConfig("Wakflo API", "1.0.0")

	// Configure OpenAPI documentation
	apicfg.Info = &huma.Info{
		Title:          "Wakflo API",
		Description:    "Wakflo workflow automation API",
		Version:        "1.0.0",
		TermsOfService: "https://wakflo.com/terms",
		Contact: &huma.Contact{
			Name:  "API Support",
			Email: "support@wakflo.com",
			URL:   "https://wakflo.com/support",
		},
		License: &huma.License{
			Name: "Apache 2.0",
			URL:  "https://www.apache.org/licenses/LICENSE-2.0.html",
		},
	}

	// Add server configurations
	apicfg.Servers = []*huma.Server{
		{
			URL:         "http://localhost:{port}",
			Description: "Local development server",
			Variables: map[string]*huma.ServerVariable{
				"port": {
					Default:     "4000",
					Description: "API port",
				},
			},
		},
		{
			URL:         "https://{version}.api.wakflo.com",
			Description: "Production server",
			Variables: map[string]*huma.ServerVariable{
				"version": {
					Default:     "v1",
					Enum:        []string{"v1", "v2"},
					Description: "API version",
				},
			},
		},
		{
			URL:         "https://{version}.api.staging.wakflo.com",
			Description: "Staging server",
			Variables: map[string]*huma.ServerVariable{
				"version": {
					Default:     "v1",
					Enum:        []string{"v1", "v2"},
					Description: "API version",
				},
			},
		},
	}

	// Add security schemes
	apicfg.Components = &huma.Components{
		SecuritySchemes: map[string]*huma.SecurityScheme{
			"jwt": {
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "JWT",
				Description:  "JWT-based authentication and authorization",
			},
			"oauth2": {
				Type:        "oauth2",
				Description: "OAuth2 authentication",
				Flows: &huma.OAuthFlows{
					AuthorizationCode: &huma.OAuthFlow{
						AuthorizationURL: "/v1/oauth/authorize",
						TokenURL:         "/v1/oauth/token",
						RefreshURL:       "/v1/oauth/refresh",
						Scopes: map[string]string{
							"profile":        "View profile information",
							"email":          "View email information",
							"openid":         "OpenID Connect scope",
							"offline_access": "Request refresh token",
							"api":            "API access",
						},
					},
				},
			},
			"api_key": {
				Type:        "apiKey",
				In:          "header",
				Name:        "X-API-Key",
				Description: "API key-based request authorization",
			},
		},
	}

	huma.NewError = func(status int, message string, errs ...error) huma.StatusError {
		details := make([]string, len(errs))
		for i, err := range errs {
			details[i] = err.Error()
		}
		return &errors.Error{
			StatusCode: status,
			Message:    message,
			Details:    details,
		}
	}
	adapter := humachi.NewAdapter(r)
	api := huma.NewAPI(apicfg, adapter)

	r.Mount("/debug", chimw.Profiler())

	return &routes{
		di:     di,
		router: r,
		api:    api,
	}
}

func (r *routes) RegisterRoutes() {
	// orgGroup := huma.NewGroup(r.api)
	apiGroup := huma.NewGroup(r.api, "/api")
	v1Group := huma.NewGroup(apiGroup, "/v1")

	protectedGroup := huma.NewGroup(v1Group)
	// protectedGroup.UseMiddleware(r.di.Auth().Frank().AuthMiddlewareHuma(protectedGroup))
	// protectedGroup.UseMiddleware(r.di.Auth().UserReferenceMiddleware(protectedGroup))
	//
	// protectedGroup.UseMiddleware(auditLogMiddleware)

	// Register Protected Routes
	RegisterEmailAPI(protectedGroup, r.di)
	RegisterWebhookAPI(protectedGroup, r.di)
	RegisterRBACAPI(protectedGroup, r.di)

	publicGroup := huma.NewGroup(v1Group)

	RegisterWebhookPublicAPI(publicGroup, r.di)
}

// Handler returns the HTTP handler
func (r *routes) Handler() http.Handler {
	return r.router
}

// Group adds a new route group
func (r *routes) Group(fn func(r chi.Router)) {
	r.router.Group(fn)
}

// Route adds a new route group with a pattern
func (r *routes) Route(pattern string, fn func(r chi.Router)) {
	r.router.Route(pattern, fn)
}

// Use appends a middleware to the chain
func (r *routes) Use(middleware ...func(http.Handler) http.Handler) {
	r.router.Use(middleware...)
}

// Method adds a method-specific route
func (r *routes) Method(method, pattern string, handler http.HandlerFunc) {
	r.router.Method(method, pattern, handler)
}

// NotFound sets the not found handler
func (r *routes) NotFound(handler http.HandlerFunc) {
	r.router.NotFound(handler)
}

// MethodNotAllowed sets the method not allowed handler
func (r *routes) MethodNotAllowed(handler http.HandlerFunc) {
	r.router.MethodNotAllowed(handler)
}

func (r *routes) HandleFunc(pattern string, handler http.HandlerFunc) {
	r.router.HandleFunc(pattern, handler)
}

// Mount mounts this router on a parent router with a given path prefix
func (r *routes) Mount(parent chi.Router, mountPath string) {
	// Mount the router
	parent.Mount(mountPath, r.router)
}

// Handle adds a method-specific route
func (r *routes) Handle(pattern string, h http.Handler) {
	r.router.Handle(pattern, h)
}

// HumaAPI get huma api
func (r *routes) HumaAPI() huma.API {
	return r.api
}

func (r *routes) Chi() chi.Router {
	return r.router
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
