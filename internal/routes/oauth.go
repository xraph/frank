package routes

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/oauth2"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/internal/user"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
)

// OAuthRoutes handles OAuth2 routes for both the provider and client roles
type OAuthRoutes struct {
	oauthServer   *oauth2.Server
	oauthClient   *oauth2.Client
	oauthProvider *oauth2.Provider
	userService   user.Service
	config        *config.Config
	logger        logging.Logger
	handler       *handlers.OAuthHandler
}

// NewOAuthRoutes creates a new OAuth routes handler
func NewOAuthRoutes(
	oauthService *services.OAuthServices,
	client *data.Clients,
	userService user.Service,
	config *config.Config,
	logger logging.Logger,
) *OAuthRoutes {
	handler := handlers.NewOAuthHandler(
		oauthService.Server,
		oauthService.Client,
		oauthService.Provider,
		userService,
		client.DB,
		config,
		logger,
	)

	return &OAuthRoutes{
		oauthServer:   oauthService.Server,
		oauthClient:   oauthService.Client,
		oauthProvider: oauthService.Provider,
		userService:   userService,
		config:        config,
		logger:        logger,
		handler:       handler,
	}
}

// RegisterProviderRoutes registers routes for OAuth2 provider functionality
func (r *OAuthRoutes) RegisterProviderRoutes(router chi.Router) {
	// OAuth2 Authorization Server endpoints
	router.Route("/oauth", func(router chi.Router) {
		router.HandleFunc("/authorize", r.handler.OAuthAuthorize)
		router.HandleFunc("/token", r.handler.OAuthToken)
		router.HandleFunc("/introspect", r.handler.OAuthIntrospect)
		router.HandleFunc("/revoke", r.handler.OAuthRevoke)
		router.HandleFunc("/userinfo", r.handler.OAuthUserInfo)
		router.HandleFunc("/consent", r.handler.HandleConsent)
	})
}

// RegisterClientRoutes registers routes for OAuth2 client functionality
func (r *OAuthRoutes) RegisterClientRoutes(router chi.Router) {
	router.Route("/auth/oauth", func(router chi.Router) {
		router.Get("/providers", r.handler.OAuthProvidersList)
		router.Get("/providers/{provider}", r.handler.OAuthProviderAuth)
		router.Get("/callback/{provider}", r.handler.OAuthProviderCallback)
	})
}

// OAuthConfiguration handles the OpenID Connect configuration endpoint
func (r *OAuthRoutes) OAuthConfiguration(w http.ResponseWriter, req *http.Request) {
	r.handler.OAuthConfiguration(w, req)
}

// OAuthJWKS handles the JWKS endpoint for OpenID Connect
func (r *OAuthRoutes) OAuthJWKS(w http.ResponseWriter, req *http.Request) {
	r.handler.OAuthJWKS(w, req)
}
