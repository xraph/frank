package controllers

import (
	"context"

	"github.com/juicycleff/frank/config"
	oauthclienthttp "github.com/juicycleff/frank/gen/http/oauth_client/server"
	oauthclient "github.com/juicycleff/frank/gen/oauth_client"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"goa.design/clue/debug"
	"goa.design/clue/log"
	goahttp "goa.design/goa/v3/http"
	"goa.design/goa/v3/security"
)

func RegisterOauthClientHTTPService(
	mux goahttp.Muxer,
	svcs *services.Services,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
) {
	eh := errorHandler(logger)
	svc := NewOauthClient(
		svcs,
		config,
		logger,
		auther,
	)

	endpoints := oauthclient.NewEndpoints(svc)
	handler := oauthclienthttp.New(endpoints, mux, decoder, encoder, eh, errors.CustomErrorFormatter)

	endpoints.Use(debug.LogPayloads())
	endpoints.Use(log.Endpoint)

	oauthclienthttp.Mount(mux, handler)
}

// oauth_client service example implementation.
// The example methods log the requests and return zero values.
type oauthClientsrvc struct {
	svcs   *services.Services
	config *config.Config
	logger logging.Logger
	auther *AutherService
}

// NewOauthClient returns the oauth_client service implementation.
func NewOauthClient(
	svcs *services.Services,
	cfg *config.Config,
	logger logging.Logger,
	auther *AutherService,
) oauthclient.Service {
	return &oauthClientsrvc{
		svcs:   svcs,
		config: cfg,
		logger: logger,
		auther: auther,
	}
}

// OAuth2Auth implements the authorization logic for service "oauth_client" for
// the "oauth2" security scheme.
func (s *oauthClientsrvc) OAuth2Auth(ctx context.Context, token string, scheme *security.OAuth2Scheme) (context.Context, error) {
	return s.auther.OAuth2Auth(ctx, token, scheme)
}

// APIKeyAuth implements the authorization logic for service "oauth_client" for
// the "api_key" security scheme.
func (s *oauthClientsrvc) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
	return s.auther.APIKeyAuth(ctx, key, scheme)
}

// JWTAuth implements the authorization logic for service "oauth_client" for
// the "jwt" security scheme.
func (s *oauthClientsrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	return s.auther.JWTAuth(ctx, token, scheme)
}

// ListProviders List available OAuth providers
func (s *oauthClientsrvc) ListProviders(ctx context.Context, p *oauthclient.ListProvidersPayload) (res *oauthclient.ListProvidersResult, err error) {
	res = &oauthclient.ListProvidersResult{
		Providers: make([]*oauthclient.SSOProvider, 0),
	}
	log.Printf(ctx, "oauthClient.list_providers")
	return
}

// ProviderAuth Initiate authentication with an OAuth provider
func (s *oauthClientsrvc) ProviderAuth(ctx context.Context, p *oauthclient.ProviderAuthPayload) (err error) {
	log.Printf(ctx, "oauthClient.provider_auth")
	return
}

// ProviderCallback Handle OAuth provider callback
func (s *oauthClientsrvc) ProviderCallback(ctx context.Context, p *oauthclient.ProviderCallbackPayload) (res *oauthclient.ProviderCallbackResult, err error) {
	res = &oauthclient.ProviderCallbackResult{}
	log.Printf(ctx, "oauthClient.provider_callback")
	return
}
