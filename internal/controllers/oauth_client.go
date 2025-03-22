package controllers

import (
	"context"
	"fmt"

	oauthclient "github.com/juicycleff/frank/gen/oauth_client"
	"goa.design/clue/log"
	"goa.design/goa/v3/security"
)

// oauth_client service example implementation.
// The example methods log the requests and return zero values.
type oauthClientsrvc struct{}

// NewOauthClient returns the oauth_client service implementation.
func NewOauthClient() oauthclient.Service {
	return &oauthClientsrvc{}
}

// OAuth2Auth implements the authorization logic for service "oauth_client" for
// the "oauth2" security scheme.
func (s *oauthClientsrvc) OAuth2Auth(ctx context.Context, token string, scheme *security.OAuth2Scheme) (context.Context, error) {
	//
	// TBD: add authorization logic.
	//
	// In case of authorization failure this function should return
	// one of the generated error structs, e.g.:
	//
	//    return ctx, myservice.MakeUnauthorizedError("invalid token")
	//
	// Alternatively this function may return an instance of
	// goa.ServiceError with a Name field value that matches one of
	// the design error names, e.g:
	//
	//    return ctx, goa.PermanentError("unauthorized", "invalid token")
	//
	return ctx, fmt.Errorf("not implemented")
}

// APIKeyAuth implements the authorization logic for service "oauth_client" for
// the "api_key" security scheme.
func (s *oauthClientsrvc) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
	//
	// TBD: add authorization logic.
	//
	// In case of authorization failure this function should return
	// one of the generated error structs, e.g.:
	//
	//    return ctx, myservice.MakeUnauthorizedError("invalid token")
	//
	// Alternatively this function may return an instance of
	// goa.ServiceError with a Name field value that matches one of
	// the design error names, e.g:
	//
	//    return ctx, goa.PermanentError("unauthorized", "invalid token")
	//
	return ctx, fmt.Errorf("not implemented")
}

// JWTAuth implements the authorization logic for service "oauth_client" for
// the "jwt" security scheme.
func (s *oauthClientsrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	//
	// TBD: add authorization logic.
	//
	// In case of authorization failure this function should return
	// one of the generated error structs, e.g.:
	//
	//    return ctx, myservice.MakeUnauthorizedError("invalid token")
	//
	// Alternatively this function may return an instance of
	// goa.ServiceError with a Name field value that matches one of
	// the design error names, e.g:
	//
	//    return ctx, goa.PermanentError("unauthorized", "invalid token")
	//
	return ctx, fmt.Errorf("not implemented")
}

// List available OAuth providers
func (s *oauthClientsrvc) ListProviders(ctx context.Context, p *oauthclient.ListProvidersPayload) (res *oauthclient.ListProvidersResult, err error) {
	res = &oauthclient.ListProvidersResult{}
	log.Printf(ctx, "oauthClient.list_providers")
	return
}

// Initiate authentication with an OAuth provider
func (s *oauthClientsrvc) ProviderAuth(ctx context.Context, p *oauthclient.ProviderAuthPayload) (err error) {
	log.Printf(ctx, "oauthClient.provider_auth")
	return
}

// Handle OAuth provider callback
func (s *oauthClientsrvc) ProviderCallback(ctx context.Context, p *oauthclient.ProviderCallbackPayload) (res *oauthclient.ProviderCallbackResult, err error) {
	res = &oauthclient.ProviderCallbackResult{}
	log.Printf(ctx, "oauthClient.provider_callback")
	return
}
