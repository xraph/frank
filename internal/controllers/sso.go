package controllers

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/gen/sso"
	"goa.design/clue/log"
	"goa.design/goa/v3/security"
)

// sso service example implementation.
// The example methods log the requests and return zero values.
type ssosrvc struct{}

// NewSso returns the sso service implementation.
func NewSso() sso.Service {
	return &ssosrvc{}
}

// OAuth2Auth implements the authorization logic for service "sso" for the
// "oauth2" security scheme.
func (s *ssosrvc) OAuth2Auth(ctx context.Context, token string, scheme *security.OAuth2Scheme) (context.Context, error) {
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

// APIKeyAuth implements the authorization logic for service "sso" for the
// "api_key" security scheme.
func (s *ssosrvc) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
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

// JWTAuth implements the authorization logic for service "sso" for the "jwt"
// security scheme.
func (s *ssosrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
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

// List available SSO providers
func (s *ssosrvc) ListProviders(ctx context.Context, p *sso.ListProvidersPayload) (res *sso.ListProvidersResult, err error) {
	res = &sso.ListProvidersResult{}
	log.Printf(ctx, "sso.list_providers")
	return
}

// Initiate SSO authentication with a provider
func (s *ssosrvc) ProviderAuth(ctx context.Context, p *sso.ProviderAuthPayload) (err error) {
	log.Printf(ctx, "sso.provider_auth")
	return
}

// Handle SSO provider callback
func (s *ssosrvc) ProviderCallback(ctx context.Context, p *sso.ProviderCallbackPayload) (res *sso.ProviderCallbackResult, err error) {
	res = &sso.ProviderCallbackResult{}
	log.Printf(ctx, "sso.provider_callback")
	return
}

// List identity providers
func (s *ssosrvc) ListIdentityProviders(ctx context.Context, p *sso.ListIdentityProvidersPayload) (res *sso.ListIdentityProvidersResult, err error) {
	res = &sso.ListIdentityProvidersResult{}
	log.Printf(ctx, "sso.list_identity_providers")
	return
}

// Create a new identity provider
func (s *ssosrvc) CreateIdentityProvider(ctx context.Context, p *sso.CreateIdentityProviderPayload) (res *sso.IdentityProviderResponse, err error) {
	res = &sso.IdentityProviderResponse{}
	log.Printf(ctx, "sso.create_identity_provider")
	return
}

// Get identity provider by ID
func (s *ssosrvc) GetIdentityProvider(ctx context.Context, p *sso.GetIdentityProviderPayload) (res *sso.IdentityProviderResponse, err error) {
	res = &sso.IdentityProviderResponse{}
	log.Printf(ctx, "sso.get_identity_provider")
	return
}

// Update identity provider
func (s *ssosrvc) UpdateIdentityProvider(ctx context.Context, p *sso.UpdateIdentityProviderPayload) (res *sso.IdentityProviderResponse, err error) {
	res = &sso.IdentityProviderResponse{}
	log.Printf(ctx, "sso.update_identity_provider")
	return
}

// Delete identity provider
func (s *ssosrvc) DeleteIdentityProvider(ctx context.Context, p *sso.DeleteIdentityProviderPayload) (err error) {
	log.Printf(ctx, "sso.delete_identity_provider")
	return
}

// SAML metadata endpoint
func (s *ssosrvc) SamlMetadata(ctx context.Context, p *sso.SamlMetadataPayload) (res *sso.SamlMetadataResult, err error) {
	res = &sso.SamlMetadataResult{}
	log.Printf(ctx, "sso.saml_metadata")
	return
}

// SAML assertion consumer service
func (s *ssosrvc) SamlAcs(ctx context.Context, p *sso.SamlAcsPayload) (res string, err error) {
	log.Printf(ctx, "sso.saml_acs")
	return
}
