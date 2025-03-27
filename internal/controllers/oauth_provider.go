package controllers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/juicycleff/frank/config"
	oathproviderhttp "github.com/juicycleff/frank/gen/http/oauth_provider/server"
	oauthprovider "github.com/juicycleff/frank/gen/oauth_provider"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"goa.design/clue/debug"
	"goa.design/clue/log"
	goahttp "goa.design/goa/v3/http"
	"goa.design/goa/v3/security"
)

func RegisterOauthProviderHTTPService(
	mux goahttp.Muxer,
	svcs *services.Services,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
) {
	eh := errorHandler(logger)
	svc := NewOauthProvider(
		svcs,
		config,
		logger,
		auther,
	)

	endpoints := oauthprovider.NewEndpoints(svc)
	handler := oathproviderhttp.New(endpoints, mux, decoder, encoder, eh, errors.CustomErrorFormatter)

	endpoints.Use(debug.LogPayloads())
	endpoints.Use(log.Endpoint)

	oathproviderhttp.Mount(mux, handler)
}

// oauth_provider service example implementation.
// The example methods log the requests and return zero values.
type oauthProvidersrvc struct {
	svcs   *services.Services
	config *config.Config
	logger logging.Logger
	auther *AutherService
}

// NewOauthProvider returns the oauth_provider service implementation.
func NewOauthProvider(
	svcs *services.Services,
	cfg *config.Config,
	logger logging.Logger,
	auther *AutherService,
) oauthprovider.Service {

	// oauthHandlers := oauth2.NewHandlers(svcs.OAuth.Server, cfg, db, logger)
	return &oauthProvidersrvc{
		svcs:   svcs,
		config: cfg,
		logger: logger,
		auther: auther,
	}
}

// OAuth2Auth implements the authorization logic for service "oauth_provider"
// for the "oauth2" security scheme.
func (s *oauthProvidersrvc) OAuth2Auth(ctx context.Context, token string, scheme *security.OAuth2Scheme) (context.Context, error) {
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

// APIKeyAuth implements the authorization logic for service "oauth_provider"
// for the "api_key" security scheme.
func (s *oauthProvidersrvc) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
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

// JWTAuth implements the authorization logic for service "oauth_provider" for
// the "jwt" security scheme.
func (s *oauthProvidersrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
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

// Authorize OAuth2 authorization endpoint
func (s *oauthProvidersrvc) Authorize(ctx context.Context, p *oauthprovider.AuthorizePayload) (res string, err error) {
	// // Get provider from path
	// provider := utils.GetPathVar(r, "provider")
	// if provider == "" {
	// 	utils.RespondError(w, errors.New(errors.CodeInvalidInput, "provider is required"))
	// 	return
	// }
	//
	// // Generate state parameter for CSRF protection
	// state, err := utils.GenerateStateToken()
	// if err != nil {
	// 	utils.RespondError(w, errors.Wrap(errors.CodeCryptoError, err, "failed to generate state token"))
	// 	return
	// }
	//
	// // Get redirect URI from query parameter or use default
	// redirectURI := p.RedirectURI
	// if redirectURI == "" {
	// 	redirectURI = h.config.Server.BaseURL + "/oauth/callback/" + provider
	// }
	//
	// // Store state and redirect URI in session
	// session, err := utils.GetSession(r, h.config)
	// if err != nil {
	// 	utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to get session"))
	// 	return
	// }
	//
	// session.Values["oauth_state"] = state
	// session.Values["oauth_provider"] = provider
	// session.Values["oauth_redirect_uri"] = redirectURI
	// if err := session.Save(r, w); err != nil {
	// 	utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to save session"))
	// 	return
	// }
	//
	// // Generate login URL with state
	// loginURL, err := h.oauthClient.GetLoginURL(provider, state, nil)
	// if err != nil {
	// 	utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to generate login URL"))
	// 	return
	// }
	//
	// // Redirect user to login URL
	// http.Redirect(w, r, loginURL, http.StatusFound)
	return
}

// Token OAuth2 token endpoint
func (s *oauthProvidersrvc) Token(ctx context.Context, p *oauthprovider.TokenPayload) (res *oauthprovider.TokenResult, err error) {
	res = &oauthprovider.TokenResult{}
	log.Printf(ctx, "oauthProvider.token")
	return
}

// Introspect OAuth2 token introspection endpoint
func (s *oauthProvidersrvc) Introspect(ctx context.Context, p *oauthprovider.IntrospectPayload) (res *oauthprovider.IntrospectResult, err error) {
	res = &oauthprovider.IntrospectResult{}
	log.Printf(ctx, "oauthProvider.introspect")
	return
}

// Revoke OAuth2 token revocation endpoint
func (s *oauthProvidersrvc) Revoke(ctx context.Context, p *oauthprovider.RevokePayload) (err error) {
	log.Printf(ctx, "oauthProvider.revoke")
	return
}

// Consent Handle user consent for OAuth authorization
func (s *oauthProvidersrvc) Consent(ctx context.Context, p *oauthprovider.ConsentPayload) (res *oauthprovider.ConsentResult, err error) {
	res = &oauthprovider.ConsentResult{}
	log.Printf(ctx, "oauthProvider.consent")
	return
}

// Userinfo OAuth2 UserInfo endpoint for OpenID Connect
func (s *oauthProvidersrvc) Userinfo(ctx context.Context, p *oauthprovider.UserinfoPayload) (res *oauthprovider.UserinfoResult, err error) {
	res = &oauthprovider.UserinfoResult{}
	log.Printf(ctx, "oauthProvider.userinfo")
	return
}

// ListClients List OAuth clients
func (s *oauthProvidersrvc) ListClients(ctx context.Context, p *oauthprovider.ListClientsPayload) (res *oauthprovider.ListClientsResult, err error) {
	res = &oauthprovider.ListClientsResult{}
	log.Printf(ctx, "oauthProvider.list_clients")
	return
}

// CreateClient Create a new OAuth client
func (s *oauthProvidersrvc) CreateClient(ctx context.Context, p *oauthprovider.CreateClientPayload) (res *oauthprovider.OAuthClientWithSecretResponse, err error) {
	res = &oauthprovider.OAuthClientWithSecretResponse{}
	log.Printf(ctx, "oauthProvider.create_client")
	return
}

// GetClient Get OAuth client by ID
func (s *oauthProvidersrvc) GetClient(ctx context.Context, p *oauthprovider.GetClientPayload) (res *oauthprovider.OAuthClientResponse, err error) {
	res = &oauthprovider.OAuthClientResponse{}
	log.Printf(ctx, "oauthProvider.get_client")
	return
}

// UpdateClient Update OAuth client
func (s *oauthProvidersrvc) UpdateClient(ctx context.Context, p *oauthprovider.UpdateClientPayload) (res *oauthprovider.OAuthClientResponse, err error) {
	res = &oauthprovider.OAuthClientResponse{}
	log.Printf(ctx, "oauthProvider.update_client")
	return
}

// DeleteClient Delete OAuth client
func (s *oauthProvidersrvc) DeleteClient(ctx context.Context, p *oauthprovider.DeleteClientPayload) (err error) {
	log.Printf(ctx, "oauthProvider.delete_client")
	return
}

// RotateClientSecret Rotate OAuth client secret
func (s *oauthProvidersrvc) RotateClientSecret(ctx context.Context, p *oauthprovider.RotateClientSecretPayload) (res *oauthprovider.RotateClientSecretResult, err error) {
	res = &oauthprovider.RotateClientSecretResult{}
	log.Printf(ctx, "oauthProvider.rotate_client_secret")
	return
}

// ListScopes List OAuth scopes
func (s *oauthProvidersrvc) ListScopes(ctx context.Context, p *oauthprovider.ListScopesPayload) (res *oauthprovider.ListScopesResult, err error) {
	res = &oauthprovider.ListScopesResult{}
	log.Printf(ctx, "oauthProvider.list_scopes")
	return
}

// CreateScope Create a new OAuth scope
func (s *oauthProvidersrvc) CreateScope(ctx context.Context, p *oauthprovider.CreateScopePayload) (res *oauthprovider.OAuthScopeResponse, err error) {
	res = &oauthprovider.OAuthScopeResponse{}
	log.Printf(ctx, "oauthProvider.create_scope")
	return
}

// GetScope Get OAuth scope by ID
func (s *oauthProvidersrvc) GetScope(ctx context.Context, p *oauthprovider.GetScopePayload) (res *oauthprovider.OAuthScopeResponse, err error) {
	res = &oauthprovider.OAuthScopeResponse{}
	log.Printf(ctx, "oauthProvider.get_scope")
	return
}

// UpdateScope Update OAuth scope
func (s *oauthProvidersrvc) UpdateScope(ctx context.Context, p *oauthprovider.UpdateScopePayload) (res *oauthprovider.OAuthScopeResponse, err error) {
	res = &oauthprovider.OAuthScopeResponse{}
	log.Printf(ctx, "oauthProvider.update_scope")
	return
}

// DeleteScope Delete OAuth scope
func (s *oauthProvidersrvc) DeleteScope(ctx context.Context, p *oauthprovider.DeleteScopePayload) (err error) {
	log.Printf(ctx, "oauthProvider.delete_scope")
	return
}

// OidcConfiguration OpenID Connect discovery configuration
func (s *oauthProvidersrvc) OidcConfiguration(ctx context.Context) (res *oauthprovider.OidcConfigurationResult, err error) {
	res = &oauthprovider.OidcConfigurationResult{}
	baseURL := fmt.Sprintf("%s", s.config.Server.BaseURL)

	res = &oauthprovider.OidcConfigurationResult{
		Issuer:                baseURL,
		AuthorizationEndpoint: baseURL + "/v1/oauth/authorize",
		TokenEndpoint:         baseURL + "/v1/oauth/token",
		UserinfoEndpoint:      baseURL + "/v1/oauth/userinfo",
		JwksURI:               baseURL + "/v1/.well-known/jwks.json",
		ResponseTypesSupported: []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported: []string{
			"openid",
			"email",
			"profile",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
		},
		ClaimsSupported: []string{
			"sub",
			"iss",
			"auth_time",
			"name",
			"given_name",
			"family_name",
			"email",
			"email_verified",
		},
	}

	return res, nil
}

// Jwks JSON Web Key Set
func (s *oauthProvidersrvc) Jwks(ctx context.Context) (res *oauthprovider.JwksResult, err error) {
	res = &oauthprovider.JwksResult{}
	log.Printf(ctx, "oauthProvider.jwks")
	return
}

// handleProviderAuthorize handles OAuth2 authorization requests when acting as a provider
func (s *oauthProvidersrvc) handleProviderAuthorize(w http.ResponseWriter, r *http.Request) {

	// Let the OAuth server handle the authorization endpoint
	// s.svcs.OAuth.HandleAuthorize(w, r)
}

// handleClientAuthorize handles OAuth2 authorization when acting as a client
func (s *oauthProvidersrvc) handleClientAuthorize(w http.ResponseWriter, r *http.Request) {
	// // Get provider from query parameter
	// provider := r.URL.Query().Get("provider")
	// if provider == "" {
	// 	utils.RespondError(w, errors.New(errors.CodeInvalidInput, "provider parameter is required"))
	// 	return
	// }
	//
	// // Check if we have this provider configured
	// _, err := h.oauthClient.GetLoginURL(provider, "", nil)
	// if err != nil {
	// 	utils.RespondError(w, errors.Wrap(errors.CodeProviderNotFound, err, "provider not found or not configured"))
	// 	return
	// }
	//
	// // Generate state parameter for CSRF protection
	// state, err := utils.GenerateStateToken()
	// if err != nil {
	// 	utils.RespondError(w, errors.Wrap(errors.CodeCryptoError, err, "failed to generate state token"))
	// 	return
	// }
	//
	// // Get redirect URI from query parameter or use default
	// redirectURI := r.URL.Query().Get("redirect_uri")
	// if redirectURI == "" {
	// 	redirectURI = h.config.Server.BaseURL + "/oauth/callback/" + provider
	// }
	//
	// // Store state and redirect URI in session
	// session, err := utils.GetSession(r, h.config)
	// if err != nil {
	// 	utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to get session"))
	// 	return
	// }
	//
	// session.Values["oauth_state"] = state
	// session.Values["oauth_provider"] = provider
	// session.Values["oauth_redirect_uri"] = redirectURI
	// if err := session.Save(r, w); err != nil {
	// 	utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to save session"))
	// 	return
	// }
	//
	// // Generate login URL with state
	// loginURLWithState, err := h.oauthClient.GetLoginURL(provider, state, nil)
	// if err != nil {
	// 	utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to generate login URL"))
	// 	return
	// }
	//
	// // Redirect user to login URL
	// http.Redirect(w, r, loginURLWithState, http.StatusFound)
}
