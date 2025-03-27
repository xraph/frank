package controllers

import (
	"context"
	"net/http"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/gen/designtypes"
	ssohttp "github.com/juicycleff/frank/gen/http/sso/server"
	"github.com/juicycleff/frank/gen/sso"
	sso2 "github.com/juicycleff/frank/internal/auth/sso"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/automapper"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
	"github.com/samber/lo"
	"goa.design/clue/debug"
	"goa.design/clue/log"
	goahttp "goa.design/goa/v3/http"
	"goa.design/goa/v3/security"
)

func RegisterSSOHTTPService(
	mux goahttp.Muxer,
	svcs *services.Services,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
) {
	eh := errorHandler(logger)
	svc := NewSso(
		svcs,
		config,
		logger,
		auther,
	)

	endpoints := sso.NewEndpoints(svc)
	handler := ssohttp.New(endpoints, mux, decoder, encoder, eh, errors.CustomErrorFormatter)

	endpoints.Use(debug.LogPayloads())
	endpoints.Use(log.Endpoint)

	ssohttp.Mount(mux, handler)
}

// sso service example implementation.
// The example methods log the requests and return zero values.
type ssosrvc struct {
	svcs   *services.Services
	config *config.Config
	logger logging.Logger
	auther *AutherService
	mapper *automapper.Mapper
}

// NewSso returns the sso service implementation.
func NewSso(
	svcs *services.Services,
	cfg *config.Config,
	logger logging.Logger,
	auther *AutherService,
) sso.Service {

	mapper := automapper.NewMapper()

	// Create and configure the mapper
	userMapper := automapper.CreateMap[*ent.SSOState, sso.SSOProvider]()
	automapper.RegisterWithTypes(mapper, userMapper)

	return &ssosrvc{
		svcs:   svcs,
		config: cfg,
		logger: logger,
		auther: auther,
		mapper: automapper.NewMapper(),
	}
}

// OAuth2Auth implements the authorization logic for service "sso" for the
// "oauth2" security scheme.
func (s *ssosrvc) OAuth2Auth(ctx context.Context, token string, scheme *security.OAuth2Scheme) (context.Context, error) {
	return s.auther.OAuth2Auth(ctx, token, scheme)
}

// APIKeyAuth implements the authorization logic for service "sso" for the
// "api_key" security scheme.
func (s *ssosrvc) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
	return s.auther.APIKeyAuth(ctx, key, scheme)
}

// JWTAuth implements the authorization logic for service "sso" for the "jwt"
// security scheme.
func (s *ssosrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	return s.auther.JWTAuth(ctx, token, scheme)
}

// ListProviders List available SSO providers
func (s *ssosrvc) ListProviders(ctx context.Context, p *sso.ListProvidersPayload) (res *sso.ListProvidersResult, err error) {
	res = &sso.ListProvidersResult{}
	log.Printf(ctx, "sso.list_providers")

	sso2.AvailableProviders()
	return
}

// ProviderAuth Initiate SSO authentication with a provider
func (s *ssosrvc) ProviderAuth(ctx context.Context, p *sso.ProviderAuthPayload) (err error) {
	info, ok := middleware.GetRequestInfo(ctx)
	if !ok {
		return errors.New(errors.CodeInternalServer, "failed to get request info")
	}

	providerID := p.Provider
	redirectURI := s.config.Server.BaseURL + "/v1/auth/sso/callback/" + providerID
	if p.RedirectURI == nil {
		redirectURI = *p.RedirectURI
	}

	// Create options
	options := map[string]interface{}{}

	// Store state in session
	state, err := utils.GenerateStateToken()
	if err != nil {
		return errors.Wrap(errors.CodeCryptoError, err, "failed to generate state token")
	}

	// Store state and other data in session
	session, err := utils.GetSession(info.Req, s.config)
	if err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to get session")
	}

	session.Values["sso_state"] = state
	session.Values["sso_provider"] = providerID
	session.Values["sso_redirect_uri"] = redirectURI
	if err := session.Save(info.Req, info.Res); err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to save session")
	}

	// Initiate SSO
	authURL, err := s.svcs.SSO.InitiateSSO(ctx, providerID, redirectURI, options)
	if err != nil {
		return
	}

	p.RedirectURI = &authURL

	return
}

// ProviderCallback Handle SSO provider callback
func (s *ssosrvc) ProviderCallback(ctx context.Context, p *sso.ProviderCallbackPayload) (res *sso.ProviderCallbackResult, err error) {
	res = &sso.ProviderCallbackResult{}

	info, ok := middleware.GetRequestInfo(ctx)
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "failed to get request info")
	}

	// Get provider ID from path
	providerID := p.Provider

	// Get code and state from query parameters
	code := ""
	state := ""
	if p.Code != nil {
		code = *p.Code
	}
	if p.State != nil {
		state = *p.State
	}

	if code == "" || state == "" {
		err = errors.New(errors.CodeInvalidInput, "code and state parameters are required")
		return
	}

	// Verify state
	session, err := utils.GetSession(info.Req, s.config)
	if err != nil {
		err = errors.Wrap(errors.CodeInternalServer, err, "failed to get session")
		return
	}

	storedState, ok := session.Values["sso_state"].(string)
	if !ok || storedState != state {
		err = errors.New(errors.CodeInvalidOAuthState, "invalid state parameter")
		return
	}

	storedProvider, ok := session.Values["sso_provider"].(string)
	if !ok || storedProvider != providerID {
		err = errors.New(errors.CodeSSOMismatch, "provider mismatch")
		return
	}

	// Complete SSO
	userInfo, err := s.svcs.SSO.CompleteSSO(ctx, state, code)
	if err != nil {
		err = errors.Wrap(errors.CodeInvalidOAuthState, err, "failed to complete SSO")
		return
	}

	// Find or create user
	user, err := s.svcs.SSO.FindOrCreateUser(ctx, userInfo)
	if err != nil {
		err = errors.Wrap(errors.CodeInvalidOAuthState, err, "failed to find or create user")
		return
	}

	// Update session
	session.Values["user_id"] = user.ID
	session.Values["authenticated"] = true

	// Add organization ID if available
	if userInfo.OrganizationID != "" {
		session.Values["organization_id"] = userInfo.OrganizationID
	}

	// Save session
	if err = session.Save(info.Req, info.Res); err != nil {
		err = errors.Wrap(errors.CodeInternalServer, err, "failed to save session")
		return
	}

	// Clear SSO-specific values
	delete(session.Values, "sso_state")
	delete(session.Values, "sso_provider")

	// Redirect to the redirect URI if specified
	redirectURI, ok := session.Values["sso_redirect_uri"].(string)
	delete(session.Values, "sso_redirect_uri")

	if ok && redirectURI != "" {
		// Save session before redirect
		if err = session.Save(info.Req, info.Res); err != nil {
			err = errors.Wrap(errors.CodeInternalServer, err, "failed to save session")
			return
		}

		http.Redirect(info.Res, info.Req, redirectURI, http.StatusFound)
		return
	}

	res.Authenticated = true
	res.Message = "SSO authentication successful"

	userOut := &designtypes.User{}
	mapper := automapper.CreateMap[*ent.User, designtypes.User]()
	automapper.MapTo(user, userOut, mapper)
	res.User = userOut

	err = nil
	return
}

// ListIdentityProviders List identity providers
func (s *ssosrvc) ListIdentityProviders(ctx context.Context, p *sso.ListIdentityProvidersPayload) (res *sso.ListIdentityProvidersResult, err error) {
	res = &sso.ListIdentityProvidersResult{}
	// Get organization ID if available
	orgID, _ := middleware.GetOrganizationID(ctx)

	// Get providers
	providers, err := s.svcs.SSO.GetProviders(ctx, orgID)
	if err != nil {
		return nil, err
	}

	mapper := automapper.CreateMap[*ent.IdentityProvider, sso.IdentityProviderResponse]()
	provData := automapper.MapToArray(providers, mapper)

	res.Providers = lo.Map(provData, func(item sso.IdentityProviderResponse, index int) *sso.IdentityProviderResponse {
		return &item
	})

	return res, nil
}

// CreateIdentityProvider Create a new identity provider
func (s *ssosrvc) CreateIdentityProvider(ctx context.Context, p *sso.CreateIdentityProviderPayload) (res *sso.IdentityProviderResponse, err error) {
	res = &sso.IdentityProviderResponse{}

	input := sso2.IdentityProviderInput{
		Name:              p.Provider.Name,
		Active:            &p.Provider.Active,
		Domains:           p.Provider.Domains,
		ProviderType:      p.Provider.ProviderType,
		AttributesMapping: p.Provider.AttributesMapping,
	}

	if p.Provider.ClientID != nil {
		input.ClientID = *p.Provider.ClientID
	}
	if p.Provider.ClientSecret != nil {
		input.ClientSecret = *p.Provider.ClientSecret
	}
	if p.Provider.Issuer != nil {
		input.Issuer = *p.Provider.Issuer
	}
	if p.Provider.MetadataURL != nil {
		input.MetadataURL = *p.Provider.MetadataURL
	}
	if p.Provider.RedirectURI != nil {
		//
	}
	if p.Provider.JwksURI != nil {
		input.JwksURI = *p.Provider.JwksURI
	}
	if p.Provider.UserinfoEndpoint != nil {
		input.UserinfoEndpoint = *p.Provider.UserinfoEndpoint
	}
	if p.Provider.TokenEndpoint != nil {
		input.TokenEndpoint = *p.Provider.TokenEndpoint
	}
	if p.Provider.AuthorizationEndpoint != nil {
		input.AuthorizationEndpoint = *p.Provider.AuthorizationEndpoint
	}
	if p.Provider.PrivateKey != nil {
		input.PrivateKey = *p.Provider.PrivateKey
	}
	if p.Provider.Certificate != nil {
		input.Certificate = *p.Provider.Certificate
	}

	provider, err := s.svcs.SSO.CreateIdentityProvider(ctx, &input, p.OrganizationID)
	if err != nil {
		return nil, err
	}

	userOut := &sso.IdentityProviderResponse{}
	mapper := automapper.CreateMap[*ent.IdentityProvider, sso.IdentityProviderResponse]()
	automapper.MapTo(provider, userOut, mapper)
	res = userOut
	return res, nil
}

// GetIdentityProvider Get identity provider by ID
func (s *ssosrvc) GetIdentityProvider(ctx context.Context, p *sso.GetIdentityProviderPayload) (res *sso.IdentityProviderResponse, err error) {
	res = &sso.IdentityProviderResponse{}

	provider, err := s.svcs.SSO.GetProvider(ctx, p.ID)
	if err != nil {
		return nil, err
	}

	userOut := &sso.IdentityProviderResponse{}
	mapper := automapper.CreateMap[*ent.IdentityProvider, sso.IdentityProviderResponse]()
	automapper.MapTo(provider, userOut, mapper)
	res = userOut
	return res, nil
}

// UpdateIdentityProvider Update identity provider
func (s *ssosrvc) UpdateIdentityProvider(ctx context.Context, p *sso.UpdateIdentityProviderPayload) (res *sso.IdentityProviderResponse, err error) {
	res = &sso.IdentityProviderResponse{}

	res = &sso.IdentityProviderResponse{}

	input := sso2.IdentityProviderInput{
		AttributesMapping: p.Provider.AttributesMapping,
	}

	if p.Provider.Active != nil {
		input.Active = p.Provider.Active
	}
	if p.Provider.ClientID != nil {
		input.ClientID = *p.Provider.ClientID
	}
	if p.Provider.Domains != nil {
		input.Domains = p.Provider.Domains
	}
	if p.Provider.AttributesMapping != nil {
		input.AttributesMapping = p.Provider.AttributesMapping
	}
	if p.Provider.ClientSecret != nil {
		input.ClientSecret = *p.Provider.ClientSecret
	}
	if p.Provider.Issuer != nil {
		input.Issuer = *p.Provider.Issuer
	}
	if p.Provider.MetadataURL != nil {
		input.MetadataURL = *p.Provider.MetadataURL
	}
	if p.Provider.RedirectURI != nil {
		//
	}
	if p.Provider.JwksURI != nil {
		input.JwksURI = *p.Provider.JwksURI
	}
	if p.Provider.UserinfoEndpoint != nil {
		input.UserinfoEndpoint = *p.Provider.UserinfoEndpoint
	}
	if p.Provider.TokenEndpoint != nil {
		input.TokenEndpoint = *p.Provider.TokenEndpoint
	}
	if p.Provider.AuthorizationEndpoint != nil {
		input.AuthorizationEndpoint = *p.Provider.AuthorizationEndpoint
	}
	if p.Provider.PrivateKey != nil {
		input.PrivateKey = *p.Provider.PrivateKey
	}
	if p.Provider.Certificate != nil {
		input.Certificate = *p.Provider.Certificate
	}

	provider, err := s.svcs.SSO.UpdateIdentityProvider(ctx, p.ID, &input)
	if err != nil {
		return nil, err
	}

	userOut := &sso.IdentityProviderResponse{}
	mapper := automapper.CreateMap[*ent.IdentityProvider, sso.IdentityProviderResponse]()
	automapper.MapTo(provider, userOut, mapper)
	res = userOut
	return res, nil
}

// DeleteIdentityProvider Delete identity provider
func (s *ssosrvc) DeleteIdentityProvider(ctx context.Context, p *sso.DeleteIdentityProviderPayload) (err error) {
	return s.svcs.SSO.DeleteIdentityProvider(ctx, p.ID)
}

// SamlMetadata SAML metadata endpoint
func (s *ssosrvc) SamlMetadata(ctx context.Context, p *sso.SamlMetadataPayload) (res *sso.SamlMetadataResult, err error) {
	res = &sso.SamlMetadataResult{}
	log.Printf(ctx, "sso.saml_metadata")
	return
}

// SamlAcs SAML assertion consumer service
func (s *ssosrvc) SamlAcs(ctx context.Context, p *sso.SamlAcsPayload) (res string, err error) {
	log.Printf(ctx, "sso.saml_acs")
	return
}
