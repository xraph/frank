package controllers

import (
	"context"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/apikeys"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/pkg/logging"
	"goa.design/goa/v3/security"
)

type AutherService struct {
	authMw *middleware.AuthGoaMW
}

func NewAuther(
	cfg *config.Config,
	logger logging.Logger,
	sessionManager *session.Manager,
	cookieHandler *session.CookieHandler,
	apiKeyService apikeys.Service,
) *AutherService {
	return &AutherService{
		authMw: middleware.AuthGoa(cfg, logger, sessionManager, apiKeyService, cookieHandler),
	}
}

// OAuth2Auth implements the authorization logic for the OAuth2 security scheme.
func (a *AutherService) OAuth2Auth(ctx context.Context, token string, schema *security.OAuth2Scheme) (context.Context, error) {
	return a.authMw.AuthWithOptionsGoa()(ctx, token, &middleware.AuthScheme{
		Name:           schema.Name,
		Scopes:         schema.Scopes,
		RequiredScopes: schema.RequiredScopes,
	})
}

// APIKeyAuth implements the authorization logic for the APIKey security scheme.
func (a *AutherService) APIKeyAuth(ctx context.Context, key string, schema *security.APIKeyScheme) (context.Context, error) {
	return a.authMw.AuthWithOptionsGoa()(ctx, key, &middleware.AuthScheme{
		Name:           schema.Name,
		Scopes:         schema.Scopes,
		RequiredScopes: schema.RequiredScopes,
	})
}

// JWTAuth implements the authorization logic for the JWT security scheme.
func (a *AutherService) JWTAuth(ctx context.Context, token string, schema *security.JWTScheme) (context.Context, error) {
	return a.authMw.AuthWithOptionsGoa()(ctx, token, &middleware.AuthScheme{
		Name:           schema.Name,
		Scopes:         schema.Scopes,
		RequiredScopes: schema.RequiredScopes,
	})
}
