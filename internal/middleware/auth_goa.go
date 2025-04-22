package middleware

import (
	"context"

	"github.com/gorilla/sessions"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/apikeys"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// AuthGoa middleware extracts and validates authentication information
func AuthGoa(
	cfg *config.Config,
	logger logging.Logger,
	sessionManager *session.Manager,
	sessionStore sessions.Store,
	apiKeyService apikeys.Service,
	cookieHandler *session.CookieHandler,
) *AuthGoaMW {
	options := DefaultAuthOptions()
	options.SessionManager = sessionManager
	options.SessionStore = sessionStore
	options.APIKeyService = apiKeyService
	options.CookieHandler = cookieHandler

	return &AuthGoaMW{cfg, logger, &options}
}

type AuthGoaMW struct {
	cfg     *config.Config
	logger  logging.Logger
	options *AuthOptions
}

type AuthScheme struct {
	Name           string
	Scopes         []string
	RequiredScopes []string
}

// AuthWithOptionsGoa returns an Auth middleware with custom options
func (a *AuthGoaMW) AuthWithOptionsGoa() func(context.Context, string, *AuthScheme) (context.Context, error) {
	options := a.options
	cfg := a.cfg
	logger := a.logger
	return func(ctx context.Context, token string, schema *AuthScheme) (context.Context, error) {
		// Get the route pattern from Chi's context
		info, ok := GetRequestInfo(ctx)
		if !ok {
			return nil, errors.New(errors.CodeInternalServer, "failed to get request info")
		}

		authenticated, ctx, err := PrefillAuthWithOptions(info.Req, ctx, cfg, logger, options)

		// Check if authentication is required but not provided
		if options.Required && !authenticated {
			return nil, err
		}

		// Add authentication status to context
		ctx = context.WithValue(ctx, AuthenticatedKey, authenticated)
		return ctx, nil
	}
}
