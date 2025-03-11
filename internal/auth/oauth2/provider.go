package oauth2

import (
	"context"
	"errors"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/oauthclient"
	"github.com/juicycleff/frank/ent/oauthscope"
	"github.com/juicycleff/frank/pkg/logging"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Provider handles OAuth2 provider functionality for third-party applications
type Provider struct {
	db     *ent.Client
	config *config.Config
	logger logging.Logger
}

// NewProvider creates a new OAuth2 provider
func NewProvider(db *ent.Client, cfg *config.Config, logger logging.Logger) *Provider {
	return &Provider{
		db:     db,
		config: cfg,
		logger: logger,
	}
}

// GetOAuth2Config returns an OAuth2 config for a specific client
func (p *Provider) GetOAuth2Config(ctx context.Context, clientID string, redirectURI string) (*oauth2.Config, error) {
	// Retrieve client information from the database
	client, err := p.db.OAuthClient.
		Query().
		Where(oauthclient.ClientID(clientID)).
		Where(oauthclient.Active(true)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("client not found or inactive")
		}
		return nil, err
	}

	// Validate redirect URI
	validRedirect := false
	for _, allowedURI := range client.RedirectUris {
		if allowedURI == redirectURI {
			validRedirect = true
			break
		}
	}

	if !validRedirect {
		return nil, errors.New("invalid redirect URI")
	}

	// Fetch scopes for this client
	scopes, err := p.db.OAuthClient.
		QueryScopes(client).
		Where(oauthscope.Public(true)).
		All(ctx)

	if err != nil {
		return nil, err
	}

	// Extract scope names
	scopeNames := make([]string, len(scopes))
	for i, scope := range scopes {
		scopeNames[i] = scope.Name
	}

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		RedirectURL:  redirectURI,
		Scopes:       scopeNames,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.config.Server.BaseURL + "/oauth2/authorize",
			TokenURL: p.config.Server.BaseURL + "/oauth2/token",
		},
	}

	return oauth2Config, nil
}

// ValidateClient validates a client ID and secret
func (p *Provider) ValidateClient(ctx context.Context, clientID, clientSecret string) (bool, error) {
	client, err := p.db.OAuthClient.
		Query().
		Where(oauthclient.ClientID(clientID)).
		Where(oauthclient.Active(true)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	// For public clients, we don't need to validate the secret
	if client.Public {
		return true, nil
	}

	// Otherwise, compare client secret
	return client.ClientSecret == clientSecret, nil
}

// GetClientCredentialsConfig returns a client credentials config for machine-to-machine auth
func (p *Provider) GetClientCredentialsConfig(ctx context.Context, clientID, clientSecret string, scopes []string) (*clientcredentials.Config, error) {
	// Validate client exists and is active
	_, err := p.db.OAuthClient.
		Query().
		Where(oauthclient.ClientID(clientID)).
		Where(oauthclient.Active(true)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("client not found or inactive")
		}
		return nil, err
	}

	// Create ClientCredentials config
	return &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     p.config.Server.BaseURL + "/oauth2/token",
		Scopes:       scopes,
	}, nil
}

// GetSupportedScopes returns all available OAuth scopes
func (p *Provider) GetSupportedScopes(ctx context.Context) ([]string, error) {
	scopes, err := p.db.OAuthScope.
		Query().
		Where(oauthscope.Public(true)).
		All(ctx)

	if err != nil {
		return nil, err
	}

	scopeNames := make([]string, len(scopes))
	for i, scope := range scopes {
		scopeNames[i] = scope.Name
	}

	return scopeNames, nil
}

// GetDefaultScopes returns the default scopes to be used when none specified
func (p *Provider) GetDefaultScopes(ctx context.Context) ([]string, error) {
	scopes, err := p.db.OAuthScope.
		Query().
		Where(oauthscope.DefaultScope(true)).
		Where(oauthscope.Public(true)).
		All(ctx)

	if err != nil {
		return nil, err
	}

	scopeNames := make([]string, len(scopes))
	for i, scope := range scopes {
		scopeNames[i] = scope.Name
	}

	return scopeNames, nil
}

// GetTokenExpiry returns the token expiry duration for a client
func (p *Provider) GetTokenExpiry(ctx context.Context, clientID string) (time.Duration, error) {
	client, err := p.db.OAuthClient.
		Query().
		Where(oauthclient.ClientID(clientID)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return 0, errors.New("client not found")
		}
		return 0, err
	}

	return time.Duration(client.TokenExpirySeconds) * time.Second, nil
}
