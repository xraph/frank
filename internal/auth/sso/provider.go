package sso

import (
	"context"

	"github.com/juicycleff/frank/ent"
)

// IdentityProvider defines the common interface for all SSO identity providers
type IdentityProvider interface {
	// GetName returns the name of the provider
	GetName() string

	// GetType returns the type of the provider (e.g., "saml", "oidc")
	GetType() string

	// GetAuthURL returns the URL to initiate the authentication flow
	GetAuthURL(state string, options map[string]interface{}) (string, error)

	// ExchangeCode exchanges an authorization code for user information
	ExchangeCode(ctx context.Context, code string, state string) (*UserInfo, error)

	// ValidateToken validates a token and returns user information
	ValidateToken(ctx context.Context, token string) (*UserInfo, error)

	// GetConfig returns the provider's configuration
	GetConfig() ProviderConfig
}

// UserInfo contains information about an authenticated user
type UserInfo struct {
	ID                string                 // Unique identifier from the provider
	Email             string                 // User's email address
	EmailVerified     bool                   // Whether the email is verified
	Name              string                 // User's full name
	FirstName         string                 // User's first name
	LastName          string                 // User's last name
	ProfilePicture    string                 // URL to the user's profile picture
	Locale            string                 // User's locale
	ProviderType      string                 // Type of the provider (e.g., "saml", "oidc")
	ProviderName      string                 // Name of the provider
	RawAttributes     map[string]interface{} // Raw attributes from the provider
	Groups            []string               // User's groups/roles from the provider
	OrganizationID    string                 // ID of the user's organization
	OrganizationName  string                 // Name of the user's organization
	OrganizationEmail string                 // User's email in the organization context
}

// ProviderConfig contains configuration for an identity provider
type ProviderConfig struct {
	Name              string
	Type              string
	ClientID          string
	ClientSecret      string
	RedirectURI       string
	Scopes            []string
	AuthURL           string
	TokenURL          string
	UserInfoURL       string
	JWKSURL           string
	Issuer            string
	AllowedDomains    []string
	AttributeMappings map[string]string
	OrganizationID    string
	Metadata          map[string]interface{}
}

// ProviderFactory creates a new identity provider
type ProviderFactory interface {
	CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error)
}

// AvailableProviders returns a map of available identity provider types and their factories
func AvailableProviders() map[string]ProviderFactory {
	return map[string]ProviderFactory{
		"oidc": &OIDCProviderFactory{},
		"saml": &SAMLProviderFactory{},
		// Add other provider factories here
	}
}

// CreateIdentityProvider creates a new identity provider from a configuration
func CreateIdentityProvider(providerConfig *ent.IdentityProvider) (IdentityProvider, error) {
	factories := AvailableProviders()

	factory, ok := factories[providerConfig.ProviderType]
	if !ok {
		return nil, ErrUnsupportedProviderType
	}

	return factory.CreateProvider(providerConfig)
}
