package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"golang.org/x/oauth2"
)

// OIDCProvider implements the IdentityProvider interface for OIDC
type OIDCProvider struct {
	name         string
	config       ProviderConfig
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
	logger       logging.Logger
}

// OIDCProviderFactory creates OIDC providers
type OIDCProviderFactory struct{}

// CreateProvider creates a new OIDC provider from a configuration
func (f *OIDCProviderFactory) CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error) {
	if config.ProviderType != "oidc" {
		return nil, ErrUnsupportedProviderType
	}

	// Parse attributes mapping
	attributesMapping := make(map[string]string)
	if config.AttributesMapping != nil {
		attributesMapping = config.AttributesMapping
	}

	// Build provider configuration
	providerConfig := ProviderConfig{
		Name:              config.Name,
		Type:              "oidc",
		ClientID:          config.ClientID,
		ClientSecret:      config.ClientSecret,
		RedirectURI:       config.RedirectURI,
		AuthURL:           config.AuthorizationEndpoint,
		TokenURL:          config.TokenEndpoint,
		UserInfoURL:       config.UserinfoEndpoint,
		JWKSURL:           config.JwksURI,
		Issuer:            config.Issuer,
		AttributeMappings: attributesMapping,
		OrganizationID:    config.OrganizationID,
		Metadata:          config.Metadata,
	}

	// Parse scopes from metadata
	scopes := []string{"openid", "profile", "email"}
	if scopesArr, ok := config.Metadata["scopes"].([]interface{}); ok {
		for _, s := range scopesArr {
			if scope, ok := s.(string); ok {
				scopes = append(scopes, scope)
			}
		}
	}
	providerConfig.Scopes = scopes

	// Parse allowed domains
	var allowedDomains []string
	if config.Domains != nil {
		allowedDomains = config.Domains
	}
	providerConfig.AllowedDomains = allowedDomains

	logger := logging.GetLogger()

	// Create OIDC provider
	oidcProvider := &OIDCProvider{
		name:   config.Name,
		config: providerConfig,
		logger: logger,
	}

	// Initialize OIDC provider
	if err := oidcProvider.initProvider(context.Background()); err != nil {
		return nil, err
	}

	return oidcProvider, nil
}

// initProvider initializes the OIDC provider
func (p *OIDCProvider) initProvider(ctx context.Context) error {
	var err error
	var provider *oidc.Provider

	// If issuer is provided, use auto-discovery
	if p.config.Issuer != "" {
		provider, err = oidc.NewProvider(ctx, p.config.Issuer)
		if err != nil {
			return errors.Wrap(errors.CodeIdentityProviderError, err, "failed to initialize OIDC provider from issuer")
		}
	} else if p.config.AuthURL != "" && p.config.TokenURL != "" && p.config.JWKSURL != "" {
		// If endpoints are provided explicitly, create provider manually
		// This is useful for providers that don't support discovery
		keySet := oidc.NewRemoteKeySet(ctx, p.config.JWKSURL)

		providerConfig := &oidc.ProviderConfig{
			AuthURL:  p.config.AuthURL,
			TokenURL: p.config.TokenURL,
		}
		provider = providerConfig.NewProvider(ctx)

		p.verifier = oidc.NewVerifier(p.config.Issuer, keySet, &oidc.Config{
			ClientID: p.config.ClientID,
		})
	} else {
		return errors.New(errors.CodeInvalidInput, "insufficient OIDC configuration: either issuer or explicit endpoints required")
	}

	// Set up the OAuth2 config with our custom endpoints
	p.oauth2Config = &oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		RedirectURL:  p.config.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       p.config.Scopes,
	}

	p.provider = provider

	if p.verifier == nil {
		// Create ID token verifier
		p.verifier = provider.Verifier(&oidc.Config{
			ClientID: p.config.ClientID,
		})
	}

	return nil
}

// GetName returns the name of the provider
func (p *OIDCProvider) GetName() string {
	return p.name
}

// GetType returns the type of the provider
func (p *OIDCProvider) GetType() string {
	return "oidc"
}

// GetAuthURL returns the URL to initiate authentication
func (p *OIDCProvider) GetAuthURL(state string, options map[string]interface{}) (string, error) {
	if p.oauth2Config == nil {
		return "", errors.New(errors.CodeConfigurationError, "OIDC provider not properly initialized")
	}

	// Set up auth options
	authOptions := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
	}

	// Add prompt option if provided
	if prompt, ok := options["prompt"].(string); ok {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("prompt", prompt))
	}

	// Add login_hint option if provided
	if loginHint, ok := options["login_hint"].(string); ok {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("login_hint", loginHint))
	}

	// Add hd (hosted domain) option for Google if provided
	if hostedDomain, ok := options["hd"].(string); ok {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("hd", hostedDomain))
	}

	// Get the auth URL
	authURL := p.oauth2Config.AuthCodeURL(state, authOptions...)
	return authURL, nil
}

// ExchangeCode exchanges an authorization code for user information
func (p *OIDCProvider) ExchangeCode(ctx context.Context, code string, state string) (*UserInfo, error) {
	if p.oauth2Config == nil || p.verifier == nil {
		return nil, errors.New(errors.CodeConfigurationError, "OIDC provider not properly initialized")
	}

	// Exchange code for tokens
	oauth2Token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, errors.Wrap(errors.CodeOAuthFailed, err, "failed to exchange code for token")
	}

	// Extract ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New(errors.CodeOAuthFailed, "ID token missing from OAuth2 token response")
	}

	// Verify ID token
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to verify ID token")
	}

	// Extract claims from ID token
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to parse ID token claims")
	}

	// Get additional user info from userinfo endpoint if available
	var userinfo map[string]interface{}
	if p.config.UserInfoURL != "" {
		userinfoData, err := p.fetchUserInfo(ctx, oauth2Token.AccessToken)
		if err != nil {
			p.logger.Warn("Failed to fetch userinfo", logging.Error(err))
		} else {
			userinfo = userinfoData
		}
	}

	// Merge claims and userinfo
	mergedClaims := mergeMaps(claims, userinfo)

	// Extract user information
	userInfo, err := p.extractUserInfo(mergedClaims)
	if err != nil {
		return nil, err
	}

	// Validate domain if allowed domains are specified
	if len(p.config.AllowedDomains) > 0 && userInfo.Email != "" {
		parts := strings.Split(userInfo.Email, "@")
		if len(parts) != 2 {
			return nil, errors.New(errors.CodeInvalidInput, "invalid email format")
		}

		domain := parts[1]
		allowed := false
		for _, allowedDomain := range p.config.AllowedDomains {
			if allowedDomain == domain {
				allowed = true
				break
			}
		}

		if !allowed {
			return nil, errors.New(errors.CodeForbidden, fmt.Sprintf("domain %s is not allowed for this provider", domain))
		}
	}

	return userInfo, nil
}

// ValidateToken validates an ID token and returns user information
func (p *OIDCProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	if p.verifier == nil {
		return nil, errors.New(errors.CodeConfigurationError, "OIDC provider not properly initialized")
	}

	// Verify ID token
	idToken, err := p.verifier.Verify(ctx, token)
	if err != nil {
		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to verify ID token")
	}

	// Extract claims from ID token
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to parse ID token claims")
	}

	// Extract user information
	userInfo, err := p.extractUserInfo(claims)
	if err != nil {
		return nil, err
	}

	return userInfo, nil
}

// GetConfig returns the provider's configuration
func (p *OIDCProvider) GetConfig() ProviderConfig {
	return p.config
}

// fetchUserInfo fetches user information from the userinfo endpoint
func (p *OIDCProvider) fetchUserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	// Fetch userinfo
	userinfoReq, err := http.NewRequest("GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, errors.Wrap(errors.CodeNetworkError, err, "failed to create userinfo request")
	}

	// Add access token to the request
	userinfoReq.Header.Set("Authorization", "Bearer "+accessToken)

	// Execute the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(userinfoReq)
	if err != nil {
		return nil, errors.Wrap(errors.CodeNetworkError, err, "failed to execute userinfo request")
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.New(errors.CodeNetworkError, fmt.Sprintf("userinfo request failed with status %d: %s", resp.StatusCode, string(body)))
	}

	// Parse response body
	var userinfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userinfo); err != nil {
		return nil, errors.Wrap(errors.CodeInvalidInput, err, "failed to parse userinfo response")
	}

	return userinfo, nil
}

// extractUserInfo extracts user information from OIDC claims
func (p *OIDCProvider) extractUserInfo(claims map[string]interface{}) (*UserInfo, error) {
	// Initialize user info with defaults
	userInfo := &UserInfo{
		ProviderType:   "oidc",
		ProviderName:   p.name,
		RawAttributes:  claims,
		OrganizationID: p.config.OrganizationID,
	}

	// Map attributes based on configuration
	p.mapAttributes(userInfo, claims)

	// Ensure we have a user ID
	if userInfo.ID == "" {
		if sub, ok := claims["sub"].(string); ok {
			userInfo.ID = sub
		} else {
			return nil, errors.New(errors.CodeInvalidInput, "subject identifier (sub) missing from ID token")
		}
	}

	return userInfo, nil
}

// mapAttributes maps OIDC claims to user info fields based on configuration
func (p *OIDCProvider) mapAttributes(userInfo *UserInfo, claims map[string]interface{}) {
	// Map known attributes based on configuration
	mappings := p.config.AttributeMappings
	if mappings == nil {
		mappings = defaultOIDCAttributeMappings()
	}

	// Apply mappings
	for claimName, userAttr := range mappings {
		if value, ok := claims[claimName]; ok {
			switch userAttr {
			case "id":
				if strVal, ok := value.(string); ok {
					userInfo.ID = strVal
				}
			case "email":
				if strVal, ok := value.(string); ok {
					userInfo.Email = strVal
				}
			case "email_verified":
				if boolVal, ok := value.(bool); ok {
					userInfo.EmailVerified = boolVal
				} else if strVal, ok := value.(string); ok {
					userInfo.EmailVerified = strVal == "true" || strVal == "1"
				}
			case "name":
				if strVal, ok := value.(string); ok {
					userInfo.Name = strVal
				}
			case "first_name":
				if strVal, ok := value.(string); ok {
					userInfo.FirstName = strVal
				}
			case "last_name":
				if strVal, ok := value.(string); ok {
					userInfo.LastName = strVal
				}
			case "picture":
				if strVal, ok := value.(string); ok {
					userInfo.ProfilePicture = strVal
				}
			case "locale":
				if strVal, ok := value.(string); ok {
					userInfo.Locale = strVal
				}
			case "groups":
				if groups, ok := value.([]interface{}); ok {
					for _, group := range groups {
						if strVal, ok := group.(string); ok {
							userInfo.Groups = append(userInfo.Groups, strVal)
						}
					}
				} else if strVal, ok := value.(string); ok {
					userInfo.Groups = strings.Split(strVal, ",")
				}
			case "organization_name":
				if strVal, ok := value.(string); ok {
					userInfo.OrganizationName = strVal
				}
			case "organization_email":
				if strVal, ok := value.(string); ok {
					userInfo.OrganizationEmail = strVal
				}
			}
		}
	}

	// If name is not set, try to construct it from first and last name
	if userInfo.Name == "" && (userInfo.FirstName != "" || userInfo.LastName != "") {
		userInfo.Name = strings.TrimSpace(userInfo.FirstName + " " + userInfo.LastName)
	}
}

// defaultOIDCAttributeMappings returns default mappings for common OIDC claims
func defaultOIDCAttributeMappings() map[string]string {
	return map[string]string{
		"sub":            "id",
		"email":          "email",
		"email_verified": "email_verified",
		"name":           "name",
		"given_name":     "first_name",
		"family_name":    "last_name",
		"picture":        "picture",
		"profile":        "profile",
		"locale":         "locale",
		"groups":         "groups",
		"roles":          "groups", // Some providers use "roles" instead of "groups"
	}
}

// Helper function to merge two maps
func mergeMaps(map1, map2 map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Copy map1 to result
	for k, v := range map1 {
		result[k] = v
	}

	// Add or overwrite with map2
	if map2 != nil {
		for k, v := range map2 {
			result[k] = v
		}
	}

	return result
}
