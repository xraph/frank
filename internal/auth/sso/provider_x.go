package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/errors"
	"golang.org/x/oauth2"
)

// TwitterProvider implements the IdentityProvider interface for Twitter/X
type TwitterProvider struct {
	name       string
	config     ProviderConfig
	oauth2Cfg  *oauth2.Config
	httpClient *http.Client
}

// TwitterProviderFactory creates Twitter providers
type TwitterProviderFactory struct{}

// CreateProvider creates a new Twitter provider from a configuration
func (f *TwitterProviderFactory) CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error) {
	if config.ProviderType != "oauth2" || !isTwitterProvider(config) {
		return nil, ErrUnsupportedProviderType
	}

	// Parse scopes - Twitter OAuth 2.0 requires specific scopes
	scopes := []string{"tweet.read", "users.read", "offline.access"}

	// Add additional scopes if provided in metadata
	if config.Metadata != nil {
		if scopesArr, ok := config.Metadata["scopes"].([]interface{}); ok {
			for _, s := range scopesArr {
				if scope, ok := s.(string); ok {
					// Avoid duplicates
					if !contains(scopes, scope) {
						scopes = append(scopes, scope)
					}
				}
			}
		}
	}

	// Parse attributes mapping
	attributesMapping := make(map[string]string)
	if config.AttributesMapping != nil {
		attributesMapping = config.AttributesMapping
	}

	// Twitter OAuth 2.0 endpoints
	endpoint := oauth2.Endpoint{
		AuthURL:  "https://twitter.com/i/oauth2/authorize",
		TokenURL: "https://api.twitter.com/2/oauth2/token",
	}

	// Build provider configuration
	providerConfig := ProviderConfig{
		Name:              config.Name,
		Type:              "oauth2",
		ClientID:          config.ClientID,
		ClientSecret:      config.ClientSecret,
		RedirectURI:       config.RedirectURI,
		Scopes:            scopes,
		AuthURL:           endpoint.AuthURL,
		TokenURL:          endpoint.TokenURL,
		UserInfoURL:       "https://api.twitter.com/2/users/me",
		AttributeMappings: attributesMapping,
		OrganizationID:    config.OrganizationID,
		Metadata:          config.Metadata,
	}

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURI,
		Scopes:       scopes,
		Endpoint:     endpoint,
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	return &TwitterProvider{
		name:       config.Name,
		config:     providerConfig,
		oauth2Cfg:  oauth2Config,
		httpClient: httpClient,
	}, nil
}

// isTwitterProvider checks if the provider configuration is for Twitter
func isTwitterProvider(config *ent.IdentityProvider) bool {
	if config.Metadata == nil {
		return false
	}

	provider, ok := config.Metadata["provider"]
	if !ok {
		return false
	}

	return provider == "twitter" || provider == "x"
}

// GetName returns the name of the provider
func (p *TwitterProvider) GetName() string {
	return p.name
}

// GetType returns the type of the provider
func (p *TwitterProvider) GetType() string {
	return "oauth2"
}

// GetAuthURL returns the URL to initiate authentication
func (p *TwitterProvider) GetAuthURL(state string, options map[string]interface{}) (string, error) {
	// Twitter OAuth 2.0 requires code_challenge for PKCE
	var opts []oauth2.AuthCodeOption

	// Add response_type=code (required)
	opts = append(opts, oauth2.SetAuthURLParam("response_type", "code"))

	// Add code_challenge method and challenge if provided in options
	if options != nil {
		if codeChallenge, ok := options["code_challenge"].(string); ok {
			opts = append(opts, oauth2.SetAuthURLParam("code_challenge", codeChallenge))
			opts = append(opts, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
		}
	}

	// Generate authorization URL
	return p.oauth2Cfg.AuthCodeURL(state, opts...), nil
}

// ExchangeCode exchanges an authorization code for user information
func (p *TwitterProvider) ExchangeCode(ctx context.Context, code string, state string) (*UserInfo, error) {
	// Create token request options
	var tokenOpts []oauth2.AuthCodeOption

	// Add code_verifier if provided in context
	if codeVerifier, ok := ctx.Value("code_verifier").(string); ok {
		tokenOpts = append(tokenOpts, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	}

	// Exchange code for token with optional code_verifier
	token, err := p.oauth2Cfg.Exchange(ctx, code, tokenOpts...)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to exchange code for token")
	}

	// Use token to get user info
	userInfo, err := p.getUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, err
	}

	return userInfo, nil
}

// ValidateToken validates a token and returns user information
func (p *TwitterProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	return p.getUserInfo(ctx, token)
}

// GetConfig returns the provider's configuration
func (p *TwitterProvider) GetConfig() ProviderConfig {
	return p.config
}

// getUserInfo fetches user information from Twitter API
func (p *TwitterProvider) getUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	// Twitter API requires specific user fields to be requested
	requestURL := p.config.UserInfoURL + "?user.fields=id,name,username,profile_image_url,description,verified,location,url,entities"

	// Create request to userinfo endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to create userinfo request")
	}

	// Add authorization header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("Accept", "application/json")

	// Execute request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to execute userinfo request")
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.New(errors.CodeIdentityProviderError, fmt.Sprintf("userinfo request failed with status %d: %s", resp.StatusCode, string(body)))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to read userinfo response")
	}

	// Parse response
	var response struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to parse userinfo response")
	}

	// Check if data was returned
	if response.Data == nil {
		return nil, errors.New(errors.CodeIdentityProviderError, "no user data returned from Twitter")
	}

	userData := response.Data

	// Extract username and name
	id := getStringValue(userData, "id")
	username := getStringValue(userData, "username")
	name := getStringValue(userData, "name")

	// Parse name into first and last name (best effort)
	var firstName, lastName string
	if nameParts := strings.Split(name, " "); len(nameParts) > 0 {
		firstName = nameParts[0]
		if len(nameParts) > 1 {
			lastName = strings.Join(nameParts[1:], " ")
		}
	}

	// Get profile image URL
	profileImageURL := getStringValue(userData, "profile_image_url")
	// Convert to original size image (remove _normal suffix)
	profileImageURL = strings.Replace(profileImageURL, "_normal", "", 1)

	// Twitter doesn't provide email through the API, so we'll need to use username as unique identifier
	// Note: To get email, the app would need elevated access and "email" scope

	// Map to UserInfo
	userInfo := &UserInfo{
		ID:             id,
		Name:           name,
		FirstName:      firstName,
		LastName:       lastName,
		ProfilePicture: profileImageURL,
		ProviderType:   "oauth2",
		ProviderName:   p.name,
		RawAttributes:  userData,
		OrganizationID: p.config.OrganizationID,
	}

	// Store username in raw attributes if it's not already there
	if _, ok := userInfo.RawAttributes["username"]; !ok {
		userInfo.RawAttributes["username"] = username
	}

	// Apply any custom attribute mappings
	p.applyAttributeMappings(userInfo, userData)

	return userInfo, nil
}

// applyAttributeMappings applies custom attribute mappings from provider configuration
func (p *TwitterProvider) applyAttributeMappings(userInfo *UserInfo, data map[string]interface{}) {
	for srcAttr, destAttr := range p.config.AttributeMappings {
		if val, ok := data[srcAttr]; ok {
			switch destAttr {
			case "id":
				if str, ok := val.(string); ok {
					userInfo.ID = str
				}
			case "email":
				if str, ok := val.(string); ok {
					userInfo.Email = str
				}
			case "name":
				if str, ok := val.(string); ok {
					userInfo.Name = str
				}
			case "first_name":
				if str, ok := val.(string); ok {
					userInfo.FirstName = str
				}
			case "last_name":
				if str, ok := val.(string); ok {
					userInfo.LastName = str
				}
			case "profile_picture":
				if str, ok := val.(string); ok {
					userInfo.ProfilePicture = str
				}
			}
		}
	}
}
