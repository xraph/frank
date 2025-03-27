package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

// FacebookProvider implements the IdentityProvider interface for Facebook
type FacebookProvider struct {
	name       string
	config     ProviderConfig
	oauth2Cfg  *oauth2.Config
	httpClient *http.Client
}

// GetName returns the name of the provider
func (p *FacebookProvider) GetName() string {
	return p.name
}

// GetType returns the type of the provider
func (p *FacebookProvider) GetType() string {
	return "oauth2"
}

// GetAuthURL returns the URL to initiate authentication
func (p *FacebookProvider) GetAuthURL(state string, options map[string]interface{}) (string, error) {
	// Add optional parameters
	var opts []oauth2.AuthCodeOption

	// Handle additional options
	if options != nil {
		if authType, ok := options["auth_type"].(string); ok {
			opts = append(opts, oauth2.SetAuthURLParam("auth_type", authType))
		}
		if displayType, ok := options["display"].(string); ok {
			opts = append(opts, oauth2.SetAuthURLParam("display", displayType))
		}
	}

	// Generate authorization URL
	return p.oauth2Cfg.AuthCodeURL(state, opts...), nil
}

// ExchangeCode exchanges an authorization code for user information
func (p *FacebookProvider) ExchangeCode(ctx context.Context, code string, state string) (*UserInfo, error) {
	// Exchange code for token
	token, err := p.oauth2Cfg.Exchange(ctx, code)
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
func (p *FacebookProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	return p.getUserInfo(ctx, token)
}

// GetConfig returns the provider's configuration
func (p *FacebookProvider) GetConfig() ProviderConfig {
	return p.config
}

// getUserInfo fetches user information from Facebook's Graph API
func (p *FacebookProvider) getUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	// Facebook requires fields parameter to specify what data to return
	fields := "id,email,first_name,last_name,name,picture,locale"

	// Create request to userinfo endpoint
	requestURL := fmt.Sprintf("%s?fields=%s&access_token=%s",
		p.config.UserInfoURL,
		fields,
		accessToken)

	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to create userinfo request")
	}

	// Execute request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to execute userinfo request")
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.New(errors.CodeIdentityProviderError, fmt.Sprintf("userinfo request failed with status %d: %s", resp.StatusCode, body))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to read userinfo response")
	}

	// Parse response
	var userInfoData map[string]interface{}
	if err := json.Unmarshal(body, &userInfoData); err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to parse userinfo response")
	}

	// Extract email (may not be available if email scope was not approved)
	email := getStringValue(userInfoData, "email")

	// Extract profile picture URL
	pictureURL := ""
	if picture, ok := userInfoData["picture"].(map[string]interface{}); ok {
		if data, ok := picture["data"].(map[string]interface{}); ok {
			if url, ok := data["url"].(string); ok {
				pictureURL = url
			}
		}
	}

	// Map to UserInfo
	userInfo := &UserInfo{
		ID:             getStringValue(userInfoData, "id"),
		Email:          email,
		EmailVerified:  email != "", // Facebook only returns verified emails
		Name:           getStringValue(userInfoData, "name"),
		FirstName:      getStringValue(userInfoData, "first_name"),
		LastName:       getStringValue(userInfoData, "last_name"),
		ProfilePicture: pictureURL,
		Locale:         getStringValue(userInfoData, "locale"),
		ProviderType:   "oauth2",
		ProviderName:   p.name,
		RawAttributes:  userInfoData,
		OrganizationID: p.config.OrganizationID,
	}

	// Apply any custom attribute mappings
	p.applyAttributeMappings(userInfo, userInfoData)

	return userInfo, nil
}

// applyAttributeMappings applies custom attribute mappings from provider configuration
func (p *FacebookProvider) applyAttributeMappings(userInfo *UserInfo, data map[string]interface{}) {
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
			case "locale":
				if str, ok := val.(string); ok {
					userInfo.Locale = str
				}
			}
		}
	}
}

// FacebookProviderFactory creates Facebook providers
type FacebookProviderFactory struct{}

// isFacebookProvider checks if the provider configuration is for Facebook
func isFacebookProvider(config *ent.IdentityProvider) bool {
	if config.Metadata == nil {
		return false
	}

	provider, ok := config.Metadata["provider"]
	if !ok {
		return false
	}

	return provider == "facebook"
}

// CreateProvider creates a new Facebook provider from a configuration
func (f *FacebookProviderFactory) CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error) {
	if config.ProviderType != "oauth2" || !isFacebookProvider(config) {
		return nil, ErrUnsupportedProviderType
	}

	// Parse scopes
	scopes := []string{"email", "public_profile"}

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

	// Build provider configuration
	providerConfig := ProviderConfig{
		Name:              config.Name,
		Type:              "oauth2",
		ClientID:          config.ClientID,
		ClientSecret:      config.ClientSecret,
		RedirectURI:       config.RedirectURI,
		Scopes:            scopes,
		AuthURL:           "https://www.facebook.com/v18.0/dialog/oauth",
		TokenURL:          "https://graph.facebook.com/v18.0/oauth/access_token",
		UserInfoURL:       "https://graph.facebook.com/v18.0/me",
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
		Endpoint:     facebook.Endpoint,
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	return &FacebookProvider{
		name:       config.Name,
		config:     providerConfig,
		oauth2Cfg:  oauth2Config,
		httpClient: httpClient,
	}, nil
}
