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
	"golang.org/x/oauth2/google"
)

// GoogleProvider implements the IdentityProvider interface for Google
type GoogleProvider struct {
	name       string
	config     ProviderConfig
	oauth2Cfg  *oauth2.Config
	httpClient *http.Client
}

// GoogleProviderFactory creates Google providers
type GoogleProviderFactory struct{}

// CreateProvider creates a new Google provider from a configuration
func (f *GoogleProviderFactory) CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error) {
	if config.ProviderType != "oauth2" || !isGoogleProvider(config) {
		return nil, ErrUnsupportedProviderType
	}

	// Parse scopes
	scopes := []string{"openid", "profile", "email"}
	if config.Domains != nil && len(config.Domains) > 0 {
		// Add domain-specific scopes if needed
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
		AuthURL:           "https://accounts.google.com/o/oauth2/auth",
		TokenURL:          "https://oauth2.googleapis.com/token",
		UserInfoURL:       "https://openidconnect.googleapis.com/v1/userinfo",
		JWKSURL:           "https://www.googleapis.com/oauth2/v3/certs",
		Issuer:            "https://accounts.google.com",
		AllowedDomains:    config.Domains,
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
		Endpoint:     google.Endpoint,
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	return &GoogleProvider{
		name:       config.Name,
		config:     providerConfig,
		oauth2Cfg:  oauth2Config,
		httpClient: httpClient,
	}, nil
}

// isGoogleProvider checks if the provider configuration is for Google
func isGoogleProvider(config *ent.IdentityProvider) bool {
	if config.Metadata == nil {
		return false
	}

	provider, ok := config.Metadata["provider"]
	if !ok {
		return false
	}

	return provider == "google"
}

// GetName returns the name of the provider
func (p *GoogleProvider) GetName() string {
	return p.name
}

// GetType returns the type of the provider
func (p *GoogleProvider) GetType() string {
	return "oauth2"
}

// GetAuthURL returns the URL to initiate authentication
func (p *GoogleProvider) GetAuthURL(state string, options map[string]interface{}) (string, error) {
	// Add optional parameters
	var opts []oauth2.AuthCodeOption

	// Add domain hint if available
	if p.config.AllowedDomains != nil && len(p.config.AllowedDomains) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("hd", p.config.AllowedDomains[0]))
	}

	// Add prompt parameter if specified
	if options != nil {
		if prompt, ok := options["prompt"].(string); ok {
			opts = append(opts, oauth2.SetAuthURLParam("prompt", prompt))
		}
	}

	// Generate authorization URL
	return p.oauth2Cfg.AuthCodeURL(state, opts...), nil
}

// ExchangeCode exchanges an authorization code for user information
func (p *GoogleProvider) ExchangeCode(ctx context.Context, code string, state string) (*UserInfo, error) {
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
func (p *GoogleProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	return p.getUserInfo(ctx, token)
}

// GetConfig returns the provider's configuration
func (p *GoogleProvider) GetConfig() ProviderConfig {
	return p.config
}

// getUserInfo fetches user information from Google's userinfo endpoint
func (p *GoogleProvider) getUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	// Create request to userinfo endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to create userinfo request")
	}

	// Add authorization header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Execute request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to execute userinfo request")
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(errors.CodeIdentityProviderError, fmt.Sprintf("userinfo request failed with status %d", resp.StatusCode))
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

	// Map to UserInfo
	userInfo := &UserInfo{
		ID:             getStringValue(userInfoData, "sub"),
		Email:          getStringValue(userInfoData, "email"),
		EmailVerified:  getBoolValue(userInfoData, "email_verified"),
		Name:           getStringValue(userInfoData, "name"),
		FirstName:      getStringValue(userInfoData, "given_name"),
		LastName:       getStringValue(userInfoData, "family_name"),
		ProfilePicture: getStringValue(userInfoData, "picture"),
		Locale:         getStringValue(userInfoData, "locale"),
		ProviderType:   "oauth2",
		ProviderName:   p.name,
		RawAttributes:  userInfoData,
		OrganizationID: p.config.OrganizationID,
	}

	// Apply domain-specific logic for Google
	// For Google, we can use the HD (hosted domain) field to determine the organization
	if hd, ok := userInfoData["hd"].(string); ok && hd != "" {
		userInfo.OrganizationName = hd
		userInfo.OrganizationEmail = userInfo.Email
	}

	// Apply any custom attribute mappings
	p.applyAttributeMappings(userInfo, userInfoData)

	// Validate domain if AllowedDomains is specified
	if len(p.config.AllowedDomains) > 0 {
		domainOk := false
		for _, domain := range p.config.AllowedDomains {
			if domain == userInfo.OrganizationName {
				domainOk = true
				break
			}
		}
		if !domainOk {
			return nil, errors.New(errors.CodeUnauthorized, "user's domain is not allowed")
		}
	}

	return userInfo, nil
}

// applyAttributeMappings applies custom attribute mappings from provider configuration
func (p *GoogleProvider) applyAttributeMappings(userInfo *UserInfo, data map[string]interface{}) {
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
			case "email_verified":
				if b, ok := val.(bool); ok {
					userInfo.EmailVerified = b
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
			case "organization_name":
				if str, ok := val.(string); ok {
					userInfo.OrganizationName = str
				}
			case "organization_email":
				if str, ok := val.(string); ok {
					userInfo.OrganizationEmail = str
				}
			}
		}
	}
}

// Helper functions to safely extract values from the userinfo response
func getStringValue(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBoolValue(data map[string]interface{}, key string) bool {
	if val, ok := data[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}
