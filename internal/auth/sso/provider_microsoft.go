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
	"golang.org/x/oauth2/microsoft"
)

// MicrosoftProvider implements the IdentityProvider interface for Microsoft
type MicrosoftProvider struct {
	name       string
	config     ProviderConfig
	oauth2Cfg  *oauth2.Config
	httpClient *http.Client
}

// MicrosoftProviderFactory creates Microsoft providers
type MicrosoftProviderFactory struct{}

// CreateProvider creates a new Microsoft provider from a configuration
func (f *MicrosoftProviderFactory) CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error) {
	if config.ProviderType != "oauth2" || !isMicrosoftProvider(config) {
		return nil, ErrUnsupportedProviderType
	}

	// Parse scopes
	scopes := []string{"openid", "profile", "email", "User.Read"}
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
		AuthURL:           "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:          "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL:       "https://graph.microsoft.com/v1.0/me",
		JWKSURL:           "https://login.microsoftonline.com/common/discovery/v2.0/keys",
		Issuer:            "https://login.microsoftonline.com/{tenantid}/v2.0",
		AllowedDomains:    config.Domains,
		AttributeMappings: attributesMapping,
		OrganizationID:    config.OrganizationID,
		Metadata:          config.Metadata,
	}

	// Check if tenant ID is specified
	tenantID := "common"
	if config.Metadata != nil {
		if tid, ok := config.Metadata["tenant_id"].(string); ok && tid != "" {
			tenantID = tid
			providerConfig.Issuer = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tid)
			providerConfig.AuthURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tid)
			providerConfig.TokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tid)
		}
	}

	// Create OAuth2 config - use Microsoft's endpoint but with custom tenant if specified
	var endpoint oauth2.Endpoint
	if tenantID == "common" {
		endpoint = microsoft.AzureADEndpoint(tenantID)
	} else {
		endpoint = oauth2.Endpoint{
			AuthURL:  providerConfig.AuthURL,
			TokenURL: providerConfig.TokenURL,
		}
	}

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

	return &MicrosoftProvider{
		name:       config.Name,
		config:     providerConfig,
		oauth2Cfg:  oauth2Config,
		httpClient: httpClient,
	}, nil
}

// isMicrosoftProvider checks if the provider configuration is for Microsoft
func isMicrosoftProvider(config *ent.IdentityProvider) bool {
	if config.Metadata == nil {
		return false
	}

	provider, ok := config.Metadata["provider"]
	if !ok {
		return false
	}

	return provider == "microsoft" || provider == "azure_ad" || provider == "office365"
}

// GetName returns the name of the provider
func (p *MicrosoftProvider) GetName() string {
	return p.name
}

// GetType returns the type of the provider
func (p *MicrosoftProvider) GetType() string {
	return "oauth2"
}

// GetAuthURL returns the URL to initiate authentication
func (p *MicrosoftProvider) GetAuthURL(state string, options map[string]interface{}) (string, error) {
	// Add optional parameters
	var opts []oauth2.AuthCodeOption

	// Add domain hint if available
	if p.config.AllowedDomains != nil && len(p.config.AllowedDomains) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("domain_hint", p.config.AllowedDomains[0]))
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
func (p *MicrosoftProvider) ExchangeCode(ctx context.Context, code string, state string) (*UserInfo, error) {
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
func (p *MicrosoftProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	return p.getUserInfo(ctx, token)
}

// GetConfig returns the provider's configuration
func (p *MicrosoftProvider) GetConfig() ProviderConfig {
	return p.config
}

// getUserInfo fetches user information from Microsoft Graph API
func (p *MicrosoftProvider) getUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	// Create request to userinfo endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL, nil)
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

	// Map to UserInfo
	userInfo := &UserInfo{
		ID:             getStringValue(userInfoData, "id"),
		Email:          getStringValue(userInfoData, "mail"),
		Name:           getStringValue(userInfoData, "displayName"),
		FirstName:      getStringValue(userInfoData, "givenName"),
		LastName:       getStringValue(userInfoData, "surname"),
		ProfilePicture: "", // Microsoft Graph requires additional permissions for photos
		Locale:         getStringValue(userInfoData, "preferredLanguage"),
		ProviderType:   "oauth2",
		ProviderName:   p.name,
		RawAttributes:  userInfoData,
		OrganizationID: p.config.OrganizationID,
	}

	// If no email is found in the 'mail' field, try 'userPrincipalName'
	if userInfo.Email == "" {
		userInfo.Email = getStringValue(userInfoData, "userPrincipalName")
	}

	// Set email verified to true for Microsoft accounts
	userInfo.EmailVerified = true

	// Extract organization information if available
	if businessPhones, ok := userInfoData["businessPhones"].([]interface{}); ok && len(businessPhones) > 0 {
		// This can be used to indicate a business account
	}

	// Try to extract domain from email
	if userInfo.Email != "" {
		parts := splitEmailParts(userInfo.Email)
		if len(parts) == 2 {
			userInfo.OrganizationName = parts[1]
			userInfo.OrganizationEmail = userInfo.Email
		}
	}

	// Apply any custom attribute mappings
	p.applyAttributeMappings(userInfo, userInfoData)

	// Validate domain if AllowedDomains is specified
	if len(p.config.AllowedDomains) > 0 && userInfo.OrganizationName != "" {
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
func (p *MicrosoftProvider) applyAttributeMappings(userInfo *UserInfo, data map[string]interface{}) {
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
