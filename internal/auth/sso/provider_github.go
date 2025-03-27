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
	"golang.org/x/oauth2/github"
)

// GitHubProvider implements the IdentityProvider interface for GitHub
type GitHubProvider struct {
	name       string
	config     ProviderConfig
	oauth2Cfg  *oauth2.Config
	httpClient *http.Client
}

// GitHubProviderFactory creates GitHub providers
type GitHubProviderFactory struct{}

// CreateProvider creates a new GitHub provider from a configuration
func (f *GitHubProviderFactory) CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error) {
	if config.ProviderType != "oauth2" || !isGitHubProvider(config) {
		return nil, ErrUnsupportedProviderType
	}

	// Parse scopes
	scopes := []string{"user:email", "read:user"}
	if config.Domains != nil && len(config.Domains) > 0 {
		// GitHub doesn't support domain restrictions via OAuth
		// Organizations will need to be checked after authentication
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
		AuthURL:           "https://github.com/login/oauth/authorize",
		TokenURL:          "https://github.com/login/oauth/access_token",
		UserInfoURL:       "https://api.github.com/user",
		Issuer:            "https://github.com",
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
		Endpoint:     github.Endpoint,
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	return &GitHubProvider{
		name:       config.Name,
		config:     providerConfig,
		oauth2Cfg:  oauth2Config,
		httpClient: httpClient,
	}, nil
}

// isGitHubProvider checks if the provider configuration is for GitHub
func isGitHubProvider(config *ent.IdentityProvider) bool {
	if config.Metadata == nil {
		return false
	}

	provider, ok := config.Metadata["provider"]
	if !ok {
		return false
	}

	return provider == "github"
}

// GetName returns the name of the provider
func (p *GitHubProvider) GetName() string {
	return p.name
}

// GetType returns the type of the provider
func (p *GitHubProvider) GetType() string {
	return "oauth2"
}

// GetAuthURL returns the URL to initiate authentication
func (p *GitHubProvider) GetAuthURL(state string, options map[string]interface{}) (string, error) {
	// Add optional parameters
	var opts []oauth2.AuthCodeOption

	// Add login hint if specified
	if options != nil {
		if login, ok := options["login"].(string); ok {
			opts = append(opts, oauth2.SetAuthURLParam("login", login))
		}
		if allowSignup, ok := options["allow_signup"].(bool); ok && allowSignup {
			opts = append(opts, oauth2.SetAuthURLParam("allow_signup", "true"))
		}
	}

	// Generate authorization URL
	return p.oauth2Cfg.AuthCodeURL(state, opts...), nil
}

// ExchangeCode exchanges an authorization code for user information
func (p *GitHubProvider) ExchangeCode(ctx context.Context, code string, state string) (*UserInfo, error) {
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
func (p *GitHubProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	return p.getUserInfo(ctx, token)
}

// GetConfig returns the provider's configuration
func (p *GitHubProvider) GetConfig() ProviderConfig {
	return p.config
}

// getUserInfo fetches user information from GitHub API
func (p *GitHubProvider) getUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	// Create request to userinfo endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to create userinfo request")
	}

	// Add authorization header
	req.Header.Add("Authorization", fmt.Sprintf("token %s", accessToken))
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

	// Get email - GitHub might not return the email in the user endpoint if it's private
	// We need to make a separate call to get the email
	email := getStringValue(userInfoData, "email")
	if email == "" || !getBoolValue(userInfoData, "email_verified") {
		email, _ = p.getPrimaryEmail(ctx, accessToken)
	}

	// Map to UserInfo
	userInfo := &UserInfo{
		ID:             getStringValue(userInfoData, "id"),
		Email:          email,
		EmailVerified:  email != "", // GitHub only returns verified emails
		Name:           getStringValue(userInfoData, "name"),
		ProfilePicture: getStringValue(userInfoData, "avatar_url"),
		ProviderType:   "oauth2",
		ProviderName:   p.name,
		RawAttributes:  userInfoData,
		OrganizationID: p.config.OrganizationID,
	}

	// Extract first and last name if available
	if userInfo.Name != "" {
		parts := strings.Split(userInfo.Name, " ")
		if len(parts) > 0 {
			userInfo.FirstName = parts[0]
			if len(parts) > 1 {
				userInfo.LastName = strings.Join(parts[1:], " ")
			}
		}
	}

	// GitHub doesn't provide locale information
	userInfo.Locale = "en"

	// Try to extract GitHub organization memberships if needed
	if len(p.config.AllowedDomains) > 0 {
		orgs, err := p.getUserOrganizations(ctx, accessToken)
		if err == nil {
			// Check if user belongs to any of the allowed organizations
			for _, org := range orgs {
				orgLogin := getStringValue(org, "login")
				for _, allowedOrg := range p.config.AllowedDomains {
					if orgLogin == allowedOrg {
						userInfo.OrganizationName = orgLogin
						userInfo.Groups = append(userInfo.Groups, orgLogin)
						break
					}
				}
				if userInfo.OrganizationName != "" {
					break
				}
			}

			// If organization check is required but user doesn't belong to any allowed org
			if userInfo.OrganizationName == "" && len(p.config.AllowedDomains) > 0 {
				return nil, errors.New(errors.CodeUnauthorized, "user is not a member of any allowed GitHub organization")
			}
		}
	}

	// Apply any custom attribute mappings
	p.applyAttributeMappings(userInfo, userInfoData)

	return userInfo, nil
}

// getPrimaryEmail fetches the user's primary email from GitHub API
func (p *GitHubProvider) getPrimaryEmail(ctx context.Context, accessToken string) (string, bool) {
	// Create request to emails endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", false
	}

	// Add authorization header
	req.Header.Add("Authorization", fmt.Sprintf("token %s", accessToken))
	req.Header.Add("Accept", "application/json")

	// Execute request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return "", false
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}

	// Parse response
	var emails []map[string]interface{}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", false
	}

	// Find primary email
	for _, email := range emails {
		isPrimary := getBoolValue(email, "primary")
		isVerified := getBoolValue(email, "verified")
		if isPrimary && isVerified {
			return getStringValue(email, "email"), true
		}
	}

	// If no primary email found, return the first verified email
	for _, email := range emails {
		isVerified := getBoolValue(email, "verified")
		if isVerified {
			return getStringValue(email, "email"), true
		}
	}

	return "", false
}

// getUserOrganizations fetches the user's organization memberships from GitHub API
func (p *GitHubProvider) getUserOrganizations(ctx context.Context, accessToken string) ([]map[string]interface{}, error) {
	// Create request to organizations endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/orgs", nil)
	if err != nil {
		return nil, err
	}

	// Add authorization header
	req.Header.Add("Authorization", fmt.Sprintf("token %s", accessToken))
	req.Header.Add("Accept", "application/json")

	// Execute request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("organizations request failed with status %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse response
	var organizations []map[string]interface{}
	if err := json.Unmarshal(body, &organizations); err != nil {
		return nil, err
	}

	return organizations, nil
}

// applyAttributeMappings applies custom attribute mappings from provider configuration
func (p *GitHubProvider) applyAttributeMappings(userInfo *UserInfo, data map[string]interface{}) {
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
