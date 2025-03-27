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
)

// SlackProvider implements the IdentityProvider interface for Slack
type SlackProvider struct {
	name       string
	config     ProviderConfig
	oauth2Cfg  *oauth2.Config
	httpClient *http.Client
}

// SlackProviderFactory creates Slack providers
type SlackProviderFactory struct{}

// CreateProvider creates a new Slack provider from a configuration
func (f *SlackProviderFactory) CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error) {
	if config.ProviderType != "oauth2" || !isSlackProvider(config) {
		return nil, ErrUnsupportedProviderType
	}

	// Default Slack scopes
	scopes := []string{"identity.basic", "identity.email", "identity.avatar"}

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

	// Slack OAuth2 endpoints
	endpoint := oauth2.Endpoint{
		AuthURL:  "https://slack.com/oauth/v2/authorize",
		TokenURL: "https://slack.com/api/oauth.v2.access",
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
		UserInfoURL:       "https://slack.com/api/users.identity",
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

	return &SlackProvider{
		name:       config.Name,
		config:     providerConfig,
		oauth2Cfg:  oauth2Config,
		httpClient: httpClient,
	}, nil
}

// isSlackProvider checks if the provider configuration is for Slack
func isSlackProvider(config *ent.IdentityProvider) bool {
	if config.Metadata == nil {
		return false
	}

	provider, ok := config.Metadata["provider"]
	if !ok {
		return false
	}

	return provider == "slack"
}

// GetName returns the name of the provider
func (p *SlackProvider) GetName() string {
	return p.name
}

// GetType returns the type of the provider
func (p *SlackProvider) GetType() string {
	return "oauth2"
}

// GetAuthURL returns the URL to initiate authentication
func (p *SlackProvider) GetAuthURL(state string, options map[string]interface{}) (string, error) {
	// Initialize optional parameters
	var opts []oauth2.AuthCodeOption

	// Slack requires user_scope for Sign in with Slack
	opts = append(opts, oauth2.SetAuthURLParam("user_scope", p.oauth2Cfg.Scopes[0]))
	for i := 1; i < len(p.oauth2Cfg.Scopes); i++ {
		// opts[0].Value += "," + p.oauth2Cfg.Scopes[i]
	}

	// Handle additional options
	if options != nil {
		if team, ok := options["team"].(string); ok {
			opts = append(opts, oauth2.SetAuthURLParam("team", team))
		}
	}

	// Generate authorization URL
	return p.oauth2Cfg.AuthCodeURL(state, opts...), nil
}

// ExchangeCode exchanges an authorization code for user information
func (p *SlackProvider) ExchangeCode(ctx context.Context, code string, state string) (*UserInfo, error) {
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
func (p *SlackProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	return p.getUserInfo(ctx, token)
}

// GetConfig returns the provider's configuration
func (p *SlackProvider) GetConfig() ProviderConfig {
	return p.config
}

// getUserInfo fetches user information from Slack API
func (p *SlackProvider) getUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	// Create request to userinfo endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to create userinfo request")
	}

	// Add authorization header (Slack uses Bearer token)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

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
		OK    bool                   `json:"ok"`
		Error string                 `json:"error,omitempty"`
		User  map[string]interface{} `json:"user"`
		Team  map[string]interface{} `json:"team"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to parse userinfo response")
	}

	// Check if response was successful
	if !response.OK {
		return nil, errors.New(errors.CodeIdentityProviderError, fmt.Sprintf("userinfo request failed: %s", response.Error))
	}

	// Extract user info
	userData := response.User
	if userData == nil {
		return nil, errors.New(errors.CodeIdentityProviderError, "no user data returned from Slack")
	}

	// Extract team info if available
	teamData := response.Team

	// Basic user info
	id := getStringValue(userData, "id")
	name := getStringValue(userData, "name")

	// Extract email
	email := ""
	if profile, ok := userData["profile"].(map[string]interface{}); ok {
		email = getStringValue(profile, "email")

		// If name is empty, try display name or real name from profile
		if name == "" {
			name = getStringValue(profile, "display_name")
		}
		if name == "" {
			name = getStringValue(profile, "real_name")
		}

		// Try to parse first and last name
		firstName := getStringValue(profile, "first_name")
		lastName := getStringValue(profile, "last_name")

		// Get profile picture
		profilePicture := getStringValue(profile, "image_192")
		if profilePicture == "" {
			profilePicture = getStringValue(profile, "image_original")
		}
		if profilePicture == "" {
			profilePicture = getStringValue(profile, "image_512")
		}

		// Create merged data for attribute mapping
		mergedData := make(map[string]interface{})
		for k, v := range userData {
			mergedData[k] = v
		}

		// Add team data if available
		organizationName := ""
		if teamData != nil {
			organizationName = getStringValue(teamData, "name")
			if id, ok := teamData["id"].(string); ok {
				mergedData["team_id"] = id
			}
			if teamName, ok := teamData["name"].(string); ok {
				mergedData["team_name"] = teamName
			}
		}

		// Map to UserInfo
		userInfo := &UserInfo{
			ID:               id,
			Email:            email,
			EmailVerified:    email != "", // Slack only returns verified emails
			Name:             name,
			FirstName:        firstName,
			LastName:         lastName,
			ProfilePicture:   profilePicture,
			ProviderType:     "oauth2",
			ProviderName:     p.name,
			RawAttributes:    mergedData,
			OrganizationID:   p.config.OrganizationID,
			OrganizationName: organizationName,
		}

		// Apply any custom attribute mappings
		p.applyAttributeMappings(userInfo, mergedData)

		return userInfo, nil
	}

	// If we reach here, we couldn't extract enough information
	return nil, errors.New(errors.CodeIdentityProviderError, "could not extract required user information from Slack response")
}

// applyAttributeMappings applies custom attribute mappings from provider configuration
func (p *SlackProvider) applyAttributeMappings(userInfo *UserInfo, data map[string]interface{}) {
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
			case "organization_name":
				if str, ok := val.(string); ok {
					userInfo.OrganizationName = str
				}
			}
		}
	}
}
