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

// DiscordProvider implements the IdentityProvider interface for Discord
type DiscordProvider struct {
	name       string
	config     ProviderConfig
	oauth2Cfg  *oauth2.Config
	httpClient *http.Client
}

// DiscordProviderFactory creates Discord providers
type DiscordProviderFactory struct{}

// CreateProvider creates a new Discord provider from a configuration
func (f *DiscordProviderFactory) CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error) {
	if config.ProviderType != "oauth2" || !isDiscordProvider(config) {
		return nil, ErrUnsupportedProviderType
	}

	// Default Discord scopes
	scopes := []string{"identify", "email"}

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

	// Discord OAuth2 endpoints
	endpoint := oauth2.Endpoint{
		AuthURL:  "https://discord.com/api/oauth2/authorize",
		TokenURL: "https://discord.com/api/oauth2/token",
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
		UserInfoURL:       "https://discord.com/api/users/@me",
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

	return &DiscordProvider{
		name:       config.Name,
		config:     providerConfig,
		oauth2Cfg:  oauth2Config,
		httpClient: httpClient,
	}, nil
}

// isDiscordProvider checks if the provider configuration is for Discord
func isDiscordProvider(config *ent.IdentityProvider) bool {
	if config.Metadata == nil {
		return false
	}

	provider, ok := config.Metadata["provider"]
	if !ok {
		return false
	}

	return provider == "discord"
}

// GetName returns the name of the provider
func (p *DiscordProvider) GetName() string {
	return p.name
}

// GetType returns the type of the provider
func (p *DiscordProvider) GetType() string {
	return "oauth2"
}

// GetAuthURL returns the URL to initiate authentication
func (p *DiscordProvider) GetAuthURL(state string, options map[string]interface{}) (string, error) {
	// Initialize optional parameters
	var opts []oauth2.AuthCodeOption

	// Discord-specific options
	if options != nil {
		// Handle prompt option
		if prompt, ok := options["prompt"].(string); ok {
			opts = append(opts, oauth2.SetAuthURLParam("prompt", prompt))
		}

		// Handle permissions
		if permissions, ok := options["permissions"].(string); ok {
			opts = append(opts, oauth2.SetAuthURLParam("permissions", permissions))
		}

		// Handle guild_id for Discord server-specific auth
		if guildID, ok := options["guild_id"].(string); ok {
			opts = append(opts, oauth2.SetAuthURLParam("guild_id", guildID))
		}

		// Handle disable_guild_select
		if disableGuildSelect, ok := options["disable_guild_select"].(bool); ok && disableGuildSelect {
			opts = append(opts, oauth2.SetAuthURLParam("disable_guild_select", "true"))
		}
	}

	// Generate authorization URL
	return p.oauth2Cfg.AuthCodeURL(state, opts...), nil
}

// ExchangeCode exchanges an authorization code for user information
func (p *DiscordProvider) ExchangeCode(ctx context.Context, code string, state string) (*UserInfo, error) {
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
func (p *DiscordProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	return p.getUserInfo(ctx, token)
}

// GetConfig returns the provider's configuration
func (p *DiscordProvider) GetConfig() ProviderConfig {
	return p.config
}

// getUserInfo fetches user information from Discord API
func (p *DiscordProvider) getUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
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
		return nil, errors.New(errors.CodeIdentityProviderError, fmt.Sprintf("userinfo request failed with status %d: %s", resp.StatusCode, string(body)))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to read userinfo response")
	}

	// Parse response
	var userData map[string]interface{}
	if err := json.Unmarshal(body, &userData); err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to parse userinfo response")
	}

	// Extract basic information
	id := getStringValue(userData, "id")
	username := getStringValue(userData, "username")
	discriminator := getStringValue(userData, "discriminator") // May be empty in new Discord usernames
	globalName := getStringValue(userData, "global_name")      // New Discord username system

	// Construct full username (handle legacy discriminator system)
	fullUsername := username
	if discriminator != "" && discriminator != "0" {
		fullUsername = username + "#" + discriminator
	}

	// Use global_name if available, otherwise use username
	name := globalName
	if name == "" {
		name = fullUsername
	}

	// Extract email and verified status
	email := getStringValue(userData, "email")
	emailVerified := false
	if verified, ok := userData["verified"].(bool); ok {
		emailVerified = verified
	}

	// Extract avatar URL
	avatarURL := ""
	avatar := getStringValue(userData, "avatar")
	if avatar != "" {
		// Discord avatar URL format
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", id, avatar)
	}

	// Extract locale
	locale := getStringValue(userData, "locale")

	// Map to UserInfo
	userInfo := &UserInfo{
		ID:            id,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		// Discord doesn't provide first/last name split
		ProfilePicture: avatarURL,
		Locale:         locale,
		ProviderType:   "oauth2",
		ProviderName:   p.name,
		RawAttributes:  userData,
		OrganizationID: p.config.OrganizationID,
	}

	// Add Discord-specific info to raw attributes if not already present
	if _, ok := userInfo.RawAttributes["username"]; !ok {
		userInfo.RawAttributes["username"] = username
	}

	if discriminator != "" && discriminator != "0" {
		if _, ok := userInfo.RawAttributes["discriminator"]; !ok {
			userInfo.RawAttributes["discriminator"] = discriminator
		}
	}

	// Apply any custom attribute mappings
	p.applyAttributeMappings(userInfo, userData)

	return userInfo, nil
}

// applyAttributeMappings applies custom attribute mappings from provider configuration
func (p *DiscordProvider) applyAttributeMappings(userInfo *UserInfo, data map[string]interface{}) {
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
			}
		}
	}
}
