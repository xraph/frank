package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/logging"
	"golang.org/x/oauth2"
)

// Client represents an OAuth2 client implementation for connecting to external providers
type Client struct {
	config  *config.Config
	logger  logging.Logger
	clients map[string]*oauth2.Config
}

// NewClient creates a new OAuth2 client
func NewClient(cfg *config.Config, logger logging.Logger) *Client {
	return &Client{
		config:  cfg,
		logger:  logger,
		clients: make(map[string]*oauth2.Config),
	}
}

// RegisterProvider registers an OAuth2 provider configuration
func (c *Client) RegisterProvider(providerName string, config *oauth2.Config) {
	c.clients[providerName] = config
}

// InitializeDefaultProviders initializes configurations for common OAuth providers
func (c *Client) InitializeDefaultProviders() error {
	// Initialize providers based on config
	for providerName, providerCfg := range c.config.OAuth.Providers {
		// Skip if required credentials are missing
		if providerCfg.ClientID == "" || providerCfg.ClientSecret == "" {
			c.logger.Info(fmt.Sprintf("Skipping OAuth provider '%s' due to missing credentials", providerName))
			continue
		}

		// Create OAuth2 config for this provider
		oauth2Config := &oauth2.Config{
			ClientID:     providerCfg.ClientID,
			ClientSecret: providerCfg.ClientSecret,
			RedirectURL:  providerCfg.RedirectURI,
			Scopes:       providerCfg.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  providerCfg.AuthURL,
				TokenURL: providerCfg.TokenURL,
			},
		}

		// Add to registered providers
		c.RegisterProvider(providerName, oauth2Config)
		c.logger.Info(fmt.Sprintf("Registered OAuth provider: %s", providerName))
	}

	return nil
}

// GetLoginURL returns a URL for logging in with a specific provider
func (c *Client) GetLoginURL(provider string, state string, options ...oauth2.AuthCodeOption) (string, error) {
	config, exists := c.clients[provider]
	if !exists {
		return "", fmt.Errorf("unknown provider: %s", provider)
	}

	// Generate the authorization URL with state parameter for CSRF protection
	return config.AuthCodeURL(state, options...), nil
}

// Exchange exchanges an authorization code for tokens
func (c *Client) Exchange(ctx context.Context, provider string, code string) (*oauth2.Token, error) {
	config, exists := c.clients[provider]
	if !exists {
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}

	// Exchange the code for a token
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	return token, nil
}

// GetUserInfo fetches user information from the provider's userinfo endpoint
func (c *Client) GetUserInfo(ctx context.Context, provider string, token *oauth2.Token) (map[string]interface{}, error) {
	config, exists := c.clients[provider]
	if !exists {
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}

	// Get the provider-specific configuration
	providerCfg, exists := c.config.OAuth.Providers[provider]
	if !exists {
		return nil, fmt.Errorf("provider configuration not found: %s", provider)
	}

	// Make sure there's a userinfo endpoint
	if providerCfg.UserInfoURL == "" {
		return nil, fmt.Errorf("userinfo endpoint not configured for provider: %s", provider)
	}

	// Create HTTP client with token
	client := config.Client(ctx, token)

	// Request user info
	resp, err := client.Get(providerCfg.UserInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to request user info: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info, status %d: %s", resp.StatusCode, string(body))
	}

	// Read and parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %w", err)
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	return userInfo, nil
}

// RefreshToken refreshes an OAuth2 token
func (c *Client) RefreshToken(ctx context.Context, provider string, token *oauth2.Token) (*oauth2.Token, error) {
	config, exists := c.clients[provider]
	if !exists {
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}

	// Check if token can be refreshed
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("token does not contain a refresh token")
	}

	// Create a token source from the refresh token
	src := config.TokenSource(ctx, token)

	// Get a new token
	newToken, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return newToken, nil
}

// MapUserData maps provider user data to our internal user format
func (c *Client) MapUserData(provider string, userData map[string]interface{}) (map[string]interface{}, error) {
	providerCfg, exists := c.config.OAuth.Providers[provider]
	if !exists {
		return nil, fmt.Errorf("provider configuration not found: %s", provider)
	}

	// Map the provider's user data to our internal structure
	mappedData := make(map[string]interface{})

	// Use field mapping from configuration or default mapping
	mapping := providerCfg.FieldMapping
	if len(mapping) == 0 {
		// Default mappings for common providers
		switch provider {
		case "google":
			mapping = map[string]string{
				"id":             "id",
				"email":          "email",
				"verified_email": "email_verified",
				"name":           "name",
				"given_name":     "first_name",
				"family_name":    "last_name",
				"picture":        "profile_image_url",
			}
		case "github":
			mapping = map[string]string{
				"id":         "id",
				"email":      "email",
				"name":       "name",
				"login":      "username",
				"avatar_url": "profile_image_url",
			}
		case "facebook":
			mapping = map[string]string{
				"id":         "id",
				"email":      "email",
				"name":       "name",
				"first_name": "first_name",
				"last_name":  "last_name",
				"picture":    "profile_image_url",
			}
		default:
			// Generic mapping
			mapping = map[string]string{
				"id":    "id",
				"email": "email",
				"name":  "name",
			}
		}
	}

	// Apply mapping
	for srcField, destField := range mapping {
		// Convert nested paths like "picture.data.url" to nested map access
		parts := strings.Split(srcField, ".")
		value := getUserDataNestedValue(userData, parts)

		if value != nil {
			mappedData[destField] = value
		}
	}

	// Ensure we have at least minimal required data
	if _, ok := mappedData["id"]; !ok {
		return nil, fmt.Errorf("provider data missing required 'id' field")
	}

	// Add provider and timestamp information
	mappedData["provider"] = provider
	mappedData["connected_at"] = time.Now().Unix()

	return mappedData, nil
}

// getUserDataNestedValue gets a nested value from a map using a path like "picture.data.url"
func getUserDataNestedValue(data map[string]interface{}, path []string) interface{} {
	if len(path) == 0 {
		return nil
	}

	if len(path) == 1 {
		return data[path[0]]
	}

	if nestedData, ok := data[path[0]].(map[string]interface{}); ok {
		return getUserDataNestedValue(nestedData, path[1:])
	}

	return nil
}
