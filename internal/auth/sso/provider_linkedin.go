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
	"golang.org/x/oauth2/linkedin"
)

// LinkedInProvider implements the IdentityProvider interface for LinkedIn
type LinkedInProvider struct {
	name       string
	config     ProviderConfig
	oauth2Cfg  *oauth2.Config
	httpClient *http.Client
}

// LinkedInProviderFactory creates LinkedIn providers
type LinkedInProviderFactory struct{}

// CreateProvider creates a new LinkedIn provider from a configuration
func (f *LinkedInProviderFactory) CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error) {
	if config.ProviderType != "oauth2" || !isLinkedInProvider(config) {
		return nil, ErrUnsupportedProviderType
	}

	// Parse scopes
	scopes := []string{"r_liteprofile", "r_emailaddress"}

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
		Name:         config.Name,
		Type:         "oauth2",
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURI:  config.RedirectURI,
		Scopes:       scopes,
		AuthURL:      "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL:     "https://www.linkedin.com/oauth/v2/accessToken",
		UserInfoURL:  "https://api.linkedin.com/v2/me",
		// EmailURL:          "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
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
		Endpoint:     linkedin.Endpoint,
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	return &LinkedInProvider{
		name:       config.Name,
		config:     providerConfig,
		oauth2Cfg:  oauth2Config,
		httpClient: httpClient,
	}, nil
}

// isLinkedInProvider checks if the provider configuration is for LinkedIn
func isLinkedInProvider(config *ent.IdentityProvider) bool {
	if config.Metadata == nil {
		return false
	}

	provider, ok := config.Metadata["provider"]
	if !ok {
		return false
	}

	return provider == "linkedin"
}

// GetName returns the name of the provider
func (p *LinkedInProvider) GetName() string {
	return p.name
}

// GetType returns the type of the provider
func (p *LinkedInProvider) GetType() string {
	return "oauth2"
}

// GetAuthURL returns the URL to initiate authentication
func (p *LinkedInProvider) GetAuthURL(state string, options map[string]interface{}) (string, error) {
	// Add LinkedIn-specific options
	var opts []oauth2.AuthCodeOption

	// Add response_type=code (required by LinkedIn)
	opts = append(opts, oauth2.SetAuthURLParam("response_type", "code"))

	// Handle additional options
	if options != nil {
		if loginHint, ok := options["login_hint"].(string); ok {
			opts = append(opts, oauth2.SetAuthURLParam("login_hint", loginHint))
		}
	}

	// Generate authorization URL
	return p.oauth2Cfg.AuthCodeURL(state, opts...), nil
}

// ExchangeCode exchanges an authorization code for user information
func (p *LinkedInProvider) ExchangeCode(ctx context.Context, code string, state string) (*UserInfo, error) {
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
func (p *LinkedInProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	return p.getUserInfo(ctx, token)
}

// GetConfig returns the provider's configuration
func (p *LinkedInProvider) GetConfig() ProviderConfig {
	return p.config
}

// getUserInfo fetches user information from LinkedIn API
func (p *LinkedInProvider) getUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	// LinkedIn requires separate API calls for profile and email
	profileData, err := p.getProfile(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	emailData, err := p.getEmail(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	// Extract basic profile information
	id := getStringValue(profileData, "id")
	firstName := ""
	lastName := ""

	// LinkedIn's API returns a localized name structure
	if localizedFirstName, ok := profileData["localizedFirstName"].(string); ok {
		firstName = localizedFirstName
	}

	if localizedLastName, ok := profileData["localizedLastName"].(string); ok {
		lastName = localizedLastName
	}

	// Construct full name
	name := strings.TrimSpace(firstName + " " + lastName)

	// Extract profile picture if available
	profilePicture := ""
	if profilePictureObj, ok := profileData["profilePicture"].(map[string]interface{}); ok {
		if displayImage, ok := profilePictureObj["displayImage~"].(map[string]interface{}); ok {
			if elements, ok := displayImage["elements"].([]interface{}); ok && len(elements) > 0 {
				if element, ok := elements[0].(map[string]interface{}); ok {
					if identifiers, ok := element["identifiers"].([]interface{}); ok && len(identifiers) > 0 {
						if identifier, ok := identifiers[0].(map[string]interface{}); ok {
							if identifier["identifier"] != nil {
								profilePicture = identifier["identifier"].(string)
							}
						}
					}
				}
			}
		}
	}

	// Extract email from email response
	email := ""
	emailVerified := false

	if elements, ok := emailData["elements"].([]interface{}); ok && len(elements) > 0 {
		if element, ok := elements[0].(map[string]interface{}); ok {
			if handle, ok := element["handle~"].(map[string]interface{}); ok {
				if emailAddr, ok := handle["emailAddress"].(string); ok {
					email = emailAddr
					emailVerified = true // LinkedIn only returns verified emails
				}
			}
		}
	}

	// Create a merged attributes map for custom attribute mapping
	mergedAttributes := make(map[string]interface{})
	for k, v := range profileData {
		mergedAttributes[k] = v
	}
	if email != "" {
		mergedAttributes["email"] = email
	}

	// Map to UserInfo
	userInfo := &UserInfo{
		ID:             id,
		Email:          email,
		EmailVerified:  emailVerified,
		Name:           name,
		FirstName:      firstName,
		LastName:       lastName,
		ProfilePicture: profilePicture,
		ProviderType:   "oauth2",
		ProviderName:   p.name,
		RawAttributes:  mergedAttributes,
		OrganizationID: p.config.OrganizationID,
	}

	// Apply any custom attribute mappings
	p.applyAttributeMappings(userInfo, mergedAttributes)

	return userInfo, nil
}

// getProfile fetches the LinkedIn user profile
func (p *LinkedInProvider) getProfile(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	// Create request to profile endpoint with projection for basic fields
	requestURL := p.config.UserInfoURL + "?projection=(id,localizedFirstName,localizedLastName,profilePicture(displayImage~:playableStreams))"

	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to create profile request")
	}

	// Add authorization header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("Accept", "application/json")

	// Execute request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to execute profile request")
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.New(errors.CodeIdentityProviderError, fmt.Sprintf("profile request failed with status %d: %s", resp.StatusCode, body))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to read profile response")
	}

	// Parse response
	var profileData map[string]interface{}
	if err := json.Unmarshal(body, &profileData); err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to parse profile response")
	}

	return profileData, nil
}

// getEmail fetches the LinkedIn user email
func (p *LinkedInProvider) getEmail(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	// Get email endpoint from config
	// emailURL := p.config.EmailURL
	emailURL := "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"
	// if emailURL == "" {
	// }

	req, err := http.NewRequestWithContext(ctx, "GET", emailURL, nil)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to create email request")
	}

	// Add authorization header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("Accept", "application/json")

	// Execute request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to execute email request")
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.New(errors.CodeIdentityProviderError, fmt.Sprintf("email request failed with status %d: %s", resp.StatusCode, body))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to read email response")
	}

	// Parse response
	var emailData map[string]interface{}
	if err := json.Unmarshal(body, &emailData); err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to parse email response")
	}

	return emailData, nil
}

// applyAttributeMappings applies custom attribute mappings from provider configuration
func (p *LinkedInProvider) applyAttributeMappings(userInfo *UserInfo, data map[string]interface{}) {
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
