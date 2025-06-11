package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// OIDCService defines the OIDC/OAuth2 SSO service interface
type OIDCService interface {
	// Authentication flow
	InitiateLogin(ctx context.Context, provider *model.IdentityProvider, state, redirectURL string) (string, error)
	HandleCallback(ctx context.Context, provider *model.IdentityProvider, code, state string) (*SSOUserInfo, error)

	// Configuration and validation
	ValidateConfig(config model.IdentityProviderConfig) error
	TestConnection(ctx context.Context, provider *model.IdentityProvider) error

	// Discovery and metadata
	DiscoverConfiguration(ctx context.Context, issuer string) (*OIDCConfiguration, error)

	// Token operations
	ExchangeCodeForTokens(ctx context.Context, provider *model.IdentityProvider, code, codeVerifier string) (*OIDCTokenResponse, error)
	GetUserInfo(ctx context.Context, provider *model.IdentityProvider, accessToken string) (*SSOUserInfo, error)

	// Utility methods
	GenerateCodeChallenge() (string, string, error) // Returns code_verifier, code_challenge
	ValidateIDToken(ctx context.Context, provider *model.IdentityProvider, idToken string) (*OIDCClaims, error)
}

// oidcService implements OIDC/OAuth2 SSO functionality
type oidcService struct {
	logger     logging.Logger
	baseURL    string
	httpClient *http.Client
}

// NewOIDCService creates a new OIDC service
func NewOIDCService(baseURL string, logger logging.Logger) OIDCService {
	return &oidcService{
		logger:  logger,
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// InitiateLogin initiates OIDC/OAuth2 authentication flow
func (s *oidcService) InitiateLogin(ctx context.Context, provider *model.IdentityProvider, state, redirectURL string) (string, error) {
	s.logger.Info("Initiating OIDC login", logging.String("provider", provider.Name))

	// Extract OIDC configuration
	config, err := s.extractOIDCConfig(provider.Config)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInvalidInput, "invalid OIDC configuration")
	}

	// Build authorization URL
	authURL, err := s.buildAuthorizationURL(provider, config, state)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to build authorization URL")
	}

	s.logger.Info("Generated OIDC auth URL", logging.String("url", authURL))
	return authURL, nil
}

// HandleCallback processes OIDC/OAuth2 callback after authentication
func (s *oidcService) HandleCallback(ctx context.Context, provider *model.IdentityProvider, code, state string) (*SSOUserInfo, error) {
	s.logger.Info("Processing OIDC callback", logging.String("provider", provider.Name))

	// Extract OIDC configuration
	_, err := s.extractOIDCConfig(provider.Config)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidInput, "invalid OIDC configuration")
	}

	// Exchange authorization code for tokens
	tokenResponse, err := s.ExchangeCodeForTokens(ctx, provider, code, "")
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "failed to exchange code for tokens")
	}

	var userInfo *SSOUserInfo

	// If we have an ID token, extract user info from it
	if tokenResponse.IDToken != "" {
		claims, err := s.ValidateIDToken(ctx, provider, tokenResponse.IDToken)
		if err != nil {
			s.logger.Warn("Failed to validate ID token, falling back to userinfo endpoint", logging.Error(err))
		} else {
			userInfo = s.extractUserInfoFromClaims(claims)
		}
	}

	// If no user info from ID token, try userinfo endpoint
	if userInfo == nil && tokenResponse.AccessToken != "" {
		userInfo, err = s.GetUserInfo(ctx, provider, tokenResponse.AccessToken)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeUnauthorized, "failed to get user info")
		}
	}

	if userInfo == nil {
		return nil, errors.New(errors.CodeUnauthorized, "no user information available")
	}

	// Apply custom attribute mapping if configured
	if provider.AttributeMapping != nil {
		s.applyAttributeMapping(userInfo, provider.AttributeMapping)
	}

	// Validate required fields
	if userInfo.Email == "" {
		return nil, errors.New(errors.CodeUnauthorized, "email not found in OIDC response")
	}

	s.logger.Info("Successfully processed OIDC response", logging.String("user_email", userInfo.Email))
	return userInfo, nil
}

// ValidateConfig validates OIDC provider configuration
func (s *oidcService) ValidateConfig(config model.IdentityProviderConfig) error {
	// Check for auto-discovery
	if config.Issuer != "" {
		// For auto-discovery, we only need issuer and client credentials
		if config.ClientID == "" {
			return errors.New(errors.CodeInvalidInput, "client id is required")
		}
		if config.ClientSecret == "" {
			return errors.New(errors.CodeInvalidInput, "client secret is required")
		}
		return nil
	}

	// Manual configuration requires more fields
	if config.ClientID == "" {
		return errors.New(errors.CodeInvalidInput, "missing required OIDC field: client id is required")
	}
	if config.ClientSecret == "" {
		return errors.New(errors.CodeInvalidInput, "missing required OIDC field: client secret is required")
	}
	if config.AuthURL == "" {
		return errors.New(errors.CodeInvalidInput, "missing required OIDC field: auth url is required")
	}
	if config.TokenURL == "" {
		return errors.New(errors.CodeInvalidInput, "missing required OIDC field: token url is required")
	}

	// Validate URLsΩ
	if config.AuthURL != "" {
		if _, err := url.Parse(config.AuthURL); err != nil {
			return errors.Wrapf(err, errors.CodeInvalidInput, "invalid authUrl")
		}
	}
	if config.TokenURL != "" {
		if _, err := url.Parse(config.TokenURL); err != nil {
			return errors.Wrapf(err, errors.CodeInvalidInput, "invalid tokenUrl")
		}
	}
	if config.UserInfoURL != "" {
		if _, err := url.Parse(config.UserInfoURL); err != nil {
			return errors.Wrapf(err, errors.CodeInvalidInput, "invalid userInfoUrl")
		}
	}
	if config.JWKSUrl != "" {
		if _, err := url.Parse(config.JWKSUrl); err != nil {
			return errors.Wrapf(err, errors.CodeInvalidInput, "invalid jwksUrl")
		}
	}

	return nil
}

// TestConnection tests OIDC provider connection
func (s *oidcService) TestConnection(ctx context.Context, provider *model.IdentityProvider) error {
	config, err := s.extractOIDCConfig(provider.Config)
	if err != nil {
		return fmt.Errorf("invalid OIDC configuration: %w", err)
	}

	// Test discovery endpoint if issuer is configured
	if config.Issuer != "" {
		discoveryURL := strings.TrimSuffix(config.Issuer, "/") + "/.well-known/openid_configuration"
		if err := s.testEndpoint(discoveryURL); err != nil {
			return fmt.Errorf("discovery endpoint test failed: %w", err)
		}
	}

	// Test authorization endpoint
	if config.AuthURL != "" {
		if err := s.testEndpoint(config.AuthURL); err != nil {
			return fmt.Errorf("authorization endpoint test failed: %w", err)
		}
	}

	// Test token endpoint
	if config.TokenURL != "" {
		if err := s.testEndpoint(config.TokenURL); err != nil {
			return fmt.Errorf("token endpoint test failed: %w", err)
		}
	}

	return nil
}

// DiscoverConfiguration discovers OIDC configuration from issuer
func (s *oidcService) DiscoverConfiguration(ctx context.Context, issuer string) (*OIDCConfiguration, error) {
	discoveryURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid_configuration"

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read discovery response: %w", err)
	}

	var config OIDCConfiguration
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("failed to parse discovery document: %w", err)
	}

	return &config, nil
}

// ExchangeCodeForTokens exchanges authorization code for tokens
func (s *oidcService) ExchangeCodeForTokens(ctx context.Context, provider *model.IdentityProvider, code, codeVerifier string) (*OIDCTokenResponse, error) {
	config, err := s.extractOIDCConfig(provider.Config)
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC configuration: %w", err)
	}

	// Prepare token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", s.getRedirectURI(provider))
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)

	// Add PKCE code verifier if provided
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse OIDCTokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResponse, nil
}

// GetUserInfo retrieves user information from userinfo endpoint
func (s *oidcService) GetUserInfo(ctx context.Context, provider *model.IdentityProvider, accessToken string) (*SSOUserInfo, error) {
	config, err := s.extractOIDCConfig(provider.Config)
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC configuration: %w", err)
	}

	if config.UserInfoURL == "" {
		return nil, fmt.Errorf("userinfo endpoint not configured")
	}

	// Create userinfo request
	req, err := http.NewRequestWithContext(ctx, "GET", config.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read userinfo response: %w", err)
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	return s.extractUserInfoFromUserInfoResponse(userInfo, provider), nil
}

// GenerateCodeChallenge generates PKCE code challenge and verifier
func (s *oidcService) GenerateCodeChallenge() (string, string, error) {
	// Generate code verifier
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	codeVerifier := base64.RawURLEncoding.EncodeToString(b)

	// For simplicity, using plain method (S256 would require SHA256 hashing)
	codeChallenge := codeVerifier

	return codeVerifier, codeChallenge, nil
}

// ValidateIDToken validates and parses an ID token (simplified implementation)
func (s *oidcService) ValidateIDToken(ctx context.Context, provider *model.IdentityProvider, idToken string) (*OIDCClaims, error) {
	// This is a simplified implementation
	// In production, you would:
	// 1. Verify the JWT signature using JWKS
	// 2. Validate issuer, audience, expiration, etc.
	// 3. Parse claims properly

	// For now, just decode the payload (base64)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid ID token format")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ID token payload: %w", err)
	}

	var claims OIDCClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	// Basic validation
	if claims.Exp != 0 && time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("ID token has expired")
	}

	return &claims, nil
}

// Helper methods

// extractOIDCConfig extracts OIDC configuration from provider config
func (s *oidcService) extractOIDCConfig(config model.IdentityProviderConfig) (*OIDCConfig, error) {
	oidcConfig := &OIDCConfig{}

	// Required fields
	if config.ClientID != "" {
		oidcConfig.ClientID = config.ClientID
	} else {
		return nil, fmt.Errorf("missing client_id")
	}

	if config.ClientSecret != "" {
		oidcConfig.ClientSecret = config.ClientSecret
	} else {
		return nil, fmt.Errorf("missing client_secret")
	}

	// Optional issuer for auto-discovery
	if config.Issuer != "" {
		oidcConfig.Issuer = config.Issuer
	}

	// Manual configuration URLs
	if config.AuthURL != "" {
		oidcConfig.AuthURL = config.AuthURL
	}

	if config.TokenURL != "" {
		oidcConfig.TokenURL = config.TokenURL
	}

	if config.UserInfoURL != "" {
		oidcConfig.UserInfoURL = config.UserInfoURL
	}

	if config.JWKSUrl != "" {
		oidcConfig.JWKSURL = config.JWKSUrl
	}

	// Scopes
	if config.Scopes != nil {
		oidcConfig.Scopes = config.Scopes
	} else {
		// Default scopes
		oidcConfig.Scopes = []string{"openid", "email", "profile"}
	}

	return oidcConfig, nil
}

// buildAuthorizationURL builds the OAuth2/OIDC authorization URL
func (s *oidcService) buildAuthorizationURL(provider *model.IdentityProvider, config *OIDCConfig, state string) (string, error) {
	var authURL string

	// Use discovered or configured auth URL
	if config.AuthURL != "" {
		authURL = config.AuthURL
	} else if config.Issuer != "" {
		// Try auto-discovery
		discoveredConfig, err := s.DiscoverConfiguration(context.Background(), config.Issuer)
		if err != nil {
			return "", fmt.Errorf("failed to discover configuration: %w", err)
		}
		authURL = discoveredConfig.AuthorizationEndpoint
	} else {
		return "", fmt.Errorf("no authorization URL available")
	}

	// Parse base URL
	u, err := url.Parse(authURL)
	if err != nil {
		return "", fmt.Errorf("invalid authorization URL: %w", err)
	}

	// Build query parameters
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", config.ClientID)
	q.Set("redirect_uri", s.getRedirectURI(provider))
	q.Set("scope", strings.Join(config.Scopes, " "))
	q.Set("state", state)

	// Add PKCE if supported (simplified)
	// In production, you'd check if the provider supports PKCE (codeVerifier)
	_, codeChallenge, err := s.GenerateCodeChallenge()
	if err == nil {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "plain") // Simplified
		// Store code_verifier associated with state for later use
	}

	u.RawQuery = q.Encode()

	return u.String(), nil
}

// getRedirectURI returns the callback URI for the provider
func (s *oidcService) getRedirectURI(provider *model.IdentityProvider) string {
	return fmt.Sprintf("%s/auth/oidc/callback/%s", s.baseURL, provider.ID.String())
}

// testEndpoint tests if an endpoint is accessible
func (s *oidcService) testEndpoint(endpointURL string) error {
	resp, err := s.httpClient.Get(endpointURL)
	if err != nil {
		return fmt.Errorf("failed to connect to endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return fmt.Errorf("endpoint returned client error: %d", resp.StatusCode)
	}

	return nil
}

// extractUserInfoFromClaims extracts user info from ID token claims
func (s *oidcService) extractUserInfoFromClaims(claims *OIDCClaims) *SSOUserInfo {
	userInfo := &SSOUserInfo{
		ID:         claims.Sub,
		Email:      claims.Email,
		FirstName:  claims.GivenName,
		LastName:   claims.FamilyName,
		Attributes: make(map[string]interface{}),
	}

	// Handle name fallback
	if userInfo.FirstName == "" && userInfo.LastName == "" && claims.Name != "" {
		parts := strings.SplitN(claims.Name, " ", 2)
		if len(parts) >= 1 {
			userInfo.FirstName = parts[0]
		}
		if len(parts) >= 2 {
			userInfo.LastName = parts[1]
		}
	}

	// Add profile picture
	if claims.Picture != "" {
		userInfo.Picture = claims.Picture
	}

	// Store all claims as attributes
	claimsMap := make(map[string]interface{})
	claimsBytes, _ := json.Marshal(claims)
	json.Unmarshal(claimsBytes, &claimsMap)
	userInfo.Attributes = claimsMap

	return userInfo
}

// extractUserInfoFromUserInfoResponse extracts user info from userinfo endpoint response
func (s *oidcService) extractUserInfoFromUserInfoResponse(response map[string]interface{}, provider *model.IdentityProvider) *SSOUserInfo {
	userInfo := &SSOUserInfo{
		Attributes: response,
	}

	// Extract standard claims
	if sub, ok := response["sub"].(string); ok {
		userInfo.ID = sub
	}

	if email, ok := response["email"].(string); ok {
		userInfo.Email = email
	}

	if givenName, ok := response["given_name"].(string); ok {
		userInfo.FirstName = givenName
	} else if firstName, ok := response["first_name"].(string); ok {
		userInfo.FirstName = firstName
	}

	if familyName, ok := response["family_name"].(string); ok {
		userInfo.LastName = familyName
	} else if lastName, ok := response["last_name"].(string); ok {
		userInfo.LastName = lastName
	}

	// Handle name fallback
	if userInfo.FirstName == "" && userInfo.LastName == "" {
		if name, ok := response["name"].(string); ok {
			parts := strings.SplitN(name, " ", 2)
			if len(parts) >= 1 {
				userInfo.FirstName = parts[0]
			}
			if len(parts) >= 2 {
				userInfo.LastName = parts[1]
			}
		}
	}

	// Profile picture
	if picture, ok := response["picture"].(string); ok {
		userInfo.Picture = picture
	} else if avatar, ok := response["avatar_url"].(string); ok {
		userInfo.Picture = avatar
	}

	// Provider-specific handling
	switch strings.ToLower(provider.Name) {
	case "github":
		if login, ok := response["login"].(string); ok && userInfo.ID == "" {
			userInfo.ID = login
		}
		if avatarURL, ok := response["avatar_url"].(string); ok {
			userInfo.Picture = avatarURL
		}
	case "gitlab":
		if username, ok := response["username"].(string); ok && userInfo.ID == "" {
			userInfo.ID = username
		}
	}

	return userInfo
}

// applyAttributeMapping applies custom attribute mapping
func (s *oidcService) applyAttributeMapping(userInfo *SSOUserInfo, mapping map[string]string) {
	for localAttr, oidcAttr := range mapping {
		if value, exists := userInfo.Attributes[oidcAttr]; exists {
			if valueStr, ok := value.(string); ok {
				switch localAttr {
				case "email":
					userInfo.Email = valueStr
				case "first_name":
					userInfo.FirstName = valueStr
				case "last_name":
					userInfo.LastName = valueStr
				case "profile_image_url":
					userInfo.Picture = valueStr
				}
			}
		}
	}
}

// OIDC data structures

// OIDCConfig represents OIDC provider configuration
type OIDCConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Issuer       string   `json:"issuer,omitempty"`
	AuthURL      string   `json:"auth_url,omitempty"`
	TokenURL     string   `json:"token_url,omitempty"`
	UserInfoURL  string   `json:"userinfo_url,omitempty"`
	JWKSURL      string   `json:"jwks_url,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// OIDCConfiguration represents OIDC discovery document
type OIDCConfiguration struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserInfoEndpoint       string   `json:"userinfo_endpoint"`
	JWKSUri                string   `json:"jwks_uri"`
	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
}

// OIDCTokenResponse represents OAuth2/OIDC token response
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OIDCClaims represents standard OIDC ID token claims
type OIDCClaims struct {
	Sub           string `json:"sub"`
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Exp           int64  `json:"exp"`
	Iat           int64  `json:"iat"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Locale        string `json:"locale,omitempty"`
}

// Popular OIDC provider templates
var PopularOIDCProviders = map[string]OIDCConfig{
	"google": {
		Issuer:      "https://accounts.google.com",
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:    "https://oauth2.googleapis.com/token",
		UserInfoURL: "https://www.googleapis.com/oauth2/v2/userinfo",
		JWKSURL:     "https://www.googleapis.com/oauth2/v3/certs",
		Scopes:      []string{"openid", "email", "profile"},
	},
	"microsoft": {
		Issuer:      "https://login.microsoftonline.com/common/v2.0",
		AuthURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL: "https://graph.microsoft.com/v1.0/me",
		JWKSURL:     "https://login.microsoftonline.com/common/discovery/v2.0/keys",
		Scopes:      []string{"openid", "email", "profile"},
	},
	"github": {
		AuthURL:     "https://github.com/login/oauth/authorize",
		TokenURL:    "https://github.com/login/oauth/access_token",
		UserInfoURL: "https://api.github.com/user",
		Scopes:      []string{"user:email"},
	},
	"gitlab": {
		Issuer:      "https://gitlab.com",
		AuthURL:     "https://gitlab.com/oauth/authorize",
		TokenURL:    "https://gitlab.com/oauth/token",
		UserInfoURL: "https://gitlab.com/oauth/userinfo",
		Scopes:      []string{"openid", "email", "profile"},
	},
	"discord": {
		AuthURL:     "https://discord.com/api/oauth2/authorize",
		TokenURL:    "https://discord.com/api/oauth2/token",
		UserInfoURL: "https://discord.com/api/users/@me",
		Scopes:      []string{"identify", "email"},
	},
	"facebook": {
		AuthURL:     "https://www.facebook.com/v18.0/dialog/oauth",
		TokenURL:    "https://graph.facebook.com/v18.0/oauth/access_token",
		UserInfoURL: "https://graph.facebook.com/me?fields=id,name,email,first_name,last_name,picture",
		Scopes:      []string{"email", "public_profile"},
	},
	"twitter": {
		AuthURL:     "https://twitter.com/i/oauth2/authorize",
		TokenURL:    "https://api.twitter.com/2/oauth2/token",
		UserInfoURL: "https://api.twitter.com/2/users/me?user.fields=profile_image_url",
		Scopes:      []string{"tweet.read", "users.read"},
	},
	"linkedin": {
		AuthURL:     "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL:    "https://www.linkedin.com/oauth/v2/accessToken",
		UserInfoURL: "https://api.linkedin.com/v2/people/~:(id,firstName,lastName,emailAddress,profilePicture(displayImage~:playableStreams))",
		Scopes:      []string{"r_liteprofile", "r_emailaddress"},
	},
	"apple": {
		Issuer:   "https://appleid.apple.com",
		AuthURL:  "https://appleid.apple.com/auth/authorize",
		TokenURL: "https://appleid.apple.com/auth/token",
		JWKSURL:  "https://appleid.apple.com/auth/keys",
		Scopes:   []string{"name", "email"},
	},
}

// GetProviderTemplate returns a pre-configured template for popular providers
func GetProviderTemplate(providerName string) (*OIDCConfig, bool) {
	template, exists := PopularOIDCProviders[strings.ToLower(providerName)]
	if !exists {
		return nil, false
	}

	// Return a copy to avoid modification of the template
	configCopy := template
	return &configCopy, true
}
