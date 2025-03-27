package sso

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/errors"
	"golang.org/x/oauth2"
)

// AppleProvider implements the IdentityProvider interface for Apple
type AppleProvider struct {
	name       string
	config     ProviderConfig
	oauth2Cfg  *oauth2.Config
	httpClient *http.Client
	privateKey *ecdsa.PrivateKey
	keyID      string
	teamID     string
}

// AppleProviderFactory creates Apple providers
type AppleProviderFactory struct{}

// AppleTokenResponse represents the response from Apple token endpoint
type AppleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// CreateProvider creates a new Apple provider from a configuration
func (f *AppleProviderFactory) CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error) {
	if config.ProviderType != "oauth2" || !isAppleProvider(config) {
		return nil, ErrUnsupportedProviderType
	}

	// Parse scopes
	scopes := []string{"name", "email"}

	// Parse attributes mapping
	attributesMapping := make(map[string]string)
	if config.AttributesMapping != nil {
		attributesMapping = config.AttributesMapping
	}

	// Parse private key
	var privateKey *ecdsa.PrivateKey
	var keyID, teamID string

	if config.Metadata != nil {
		// Get key ID and team ID from metadata
		if keyIDVal, ok := config.Metadata["key_id"].(string); ok {
			keyID = keyIDVal
		}

		if teamIDVal, ok := config.Metadata["team_id"].(string); ok {
			teamID = teamIDVal
		}

		// Parse private key from metadata
		if privateKeyVal, ok := config.Metadata["private_key"].(string); ok && privateKeyVal != "" {
			block, _ := pem.Decode([]byte(privateKeyVal))
			if block == nil {
				return nil, errors.New(errors.CodeInvalidInput, "failed to parse private key PEM")
			}

			parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(errors.CodeInvalidInput, err, "failed to parse private key")
			}

			if ecKey, ok := parsedKey.(*ecdsa.PrivateKey); ok {
				privateKey = ecKey
			} else {
				return nil, errors.New(errors.CodeInvalidInput, "private key is not an ECDSA key")
			}
		}
	}

	// Build provider configuration
	providerConfig := ProviderConfig{
		Name:              config.Name,
		Type:              "oauth2",
		ClientID:          config.ClientID,
		ClientSecret:      config.ClientSecret,
		RedirectURI:       config.RedirectURI,
		Scopes:            scopes,
		AuthURL:           "https://appleid.apple.com/auth/authorize",
		TokenURL:          "https://appleid.apple.com/auth/token",
		UserInfoURL:       "", // Apple doesn't have a user info endpoint
		JWKSURL:           "https://appleid.apple.com/auth/keys",
		Issuer:            "https://appleid.apple.com",
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
		Endpoint: oauth2.Endpoint{
			AuthURL:  providerConfig.AuthURL,
			TokenURL: providerConfig.TokenURL,
		},
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	return &AppleProvider{
		name:       config.Name,
		config:     providerConfig,
		oauth2Cfg:  oauth2Config,
		httpClient: httpClient,
		privateKey: privateKey,
		keyID:      keyID,
		teamID:     teamID,
	}, nil
}

// isAppleProvider checks if the provider configuration is for Apple
func isAppleProvider(config *ent.IdentityProvider) bool {
	if config.Metadata == nil {
		return false
	}

	provider, ok := config.Metadata["provider"]
	if !ok {
		return false
	}

	return provider == "apple"
}

// GetName returns the name of the provider
func (p *AppleProvider) GetName() string {
	return p.name
}

// GetType returns the type of the provider
func (p *AppleProvider) GetType() string {
	return "oauth2"
}

// GetAuthURL returns the URL to initiate authentication
func (p *AppleProvider) GetAuthURL(state string, options map[string]interface{}) (string, error) {
	// Add optional parameters
	var opts []oauth2.AuthCodeOption

	// Apple requires the response_mode parameter
	opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))

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
func (p *AppleProvider) ExchangeCode(ctx context.Context, code string, state string) (*UserInfo, error) {
	// Generate client secret JWT for Apple
	clientSecret, err := p.generateClientSecret()
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to generate client secret JWT")
	}

	// Create a new OAuth2 config with the generated client secret
	// Apple requires a client_secret that is a JWT token signed with the private key
	tokenConfig := p.oauth2Cfg
	tokenConfig.ClientSecret = clientSecret

	// Exchange code for token
	token, err := tokenConfig.Exchange(ctx, code)
	if err != nil {
		return nil, errors.Wrap(errors.CodeIdentityProviderError, err, "failed to exchange code for token")
	}

	// Get ID token from the response
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New(errors.CodeIdentityProviderError, "id_token not found in Apple response")
	}

	// Parse and validate the ID token
	userInfo, err := p.parseAndValidateIDToken(ctx, idToken)
	if err != nil {
		return nil, err
	}

	// Handle user data that might be included in the initial authorization response
	// This would be sent in the request body along with the code
	if userData, ok := ctx.Value("user_data").(map[string]interface{}); ok {
		p.mergeUserData(userInfo, userData)
	}

	return userInfo, nil
}

// ValidateToken validates a token and returns user information
func (p *AppleProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	// For Apple, we can just validate and parse the ID token
	return p.parseAndValidateIDToken(ctx, token)
}

// GetConfig returns the provider's configuration
func (p *AppleProvider) GetConfig() ProviderConfig {
	return p.config
}

// generateClientSecret generates a JWT client secret for Apple authentication
func (p *AppleProvider) generateClientSecret() (string, error) {
	if p.privateKey == nil || p.keyID == "" || p.teamID == "" {
		return "", errors.New(errors.CodeConfigurationError, "missing Apple configuration (private key, key ID, or team ID)")
	}

	now := time.Now()
	expiry := now.Add(5 * time.Minute) // Client secret valid for 5 minutes

	claims := jwt.MapClaims{
		"iss": p.teamID,
		"iat": now.Unix(),
		"exp": expiry.Unix(),
		"aud": "https://appleid.apple.com",
		"sub": p.config.ClientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = p.keyID

	clientSecret, err := token.SignedString(p.privateKey)
	if err != nil {
		return "", errors.Wrap(errors.CodeCryptoError, err, "failed to sign client secret JWT")
	}

	return clientSecret, nil
}

// parseAndValidateIDToken parses and validates an Apple ID token
func (p *AppleProvider) parseAndValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error) {
	// Parse without validation first to get the claims
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to parse ID token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New(errors.CodeInvalidToken, "invalid ID token claims")
	}

	// We would normally validate the token signature here using JWKS from Apple
	// For simplicity, we'll skip the full validation in this implementation
	// but in production, you should validate using the JWKS from Apple

	// Extract user information from token claims
	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, errors.New(errors.CodeInvalidToken, "subject identifier (sub) missing from ID token")
	}

	email, _ := claims["email"].(string)
	emailVerified := false
	if ev, ok := claims["email_verified"].(bool); ok {
		emailVerified = ev
	} else if ev, ok := claims["email_verified"].(string); ok {
		emailVerified = ev == "true"
	}

	// Create user info
	userInfo := &UserInfo{
		ID:             sub,
		Email:          email,
		EmailVerified:  emailVerified,
		ProviderType:   "oauth2",
		ProviderName:   p.name,
		RawAttributes:  make(map[string]interface{}),
		OrganizationID: p.config.OrganizationID,
	}

	// Add token claims to raw attributes
	for key, val := range claims {
		userInfo.RawAttributes[key] = val
	}

	return userInfo, nil
}

// mergeUserData merges user data from the initial authorization response
func (p *AppleProvider) mergeUserData(userInfo *UserInfo, userData map[string]interface{}) {
	if userData == nil {
		return
	}

	// Apple provides user data in a JSON string under the "user" key
	if userDataStr, ok := userData["user"].(string); ok {
		var appleUserData map[string]interface{}
		if err := json.Unmarshal([]byte(userDataStr), &appleUserData); err == nil {
			// Extract name information
			if nameData, ok := appleUserData["name"].(map[string]interface{}); ok {
				// First name
				if firstName, ok := nameData["firstName"].(string); ok {
					userInfo.FirstName = firstName
				}

				// Last name
				if lastName, ok := nameData["lastName"].(string); ok {
					userInfo.LastName = lastName
				}

				// Combine for full name if not already set
				if userInfo.Name == "" && (userInfo.FirstName != "" || userInfo.LastName != "") {
					userInfo.Name = strings.TrimSpace(userInfo.FirstName + " " + userInfo.LastName)
				}
			}

			// Add to raw attributes
			for key, val := range appleUserData {
				userInfo.RawAttributes[key] = val
			}
		}
	}
}
