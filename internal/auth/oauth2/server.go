package oauth2

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/logging"
)

// Server represents the OAuth2 authorization server that handles token issuance and validation
type Server struct {
	db      *ent.Client
	config  *config.Config
	logger  logging.Logger
	storage Storage
	clients map[string]*Client
}

// ServerOption represents optional parameters for the OAuth2 server
type ServerOption func(*Server)

// WithStorage sets a custom storage implementation
func WithStorage(storage Storage) ServerOption {
	return func(s *Server) {
		s.storage = storage
	}
}

// NewServer creates a new OAuth2 server
func NewServer(db *ent.Client, cfg *config.Config, logger logging.Logger, options ...ServerOption) *Server {
	s := &Server{
		db:      db,
		config:  cfg,
		logger:  logger,
		clients: make(map[string]*Client),
	}

	// Apply options
	for _, option := range options {
		option(s)
	}

	// If no storage is provided, use the default EntStorage
	if s.storage == nil {
		s.storage = NewEntStorage(db, logger)
	}

	return s
}

// ValidateAuthorizationRequest validates an authorization request
func (s *Server) ValidateAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	// Extract and validate required parameters
	query := r.URL.Query()
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	responseType := query.Get("response_type")
	scope := query.Get("scope")
	state := query.Get("state")

	// Optional PKCE parameters
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")

	// Validate required parameters
	if clientID == "" {
		return nil, errors.New("missing client_id parameter")
	}
	if redirectURI == "" {
		return nil, errors.New("missing redirect_uri parameter")
	}
	if responseType == "" {
		return nil, errors.New("missing response_type parameter")
	}

	// Only support 'code' response type for authorization code flow
	if responseType != "code" {
		return nil, fmt.Errorf("unsupported response_type: %s", responseType)
	}

	// Validate client and redirect URI
	client, err := s.storage.GetClient(r.Context(), clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	// Check if redirect URI is valid for this client
	validRedirect := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		return nil, errors.New("invalid redirect_uri")
	}

	// Check if PKCE is required for this client
	if client.RequiresPKCE && codeChallenge == "" {
		return nil, errors.New("code_challenge is required for this client")
	}

	// Validate code challenge method if provided
	if codeChallenge != "" && codeChallengeMethod != "" {
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			return nil, errors.New("invalid code_challenge_method, must be 'S256' or 'plain'")
		}
	} else if codeChallenge != "" {
		// Default to S256 if code challenge is provided but method is not
		codeChallengeMethod = "S256"
	}

	// Parse scopes
	var scopes []string
	if scope != "" {
		scopes = strings.Split(scope, " ")
	}

	// Validate scopes
	if len(scopes) > 0 {
		validScopes, err := s.storage.ValidateScopes(r.Context(), clientID, scopes)
		if err != nil {
			return nil, fmt.Errorf("error validating scopes: %w", err)
		}
		if !validScopes {
			return nil, errors.New("invalid scopes requested")
		}
	} else {
		// Use default scopes if none provided
		defaultScopes, err := s.storage.GetDefaultScopes(r.Context())
		if err != nil {
			return nil, fmt.Errorf("error getting default scopes: %w", err)
		}
		scopes = defaultScopes
	}

	// Create and return the authorization request
	authReq := &AuthorizationRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scopes:              scopes,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Client:              client,
	}

	return authReq, nil
}

// CreateAuthorizationCode creates an authorization code for a user
func (s *Server) CreateAuthorizationCode(ctx context.Context, authReq *AuthorizationRequest, userID string, organizationID string) (string, error) {
	// Generate a secure random code
	code, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization code: %w", err)
	}

	// Calculate expiration time
	expiresAt := time.Now().Add(time.Duration(authReq.Client.AuthCodeExpirySeconds) * time.Second)

	// Store the authorization code
	err = s.storage.StoreAuthorizationCode(ctx, &AuthorizationCode{
		Code:                code,
		ClientID:            authReq.ClientID,
		RedirectURI:         authReq.RedirectURI,
		ExpiresAt:           expiresAt,
		Scopes:              authReq.Scopes,
		UserID:              userID,
		OrganizationID:      organizationID,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
		State:               authReq.State,
	})

	if err != nil {
		return "", fmt.Errorf("failed to store authorization code: %w", err)
	}

	return code, nil
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens
func (s *Server) ExchangeAuthorizationCode(ctx context.Context, code, clientID, clientSecret, redirectURI, codeVerifier string) (*TokenResponse, error) {
	// Validate the client credentials
	client, err := s.storage.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	// For confidential clients, validate client secret
	if !client.Public && client.ClientSecret != clientSecret {
		return nil, errors.New("invalid client credentials")
	}

	// Retrieve the authorization code
	authCode, err := s.storage.GetAuthorizationCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization code: %w", err)
	}

	// Check if the code has expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil, errors.New("authorization code has expired")
	}

	// Validate the code belongs to the right client
	if authCode.ClientID != clientID {
		return nil, errors.New("authorization code was not issued to this client")
	}

	// Validate the redirect URI
	if authCode.RedirectURI != redirectURI {
		return nil, errors.New("redirect URI does not match the one used during authorization")
	}

	// Validate PKCE code verifier if code challenge exists
	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, errors.New("code_verifier is required")
		}

		var calculatedChallenge string
		if authCode.CodeChallengeMethod == "S256" {
			// Implement S256 transformation: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
			hash := crypto.SHA256Hash(codeVerifier)
			calculatedChallenge = base64.RawURLEncoding.EncodeToString(hash)
		} else {
			// Plain transformation
			calculatedChallenge = codeVerifier
		}

		if calculatedChallenge != authCode.CodeChallenge {
			return nil, errors.New("invalid code_verifier")
		}
	}

	// Mark the authorization code as used
	err = s.storage.MarkAuthorizationCodeAsUsed(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to mark authorization code as used: %w", err)
	}

	// Generate tokens
	tokens, err := s.generateTokens(ctx, authCode.ClientID, authCode.UserID, authCode.OrganizationID, authCode.Scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return tokens, nil
}

// RefreshAccessToken refreshes an access token using a refresh token
func (s *Server) RefreshAccessToken(ctx context.Context, refreshToken, clientID, clientSecret string) (*TokenResponse, error) {
	// Validate the client credentials
	client, err := s.storage.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	// For confidential clients, validate client secret
	if !client.Public && client.ClientSecret != clientSecret {
		return nil, errors.New("invalid client credentials")
	}

	// Get token information for the refresh token
	tokenInfo, err := s.storage.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Validate the token belongs to the right client
	if tokenInfo.ClientID != clientID {
		return nil, errors.New("refresh token was not issued to this client")
	}

	// Check if the token has expired
	if time.Now().After(tokenInfo.ExpiresAt) {
		return nil, errors.New("refresh token has expired")
	}

	// Check if the token has been revoked
	if tokenInfo.Revoked {
		return nil, errors.New("refresh token has been revoked")
	}

	// Revoke the current refresh token
	err = s.storage.RevokeRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
	}

	// Generate new tokens
	newAccessToken, err := s.generateAccessToken(ctx, tokenInfo.ClientID, tokenInfo.UserID, tokenInfo.OrganizationID, tokenInfo.Scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new access token: %w", err)
	}

	return newAccessToken, nil
}

// ValidateAccessToken validates an access token and returns its claims
func (s *Server) ValidateAccessToken(ctx context.Context, accessToken string) (*TokenInfo, error) {
	tokenInfo, err := s.storage.GetAccessToken(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	// Check if the token has expired
	if time.Now().After(tokenInfo.ExpiresAt) {
		return nil, errors.New("access token has expired")
	}

	// Check if the token has been revoked
	if tokenInfo.Revoked {
		return nil, errors.New("access token has been revoked")
	}

	return tokenInfo, nil
}

// RevokeToken revokes a token (either access or refresh)
func (s *Server) RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
	// Validate the client credentials
	client, err := s.storage.GetClient(ctx, clientID)
	if err != nil {
		return fmt.Errorf("invalid client: %w", err)
	}

	// For confidential clients, validate client secret
	if !client.Public && client.ClientSecret != clientSecret {
		return errors.New("invalid client credentials")
	}

	// Determine token type and revoke accordingly
	switch tokenTypeHint {
	case "access_token":
		return s.storage.RevokeAccessToken(ctx, token)
	case "refresh_token":
		return s.storage.RevokeRefreshToken(ctx, token)
	default:
		// If token type is not specified, try both
		err1 := s.storage.RevokeAccessToken(ctx, token)
		err2 := s.storage.RevokeRefreshToken(ctx, token)

		// If both failed, return an error
		if err1 != nil && err2 != nil {
			return errors.New("token not found or already revoked")
		}

		return nil
	}
}

// generateTokens generates new access and refresh tokens
func (s *Server) generateTokens(ctx context.Context, clientID, userID, organizationID string, scopes []string) (*TokenResponse, error) {
	// Get client to determine token lifetimes
	client, err := s.storage.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	// Generate access token
	accessToken, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token if applicable
	var refreshToken string
	var refreshTokenExpiresAt time.Time

	// Only generate refresh token if the client has the refresh_token grant type
	hasRefreshGrant := false
	for _, grant := range client.AllowedGrantTypes {
		if grant == "refresh_token" {
			hasRefreshGrant = true
			break
		}
	}

	if hasRefreshGrant {
		refreshToken, err = crypto.GenerateRandomString(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate refresh token: %w", err)
		}
		refreshTokenExpiresAt = time.Now().Add(time.Duration(client.RefreshTokenExpirySeconds) * time.Second)
	}

	// Calculate token expiration
	expiresIn := client.TokenExpirySeconds
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	// Store access token
	accessTokenInfo := &TokenInfo{
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		ClientID:       clientID,
		UserID:         userID,
		OrganizationID: organizationID,
		Scopes:         scopes,
		ExpiresIn:      expiresIn,
		ExpiresAt:      expiresAt,
		TokenType:      "bearer",
		CreatedAt:      time.Now(),
	}

	err = s.storage.StoreAccessToken(ctx, accessTokenInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	// If refresh token was generated, store it
	if refreshToken != "" {
		refreshTokenInfo := &TokenInfo{
			AccessToken:    "",
			RefreshToken:   refreshToken,
			ClientID:       clientID,
			UserID:         userID,
			OrganizationID: organizationID,
			Scopes:         scopes,
			ExpiresAt:      refreshTokenExpiresAt,
			TokenType:      "refresh",
			CreatedAt:      time.Now(),
		}

		err = s.storage.StoreRefreshToken(ctx, refreshTokenInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to store refresh token: %w", err)
		}
	}

	// Create token response
	response := &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        strings.Join(scopes, " "),
	}

	return response, nil
}

// generateAccessToken generates a new access token for an existing refresh token scenario
func (s *Server) generateAccessToken(ctx context.Context, clientID, userID, organizationID string, scopes []string) (*TokenResponse, error) {
	// Get client to determine token lifetime
	client, err := s.storage.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	// Generate access token
	accessToken, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate new refresh token
	refreshToken, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Calculate token expirations
	expiresIn := client.TokenExpirySeconds
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)
	refreshExpiresAt := time.Now().Add(time.Duration(client.RefreshTokenExpirySeconds) * time.Second)

	// Store new access token
	accessTokenInfo := &TokenInfo{
		AccessToken:    accessToken,
		RefreshToken:   "",
		ClientID:       clientID,
		UserID:         userID,
		OrganizationID: organizationID,
		Scopes:         scopes,
		ExpiresIn:      expiresIn,
		ExpiresAt:      expiresAt,
		TokenType:      "bearer",
		CreatedAt:      time.Now(),
	}

	err = s.storage.StoreAccessToken(ctx, accessTokenInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	// Store new refresh token
	refreshTokenInfo := &TokenInfo{
		AccessToken:    "",
		RefreshToken:   refreshToken,
		ClientID:       clientID,
		UserID:         userID,
		OrganizationID: organizationID,
		Scopes:         scopes,
		ExpiresAt:      refreshExpiresAt,
		TokenType:      "refresh",
		CreatedAt:      time.Now(),
	}

	err = s.storage.StoreRefreshToken(ctx, refreshTokenInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Create token response
	response := &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        strings.Join(scopes, " "),
	}

	return response, nil
}

// HandleClientCredentials handles the client credentials grant type
func (s *Server) HandleClientCredentials(ctx context.Context, clientID, clientSecret string, requestedScopes []string) (*TokenResponse, error) {
	// Validate client credentials
	client, err := s.storage.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	// Client Credentials grant requires a secret
	if client.ClientSecret != clientSecret {
		return nil, errors.New("invalid client credentials")
	}

	// Check if client credentials grant is allowed for this client
	clientCredentialsAllowed := false
	for _, grant := range client.AllowedGrantTypes {
		if grant == "client_credentials" {
			clientCredentialsAllowed = true
			break
		}
	}

	if !clientCredentialsAllowed {
		return nil, errors.New("client_credentials grant type not allowed for this client")
	}

	// Validate scopes
	if len(requestedScopes) > 0 {
		validScopes, err := s.storage.ValidateScopes(ctx, clientID, requestedScopes)
		if err != nil {
			return nil, fmt.Errorf("error validating scopes: %w", err)
		}
		if !validScopes {
			return nil, errors.New("invalid scopes requested")
		}
	} else {
		// Use default scopes if none provided
		defaultScopes, err := s.storage.GetDefaultScopes(ctx)
		if err != nil {
			return nil, fmt.Errorf("error getting default scopes: %w", err)
		}
		requestedScopes = defaultScopes
	}

	// Generate access token (no refresh token for client credentials)
	accessToken, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Calculate token expiration
	expiresIn := client.TokenExpirySeconds
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	// For client credentials, the token is associated with the client but not with a user
	tokenInfo := &TokenInfo{
		AccessToken:    accessToken,
		RefreshToken:   "", // No refresh token for client credentials
		ClientID:       clientID,
		UserID:         "", // No user for client credentials
		OrganizationID: client.OrganizationID,
		Scopes:         requestedScopes,
		ExpiresIn:      expiresIn,
		ExpiresAt:      expiresAt,
		TokenType:      "bearer",
		CreatedAt:      time.Now(),
	}

	// Store the access token
	err = s.storage.StoreAccessToken(ctx, tokenInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	// Create token response
	response := &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       strings.Join(requestedScopes, " "),
	}

	return response, nil
}
