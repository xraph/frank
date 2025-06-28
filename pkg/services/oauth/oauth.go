package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// OAuthService defines the interface for OAuth2 operations
type OAuthService interface {
	// Authorization Flow
	Authorize(ctx context.Context, req model.AuthorizeRequest) (*model.AuthorizeResponse, error)
	ExchangeCodeForToken(ctx context.Context, req model.TokenRequest) (*model.TokenResponse, error)
	RefreshToken(ctx context.Context, req model.TokenRequest) (*model.TokenResponse, error)
	RevokeToken(ctx context.Context, req model.RevokeTokenRequest) error
	IntrospectToken(ctx context.Context, req model.IntrospectTokenRequest) (*model.IntrospectTokenResponse, error)

	// Client Credentials Flow
	ClientCredentials(ctx context.Context, req model.OAuthClientCredentials) (*model.ClientCredentialsResponse, error)

	// Validation
	ValidateAuthorizationRequest(ctx context.Context, req model.AuthorizeRequest) error
	ValidateTokenRequest(ctx context.Context, req model.TokenRequest) error
	ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*ent.OAuthClient, error)

	// PKCE Support
	ValidatePKCE(codeVerifier, codeChallenge, method string) error
	GenerateCodeChallenge(codeVerifier string) (string, error)

	// Utility
	GetUserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error)
	GetTokenInfo(ctx context.Context, accessToken string) (*ent.OAuthToken, error)
	CleanupExpiredTokens(ctx context.Context) (int, error)
}

// oauthService implements OAuthService
type oauthService struct {
	oauthRepo repository.OAuthRepository
	userRepo  repository.UserRepository
	logger    logging.Logger
}

// NewOAuthService creates a new OAuth service
func NewOAuthService(
	oauthRepo repository.OAuthRepository,
	userRepo repository.UserRepository,
	logger logging.Logger,
) OAuthService {
	return &oauthService{
		oauthRepo: oauthRepo,
		userRepo:  userRepo,
		logger:    logger.Named("oauth"),
	}
}

// Authorize handles OAuth2 authorization requests
func (s *oauthService) Authorize(ctx context.Context, req model.AuthorizeRequest) (*model.AuthorizeResponse, error) {
	s.logger.Info("Processing authorization request",
		logging.String("client_id", req.ClientID),
		logging.String("response_type", req.ResponseType))

	// Validate the authorization request
	if err := s.ValidateAuthorizationRequest(ctx, req); err != nil {
		return nil, err
	}

	// Get client
	client, err := s.oauthRepo.GetClientByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Client not found")
	}

	// Validate redirect URI
	if !s.isValidRedirectURI(client.RedirectUris, req.RedirectURI) {
		return nil, errors.New(errors.CodeBadRequest, "Invalid redirect URI")
	}

	// Parse scopes
	scopes := s.parseScopes(req.Scope)
	if len(scopes) == 0 {
		// Use default scopes if none specified
		defaultScopes, err := s.oauthRepo.GetDefaultScopes(ctx)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get default scopes")
		}
		for _, scope := range defaultScopes {
			scopes = append(scopes, scope.Name)
		}
	}

	// Generate authorization code
	code, err := s.generateSecureToken(32)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to generate authorization code")
	}

	// Create authorization record
	authInput := repository.CreateOAuthAuthorizationInput{
		ClientID:            client.ID,
		Code:                code,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		RedirectURI:         req.RedirectURI,
		ScopeNames:          scopes,
		State:               req.State,
		Nonce:               req.Nonce,
		OrganizationID:      &client.OrganizationID,
		ExpiresAt:           time.Now().Add(10 * time.Minute), // 10 minutes expiry
	}

	// Get user from context (assuming middleware sets this)
	userID, ok := ctx.Value("user_id").(xid.ID)
	if !ok {
		return nil, errors.New(errors.CodeUnauthorized, "User not authenticated")
	}
	authInput.UserID = userID

	if orgID, ok := ctx.Value("organization_id").(xid.ID); ok {
		authInput.OrganizationID = &orgID
	}

	_, err = s.oauthRepo.CreateAuthorization(ctx, authInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create authorization")
	}

	s.logger.Info("Authorization code generated successfully",
		logging.String("client_id", req.ClientID),
		logging.String("user_id", userID.String()))

	return &model.AuthorizeResponse{
		Code:        code,
		State:       req.State,
		RedirectURI: fmt.Sprintf("%s?code=%s&state=%s", req.RedirectURI, code, req.State),
		ExpiresIn:   600, // 10 minutes
	}, nil
}

// ExchangeCodeForToken exchanges authorization code for access token
func (s *oauthService) ExchangeCodeForToken(ctx context.Context, req model.TokenRequest) (*model.TokenResponse, error) {
	s.logger.Info("Exchanging authorization code for token",
		logging.String("client_id", req.ClientID),
		logging.String("grant_type", req.GrantType))

	// Validate token request
	if err := s.ValidateTokenRequest(ctx, req); err != nil {
		return nil, err
	}

	// Get authorization by code
	auth, err := s.oauthRepo.GetAuthorizationByCode(ctx, req.Code)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Invalid authorization code")
	}

	// Check if code is expired
	if time.Now().After(auth.ExpiresAt) {
		return nil, errors.New(errors.CodeBadRequest, "Authorization code expired")
	}

	// Check if code is already used
	if auth.Used {
		return nil, errors.New(errors.CodeBadRequest, "Authorization code already used")
	}

	// Validate client
	client, err := s.ValidateClientCredentials(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	// Validate redirect URI
	if req.RedirectURI != auth.RedirectURI {
		return nil, errors.New(errors.CodeBadRequest, "Redirect URI mismatch")
	}

	// Validate PKCE if required
	if client.RequiresPkce || auth.CodeChallenge != "" {
		if err := s.ValidatePKCE(req.CodeVerifier, auth.CodeChallenge, auth.CodeChallengeMethod); err != nil {
			return nil, err
		}
	}

	// Generate tokens
	accessToken, err := s.generateSecureToken(32)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to generate access token")
	}

	refreshToken, err := s.generateSecureToken(32)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to generate refresh token")
	}

	// Create token record
	tokenInput := repository.CreateOAuthTokenInput{
		AccessToken:    accessToken,
		RefreshToken:   &refreshToken,
		TokenType:      "bearer",
		ClientID:       client.ID,
		UserID:         auth.UserID,
		OrganizationID: &auth.OrganizationID,
		ScopeNames:     auth.ScopeNames,
		ExpiresIn:      client.TokenExpirySeconds,
		ExpiresAt:      time.Now().Add(time.Duration(client.TokenExpirySeconds) * time.Second),
		RefreshTokenExpiresAt: func() *time.Time {
			t := time.Now().Add(time.Duration(client.RefreshTokenExpirySeconds) * time.Second)
			return &t
		}(),
	}

	_, err = s.oauthRepo.CreateToken(ctx, tokenInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create token")
	}

	// Mark authorization as used
	if err := s.oauthRepo.DeleteAuthorizationByCode(ctx, req.Code); err != nil {
		s.logger.Warn("Failed to cleanup authorization code", logging.Error(err))
	}

	s.logger.Info("Token exchange successful",
		logging.String("client_id", req.ClientID),
		logging.String("user_id", auth.UserID.String()))

	return &model.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		ExpiresIn:    client.TokenExpirySeconds,
		RefreshToken: refreshToken,
		Scope:        strings.Join(auth.ScopeNames, " "),
	}, nil
}

// RefreshToken handles refresh token requests
func (s *oauthService) RefreshToken(ctx context.Context, req model.TokenRequest) (*model.TokenResponse, error) {
	s.logger.Info("Refreshing token", logging.String("client_id", req.ClientID))

	// Get token by refresh token
	token, err := s.oauthRepo.GetTokenByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Invalid refresh token")
	}

	// Check if refresh token is expired
	if token.RefreshTokenExpiresAt != nil && time.Now().After(*token.RefreshTokenExpiresAt) {
		return nil, errors.New(errors.CodeBadRequest, "Refresh token expired")
	}

	// Validate client
	client, err := s.ValidateClientCredentials(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	// Check if client matches
	if token.ClientID != client.ID {
		return nil, errors.New(errors.CodeBadRequest, "Client mismatch")
	}

	// Generate new tokens
	newAccessToken, err := s.generateSecureToken(32)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to generate access token")
	}

	newRefreshToken, err := s.generateSecureToken(32)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to generate refresh token")
	}

	// Update token
	updateInput := repository.UpdateOAuthTokenInput{
		AccessToken:  &newAccessToken,
		RefreshToken: &newRefreshToken,
		ExpiresAt: func() *time.Time {
			t := time.Now().Add(time.Duration(client.TokenExpirySeconds) * time.Second)
			return &t
		}(),
		RefreshTokenExpiresAt: func() *time.Time {
			t := time.Now().Add(time.Duration(client.RefreshTokenExpirySeconds) * time.Second)
			return &t
		}(),
	}

	updatedToken, err := s.oauthRepo.UpdateToken(ctx, token.ID, updateInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update token")
	}

	s.logger.Info("Token refreshed successfully",
		logging.String("client_id", req.ClientID),
		logging.String("user_id", token.UserID.String()))

	return &model.TokenResponse{
		AccessToken:  newAccessToken,
		TokenType:    "bearer",
		ExpiresIn:    client.TokenExpirySeconds,
		RefreshToken: newRefreshToken,
		Scope:        strings.Join(updatedToken.ScopeNames, " "),
	}, nil
}

// RevokeToken revokes an access or refresh token
func (s *oauthService) RevokeToken(ctx context.Context, req model.RevokeTokenRequest) error {
	s.logger.Info("Revoking token", logging.String("client_id", req.ClientID))

	// Validate client
	_, err := s.ValidateClientCredentials(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return err
	}

	// Try to revoke as access token first
	if err := s.oauthRepo.RevokeToken(ctx, req.Token); err == nil {
		s.logger.Info("Access token revoked", logging.String("client_id", req.ClientID))
		return nil
	}

	// Try to revoke as refresh token
	if err := s.oauthRepo.RevokeTokenByRefreshToken(ctx, req.Token); err == nil {
		s.logger.Info("Refresh token revoked", logging.String("client_id", req.ClientID))
		return nil
	}

	// Token not found - return success per OAuth2 spec
	s.logger.Info("Token not found for revocation", logging.String("client_id", req.ClientID))
	return nil
}

// IntrospectToken provides token introspection
func (s *oauthService) IntrospectToken(ctx context.Context, req model.IntrospectTokenRequest) (*model.IntrospectTokenResponse, error) {
	s.logger.Info("Introspecting token", logging.String("client_id", req.ClientID))

	// Validate client
	_, err := s.ValidateClientCredentials(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	// Get token
	token, err := s.oauthRepo.ValidateAccessToken(ctx, req.Token)
	if err != nil {
		// Return inactive token response
		return &model.IntrospectTokenResponse{Active: false}, nil
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		return &model.IntrospectTokenResponse{Active: false}, nil
	}

	// Get user for username
	user, err := s.userRepo.GetByID(ctx, token.UserID)
	if err != nil {
		s.logger.Warn("Failed to get user for token introspection", logging.Error(err))
	}

	response := &model.IntrospectTokenResponse{
		Active:    true,
		Scope:     strings.Join(token.ScopeNames, " "),
		ClientID:  req.ClientID,
		TokenType: token.TokenType,
		ExpiresAt: token.ExpiresAt.Unix(),
		IssuedAt:  token.CreatedAt.Unix(),
		Subject:   token.UserID.String(),
	}

	if user != nil {
		response.Username = user.Email
	}

	return response, nil
}

// ClientCredentials handles client credentials flow
func (s *oauthService) ClientCredentials(ctx context.Context, req model.OAuthClientCredentials) (*model.ClientCredentialsResponse, error) {
	s.logger.Info("Processing client credentials request", logging.String("client_id", req.ClientID))

	// Validate client
	client, err := s.ValidateClientCredentials(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	// Parse scopes
	scopes := s.parseScopes(req.Scope)

	// Generate access token
	accessToken, err := s.generateSecureToken(32)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to generate access token")
	}

	// Create token record (no user for client credentials)
	tokenInput := repository.CreateOAuthTokenInput{
		AccessToken:    accessToken,
		TokenType:      "bearer",
		ClientID:       client.ID,
		OrganizationID: &client.OrganizationID,
		ScopeNames:     scopes,
		ExpiresIn:      client.TokenExpirySeconds,
		ExpiresAt:      time.Now().Add(time.Duration(client.TokenExpirySeconds) * time.Second),
	}

	_, err = s.oauthRepo.CreateToken(ctx, tokenInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create token")
	}

	s.logger.Info("Client credentials token created", logging.String("client_id", req.ClientID))

	return &model.ClientCredentialsResponse{
		AccessToken: accessToken,
		TokenType:   "bearer",
		ExpiresIn:   client.TokenExpirySeconds,
		Scope:       strings.Join(scopes, " "),
	}, nil
}

// ValidateAuthorizationRequest validates OAuth2 authorization request
func (s *oauthService) ValidateAuthorizationRequest(ctx context.Context, req model.AuthorizeRequest) error {
	if req.ResponseType != "code" {
		return errors.New(errors.CodeBadRequest, "Unsupported response type")
	}

	if req.ClientID == "" {
		return errors.New(errors.CodeBadRequest, "Client ID is required")
	}

	if req.RedirectURI == "" {
		return errors.New(errors.CodeBadRequest, "Redirect URI is required")
	}

	return nil
}

// ValidateTokenRequest validates OAuth2 token request
func (s *oauthService) ValidateTokenRequest(ctx context.Context, req model.TokenRequest) error {
	switch req.GrantType {
	case "authorization_code":
		if req.Code == "" {
			return errors.New(errors.CodeBadRequest, "Authorization code is required")
		}
		if req.RedirectURI == "" {
			return errors.New(errors.CodeBadRequest, "Redirect URI is required")
		}
	case "refresh_token":
		if req.RefreshToken == "" {
			return errors.New(errors.CodeBadRequest, "Refresh token is required")
		}
	case "client_credentials":
		// No additional validation needed
	default:
		return errors.New(errors.CodeBadRequest, "Unsupported grant type")
	}

	if req.ClientID == "" {
		return errors.New(errors.CodeBadRequest, "Client ID is required")
	}

	return nil
}

// ValidateClientCredentials validates client credentials
func (s *oauthService) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*ent.OAuthClient, error) {
	client, err := s.oauthRepo.GetClientByClientID(ctx, clientID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "Invalid client")
	}

	if !client.Active {
		return nil, errors.New(errors.CodeUnauthorized, "Client is inactive")
	}

	// Public clients don't require secret
	if client.Public {
		return client, nil
	}

	// Validate client secret using secure comparison
	if !s.secureCompare(clientSecret, client.ClientSecret) {
		return nil, errors.New(errors.CodeUnauthorized, "Invalid client credentials")
	}

	return client, nil
}

// ValidatePKCE validates PKCE code challenge
func (s *oauthService) ValidatePKCE(codeVerifier, codeChallenge, method string) error {
	if codeChallenge == "" {
		return errors.New(errors.CodeBadRequest, "Code challenge is required")
	}

	if codeVerifier == "" {
		return errors.New(errors.CodeBadRequest, "Code verifier is required")
	}

	switch method {
	case "plain":
		if codeVerifier != codeChallenge {
			return errors.New(errors.CodeBadRequest, "PKCE validation failed")
		}
	case "S256", "":
		expectedChallenge, err := s.GenerateCodeChallenge(codeVerifier)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternalServer, "Failed to generate code challenge")
		}
		if expectedChallenge != codeChallenge {
			return errors.New(errors.CodeBadRequest, "PKCE validation failed")
		}
	default:
		return errors.New(errors.CodeBadRequest, "Unsupported code challenge method")
	}

	return nil
}

// GenerateCodeChallenge generates PKCE code challenge
func (s *oauthService) GenerateCodeChallenge(codeVerifier string) (string, error) {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// GetUserInfo returns user information for a valid access token
func (s *oauthService) GetUserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	token, err := s.GetTokenInfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.GetByID(ctx, token.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "User not found")
	}

	userInfo := map[string]interface{}{
		"sub":   user.ID.String(),
		"email": user.Email,
	}

	if user.FirstName != "" {
		userInfo["given_name"] = user.FirstName
	}
	if user.LastName != "" {
		userInfo["family_name"] = user.LastName
	}
	if user.FirstName != "" || user.LastName != "" {
		userInfo["name"] = strings.TrimSpace(user.FirstName + " " + user.LastName)
	}

	return userInfo, nil
}

// GetTokenInfo returns token information
func (s *oauthService) GetTokenInfo(ctx context.Context, accessToken string) (*ent.OAuthToken, error) {
	token, err := s.oauthRepo.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "Invalid access token")
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, errors.New(errors.CodeUnauthorized, "Token expired")
	}

	if token.Revoked {
		return nil, errors.New(errors.CodeUnauthorized, "Token revoked")
	}

	return token, nil
}

// CleanupExpiredTokens removes expired tokens
func (s *oauthService) CleanupExpiredTokens(ctx context.Context) (int, error) {
	count, err := s.oauthRepo.CleanupExpiredTokens(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to cleanup expired tokens")
	}

	if count > 0 {
		s.logger.Info("Cleaned up expired tokens", logging.Int("count", count))
	}

	return count, nil
}

// Helper methods

func (s *oauthService) generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (s *oauthService) parseScopes(scopeStr string) []string {
	if scopeStr == "" {
		return []string{}
	}
	return strings.Fields(scopeStr)
}

func (s *oauthService) isValidRedirectURI(allowedURIs []string, redirectURI string) bool {
	for _, uri := range allowedURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

func (s *oauthService) secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
