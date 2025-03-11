package oauth2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/oauthauthorization"
	"github.com/juicycleff/frank/ent/oauthclient"
	"github.com/juicycleff/frank/ent/oauthscope"
	"github.com/juicycleff/frank/ent/oauthtoken"
	"github.com/juicycleff/frank/pkg/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Storage defines the interface for OAuth2 storage
type Storage interface {
	// Client operations
	GetClient(ctx context.Context, clientID string) (*ClientConfig, error)

	// Authorization code operations
	StoreAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
	MarkAuthorizationCodeAsUsed(ctx context.Context, code string) error

	// Token operations
	StoreAccessToken(ctx context.Context, token *TokenInfo) error
	GetAccessToken(ctx context.Context, token string) (*TokenInfo, error)
	RevokeAccessToken(ctx context.Context, token string) error

	StoreRefreshToken(ctx context.Context, token *TokenInfo) error
	GetRefreshToken(ctx context.Context, token string) (*TokenInfo, error)
	RevokeRefreshToken(ctx context.Context, token string) error

	// Scope operations
	ValidateScopes(ctx context.Context, clientID string, scopes []string) (bool, error)
	GetDefaultScopes(ctx context.Context) ([]string, error)
}

// EntStorage implements the Storage interface using Ent
type EntStorage struct {
	db     *ent.Client
	logger logging.Logger
}

// NewEntStorage creates a new Ent-based OAuth2 storage
func NewEntStorage(db *ent.Client, logger logging.Logger) *EntStorage {
	return &EntStorage{
		db:     db,
		logger: logger,
	}
}

// GetClient retrieves a client by ID
func (s *EntStorage) GetClient(ctx context.Context, clientID string) (*ClientConfig, error) {
	client, err := s.db.OAuthClient.
		Query().
		Where(oauthclient.ClientID(clientID)).
		Where(oauthclient.Active(true)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("client not found or inactive")
		}
		return nil, fmt.Errorf("error fetching client: %w", err)
	}

	// Convert to our Client model
	result := &ClientConfig{
		ClientID:                  client.ClientID,
		ClientSecret:              client.ClientSecret,
		RedirectURIs:              client.RedirectUris,
		Name:                      client.ClientName,
		Description:               client.ClientDescription,
		OrganizationID:            client.OrganizationID,
		Public:                    client.Public,
		Active:                    client.Active,
		AllowedGrantTypes:         client.AllowedGrantTypes,
		TokenExpirySeconds:        client.TokenExpirySeconds,
		RefreshTokenExpirySeconds: client.RefreshTokenExpirySeconds,
		AuthCodeExpirySeconds:     client.AuthCodeExpirySeconds,
		RequiresPKCE:              client.RequiresPkce,
		RequiresConsent:           client.RequiresConsent,
	}

	// Load allowed scopes
	scopes, err := client.QueryScopes().All(ctx)
	if err != nil {
		s.logger.Warn("Error loading client scopes, using empty scope list", zap.Field{Key: "error", Type: zapcore.StringType, String: fmt.Sprint(err)})
	} else {
		result.AllowedScopes = make([]string, len(scopes))
		for i, scope := range scopes {
			result.AllowedScopes[i] = scope.Name
		}
	}

	return result, nil
}

// StoreAuthorizationCode stores an authorization code
func (s *EntStorage) StoreAuthorizationCode(ctx context.Context, code *AuthorizationCode) error {
	// First find the client to get its ID
	client, err := s.db.OAuthClient.
		Query().
		Where(oauthclient.ClientID(code.ClientID)).
		First(ctx)

	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}

	// Find the user
	user, err := s.db.User.Get(ctx, code.UserID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Find the scopes
	scopes, err := s.db.OAuthScope.
		Query().
		Where(oauthscope.NameIn(code.Scopes...)).
		All(ctx)

	if err != nil {
		return fmt.Errorf("error fetching scopes: %w", err)
	}

	// Create the authorization
	auth, err := s.db.OAuthAuthorization.
		Create().
		SetClientID(client.ID).
		SetUserID(user.ID).
		SetCode(code.Code).
		SetRedirectURI(code.RedirectURI).
		SetScopeNames(code.Scopes).
		SetExpiresAt(code.ExpiresAt).
		SetState(code.State).
		SetUsed(false).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("error creating authorization code: %w", err)
	}

	// Set the code challenge if present
	if code.CodeChallenge != "" {
		_, err = s.db.OAuthAuthorization.
			UpdateOne(auth).
			SetCodeChallenge(code.CodeChallenge).
			SetCodeChallengeMethod(code.CodeChallengeMethod).
			Save(ctx)

		if err != nil {
			return fmt.Errorf("error updating code challenge: %w", err)
		}
	}

	// Set organization if present
	if code.OrganizationID != "" {
		_, err = s.db.OAuthAuthorization.
			UpdateOne(auth).
			SetOrganizationID(code.OrganizationID).
			Save(ctx)

		if err != nil {
			return fmt.Errorf("error updating organization: %w", err)
		}
	}

	// Add scopes to the authorization
	if len(scopes) > 0 {
		_, err = auth.Update().
			AddScopes(scopes...).
			Save(ctx)

		if err != nil {
			return fmt.Errorf("error adding scopes to authorization: %w", err)
		}
	}

	return nil
}

// ValidateScopes checks if the requested scopes are valid for the given client
func (s *EntStorage) ValidateScopes(ctx context.Context, clientID string, scopes []string) (bool, error) {
	// Get the client first
	client, err := s.db.OAuthClient.
		Query().
		Where(oauthclient.ClientID(clientID)).
		Where(oauthclient.Active(true)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return false, errors.New("client not found or inactive")
		}
		return false, fmt.Errorf("error fetching client: %w", err)
	}

	// Get all scopes associated with the client
	clientScopes, err := client.QueryScopes().All(ctx)
	if err != nil {
		return false, fmt.Errorf("error fetching client scopes: %w", err)
	}

	// If client has no specific scopes, check against all public scopes
	if len(clientScopes) == 0 {
		publicScopes, err := s.db.OAuthScope.
			Query().
			Where(oauthscope.Public(true)).
			All(ctx)

		if err != nil {
			return false, fmt.Errorf("error fetching public scopes: %w", err)
		}

		// Create a map for quick lookup
		validScopes := make(map[string]bool)
		for _, scope := range publicScopes {
			validScopes[scope.Name] = true
		}

		// Check all requested scopes
		for _, scope := range scopes {
			if !validScopes[scope] {
				return false, nil
			}
		}

		return true, nil
	}

	// Create a map of allowed scopes for this client
	allowedScopes := make(map[string]bool)
	for _, scope := range clientScopes {
		allowedScopes[scope.Name] = true
	}

	// Check if all requested scopes are allowed
	for _, scope := range scopes {
		if !allowedScopes[scope] {
			return false, nil
		}
	}

	return true, nil
}

// GetDefaultScopes returns the default scopes to use when none are specified
func (s *EntStorage) GetDefaultScopes(ctx context.Context) ([]string, error) {
	// Get all default scopes
	defaultScopes, err := s.db.OAuthScope.
		Query().
		Where(oauthscope.DefaultScope(true)).
		Where(oauthscope.Public(true)).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("error fetching default scopes: %w", err)
	}

	// Extract scope names
	result := make([]string, len(defaultScopes))
	for i, scope := range defaultScopes {
		result[i] = scope.Name
	}

	// If no default scopes defined, return minimal scopes
	if len(result) == 0 {
		return []string{"profile"}, nil
	}

	return result, nil
}

// GetAuthorizationCode retrieves an authorization code
func (s *EntStorage) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	auth, err := s.db.OAuthAuthorization.
		Query().
		Where(oauthauthorization.Code(code)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("authorization code not found")
		}
		return nil, fmt.Errorf("error fetching authorization code: %w", err)
	}

	// Check if the code is already used
	if auth.Used {
		return nil, errors.New("authorization code already used")
	}

	// Check if the code has expired
	if time.Now().After(auth.ExpiresAt) {
		return nil, errors.New("authorization code has expired")
	}

	// Get the client ID (not the internal ID)
	client, err := s.db.OAuthClient.Get(ctx, auth.ClientID)
	if err != nil {
		return nil, fmt.Errorf("error fetching client: %w", err)
	}

	result := &AuthorizationCode{
		Code:                code,
		ClientID:            client.ClientID,
		RedirectURI:         auth.RedirectURI,
		ExpiresAt:           auth.ExpiresAt,
		Scopes:              auth.ScopeNames,
		UserID:              auth.UserID,
		OrganizationID:      auth.OrganizationID,
		CodeChallenge:       auth.CodeChallenge,
		CodeChallengeMethod: auth.CodeChallengeMethod,
		State:               auth.State,
		Used:                auth.Used,
	}

	if auth.UsedAt != nil {
		result.UsedAt = auth.UsedAt
	}

	return result, nil
}

// MarkAuthorizationCodeAsUsed marks an authorization code as used
func (s *EntStorage) MarkAuthorizationCodeAsUsed(ctx context.Context, code string) error {
	// Find the authorization code
	auth, err := s.db.OAuthAuthorization.
		Query().
		Where(oauthauthorization.Code(code)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New("authorization code not found")
		}
		return fmt.Errorf("error fetching authorization code: %w", err)
	}

	// Get current time
	now := time.Now()

	// Mark as used
	_, err = s.db.OAuthAuthorization.
		UpdateOne(auth).
		SetUsed(true).
		SetNillableUsedAt(&now).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("error marking authorization code as used: %w", err)
	}

	return nil
}

// StoreAccessToken stores an access token
func (s *EntStorage) StoreAccessToken(ctx context.Context, token *TokenInfo) error {
	// Check if client exists
	client, err := s.db.OAuthClient.
		Query().
		Where(oauthclient.ClientID(token.ClientID)).
		First(ctx)

	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}

	// Create token entity
	tokenCreate := s.db.OAuthToken.
		Create().
		SetAccessToken(token.AccessToken).
		SetTokenType(token.TokenType).
		SetClientID(client.ID).
		SetExpiresIn(token.ExpiresIn).
		SetExpiresAt(token.ExpiresAt).
		SetScopeNames(token.Scopes).
		SetCreatedAt(token.CreatedAt).
		SetUpdatedAt(token.CreatedAt).
		SetRevoked(false)

	// Add user if present
	if token.UserID != "" {
		tokenCreate = tokenCreate.SetUserID(token.UserID)
	}

	// Add organization if present
	if token.OrganizationID != "" {
		tokenCreate = tokenCreate.SetOrganizationID(token.OrganizationID)
	}

	// Add refresh token if present
	if token.RefreshToken != "" {
		tokenCreate = tokenCreate.SetRefreshToken(token.RefreshToken)
	}

	// Add IP address if present
	if token.IPAddress != "" {
		tokenCreate = tokenCreate.SetIPAddress(token.IPAddress)
	}

	// Add user agent if present
	if token.UserAgent != "" {
		tokenCreate = tokenCreate.SetUserAgent(token.UserAgent)
	}

	// Save the token
	_, err = tokenCreate.Save(ctx)
	if err != nil {
		return fmt.Errorf("error storing access token: %w", err)
	}

	return nil
}

// GetAccessToken retrieves an access token
func (s *EntStorage) GetAccessToken(ctx context.Context, token string) (*TokenInfo, error) {
	tokenEntity, err := s.db.OAuthToken.
		Query().
		Where(oauthtoken.AccessToken(token)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("access token not found")
		}
		return nil, fmt.Errorf("error fetching access token: %w", err)
	}

	// Get the client ID (not the internal ID)
	client, err := s.db.OAuthClient.Get(ctx, tokenEntity.ClientID)
	if err != nil {
		return nil, fmt.Errorf("error fetching client: %w", err)
	}

	result := &TokenInfo{
		AccessToken:    token,
		RefreshToken:   tokenEntity.RefreshToken,
		ClientID:       client.ClientID,
		UserID:         tokenEntity.UserID,
		OrganizationID: tokenEntity.OrganizationID,
		Scopes:         tokenEntity.ScopeNames,
		ExpiresIn:      tokenEntity.ExpiresIn,
		ExpiresAt:      tokenEntity.ExpiresAt,
		TokenType:      tokenEntity.TokenType,
		Revoked:        tokenEntity.Revoked,
		CreatedAt:      tokenEntity.CreatedAt,
		IPAddress:      tokenEntity.IPAddress,
		UserAgent:      tokenEntity.UserAgent,
	}

	if tokenEntity.RevokedAt != nil {
		result.RevokedAt = tokenEntity.RevokedAt
	}

	return result, nil
}

// RevokeAccessToken revokes an access token
func (s *EntStorage) RevokeAccessToken(ctx context.Context, token string) error {
	// Find the token
	tokenEntity, err := s.db.OAuthToken.
		Query().
		Where(oauthtoken.AccessToken(token)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New("access token not found")
		}
		return fmt.Errorf("error fetching access token: %w", err)
	}

	// Get current time
	now := time.Now()

	// Mark as revoked
	_, err = s.db.OAuthToken.
		UpdateOne(tokenEntity).
		SetRevoked(true).
		SetNillableRevokedAt(&now).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("error revoking access token: %w", err)
	}

	return nil
}

// StoreRefreshToken stores a refresh token
func (s *EntStorage) StoreRefreshToken(ctx context.Context, token *TokenInfo) error {
	// Check if client exists
	client, err := s.db.OAuthClient.
		Query().
		Where(oauthclient.ClientID(token.ClientID)).
		First(ctx)

	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}

	// Create token entity
	tokenCreate := s.db.OAuthToken.
		Create().
		SetRefreshToken(token.RefreshToken).
		SetTokenType("refresh").
		SetClientID(client.ID).
		SetExpiresAt(token.ExpiresAt).
		SetScopeNames(token.Scopes).
		SetCreatedAt(token.CreatedAt).
		SetUpdatedAt(token.CreatedAt).
		SetRevoked(false)

	// Add user if present
	if token.UserID != "" {
		tokenCreate = tokenCreate.SetUserID(token.UserID)
	}

	// Add organization if present
	if token.OrganizationID != "" {
		tokenCreate = tokenCreate.SetOrganizationID(token.OrganizationID)
	}

	// Save the token
	_, err = tokenCreate.Save(ctx)
	if err != nil {
		return fmt.Errorf("error storing refresh token: %w", err)
	}

	return nil
}

// GetRefreshToken retrieves a refresh token
func (s *EntStorage) GetRefreshToken(ctx context.Context, token string) (*TokenInfo, error) {
	tokenEntity, err := s.db.OAuthToken.
		Query().
		Where(oauthtoken.RefreshToken(token)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("refresh token not found")
		}
		return nil, fmt.Errorf("error fetching refresh token: %w", err)
	}

	// Get the client ID (not the internal ID)
	client, err := s.db.OAuthClient.Get(ctx, tokenEntity.ClientID)
	if err != nil {
		return nil, fmt.Errorf("error fetching client: %w", err)
	}

	result := &TokenInfo{
		AccessToken:    tokenEntity.AccessToken,
		RefreshToken:   token,
		ClientID:       client.ClientID,
		UserID:         tokenEntity.UserID,
		OrganizationID: tokenEntity.OrganizationID,
		Scopes:         tokenEntity.ScopeNames,
		ExpiresAt:      tokenEntity.ExpiresAt,
		TokenType:      tokenEntity.TokenType,
		Revoked:        tokenEntity.Revoked,
		CreatedAt:      tokenEntity.CreatedAt,
	}

	if tokenEntity.RevokedAt != nil {
		result.RevokedAt = tokenEntity.RevokedAt
	}

	return result, nil
}

// RevokeRefreshToken revokes a refresh token
func (s *EntStorage) RevokeRefreshToken(ctx context.Context, token string) error {
	// Find the token
	tokenEntity, err := s.db.OAuthToken.
		Query().
		Where(oauthtoken.RefreshToken(token)).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New("refresh token not found")
		}
		return fmt.Errorf("error fetching refresh token: %w", err)
	}

	// Get current time
	now := time.Now()

	// Mark as revoked
	_, err = s.db.OAuthToken.
		UpdateOne(tokenEntity).
		SetRevoked(true).
		SetNillableRevokedAt(&now).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("error revoking refresh token: %w", err)
	}

	return nil
}
