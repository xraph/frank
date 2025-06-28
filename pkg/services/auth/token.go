package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/xid"
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/crypto"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
)

// TokenService defines the interface for token operations
type TokenService interface {
	// Access Token operations
	CreateAccessToken(ctx context.Context, userID xid.ID, organizationID *xid.ID, sessionID xid.ID) (*AccessToken, error)
	ValidateAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error)
	RevokeAccessToken(ctx context.Context, tokenString string) error

	// Refresh Token operations
	CreateRefreshToken(ctx context.Context, userID xid.ID, sessionID xid.ID) (*RefreshToken, error)
	ValidateRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error)
	RevokeRefreshToken(ctx context.Context, tokenString string) error
	RevokeAllUserTokens(ctx context.Context, userID xid.ID) error

	// Token introspection
	IntrospectToken(ctx context.Context, tokenString string) (*TokenIntrospection, error)
	GetTokenMetadata(ctx context.Context, tokenString string) (*TokenMetadata, error)

	// API Key tokens
	CreateAPIKeyToken(ctx context.Context, userID xid.ID, organizationID *xid.ID, keyID xid.ID, scopes []string) (*APIKeyToken, error)
	ValidateAPIKeyToken(ctx context.Context, tokenString string) (*APIKeyTokenClaims, error)

	// Token management
	CleanupExpiredTokens(ctx context.Context) (int, error)
	GetUserTokens(ctx context.Context, userID xid.ID) ([]*TokenInfo, error)
	RevokeTokensBySession(ctx context.Context, sessionID xid.ID) error
}

// Token types and structures

type AccessToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
	Subject   string    `json:"subject"`
}

type RefreshToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
	Subject   string    `json:"subject"`
}

type APIKeyToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
	Subject   string    `json:"subject"`
	Scopes    []string  `json:"scopes"`
}

// JWT Claims structures

type AccessTokenClaims = crypto.AccessTokenClaims

type RefreshTokenClaims = crypto.RefreshTokenClaims

type APIKeyTokenClaims = crypto.APIKeyTokenClaims

// Token metadata and introspection types

type TokenIntrospection struct {
	Active     bool     `json:"active"`
	TokenType  string   `json:"token_type,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	ClientID   string   `json:"client_id,omitempty"`
	Username   string   `json:"username,omitempty"`
	ExpiresAt  int64    `json:"exp,omitempty"`
	IssuedAt   int64    `json:"iat,omitempty"`
	NotBefore  int64    `json:"nbf,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   []string `json:"aud,omitempty"`
	Issuer     string   `json:"iss,omitempty"`
	JWTTokenID string   `json:"jti,omitempty"`
}

type TokenMetadata struct {
	TokenID    string                 `json:"token_id"`
	TokenType  string                 `json:"token_type"`
	UserID     xid.ID                 `json:"user_id"`
	SessionID  *xid.ID                `json:"session_id,omitempty"`
	IssuedAt   time.Time              `json:"issued_at"`
	ExpiresAt  time.Time              `json:"expires_at"`
	LastUsedAt *time.Time             `json:"last_used_at,omitempty"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	Scopes     []string               `json:"scopes,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type TokenInfo struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	Active    bool       `json:"active"`
	Scopes    []string   `json:"scopes,omitempty"`
}

// tokenService implements the TokenService interface
type tokenService struct {
	config        *TokenConfig
	sessionRepo   repository.SessionRepository
	userRepo      repository.UserRepository
	apiKeyRepo    repository.ApiKeyRepository
	crypto        crypto.Util
	logger        logging.Logger
	revokedTokens map[string]time.Time // In-memory revocation list (should use Redis in production)
}

// TokenConfig holds token-related configuration
type TokenConfig struct {
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	APIKeyTokenDuration  time.Duration
	SecretKey            []byte
	Issuer               string
	Audience             []string
	SigningMethod        jwt.SigningMethod
}

// NewTokenService creates a new token service
func NewTokenService(
	repos repository.Repository,
	crypto crypto.Util,
	logger logging.Logger,
	cfg *config.AuthConfig,
) TokenService {

	mcfg := defaultTokenConfig()
	if cfg.RefreshTokenDuration > 0 {
		mcfg.RefreshTokenDuration = cfg.RefreshTokenDuration
	}
	if cfg.AccessTokenDuration > 0 {
		mcfg.AccessTokenDuration = cfg.AccessTokenDuration
	}
	if cfg.TokenIssuer != "" {
		mcfg.Issuer = cfg.TokenIssuer
	}
	if cfg.TokenAudience != nil {
		mcfg.Audience = cfg.TokenAudience
	}

	return &tokenService{
		config:        mcfg,
		sessionRepo:   repos.Session(),
		userRepo:      repos.User(),
		apiKeyRepo:    repos.APIKey(),
		logger:        logger,
		crypto:        crypto,
		revokedTokens: make(map[string]time.Time),
	}
}

// defaultTokenConfig returns default token configuration
func defaultTokenConfig() *TokenConfig {
	return &TokenConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 30 * 24 * time.Hour,       // 30 days
		APIKeyTokenDuration:  365 * 24 * time.Hour,      // 1 year
		SecretKey:            []byte("your-secret-key"), // Should come from config
		Issuer:               "frank-auth",
		Audience:             []string{"frank-api"},
		SigningMethod:        jwt.SigningMethodHS256,
	}
}

// CreateAccessToken creates a new JWT access token
func (s *tokenService) CreateAccessToken(ctx context.Context, userID xid.ID, organizationID *xid.ID, sessionID xid.ID) (*AccessToken, error) {
	now := time.Now()
	expiresAt := now.Add(s.config.AccessTokenDuration)
	tokenID := s.generateTokenID()

	// Create claims
	claims := &AccessTokenClaims{
		UserID:         userID,
		OrganizationID: organizationID,
		SessionID:      sessionID,
		TokenType:      "access_token",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			Subject:   userID.String(),
			Issuer:    s.config.Issuer,
			Audience:  s.config.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	// TODO: Add user scopes/permissions to claims
	// scopes, err := s.getUserScopes(ctx, userID, organizationID)
	// claims.Scopes = scopes

	// Create and sign token
	tokenString, err := s.crypto.JWT().GenerateAccessToken(claims) // token.SignedString(s.config.SecretKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to sign access token")
	}

	return &AccessToken{
		Token:     tokenString,
		ExpiresAt: expiresAt,
		IssuedAt:  now,
		Subject:   userID.String(),
	}, nil
}

// ValidateAccessToken validates and parses an access token
func (s *tokenService) ValidateAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error) {
	if tokenString == "" {
		return nil, errors.New(errors.CodeUnauthorized, "token is required")
	}

	// Check if token is revoked
	if s.isTokenRevoked(tokenString) {
		return nil, errors.New(errors.CodeUnauthorized, "token has been revoked")
	}

	// Parse and validate token
	claims, err := s.crypto.JWT().ValidateAccessToken(tokenString)
	if err != nil {
		fmt.Println("failed to validate access token", err)
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "invalid token")
	}

	// Validate token type
	if claims.TokenType != "access_token" {
		return nil, errors.New(errors.CodeUnauthorized, "invalid token type")
	}

	// Validate session if session ID is present
	if claims.SessionID != (xid.ID{}) {
		valid, err := s.sessionRepo.IsActiveSession(ctx, "")
		if err != nil || !valid {
			return nil, errors.New(errors.CodeUnauthorized, "invalid session")
		}
	}

	return claims, nil
}

// RevokeAccessToken revokes an access token
func (s *tokenService) RevokeAccessToken(ctx context.Context, tokenString string) error {
	// Parse token to get expiration time
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.config.SecretKey, nil
	})

	if err != nil {
		return errors.Wrap(err, errors.CodeBadRequest, "invalid token")
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		return errors.New(errors.CodeBadRequest, "invalid token claims")
	}

	// Add to revocation list
	s.revokedTokens[tokenString] = claims.ExpiresAt.Time

	return nil
}

// CreateRefreshToken creates a new refresh token
func (s *tokenService) CreateRefreshToken(ctx context.Context, userID xid.ID, sessionID xid.ID) (*RefreshToken, error) {
	now := time.Now()
	expiresAt := now.Add(s.config.RefreshTokenDuration)
	tokenID := s.generateTokenID()

	// Create claims
	claims := RefreshTokenClaims{
		UserID:    userID,
		SessionID: sessionID,
		TokenType: "refresh_token",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			Subject:   userID.String(),
			Issuer:    s.config.Issuer,
			Audience:  s.config.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	// Create and sign token
	token := jwt.NewWithClaims(s.config.SigningMethod, claims)
	tokenString, err := token.SignedString(s.config.SecretKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to sign refresh token")
	}

	return &RefreshToken{
		Token:     tokenString,
		ExpiresAt: expiresAt,
		IssuedAt:  now,
		Subject:   userID.String(),
	}, nil
}

// ValidateRefreshToken validates and parses a refresh token
func (s *tokenService) ValidateRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error) {
	if tokenString == "" {
		return nil, errors.New(errors.CodeUnauthorized, "refresh token is required")
	}

	// Check if token is revoked
	if s.isTokenRevoked(tokenString) {
		return nil, errors.New(errors.CodeUnauthorized, "refresh token has been revoked")
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != s.config.SigningMethod {
			return nil, errors.New(errors.CodeUnauthorized, "invalid signing method")
		}
		return s.config.SecretKey, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "invalid refresh token")
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok || !token.Valid {
		return nil, errors.New(errors.CodeUnauthorized, "invalid refresh token claims")
	}

	// Validate token type
	if claims.TokenType != "refresh_token" {
		return nil, errors.New(errors.CodeUnauthorized, "invalid token type")
	}

	return claims, nil
}

// RevokeRefreshToken revokes a refresh token
func (s *tokenService) RevokeRefreshToken(ctx context.Context, tokenString string) error {
	// Parse token to get expiration time
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.config.SecretKey, nil
	})

	if err != nil {
		return errors.Wrap(err, errors.CodeBadRequest, "invalid refresh token")
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok {
		return errors.New(errors.CodeBadRequest, "invalid refresh token claims")
	}

	// Add to revocation list
	s.revokedTokens[tokenString] = claims.ExpiresAt.Time

	return nil
}

// RevokeAllUserTokens revokes all tokens for a specific user
func (s *tokenService) RevokeAllUserTokens(ctx context.Context, userID xid.ID) error {
	// In a production system, this would need to:
	// 1. Mark all user sessions as invalid
	// 2. Add all user tokens to revocation list
	// 3. Potentially use a user generation number/timestamp approach

	// For now, invalidate all user sessions
	err := s.sessionRepo.InvalidateAllUserSessions(ctx, userID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to invalidate user sessions")
	}

	return nil
}

// CreateAPIKeyToken creates a token for API key authentication
func (s *tokenService) CreateAPIKeyToken(ctx context.Context, userID xid.ID, organizationID *xid.ID, keyID xid.ID, scopes []string) (*APIKeyToken, error) {
	now := time.Now()
	expiresAt := now.Add(s.config.APIKeyTokenDuration)
	tokenID := s.generateTokenID()

	// Create claims
	claims := APIKeyTokenClaims{
		UserID:         userID,
		OrganizationID: organizationID,
		KeyID:          keyID,
		TokenType:      "api_key",
		Scopes:         scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			Subject:   userID.String(),
			Issuer:    s.config.Issuer,
			Audience:  s.config.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	// Create and sign token
	token := jwt.NewWithClaims(s.config.SigningMethod, claims)
	tokenString, err := token.SignedString(s.config.SecretKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to sign API key token")
	}

	return &APIKeyToken{
		Token:     tokenString,
		ExpiresAt: expiresAt,
		IssuedAt:  now,
		Subject:   userID.String(),
		Scopes:    scopes,
	}, nil
}

// ValidateAPIKeyToken validates and parses an API key token
func (s *tokenService) ValidateAPIKeyToken(ctx context.Context, tokenString string) (*APIKeyTokenClaims, error) {
	if tokenString == "" {
		return nil, errors.New(errors.CodeUnauthorized, "API key token is required")
	}

	// Check if token is revoked
	if s.isTokenRevoked(tokenString) {
		return nil, errors.New(errors.CodeUnauthorized, "API key token has been revoked")
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &APIKeyTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != s.config.SigningMethod {
			return nil, errors.New(errors.CodeUnauthorized, "invalid signing method")
		}
		return s.config.SecretKey, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "invalid API key token")
	}

	claims, ok := token.Claims.(*APIKeyTokenClaims)
	if !ok || !token.Valid {
		return nil, errors.New(errors.CodeUnauthorized, "invalid API key token claims")
	}

	// Validate token type
	if claims.TokenType != "api_key" {
		return nil, errors.New(errors.CodeUnauthorized, "invalid token type")
	}

	// Validate API key is still active
	apiKey, err := s.apiKeyRepo.GetByID(ctx, claims.KeyID)
	if err != nil || !apiKey.Active {
		return nil, errors.New(errors.CodeUnauthorized, "API key is inactive")
	}

	return claims, nil
}

// IntrospectToken provides detailed information about a token
func (s *tokenService) IntrospectToken(ctx context.Context, tokenString string) (*TokenIntrospection, error) {
	if tokenString == "" {
		return &TokenIntrospection{Active: false}, nil
	}

	// Check if token is revoked
	if s.isTokenRevoked(tokenString) {
		return &TokenIntrospection{Active: false}, nil
	}

	// Parse token without validation to get basic info
	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.config.SecretKey, nil
	})

	if err != nil {
		return &TokenIntrospection{Active: false}, nil
	}

	claims, ok := token.Claims.(*jwt.MapClaims)
	if !ok {
		return &TokenIntrospection{Active: false}, nil
	}

	// Build introspection response
	introspection := &TokenIntrospection{
		Active: token.Valid,
	}

	if token.Valid {
		if tokenType, ok := (*claims)["token_type"].(string); ok {
			introspection.TokenType = tokenType
		}

		if sub, ok := (*claims)["sub"].(string); ok {
			introspection.Subject = sub
		}

		if iss, ok := (*claims)["iss"].(string); ok {
			introspection.Issuer = iss
		}

		if aud, ok := (*claims)["aud"].([]interface{}); ok {
			audiences := make([]string, len(aud))
			for i, a := range aud {
				if str, ok := a.(string); ok {
					audiences[i] = str
				}
			}
			introspection.Audience = audiences
		}

		if exp, ok := (*claims)["exp"].(float64); ok {
			introspection.ExpiresAt = int64(exp)
		}

		if iat, ok := (*claims)["iat"].(float64); ok {
			introspection.IssuedAt = int64(iat)
		}

		if nbf, ok := (*claims)["nbf"].(float64); ok {
			introspection.NotBefore = int64(nbf)
		}

		if jti, ok := (*claims)["jti"].(string); ok {
			introspection.JWTTokenID = jti
		}

		if scopes, ok := (*claims)["scopes"].([]interface{}); ok {
			var scopeStrings []string
			for _, scope := range scopes {
				if str, ok := scope.(string); ok {
					scopeStrings = append(scopeStrings, str)
				}
			}
			introspection.Scope = fmt.Sprintf("%s", scopeStrings)
		}
	}

	return introspection, nil
}

// GetTokenMetadata returns metadata about a token
func (s *tokenService) GetTokenMetadata(ctx context.Context, tokenString string) (*TokenMetadata, error) {
	// This would typically query a token metadata store
	// For now, parse the token and extract available information

	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.config.SecretKey, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBadRequest, "invalid token")
	}

	claims, ok := token.Claims.(*jwt.MapClaims)
	if !ok {
		return nil, errors.New(errors.CodeBadRequest, "invalid token claims")
	}

	metadata := &TokenMetadata{}

	if jti, ok := (*claims)["jti"].(string); ok {
		metadata.TokenID = jti
	}

	if tokenType, ok := (*claims)["token_type"].(string); ok {
		metadata.TokenType = tokenType
	}

	if sub, ok := (*claims)["sub"].(string); ok {
		if userID, err := xid.FromString(sub); err == nil {
			metadata.UserID = userID
		}
	}

	if iat, ok := (*claims)["iat"].(float64); ok {
		metadata.IssuedAt = time.Unix(int64(iat), 0)
	}

	if exp, ok := (*claims)["exp"].(float64); ok {
		metadata.ExpiresAt = time.Unix(int64(exp), 0)
	}

	if scopes, ok := (*claims)["scopes"].([]interface{}); ok {
		for _, scope := range scopes {
			if str, ok := scope.(string); ok {
				metadata.Scopes = append(metadata.Scopes, str)
			}
		}
	}

	return metadata, nil
}

// CleanupExpiredTokens removes expired tokens from revocation list
func (s *tokenService) CleanupExpiredTokens(ctx context.Context) (int, error) {
	now := time.Now()
	count := 0

	// Clean up revoked tokens that have expired
	for token, expiresAt := range s.revokedTokens {
		if now.After(expiresAt) {
			delete(s.revokedTokens, token)
			count++
		}
	}

	return count, nil
}

// GetUserTokens returns all active tokens for a user
func (s *tokenService) GetUserTokens(ctx context.Context, userID xid.ID) ([]*TokenInfo, error) {
	// This would typically query a token store
	// For now, return empty list as we don't persist token metadata
	return []*TokenInfo{}, nil
}

// RevokeTokensBySession revokes all tokens for a specific session
func (s *tokenService) RevokeTokensBySession(ctx context.Context, sessionID xid.ID) error {
	// In a production system, this would query all tokens for the session
	// and add them to the revocation list
	// For now, just invalidate the session

	return s.sessionRepo.Delete(ctx, sessionID)
}

// Helper methods

func (s *tokenService) generateTokenID() string {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		// Fallback to xid if random generation fails
		return xid.New().String()
	}

	return base64.URLEncoding.EncodeToString(bytes)
}

func (s *tokenService) isTokenRevoked(tokenString string) bool {
	_, exists := s.revokedTokens[tokenString]
	return exists
}

func (s *tokenService) getUserScopes(ctx context.Context, userID xid.ID, organizationID *xid.ID) ([]string, error) {
	// TODO: Implement scope resolution based on user roles and permissions
	// This would query the user's roles and permissions and convert them to scopes
	return []string{}, nil
}
