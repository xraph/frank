package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/xid"
)

// TokenType represents different types of JWT tokens
type TokenType string

const (
	TokenTypeAccess         TokenType = "access"
	TokenTypeRefresh        TokenType = "refresh"
	TokenTypeEmailVerify    TokenType = "email_verify"
	TokenTypePasswordReset  TokenType = "password_reset"
	TokenTypeMagicLink      TokenType = "magic_link"
	TokenTypeInvitation     TokenType = "invitation"
	TokenTypeAPIKey         TokenType = "api_key"
	TokenTypeWebhookPayload TokenType = "webhook_payload"
)

// SigningMethod represents JWT signing methods
type SigningMethod string

const (
	SigningMethodHS256 SigningMethod = "HS256"
	SigningMethodHS384 SigningMethod = "HS384"
	SigningMethodHS512 SigningMethod = "HS512"
	SigningMethodRS256 SigningMethod = "RS256"
	SigningMethodRS384 SigningMethod = "RS384"
	SigningMethodRS512 SigningMethod = "RS512"
	SigningMethodES256 SigningMethod = "ES256"
	SigningMethodES384 SigningMethod = "ES384"
	SigningMethodES512 SigningMethod = "ES512"
)

// JWTConfig contains JWT configuration
type JWTConfig struct {
	SecretKey           string
	PublicKey           string
	PrivateKey          string
	SigningMethod       SigningMethod
	Issuer              string
	Audience            []string
	AccessTokenExpiry   time.Duration
	RefreshTokenExpiry  time.Duration
	VerifyTokenExpiry   time.Duration
	MagicLinkExpiry     time.Duration
	InvitationExpiry    time.Duration
	PasswordResetExpiry time.Duration
}

// CustomClaims represents custom claims for the application
type CustomClaims struct {
	jwt.RegisteredClaims
	UserID         xid.ID            `json:"user_id,omitempty"`
	OrganizationID *xid.ID           `json:"organization_id,omitempty"`
	Email          string            `json:"email,omitempty"`
	Username       string            `json:"username,omitempty"`
	TokenType      TokenType         `json:"token_type,omitempty"`
	Scopes         []string          `json:"scopes,omitempty"`
	Roles          []string          `json:"roles,omitempty"`
	Permissions    []string          `json:"permissions,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	SessionID      *xid.ID           `json:"session_id,omitempty"`
	ClientID       *xid.ID           `json:"client_id,omitempty"`
	DeviceID       string            `json:"device_id,omitempty"`
	IPAddress      string            `json:"ip_address,omitempty"`
	UserAgent      string            `json:"user_agent,omitempty"`
}

// Valid implements jwt.Claims interface
func (c CustomClaims) Valid() error {
	now := time.Now()

	// Check expiration
	if c.ExpiresAt != nil && now.After(c.ExpiresAt.Time) {
		return fmt.Errorf("token has expired")
	}

	// Check not before
	if c.NotBefore != nil && now.Before(c.NotBefore.Time) {
		return fmt.Errorf("token is not valid yet")
	}

	// Check required fields
	if c.Subject == "" {
		return fmt.Errorf("subject is required")
	}

	if c.UserID.IsNil() {
		return fmt.Errorf("user_id is required")
	}

	return nil
}

// GetExpirationTime implements jwt.Claims interface
func (c CustomClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return c.ExpiresAt, nil
}

// GetIssuedAt implements jwt.Claims interface
func (c CustomClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return c.IssuedAt, nil
}

// GetNotBefore implements jwt.Claims interface
func (c CustomClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return c.NotBefore, nil
}

// GetIssuer implements jwt.Claims interface
func (c CustomClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements jwt.Claims interface
func (c CustomClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// GetAudience implements jwt.Claims interface
func (c CustomClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}

type AccessTokenClaims struct {
	UserID         xid.ID    `json:"sub"`
	OrganizationID *xid.ID   `json:"org,omitempty"`
	SessionID      xid.ID    `json:"sid"`
	TokenType      TokenType `json:"token_type"`
	Scopes         []string  `json:"scopes,omitempty"`
	Permissions    []string  `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	UserID    xid.ID    `json:"sub"`
	SessionID xid.ID    `json:"sid"`
	TokenType TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

type APIKeyTokenClaims struct {
	UserID         xid.ID    `json:"sub"`
	OrganizationID *xid.ID   `json:"org,omitempty"`
	KeyID          xid.ID    `json:"kid"`
	TokenType      TokenType `json:"token_type"`
	Scopes         []string  `json:"scopes"`
	jwt.RegisteredClaims
}

// JWTManager provides JWT token management functionality
type JWTManager interface {
	GenerateToken(claims *CustomClaims) (string, error)
	ValidateToken(tokenString string) (*CustomClaims, error)
	GenerateAccessToken(claims *AccessTokenClaims) (string, error)
	ValidateAccessToken(tokenString string) (*AccessTokenClaims, error)
	GenerateAPIKeyToken(claims *APIKeyTokenClaims) (string, error)
	ValidateAPIKeyToken(tokenString string) (*APIKeyTokenClaims, error)
	GenerateRefreshToken(claims *RefreshTokenClaims) (string, error)
	ValidateRefreshToken(tokenString string) (*RefreshTokenClaims, error)
	RefreshToken(refreshTokenString string) (accessToken, refreshToken string, err error)
	ParseTokenWithoutValidation(tokenString string) (*CustomClaims, error)
	GetTokenExpiry(tokenType TokenType) time.Duration
	RevokeToken(tokenString string) error
	IsTokenRevoked(tokenString string) bool
}

// jwtManager implements JWTManager interface
type jwtManager struct {
	config       *JWTConfig
	signingKey   interface{}
	verifyingKey interface{}
	revokedList  map[string]time.Time // Simple in-memory revocation list
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(config *JWTConfig) (JWTManager, error) {
	if config == nil {
		return nil, fmt.Errorf("JWT config is required")
	}

	manager := &jwtManager{
		config:      config,
		revokedList: make(map[string]time.Time),
	}

	// Set up signing and verifying keys based on the signing method
	if err := manager.setupKeys(); err != nil {
		return nil, fmt.Errorf("failed to setup JWT keys: %w", err)
	}

	return manager, nil
}

// setupKeys configures the signing and verifying keys
func (j *jwtManager) setupKeys() error {
	method := string(j.config.SigningMethod)

	switch {
	case method[:2] == "HS": // HMAC methods
		if j.config.SecretKey == "" {
			return fmt.Errorf("secret key is required for HMAC signing methods")
		}
		j.signingKey = []byte(j.config.SecretKey)
		j.verifyingKey = []byte(j.config.SecretKey)

	case method[:2] == "RS" || method[:2] == "ES": // RSA/ECDSA methods
		if j.config.PrivateKey == "" {
			return fmt.Errorf("private key is required for RSA/ECDSA signing methods")
		}

		// Parse private key
		privateKeyPEM, _ := pem.Decode([]byte(j.config.PrivateKey))
		if privateKeyPEM == nil {
			return fmt.Errorf("invalid private key PEM format")
		}

		if method[:2] == "RS" {
			privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyPEM.Bytes)
			if err != nil {
				// Try PKCS8 format
				key, err := x509.ParsePKCS8PrivateKey(privateKeyPEM.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse RSA private key: %w", err)
				}
				var ok bool
				privateKey, ok = key.(*rsa.PrivateKey)
				if !ok {
					return fmt.Errorf("key is not an RSA private key")
				}
			}
			j.signingKey = privateKey
			j.verifyingKey = &privateKey.PublicKey
		}

		// Parse public key if provided
		if j.config.PublicKey != "" {
			publicKeyPEM, _ := pem.Decode([]byte(j.config.PublicKey))
			if publicKeyPEM != nil {
				publicKey, err := x509.ParsePKIXPublicKey(publicKeyPEM.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse public key: %w", err)
				}
				j.verifyingKey = publicKey
			}
		}

	default:
		return fmt.Errorf("unsupported signing method: %s", method)
	}

	return nil
}

// GenerateToken generates a new JWT token with the given claims
func (j *jwtManager) GenerateToken(claims *CustomClaims) (string, error) {
	if claims == nil {
		return "", fmt.Errorf("claims are required")
	}

	// Set standard claims if not provided
	now := time.Now()
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(now)
	}
	if claims.NotBefore == nil {
		claims.NotBefore = jwt.NewNumericDate(now)
	}
	if claims.ID == "" {
		claims.ID = xid.New().String()
	}
	if claims.Issuer == "" {
		claims.Issuer = j.config.Issuer
	}
	if len(claims.Audience) == 0 && len(j.config.Audience) > 0 {
		claims.Audience = jwt.ClaimStrings(j.config.Audience)
	}

	// Set expiration based on token type
	if claims.ExpiresAt == nil {
		expiry := j.GetTokenExpiry(claims.TokenType)
		if expiry > 0 {
			claims.ExpiresAt = jwt.NewNumericDate(now.Add(expiry))
		}
	}

	// Create token
	var token *jwt.Token
	switch j.config.SigningMethod {
	case SigningMethodHS256:
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	case SigningMethodHS384:
		token = jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	case SigningMethodHS512:
		token = jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	case SigningMethodRS256:
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	case SigningMethodRS384:
		token = jwt.NewWithClaims(jwt.SigningMethodRS384, claims)
	case SigningMethodRS512:
		token = jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	default:
		return "", fmt.Errorf("unsupported signing method: %s", j.config.SigningMethod)
	}

	// Sign token
	tokenString, err := token.SignedString(j.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates and parses a JWT token
func (j *jwtManager) ValidateToken(tokenString string) (*CustomClaims, error) {
	// Check if token is revoked
	if j.IsTokenRevoked(tokenString) {
		return nil, fmt.Errorf("token has been revoked")
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		expectedMethod := string(j.config.SigningMethod)
		if token.Method.Alg() != expectedMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.verifyingKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token claims")
	}

	return claims, nil
}

// GenerateAccessToken generates a new JWT token for access tokens
func (j *jwtManager) GenerateAccessToken(claims *AccessTokenClaims) (string, error) {
	if claims == nil {
		return "", fmt.Errorf("claims are required")
	}

	// Set standard claims if not provided
	now := time.Now()
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(now)
	}
	if claims.NotBefore == nil {
		claims.NotBefore = jwt.NewNumericDate(now)
	}
	if claims.ID == "" {
		claims.ID = xid.New().String()
	}
	if claims.Issuer == "" {
		claims.Issuer = j.config.Issuer
	}
	if len(claims.Audience) == 0 && len(j.config.Audience) > 0 {
		claims.Audience = j.config.Audience
	}

	// Set expiration based on token type
	if claims.ExpiresAt == nil {
		expiry := j.GetTokenExpiry(claims.TokenType)
		if expiry > 0 {
			claims.ExpiresAt = jwt.NewNumericDate(now.Add(expiry))
		}
	}

	// Create token
	var token *jwt.Token
	switch j.config.SigningMethod {
	case SigningMethodHS256:
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	case SigningMethodHS384:
		token = jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	case SigningMethodHS512:
		token = jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	case SigningMethodRS256:
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	case SigningMethodRS384:
		token = jwt.NewWithClaims(jwt.SigningMethodRS384, claims)
	case SigningMethodRS512:
		token = jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	default:
		return "", fmt.Errorf("unsupported signing method: %s", j.config.SigningMethod)
	}

	// Sign token
	tokenString, err := token.SignedString(j.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateAccessToken validates and parses an access JWT token
func (j *jwtManager) ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	// Check if token is revoked
	if j.IsTokenRevoked(tokenString) {
		return nil, fmt.Errorf("token has been revoked")
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		expectedMethod := string(j.config.SigningMethod)
		if token.Method.Alg() != expectedMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.verifyingKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		fmt.Println(err)
		return nil, fmt.Errorf("failed to parse token claims")
	}

	return claims, nil
}

// GenerateAPIKeyToken generates a new JWT token with the given api key claims
func (j *jwtManager) GenerateAPIKeyToken(claims *APIKeyTokenClaims) (string, error) {
	if claims == nil {
		return "", fmt.Errorf("claims are required")
	}

	// Set standard claims if not provided
	now := time.Now()
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(now)
	}
	if claims.NotBefore == nil {
		claims.NotBefore = jwt.NewNumericDate(now)
	}
	if claims.ID == "" {
		claims.ID = xid.New().String()
	}
	if claims.Issuer == "" {
		claims.Issuer = j.config.Issuer
	}
	if len(claims.Audience) == 0 && len(j.config.Audience) > 0 {
		claims.Audience = j.config.Audience
	}

	// Set expiration based on token type
	if claims.ExpiresAt == nil {
		expiry := j.GetTokenExpiry(claims.TokenType)
		if expiry > 0 {
			claims.ExpiresAt = jwt.NewNumericDate(now.Add(expiry))
		}
	}

	// Create token
	var token *jwt.Token
	switch j.config.SigningMethod {
	case SigningMethodHS256:
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	case SigningMethodHS384:
		token = jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	case SigningMethodHS512:
		token = jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	case SigningMethodRS256:
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	case SigningMethodRS384:
		token = jwt.NewWithClaims(jwt.SigningMethodRS384, claims)
	case SigningMethodRS512:
		token = jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	default:
		return "", fmt.Errorf("unsupported signing method: %s", j.config.SigningMethod)
	}

	// Sign token
	tokenString, err := token.SignedString(j.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateAPIKeyToken validates and parses an api key JWT token
func (j *jwtManager) ValidateAPIKeyToken(tokenString string) (*APIKeyTokenClaims, error) {
	// Check if token is revoked
	if j.IsTokenRevoked(tokenString) {
		return nil, fmt.Errorf("token has been revoked")
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &APIKeyTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		expectedMethod := string(j.config.SigningMethod)
		if token.Method.Alg() != expectedMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.verifyingKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(*APIKeyTokenClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token claims")
	}

	return claims, nil
}

// GenerateRefreshToken generates a new JWT token with the given refresh token claims
func (j *jwtManager) GenerateRefreshToken(claims *RefreshTokenClaims) (string, error) {
	if claims == nil {
		return "", fmt.Errorf("claims are required")
	}

	// Set standard claims if not provided
	now := time.Now()
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(now)
	}
	if claims.NotBefore == nil {
		claims.NotBefore = jwt.NewNumericDate(now)
	}
	if claims.ID == "" {
		claims.ID = xid.New().String()
	}
	if claims.Issuer == "" {
		claims.Issuer = j.config.Issuer
	}
	if len(claims.Audience) == 0 && len(j.config.Audience) > 0 {
		claims.Audience = j.config.Audience
	}

	// Set expiration based on token type
	if claims.ExpiresAt == nil {
		expiry := j.GetTokenExpiry(claims.TokenType)
		if expiry > 0 {
			claims.ExpiresAt = jwt.NewNumericDate(now.Add(expiry))
		}
	}

	// Create token
	var token *jwt.Token
	switch j.config.SigningMethod {
	case SigningMethodHS256:
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	case SigningMethodHS384:
		token = jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	case SigningMethodHS512:
		token = jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	case SigningMethodRS256:
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	case SigningMethodRS384:
		token = jwt.NewWithClaims(jwt.SigningMethodRS384, claims)
	case SigningMethodRS512:
		token = jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	default:
		return "", fmt.Errorf("unsupported signing method: %s", j.config.SigningMethod)
	}

	// Sign token
	tokenString, err := token.SignedString(j.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateRefreshToken validates and parses a JWT token
func (j *jwtManager) ValidateRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	// Check if token is revoked
	if j.IsTokenRevoked(tokenString) {
		return nil, fmt.Errorf("token has been revoked")
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		expectedMethod := string(j.config.SigningMethod)
		if token.Method.Alg() != expectedMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.verifyingKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token claims")
	}

	return claims, nil
}

// RefreshToken generates new access and refresh tokens from a refresh token
func (j *jwtManager) RefreshToken(refreshTokenString string) (accessToken, refreshToken string, err error) {
	// Validate refresh token
	claims, err := j.ValidateToken(refreshTokenString)
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Ensure this is a refresh token
	if claims.TokenType != TokenTypeRefresh {
		return "", "", fmt.Errorf("token is not a refresh token")
	}

	// Revoke the old refresh token
	if err := j.RevokeToken(refreshTokenString); err != nil {
		return "", "", fmt.Errorf("failed to revoke old refresh token: %w", err)
	}

	// Generate new access token
	accessClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: claims.Subject,
		},
		UserID:         claims.UserID,
		OrganizationID: claims.OrganizationID,
		Email:          claims.Email,
		Username:       claims.Username,
		TokenType:      TokenTypeAccess,
		Scopes:         claims.Scopes,
		Roles:          claims.Roles,
		Permissions:    claims.Permissions,
		SessionID:      claims.SessionID,
		ClientID:       claims.ClientID,
		DeviceID:       claims.DeviceID,
		IPAddress:      claims.IPAddress,
		UserAgent:      claims.UserAgent,
	}

	accessToken, err = j.GenerateToken(accessClaims)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate new refresh token
	refreshClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: claims.Subject,
		},
		UserID:         claims.UserID,
		OrganizationID: claims.OrganizationID,
		Email:          claims.Email,
		Username:       claims.Username,
		TokenType:      TokenTypeRefresh,
		SessionID:      claims.SessionID,
		ClientID:       claims.ClientID,
		DeviceID:       claims.DeviceID,
		IPAddress:      claims.IPAddress,
		UserAgent:      claims.UserAgent,
	}

	refreshToken, err = j.GenerateToken(refreshClaims)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// ParseTokenWithoutValidation parses a token without validating it
func (j *jwtManager) ParseTokenWithoutValidation(tokenString string) (*CustomClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &CustomClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token claims")
	}

	return claims, nil
}

// GetTokenExpiry returns the expiry duration for a token type
func (j *jwtManager) GetTokenExpiry(tokenType TokenType) time.Duration {
	switch tokenType {
	case TokenTypeAccess:
		return j.config.AccessTokenExpiry
	case TokenTypeRefresh:
		return j.config.RefreshTokenExpiry
	case TokenTypeEmailVerify:
		return j.config.VerifyTokenExpiry
	case TokenTypePasswordReset:
		return j.config.PasswordResetExpiry
	case TokenTypeMagicLink:
		return j.config.MagicLinkExpiry
	case TokenTypeInvitation:
		return j.config.InvitationExpiry
	default:
		return j.config.AccessTokenExpiry // Default to access token expiry
	}
}

// RevokeToken adds a token to the revocation list
func (j *jwtManager) RevokeToken(tokenString string) error {
	// Parse token to get expiry time
	claims, err := j.ParseTokenWithoutValidation(tokenString)
	if err != nil {
		return fmt.Errorf("failed to parse token for revocation: %w", err)
	}

	// Add to revocation list with expiry time
	var expiryTime time.Time
	if claims.ExpiresAt != nil {
		expiryTime = claims.ExpiresAt.Time
	} else {
		// If no expiry, set a far future date
		expiryTime = time.Now().Add(24 * 365 * time.Hour) // 1 year
	}

	j.revokedList[tokenString] = expiryTime

	// Clean up expired tokens from revocation list
	j.cleanupRevokedTokens()

	return nil
}

// IsTokenRevoked checks if a token has been revoked
func (j *jwtManager) IsTokenRevoked(tokenString string) bool {
	expiry, exists := j.revokedList[tokenString]
	if !exists {
		return false
	}

	// If token has expired, remove it from revocation list and return false
	if time.Now().After(expiry) {
		delete(j.revokedList, tokenString)
		return false
	}

	return true
}

// cleanupRevokedTokens removes expired tokens from the revocation list
func (j *jwtManager) cleanupRevokedTokens() {
	now := time.Now()
	for token, expiry := range j.revokedList {
		if now.After(expiry) {
			delete(j.revokedList, token)
		}
	}
}

// Utility functions

// ExtractTokenFromHeader extracts JWT token from Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is required")
	}

	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return authHeader[len(bearerPrefix):], nil
}

// CreateTokenPair creates both access and refresh tokens
func CreateTokenPair(manager JWTManager, userID xid.ID, orgID *xid.ID, email, username string, scopes, roles, permissions []string) (accessToken, refreshToken string, err error) {
	// Create access token
	accessClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: userID.String(),
		},
		UserID:         userID,
		OrganizationID: orgID,
		Email:          email,
		Username:       username,
		TokenType:      TokenTypeAccess,
		Scopes:         scopes,
		Roles:          roles,
		Permissions:    permissions,
	}

	accessToken, err = manager.GenerateToken(accessClaims)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Create refresh token
	refreshClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: userID.String(),
		},
		UserID:         userID,
		OrganizationID: orgID,
		Email:          email,
		Username:       username,
		TokenType:      TokenTypeRefresh,
	}

	refreshToken, err = manager.GenerateToken(refreshClaims)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// ValidateAndExtractClaims is a convenience function to validate token and extract claims
func ValidateAndExtractClaims(manager JWTManager, tokenString string, expectedTokenType TokenType) (*CustomClaims, error) {
	claims, err := manager.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if expectedTokenType != "" && claims.TokenType != expectedTokenType {
		return nil, fmt.Errorf("invalid token type: expected %s, got %s", expectedTokenType, claims.TokenType)
	}

	return claims, nil
}

// IsTokenExpired checks if a token is expired without full validation
func IsTokenExpired(tokenString string) (bool, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &CustomClaims{})
	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return false, fmt.Errorf("failed to parse token claims")
	}

	if claims.ExpiresAt == nil {
		return false, nil // Token doesn't expire
	}

	return time.Now().After(claims.ExpiresAt.Time), nil
}

// GetTokenRemainingTime returns the remaining time before token expires
func GetTokenRemainingTime(tokenString string) (time.Duration, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &CustomClaims{})
	if err != nil {
		return 0, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return 0, fmt.Errorf("failed to parse token claims")
	}

	if claims.ExpiresAt == nil {
		return time.Duration(0), nil // Token doesn't expire
	}

	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining < 0 {
		return 0, nil // Token is expired
	}

	return remaining, nil
}
