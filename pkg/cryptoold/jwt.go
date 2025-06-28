package cryptoold

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/xraph/frank/pkg/errors"
)

// JWTClaims represents JWT claims with standard and custom fields
type JWTClaims struct {
	jwt.RegisteredClaims
	UserID         string                 `json:"user_id,omitempty"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	Email          string                 `json:"email,omitempty"`
	Roles          []string               `json:"roles,omitempty"`
	Permissions    []string               `json:"permissions,omitempty"`
	Scopes         []string               `json:"scopes,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	TokenType      string                 `json:"token_type,omitempty"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	SigningMethod string
	SigningKey    []byte
	Issuer        string
	Audience      []string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	SignatureKey  interface{} // Can be []byte for HMAC or *rsa.PrivateKey for RSA
	ValidationKey interface{} // Can be []byte for HMAC or *rsa.PublicKey for RSA
	DefaultExpiry time.Duration
}

// JWTManager handles JWT operations
type JWTManager struct {
	config JWTConfig
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(config JWTConfig) *JWTManager {
	return &JWTManager{
		config: config,
	}
}

// NewJWTConfigRSA creates a new JWT configuration with RSA signing
func NewJWTConfigRSA(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, method string, issuer string, audience []string, expiry time.Duration) *JWTConfig {
	if method == "" {
		method = "RS256"
	}

	return &JWTConfig{
		SigningMethod: method,
		SignatureKey:  privateKey,
		ValidationKey: publicKey,
		DefaultExpiry: expiry,
		Issuer:        issuer,
		Audience:      audience,
	}
}

// LoadRSAPrivateKeyFromFile loads a PEM encoded RSA private key from a file
func LoadRSAPrivateKeyFromFile(file string) (*rsa.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %w", err)
	}

	return ParseRSAPrivateKeyFromPEM(keyData)
}

// LoadRSAPublicKeyFromFile loads a PEM encoded RSA public key from a file
func LoadRSAPublicKeyFromFile(file string) (*rsa.PublicKey, error) {
	keyData, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}

	return ParseRSAPublicKeyFromPEM(keyData)
}

// ParseRSAPrivateKeyFromPEM parses a PEM encoded RSA private key
func ParseRSAPrivateKeyFromPEM(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New(errors.CodeInvalidCredentials, "failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS8
		parsedKey, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		privateKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New(errors.CodeInvalidCredentials, "key is not an RSA private key")
		}

		return privateKey, nil
	}

	return privateKey, nil
}

// ParseRSAPublicKeyFromPEM parses a PEM encoded RSA public key
func ParseRSAPublicKeyFromPEM(keyData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New(errors.CodeInvalidCredentials, "failed to parse PEM block containing the key")
	}

	// Try parsing as PKCS1 public key
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return publicKey, nil
	}

	// Try parsing as X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New(errors.CodeInvalidCredentials, "certificate does not contain an RSA public key")
		}
		return publicKey, nil
	}

	// Try parsing as PKIX public key
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New(errors.CodeInvalidCredentials, "key is not an RSA public key")
	}

	return publicKey, nil
}

// GenerateAccessToken generates a new access token
func (m *JWTManager) GenerateAccessToken(userID, email string, options ...TokenOption) (string, error) {
	return m.generateToken(userID, email, m.config.AccessTTL, "access", options...)
}

// GenerateRefreshToken generates a new refresh token
func (m *JWTManager) GenerateRefreshToken(userID, email string, options ...TokenOption) (string, error) {
	return m.generateToken(userID, email, m.config.RefreshTTL, "refresh", options...)
}

// TokenOption is a function that modifies token claims
type TokenOption func(*JWTClaims)

// WithOrganization adds organization ID to token claims
func WithOrganization(orgID string) TokenOption {
	return func(claims *JWTClaims) {
		claims.OrganizationID = orgID
	}
}

// WithRoles adds roles to token claims
func WithRoles(roles []string) TokenOption {
	return func(claims *JWTClaims) {
		claims.Roles = roles
	}
}

// WithPermissions adds permissions to token claims
func WithPermissions(permissions []string) TokenOption {
	return func(claims *JWTClaims) {
		claims.Permissions = permissions
	}
}

// WithScopes adds scopes to token claims
func WithScopes(scopes []string) TokenOption {
	return func(claims *JWTClaims) {
		claims.Scopes = scopes
	}
}

// WithMetadata adds metadata to token claims
func WithMetadata(metadata map[string]interface{}) TokenOption {
	return func(claims *JWTClaims) {
		claims.Metadata = metadata
	}
}

// WithCustomClaims adds custom claims to token claims
func WithCustomClaims(customClaims map[string]interface{}) TokenOption {
	return func(claims *JWTClaims) {
		if claims.Metadata == nil {
			claims.Metadata = make(map[string]interface{})
		}
		for k, v := range customClaims {
			claims.Metadata[k] = v
		}
	}
}

// WithExpiresAt overrides the default expiration time
func WithExpiresAt(expiresAt time.Time) TokenOption {
	return func(claims *JWTClaims) {
		claims.ExpiresAt = jwt.NewNumericDate(expiresAt)
	}
}

// WithSubject sets the subject claim
func WithSubject(subject string) TokenOption {
	return func(claims *JWTClaims) {
		claims.Subject = subject
	}
}

// generateToken generates a JWT token
func (m *JWTManager) generateToken(userID, email string, ttl time.Duration, tokenType string, options ...TokenOption) (string, error) {
	now := time.Now()

	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    m.config.Issuer,
			Audience:  m.config.Audience,
		},
		UserID:    userID,
		Email:     email,
		TokenType: tokenType,
	}

	// Apply options
	for _, option := range options {
		option(claims)
	}

	// Create token
	token := jwt.NewWithClaims(jwt.GetSigningMethod(m.config.SigningMethod), claims)

	// Sign token
	tokenString, err := token.SignedString(m.config.SigningKey)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeCryptoError, "failed to sign token")
	}

	return tokenString, nil
}

// ValidateToken validates and parses a JWT token
func (m *JWTManager) ValidateToken(tokenString string) (*JWTClaims, error) {
	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if token.Method.Alg() != m.config.SigningMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
		}
		return m.config.SigningKey, nil
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidToken, "token validation failed")
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, errors.Wrap(err, errors.CodeInvalidToken, "failed to parse token")
	}

	// if err != nil {
	// 	// Handle specific JWT errors
	// 	if ve, ok := err.(*jwt.ValidationError); ok {
	// 		if ve.Errors&jwt.ErrTokenExpired != 0 {
	// 			return nil, errors.New(errors.CodeTokenExpired, "token is expired")
	// 		}
	// 		return nil, errors.Wrap(errors.CodeInvalidToken, err, "token validation failed")
	// 	}
	// 	return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to parse token")
	// }

	// Extract claims
	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New(errors.CodeInvalidToken, "invalid token claims")
}

// RefreshToken validates a refresh token and generates a new access token
func (m *JWTManager) RefreshToken(refreshToken string) (string, error) {
	// Validate refresh token
	claims, err := m.ValidateToken(refreshToken)
	if err != nil {
		return "", err
	}

	// Ensure it's a refresh token
	if claims.TokenType != "refresh" {
		return "", errors.New(errors.CodeInvalidRefreshToken, "not a refresh token")
	}

	// Generate new access token
	return m.GenerateAccessToken(claims.UserID, claims.Email,
		WithOrganization(claims.OrganizationID),
		WithRoles(claims.Roles),
		WithPermissions(claims.Permissions),
		WithScopes(claims.Scopes),
		WithMetadata(claims.Metadata),
	)
}

// GenerateToken creates a JWT token with custom claims
func (c *JWTConfig) GenerateToken(subject string, customClaims map[string]interface{}, expiry time.Duration) (string, error) {
	// If expiry is not provided, use the default
	if expiry == 0 {
		expiry = c.DefaultExpiry
	}

	// Create the claims
	now := time.Now()
	expiryTime := now.Add(expiry)

	claims := jwt.MapClaims{
		"sub": subject,
		"iat": now.Unix(),
		"exp": expiryTime.Unix(),
	}

	// Add issuer and audience if provided
	if c.Issuer != "" {
		claims["iss"] = c.Issuer
	}

	if c.Audience != nil {
		claims["aud"] = c.Audience
	}

	// Add custom claims
	for k, v := range customClaims {
		claims[k] = v
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.GetSigningMethod(c.SigningMethod), claims)

	// Sign the token
	signedToken, err := token.SignedString(c.SignatureKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// ValidateToken validates a JWT token and returns its claims
func (c *JWTConfig) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if token.Method.Alg() != c.SigningMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return c.ValidationKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, errors.New(errors.CodeInvalidToken, "invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New(errors.CodeInvalidToken, "invalid claims format")
	}

	// Validate issuer if provided
	if c.Issuer != "" {
		issuer, issuerExists := claims["iss"]
		if !issuerExists || issuer != c.Issuer {
			return nil, errors.New(errors.CodeInvalidToken, "invalid issuer")
		}
	}

	// Validate audience if provided
	if c.Audience != nil {
		aud, audExists := claims["aud"]
		if !audExists {
			return nil, errors.New(errors.CodeInvalidToken, "audience claim not found")
		}

		// Handle both string and slice audience values in the token
		switch tokenAud := aud.(type) {
		case string:
			// Single audience in token, check if it's in our allowed audiences
			found := false
			for _, allowedAud := range c.Audience {
				if tokenAud == allowedAud {
					found = true
					break
				}
			}
			if !found {
				return nil, errors.New(errors.CodeInvalidToken, "invalid audience")
			}
		case []interface{}:
			// Multiple audiences in token, check if any match our allowed audiences
			foundMatch := false
			for _, allowedAud := range c.Audience {
				for _, tokenAudItem := range tokenAud {
					// Convert to string for comparison if needed
					if audStr, ok := tokenAudItem.(string); ok && audStr == allowedAud {
						foundMatch = true
						break
					}
				}
				if foundMatch {
					break
				}
			}
			if !foundMatch {
				return nil, errors.New(errors.CodeInvalidToken, "invalid audience")
			}
		default:
			return nil, errors.New(errors.CodeInvalidToken, "invalid audience format")
		}
	}

	return claims, nil
}

// GetSubjectFromToken extracts the subject claim from a token
func (c *JWTConfig) GetSubjectFromToken(tokenString string) (string, error) {
	claims, err := c.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	// Extract subject
	sub, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New(errors.CodeInvalidToken, "subject claim not found or not a string")
	}

	return sub, nil
}

// ExtractClaimsWithoutValidation extracts claims from a token without validation
// This is useful for debugging or when you just need to see what's in a token
func ExtractClaimsWithoutValidation(tokenString string) (jwt.MapClaims, error) {
	// Parse without validating the signature
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New(errors.CodeInvalidToken, "invalid claims format")
	}

	return claims, nil
}

// IsTokenExpired checks if a token is expired without full validation
func IsTokenExpired(tokenString string) (bool, error) {
	claims, err := ExtractClaimsWithoutValidation(tokenString)
	if err != nil {
		return true, err
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return true, nil
		}
		return false, nil
	}

	return true, errors.New(errors.CodeInvalidToken, "expiration claim not found or invalid format")
}

// GenerateAccessToken creates a JWT access token for OAuth2
func (c *JWTConfig) GenerateAccessToken(userID, clientID string, scopes []string, expiry time.Duration) (string, error) {
	// Prepare custom claims for OAuth2 access token
	customClaims := map[string]interface{}{
		"client_id": clientID,
		"scope":     scopes,
	}

	return c.GenerateToken(userID, customClaims, expiry)
}

// GenerateIDToken creates an OpenID Connect ID token
func (c *JWTConfig) GenerateIDToken(userID string, userData map[string]interface{}, clientID string, nonce string, expiry time.Duration) (string, error) {
	// Prepare custom claims for ID token
	customClaims := map[string]interface{}{
		"aud": clientID,
	}

	// Add user data
	for k, v := range userData {
		// Skip duplicate claims
		if k != "sub" && k != "iss" && k != "aud" && k != "exp" && k != "iat" {
			customClaims[k] = v
		}
	}

	// Add nonce if provided
	if nonce != "" {
		customClaims["nonce"] = nonce
	}

	return c.GenerateToken(userID, customClaims, expiry)
}
