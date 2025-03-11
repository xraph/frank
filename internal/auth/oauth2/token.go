package oauth2

import (
	"time"
)

// AuthorizationRequest represents an OAuth2 authorization request
type AuthorizationRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scopes              []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Client              *ClientConfig
}

// AuthorizationCode represents an OAuth2 authorization code
type AuthorizationCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	ExpiresAt           time.Time
	Scopes              []string
	UserID              string
	OrganizationID      string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Used                bool
	UsedAt              *time.Time
}

// TokenInfo represents information about an issued OAuth2 token
type TokenInfo struct {
	AccessToken    string
	RefreshToken   string
	ClientID       string
	Subject        string
	UserID         string
	OrganizationID string
	Scopes         []string
	ExpiresIn      int
	ExpiresAt      time.Time
	TokenType      string
	Revoked        bool
	RevokedAt      *time.Time
	CreatedAt      time.Time
	IPAddress      string
	UserAgent      string
}

// TokenResponse represents the response format for a token request
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"` // For OpenID Connect
}

// ClientConfig represents an OAuth2 client configuration
type ClientConfig struct {
	ClientID                  string
	ClientSecret              string
	RedirectURIs              []string
	Name                      string
	Description               string
	OrganizationID            string
	Public                    bool
	Active                    bool
	AllowedGrantTypes         []string
	AllowedScopes             []string
	TokenExpirySeconds        int
	RefreshTokenExpirySeconds int
	AuthCodeExpirySeconds     int
	RequiresPKCE              bool
	RequiresConsent           bool
}

// TokenRequest represents a token request
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
	CodeVerifier string
	Scope        string
}
