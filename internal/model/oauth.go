package model

import (
	"time"

	"github.com/rs/xid"
)

// OAuthClient represents an OAuth2 client application
type OAuthClient struct {
	Base
	AuditBase
	ClientID                  string   `json:"clientId" example:"client_123abc" doc:"OAuth client ID"`
	ClientSecret              string   `json:"clientSecret,omitempty" example:"secret_xyz789" doc:"OAuth client secret (write-only)"`
	ClientName                string   `json:"clientName" example:"MyApp" doc:"Client application name"`
	ClientDescription         string   `json:"clientDescription,omitempty" example:"My application description" doc:"Client description"`
	ClientURI                 string   `json:"clientUri,omitempty" example:"https://myapp.com" doc:"Client website URL"`
	LogoURI                   string   `json:"logoUri,omitempty" example:"https://myapp.com/logo.png" doc:"Client logo URL"`
	RedirectURIs              []string `json:"redirectUris" example:"[\"https://myapp.com/callback\"]" doc:"Allowed redirect URIs"`
	PostLogoutRedirectURIs    []string `json:"postLogoutRedirectUris,omitempty" example:"[\"https://myapp.com/logout\"]" doc:"Post-logout redirect URIs"`
	OrganizationID            *xid.ID  `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Public                    bool     `json:"public" example:"false" doc:"Whether client is public (no secret)"`
	Active                    bool     `json:"active" example:"true" doc:"Whether client is active"`
	AllowedCORSOrigins        []string `json:"allowedCorsOrigins,omitempty" example:"[\"https://myapp.com\"]" doc:"Allowed CORS origins"`
	AllowedGrantTypes         []string `json:"allowedGrantTypes" example:"[\"authorization_code\", \"refresh_token\"]" doc:"Allowed grant types"`
	TokenExpirySeconds        int      `json:"tokenExpirySeconds" example:"3600" doc:"Access token expiry in seconds"`
	RefreshTokenExpirySeconds int      `json:"refreshTokenExpirySeconds" example:"2592000" doc:"Refresh token expiry in seconds"`
	AuthCodeExpirySeconds     int      `json:"authCodeExpirySeconds" example:"600" doc:"Authorization code expiry in seconds"`
	RequiresPKCE              bool     `json:"requiresPkce" example:"true" doc:"Whether PKCE is required"`
	RequiresConsent           bool     `json:"requiresConsent" example:"true" doc:"Whether user consent is required"`

	// Relationships
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
	Scopes       []OAuthScope         `json:"scopes,omitempty" doc:"Available scopes for this client"`
	Stats        *OAuthClientStats    `json:"stats,omitempty" doc:"Client usage statistics"`
}

// OAuthClientSummary represents a simplified OAuth client for listings
type OAuthClientSummary struct {
	ID         xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Client ID"`
	ClientID   string     `json:"clientId" example:"client_123abc" doc:"OAuth client ID"`
	ClientName string     `json:"clientName" example:"MyApp" doc:"Client name"`
	LogoURI    string     `json:"logoUri,omitempty" example:"https://myapp.com/logo.png" doc:"Logo URL"`
	Public     bool       `json:"public" example:"false" doc:"Whether client is public"`
	Active     bool       `json:"active" example:"true" doc:"Whether client is active"`
	TokenCount int        `json:"tokenCount" example:"150" doc:"Active token count"`
	LastUsed   *time.Time `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
	CreatedAt  time.Time  `json:"createdAt" example:"2023-01-01T10:00:00Z" doc:"Creation timestamp"`
}

// CreateOAuthClientRequest represents a request to create an OAuth client
type CreateOAuthClientRequest struct {
	ClientName                string   `json:"clientName" example:"MyApp" doc:"Client application name"`
	ClientDescription         *string  `json:"clientDescription,omitempty" example:"My application" doc:"Client description"`
	ClientURI                 *string  `json:"clientUri,omitempty" example:"https://myapp.com" doc:"Client website URL"`
	LogoURI                   *string  `json:"logoUri,omitempty" example:"https://myapp.com/logo.png" doc:"Client logo URL"`
	RedirectURIs              []string `json:"redirectUris" example:"[\"https://myapp.com/callback\"]" doc:"Redirect URIs"`
	PostLogoutRedirectURIs    []string `json:"postLogoutRedirectUris,omitempty" example:"[\"https://myapp.com/logout\"]" doc:"Post-logout redirect URIs"`
	Public                    bool     `json:"public" example:"false" doc:"Whether client is public"`
	AllowedCORSOrigins        []string `json:"allowedCorsOrigins,omitempty" example:"[\"https://myapp.com\"]" doc:"Allowed CORS origins"`
	AllowedGrantTypes         []string `json:"allowedGrantTypes,omitempty" example:"[\"authorization_code\"]" doc:"Allowed grant types"`
	TokenExpirySeconds        int      `json:"tokenExpirySeconds,omitempty" example:"3600" doc:"Token expiry seconds"`
	RefreshTokenExpirySeconds int      `json:"refreshTokenExpirySeconds,omitempty" example:"2592000" doc:"Refresh token expiry seconds"`
	AuthCodeExpirySeconds     int      `json:"authCodeExpirySeconds,omitempty" example:"600" doc:"Auth code expiry seconds"`
	RequiresPKCE              bool     `json:"requiresPkce" example:"true" doc:"Require PKCE"`
	RequiresConsent           bool     `json:"requiresConsent" example:"true" doc:"Require user consent"`
	ScopeNames                []string `json:"scopeNames,omitempty" example:"[\"read\", \"write\"]" doc:"Initial scopes"`
}

// CreateOAuthClientResponse represents the response to OAuth client creation
type CreateOAuthClientResponse struct {
	Client       OAuthClient `json:"client" doc:"Created OAuth client"`
	ClientSecret string      `json:"clientSecret" example:"secret_xyz789" doc:"Generated client secret"`
}

// UpdateOAuthClientRequest represents a request to update an OAuth client
type UpdateOAuthClientRequest struct {
	ClientName                string   `json:"clientName,omitempty" example:"Updated App" doc:"Updated client name"`
	ClientDescription         string   `json:"clientDescription,omitempty" example:"Updated description" doc:"Updated description"`
	ClientURI                 string   `json:"clientUri,omitempty" example:"https://updated.com" doc:"Updated client URI"`
	LogoURI                   string   `json:"logoUri,omitempty" example:"https://updated.com/logo.png" doc:"Updated logo URI"`
	RedirectURIs              []string `json:"redirectUris,omitempty" doc:"Updated redirect URIs"`
	PostLogoutRedirectURIs    []string `json:"postLogoutRedirectUris,omitempty" doc:"Updated post-logout URIs"`
	AllowedCORSOrigins        []string `json:"allowedCorsOrigins,omitempty" doc:"Updated CORS origins"`
	AllowedGrantTypes         []string `json:"allowedGrantTypes,omitempty" doc:"Updated grant types"`
	TokenExpirySeconds        int      `json:"tokenExpirySeconds,omitempty" example:"7200" doc:"Updated token expiry"`
	RefreshTokenExpirySeconds int      `json:"refreshTokenExpirySeconds,omitempty" example:"5184000" doc:"Updated refresh token expiry"`
	AuthCodeExpirySeconds     int      `json:"authCodeExpirySeconds,omitempty" example:"300" doc:"Updated auth code expiry"`
	RequiresPKCE              bool     `json:"requiresPkce,omitempty" example:"false" doc:"Updated PKCE requirement"`
	RequiresConsent           bool     `json:"requiresConsent,omitempty" example:"false" doc:"Updated consent requirement"`
	Active                    bool     `json:"active,omitempty" example:"true" doc:"Updated active status"`
}

// RegenerateClientSecretResponse represents the response to client secret regeneration
type RegenerateClientSecretResponse struct {
	ClientSecret string `json:"clientSecret" example:"new_secret_abc123" doc:"New client secret"`
	Message      string `json:"message" example:"Client secret regenerated successfully" doc:"Success message"`
}

// OAuthScope represents an OAuth2 scope
type OAuthScope struct {
	Base
	Name         string `json:"name" example:"read" doc:"Scope name"`
	Description  string `json:"description" example:"Read access to user data" doc:"Scope description"`
	DefaultScope bool   `json:"defaultScope" example:"false" doc:"Whether scope is included by default"`
	Public       bool   `json:"public" example:"true" doc:"Whether scope can be requested by any client"`
}

// CreateOAuthScopeRequest represents a request to create an OAuth scope
type CreateOAuthScopeRequest struct {
	Name         string `json:"name" example:"write" doc:"Scope name"`
	Description  string `json:"description" example:"Write access to user data" doc:"Scope description"`
	DefaultScope bool   `json:"defaultScope" example:"false" doc:"Set as default scope"`
	Public       bool   `json:"public" example:"true" doc:"Make scope public"`
}

// UpdateOAuthScopeRequest represents a request to update an OAuth scope
type UpdateOAuthScopeRequest struct {
	Description  string `json:"description,omitempty" example:"Updated description" doc:"Updated description"`
	DefaultScope bool   `json:"defaultScope,omitempty" example:"true" doc:"Updated default status"`
	Public       bool   `json:"public,omitempty" example:"false" doc:"Updated public status"`
}

// OAuthToken represents an OAuth2 access/refresh token
type OAuthToken struct {
	Base
	AccessToken           string     `json:"accessToken,omitempty" example:"access_token_123" doc:"Access token (write-only)"`
	RefreshToken          string     `json:"refreshToken,omitempty" example:"refresh_token_456" doc:"Refresh token (write-only)"`
	TokenType             string     `json:"tokenType" example:"bearer" doc:"Token type"`
	ClientID              xid.ID     `json:"clientId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"OAuth client ID"`
	UserID                xid.ID     `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	OrganizationID        *xid.ID    `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	ScopeNames            []string   `json:"scopeNames,omitempty" example:"[\"read\", \"write\"]" doc:"Granted scopes"`
	ExpiresIn             int        `json:"expiresIn" example:"3600" doc:"Token expiry in seconds"`
	ExpiresAt             time.Time  `json:"expiresAt" example:"2023-01-01T13:00:00Z" doc:"Token expiration timestamp"`
	RefreshTokenExpiresAt *time.Time `json:"refreshTokenExpiresAt,omitempty" example:"2023-01-31T12:00:00Z" doc:"Refresh token expiration"`
	Revoked               bool       `json:"revoked" example:"false" doc:"Whether token is revoked"`
	RevokedAt             *time.Time `json:"revokedAt,omitempty" example:"2023-01-01T14:00:00Z" doc:"Token revocation timestamp"`
	IPAddress             string     `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address when token was issued"`
	UserAgent             string     `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent when token was issued"`

	// Relationships
	Client       *OAuthClientSummary  `json:"client,omitempty" doc:"OAuth client information"`
	User         *UserSummary         `json:"user,omitempty" doc:"User information"`
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
	Scopes       []OAuthScope         `json:"scopes,omitempty" doc:"Granted scopes"`
}

// OAuthTokenSummary represents a simplified OAuth token for listings
type OAuthTokenSummary struct {
	ID         xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Token ID"`
	ClientName string     `json:"clientName" example:"MyApp" doc:"Client name"`
	UserEmail  string     `json:"userEmail" example:"user@example.com" doc:"User email"`
	ScopeNames []string   `json:"scopeNames" example:"[\"read\", \"write\"]" doc:"Granted scopes"`
	ExpiresAt  time.Time  `json:"expiresAt" example:"2023-01-01T13:00:00Z" doc:"Expiration timestamp"`
	Revoked    bool       `json:"revoked" example:"false" doc:"Whether token is revoked"`
	LastUsed   *time.Time `json:"lastUsed,omitempty" example:"2023-01-01T12:30:00Z" doc:"Last usage timestamp"`
	CreatedAt  time.Time  `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Creation timestamp"`
}

// OAuthAuthorization represents an OAuth2 authorization code
type OAuthAuthorization struct {
	Base
	ClientID            xid.ID     `json:"clientId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"OAuth client ID"`
	UserID              xid.ID     `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	OrganizationID      *xid.ID    `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Code                string     `json:"code,omitempty" example:"auth_code_123" doc:"Authorization code (write-only)"`
	CodeChallenge       string     `json:"codeChallenge,omitempty" example:"challenge_abc" doc:"PKCE code challenge"`
	CodeChallengeMethod string     `json:"codeChallengeMethod,omitempty" example:"S256" doc:"PKCE challenge method"`
	RedirectURI         string     `json:"redirectUri" example:"https://myapp.com/callback" doc:"Redirect URI"`
	ScopeNames          []string   `json:"scopeNames,omitempty" example:"[\"read\", \"write\"]" doc:"Requested scopes"`
	Used                bool       `json:"used" example:"false" doc:"Whether authorization code was used"`
	UsedAt              *time.Time `json:"usedAt,omitempty" example:"2023-01-01T12:05:00Z" doc:"When code was used"`
	ExpiresAt           time.Time  `json:"expiresAt" example:"2023-01-01T12:10:00Z" doc:"Code expiration timestamp"`
	State               string     `json:"state,omitempty" example:"state_xyz" doc:"OAuth state parameter"`
	Nonce               string     `json:"nonce,omitempty" example:"nonce_abc" doc:"OpenID Connect nonce"`

	// Relationships
	Client       *OAuthClientSummary  `json:"client,omitempty" doc:"OAuth client information"`
	User         *UserSummary         `json:"user,omitempty" doc:"User information"`
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
	Scopes       []OAuthScope         `json:"scopes,omitempty" doc:"Requested scopes"`
}

// AuthorizeRequest represents an OAuth2 authorization request
type AuthorizeRequest struct {
	ResponseType        string  `json:"responseType" example:"code" doc:"OAuth response type"`
	ClientID            string  `json:"clientId" example:"client_123abc" doc:"OAuth client ID"`
	RedirectURI         string  `json:"redirectUri" example:"https://myapp.com/callback" doc:"Redirect URI"`
	Scope               string  `json:"scope,omitempty" example:"read write" doc:"Requested scopes (space-separated)"`
	State               string  `json:"state,omitempty" example:"state_xyz789" doc:"OAuth state parameter"`
	CodeChallenge       *string `json:"codeChallenge,omitempty" example:"challenge_abc123" doc:"PKCE code challenge"`
	CodeChallengeMethod *string `json:"codeChallengeMethod,omitempty" example:"S256" doc:"PKCE challenge method"`
	Nonce               *string `json:"nonce,omitempty" example:"nonce_abc123" doc:"OpenID Connect nonce"`
}

// AuthorizeResponse represents an OAuth2 authorization response
type AuthorizeResponse struct {
	Code        string `json:"code,omitempty" example:"auth_code_123" doc:"Authorization code"`
	State       string `json:"state,omitempty" example:"state_xyz789" doc:"OAuth state parameter"`
	RedirectURI string `json:"redirectUri" example:"https://myapp.com/callback?code=auth_code_123&state=state_xyz789" doc:"Full redirect URI"`
	ExpiresIn   int    `json:"expiresIn" example:"600" doc:"Code expiry in seconds"`
}

// TokenRequest represents an OAuth2 token request
type TokenRequest struct {
	GrantType    string `json:"grantType" example:"authorization_code" doc:"OAuth grant type"`
	Code         string `json:"code,omitempty" example:"auth_code_123" doc:"Authorization code (for authorization_code grant)"`
	RedirectURI  string `json:"redirectUri,omitempty" example:"https://myapp.com/callback" doc:"Redirect URI"`
	ClientID     string `json:"clientId" example:"client_123abc" doc:"OAuth client ID"`
	ClientSecret string `json:"clientSecret,omitempty" example:"secret_xyz789" doc:"OAuth client secret"`
	RefreshToken string `json:"refreshToken,omitempty" example:"refresh_token_456" doc:"Refresh token (for refresh_token grant)"`
	CodeVerifier string `json:"codeVerifier,omitempty" example:"verifier_abc123" doc:"PKCE code verifier"`
	Scope        string `json:"scope,omitempty" example:"read write" doc:"Requested scopes"`
}

// TokenResponse represents an OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"accessToken" example:"access_token_123" doc:"Access token"`
	TokenType    string `json:"tokenType" example:"bearer" doc:"Token type"`
	ExpiresIn    int    `json:"expiresIn" example:"3600" doc:"Token expiry in seconds"`
	RefreshToken string `json:"refreshToken,omitempty" example:"refresh_token_456" doc:"Refresh token"`
	Scope        string `json:"scope,omitempty" example:"read write" doc:"Granted scopes"`
	IDToken      string `json:"idToken,omitempty" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." doc:"OpenID Connect ID token"`
}

// RevokeTokenRequest represents a token revocation request
type RevokeTokenRequest struct {
	Token         string `json:"token" example:"access_token_123" doc:"Token to revoke"`
	TokenTypeHint string `json:"tokenTypeHint,omitempty" example:"access_token" doc:"Token type hint"`
	ClientID      string `json:"clientId" example:"client_123abc" doc:"OAuth client ID"`
	ClientSecret  string `json:"clientSecret,omitempty" example:"secret_xyz789" doc:"OAuth client secret"`
}

// IntrospectTokenRequest represents a token introspection request
type IntrospectTokenRequest struct {
	Token         string `json:"token" example:"access_token_123" doc:"Token to introspect"`
	TokenTypeHint string `json:"tokenTypeHint,omitempty" example:"access_token" doc:"Token type hint"`
	ClientID      string `json:"clientId" example:"client_123abc" doc:"OAuth client ID"`
	ClientSecret  string `json:"clientSecret,omitempty" example:"secret_xyz789" doc:"OAuth client secret"`
}

// IntrospectTokenResponse represents a token introspection response
type IntrospectTokenResponse struct {
	Active    bool     `json:"active" example:"true" doc:"Whether token is active"`
	Scope     string   `json:"scope,omitempty" example:"read write" doc:"Token scopes"`
	ClientID  string   `json:"clientId,omitempty" example:"client_123abc" doc:"Client ID"`
	Username  string   `json:"username,omitempty" example:"user@example.com" doc:"Username"`
	TokenType string   `json:"tokenType,omitempty" example:"bearer" doc:"Token type"`
	ExpiresAt int64    `json:"exp,omitempty" example:"1672531200" doc:"Expiration timestamp (Unix)"`
	IssuedAt  int64    `json:"iat,omitempty" example:"1672527600" doc:"Issued timestamp (Unix)"`
	Subject   string   `json:"sub,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Subject (user ID)"`
	Audience  []string `json:"aud,omitempty" example:"[\"api.example.com\"]" doc:"Audience"`
	Issuer    string   `json:"iss,omitempty" example:"https://auth.example.com" doc:"Issuer"`
}

// OAuthClientListRequest represents a request to list OAuth clients
type OAuthClientListRequest struct {
	PaginationParams
	OrganizationID OptionalParam[xid.ID] `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization" query:"organizationId"`
	Public         OptionalParam[bool]   `json:"public,omitempty" example:"false" doc:"Filter by public status" query:"public"`
	Active         OptionalParam[bool]   `json:"active,omitempty" example:"true" doc:"Filter by active status" query:"active"`
	Search         string                `json:"search,omitempty" example:"myapp" doc:"Search in client name" query:"search"`
}

// OAuthClientListResponse represents a list of OAuth clients
type OAuthClientListResponse = PaginatedOutput[OAuthClientSummary]

// OAuthTokenListRequest represents a request to list OAuth tokens
type OAuthTokenListRequest struct {
	PaginationParams
	ClientID       OptionalParam[xid.ID] `json:"clientId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by client" query:"clientId"`
	UserID         OptionalParam[xid.ID] `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user" query:"userId"`
	OrganizationID OptionalParam[xid.ID] `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization" query:"organizationId"`
	Revoked        OptionalParam[bool]   `json:"revoked,omitempty" example:"false" doc:"Filter by revoked status" query:"revoked"`
	Expired        OptionalParam[bool]   `json:"expired,omitempty" example:"false" doc:"Filter by expired status" query:"expired"`
	Scope          string                `json:"scope,omitempty" example:"read" doc:"Filter by scope" query:"scope"`
}

// OAuthTokenListResponse represents a list of OAuth tokens
type OAuthTokenListResponse = PaginatedOutput[OAuthTokenSummary]

// OAuthScopeListResponse represents a list of OAuth scopes
type OAuthScopeListResponse = PaginatedOutput[OAuthScope]

// OAuthStats represents OAuth statistics
type OAuthStats struct {
	TotalClients        int `json:"totalClients" example:"25" doc:"Total OAuth clients"`
	ActiveClients       int `json:"activeClients" example:"20" doc:"Active OAuth clients"`
	PublicClients       int `json:"publicClients" example:"5" doc:"Public OAuth clients"`
	TotalTokens         int `json:"totalTokens" example:"500" doc:"Total issued tokens"`
	ActiveTokens        int `json:"activeTokens" example:"150" doc:"Active tokens"`
	RevokedTokens       int `json:"revokedTokens" example:"100" doc:"Revoked tokens"`
	ExpiredTokens       int `json:"expiredTokens" example:"250" doc:"Expired tokens"`
	TotalAuthorizations int `json:"totalAuthorizations" example:"1000" doc:"Total authorizations"`
	TotalScopes         int `json:"totalScopes" example:"10" doc:"Total scopes"`
	TokensToday         int `json:"tokensToday" example:"25" doc:"Tokens issued today"`
	AuthorizationsToday int `json:"authorizationsToday" example:"50" doc:"Authorizations today"`
}

// OAuthClientStats represents OAuth client statistics
type OAuthClientStats struct {
	TotalTokens             int        `json:"totalTokens" example:"150" doc:"Total tokens issued"`
	ActiveTokens            int        `json:"activeTokens" example:"50" doc:"Active tokens"`
	TotalAuthorizations     int        `json:"totalAuthorizations" example:"300" doc:"Total authorizations"`
	LastUsed                *time.Time `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
	TokensThisMonth         int        `json:"tokensThisMonth" example:"25" doc:"Tokens issued this month"`
	AuthorizationsThisMonth int        `json:"authorizationsThisMonth" example:"50" doc:"Authorizations this month"`
	UniqueUsers             int        `json:"uniqueUsers" example:"75" doc:"Unique users who authorized"`
	SuccessRate             float64    `json:"successRate" example:"95.5" doc:"Authorization success rate percentage"`
}

// BulkRevokeTokensRequest represents a bulk token revocation request
type BulkRevokeTokensRequest struct {
	ClientID       *xid.ID `json:"clientId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Revoke tokens for specific client"`
	UserID         *xid.ID `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Revoke tokens for specific user"`
	OrganizationID *xid.ID `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Revoke tokens for specific organization"`
	Scope          string  `json:"scope,omitempty" example:"read" doc:"Revoke tokens with specific scope"`
	Reason         string  `json:"reason,omitempty" example:"Security incident" doc:"Reason for bulk revocation"`
}

// BulkRevokeTokensResponse represents bulk token revocation response
type BulkRevokeTokensResponse struct {
	RevokedCount int    `json:"revokedCount" example:"25" doc:"Number of tokens revoked"`
	Message      string `json:"message" example:"25 tokens revoked successfully" doc:"Success message"`
}

// OAuthClientCredentials represents client credentials for machine-to-machine auth
type OAuthClientCredentials struct {
	ClientID     string `json:"clientId" example:"client_123abc" doc:"Client ID"`
	ClientSecret string `json:"clientSecret" example:"secret_xyz789" doc:"Client secret"`
	GrantType    string `json:"grantType" example:"client_credentials" doc:"Grant type"`
	Scope        string `json:"scope,omitempty" example:"api:read api:write" doc:"Requested scopes"`
}

// ClientCredentialsResponse represents client credentials token response
type ClientCredentialsResponse struct {
	AccessToken string `json:"accessToken" example:"access_token_123" doc:"Access token"`
	TokenType   string `json:"tokenType" example:"bearer" doc:"Token type"`
	ExpiresIn   int    `json:"expiresIn" example:"3600" doc:"Token expiry in seconds"`
	Scope       string `json:"scope,omitempty" example:"api:read api:write" doc:"Granted scopes"`
}

type TokenUsageStats struct {
	TotalTokens     int            `json:"totalTokens"`
	ActiveTokens    int            `json:"activeTokens"`
	ExpiredTokens   int            `json:"expiredTokens"`
	RevokedTokens   int            `json:"revokedTokens"`
	DailyBreakdown  []DailyUsage   `json:"dailyBreakdown"`
	ClientBreakdown map[string]int `json:"clientBreakdown"`
	ScopeBreakdown  map[string]int `json:"scopeBreakdown"`
}

// DailyUsage represents daily usage statistics
type DailyUsage struct {
	Date     time.Time `json:"date"`
	Messages int       `json:"messages"`
	Segments int       `json:"segments"`
	Cost     float64   `json:"cost"`
}
