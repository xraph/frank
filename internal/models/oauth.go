package models

import (
	"time"

	"github.com/uptrace/bun"
	"github.com/xraph/frank/pkg/model"
)

// APIKey model
type APIKey struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:api_keys,alias:ak"`

	Name            string                 `bun:"name,notnull" json:"name"`
	PublicKey       string                 `bun:"public_key,unique,notnull" json:"public_key"`
	SecretKey       string                 `bun:"secret_key,unique" json:"-"`
	HashedSecretKey string                 `bun:"hashed_secret_key,unique,notnull" json:"-"`
	Key             *string                `bun:"key,unique" json:"-"`        // Legacy
	HashedKey       *string                `bun:"hashed_key,unique" json:"-"` // Legacy
	UserID          *string                `bun:"user_id,type:varchar(20)" json:"user_id,omitempty"`
	OrganizationID  *string                `bun:"organization_id,type:varchar(20)" json:"organization_id,omitempty"`
	Type            model.APIKeyType       `bun:"type,notnull,default:'server'" json:"type"`
	Environment     model.Environment      `bun:"environment,notnull,default:'test'" json:"environment"`
	Active          bool                   `bun:"active,notnull,default:true" json:"active"`
	Permissions     []string               `bun:"permissions,type:jsonb" json:"permissions,omitempty"`
	Scopes          []string               `bun:"scopes,type:jsonb" json:"scopes,omitempty"`
	IPWhitelist     []string               `bun:"ip_whitelist,type:text[],array" json:"ip_whitelist,omitempty"`
	RateLimits      map[string]interface{} `bun:"rate_limits,type:jsonb" json:"rate_limits,omitempty"`
	Metadata        map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`
	LastUsed        *time.Time             `bun:"last_used" json:"last_used,omitempty"`
	ExpiresAt       *time.Time             `bun:"expires_at" json:"expires_at,omitempty"`

	// Relations
	User         *User             `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	Organization *Organization     `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
	Activities   []*APIKeyActivity `bun:"rel:has-many,join:id=key_id" json:"activities,omitempty"`
}

// APIKeyActivity model
type APIKeyActivity struct {
	CommonModel
	bun.BaseModel `bun:"table:api_key_activities,alias:aka"`

	KeyID        string                 `bun:"key_id,notnull,type:varchar(20)" json:"key_id"`
	Action       string                 `bun:"action,notnull" json:"action"`
	Endpoint     *string                `bun:"endpoint" json:"endpoint,omitempty"`
	Method       *string                `bun:"method" json:"method,omitempty"`
	StatusCode   *int                   `bun:"status_code" json:"status_code,omitempty"`
	ResponseTime *int                   `bun:"response_time" json:"response_time,omitempty"`
	IPAddress    *string                `bun:"ip_address" json:"ip_address,omitempty"`
	UserAgent    *string                `bun:"user_agent" json:"user_agent,omitempty"`
	Success      bool                   `bun:"success,notnull,default:true" json:"success"`
	Error        *string                `bun:"error" json:"error,omitempty"`
	Timestamp    time.Time              `bun:"timestamp,notnull" json:"timestamp"`
	Metadata     map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`

	// Relations
	Key *APIKey `bun:"rel:belongs-to,join:key_id=id" json:"key,omitempty"`
}

// OAuthClient model
type OAuthClient struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:oauth_clients,alias:oc"`

	ClientID                  string   `bun:"client_id,unique,notnull" json:"client_id"`
	ClientSecret              string   `bun:"client_secret,notnull" json:"-"`
	ClientName                string   `bun:"client_name,notnull" json:"client_name"`
	ClientDescription         *string  `bun:"client_description" json:"client_description,omitempty"`
	ClientURI                 *string  `bun:"client_uri" json:"client_uri,omitempty"`
	LogoURI                   *string  `bun:"logo_uri" json:"logo_uri,omitempty"`
	RedirectURIs              []string `bun:"redirect_uris,type:text[],array,notnull" json:"redirect_uris"`
	PostLogoutRedirectURIs    []string `bun:"post_logout_redirect_uris,type:text[],array" json:"post_logout_redirect_uris,omitempty"`
	OrganizationID            *string  `bun:"organization_id,type:varchar(20)" json:"organization_id,omitempty"`
	Public                    bool     `bun:"public,notnull,default:false" json:"public"`
	Active                    bool     `bun:"active,notnull,default:true" json:"active"`
	AllowedCORSOrigins        []string `bun:"allowed_cors_origins,type:text[],array" json:"allowed_cors_origins,omitempty"`
	AllowedGrantTypes         []string `bun:"allowed_grant_types,type:text[],array,notnull" json:"allowed_grant_types"`
	TokenExpirySeconds        int      `bun:"token_expiry_seconds,notnull,default:3600" json:"token_expiry_seconds"`
	RefreshTokenExpirySeconds int      `bun:"refresh_token_expiry_seconds,notnull,default:2592000" json:"refresh_token_expiry_seconds"`
	AuthCodeExpirySeconds     int      `bun:"auth_code_expiry_seconds,notnull,default:600" json:"auth_code_expiry_seconds"`
	RequiresPKCE              bool     `bun:"requires_pkce,notnull,default:true" json:"requires_pkce"`
	RequiresConsent           bool     `bun:"requires_consent,notnull,default:true" json:"requires_consent"`

	// Relations
	Organization   *Organization         `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
	Tokens         []*OAuthToken         `bun:"rel:has-many,join:id=client_id" json:"tokens,omitempty"`
	Authorizations []*OAuthAuthorization `bun:"rel:has-many,join:id=client_id" json:"authorizations,omitempty"`
	Scopes         []*OAuthScope         `bun:"rel:many-to-many,join:OAuthClientScopes" json:"scopes,omitempty"`
}

// OAuthToken model
type OAuthToken struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:oauth_tokens,alias:ot"`

	AccessToken           string     `bun:"access_token,unique,notnull" json:"-"`
	RefreshToken          *string    `bun:"refresh_token,unique" json:"-"`
	TokenType             string     `bun:"token_type,notnull,default:'bearer'" json:"token_type"`
	ClientID              string     `bun:"client_id,notnull,type:varchar(20)" json:"client_id"`
	UserID                string     `bun:"user_id,notnull,type:varchar(20)" json:"user_id"`
	OrganizationID        *string    `bun:"organization_id,type:varchar(20)" json:"organization_id,omitempty"`
	ScopeNames            []string   `bun:"scope_names,type:text[],array" json:"scope_names,omitempty"`
	ExpiresIn             int        `bun:"expires_in,notnull,default:3600" json:"expires_in"`
	ExpiresAt             time.Time  `bun:"expires_at,notnull" json:"expires_at"`
	RefreshTokenExpiresAt *time.Time `bun:"refresh_token_expires_at" json:"refresh_token_expires_at,omitempty"`
	Revoked               bool       `bun:"revoked,notnull,default:false" json:"revoked"`
	RevokedAt             *time.Time `bun:"revoked_at" json:"revoked_at,omitempty"`
	IPAddress             *string    `bun:"ip_address" json:"ip_address,omitempty"`
	UserAgent             *string    `bun:"user_agent" json:"user_agent,omitempty"`

	// Relations
	Client *OAuthClient  `bun:"rel:belongs-to,join:client_id=id" json:"client,omitempty"`
	User   *User         `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	Scopes []*OAuthScope `bun:"rel:many-to-many,join:OAuthTokenScopes" json:"scopes,omitempty"`
}

// OAuthAuthorization model
type OAuthAuthorization struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:oauth_authorizations,alias:oa"`

	ClientID            string     `bun:"client_id,notnull,type:varchar(20)" json:"client_id"`
	UserID              string     `bun:"user_id,notnull,type:varchar(20)" json:"user_id"`
	OrganizationID      *string    `bun:"organization_id,type:varchar(20)" json:"organization_id,omitempty"`
	Code                *string    `bun:"code,unique" json:"-"`
	CodeChallenge       *string    `bun:"code_challenge" json:"-"`
	CodeChallengeMethod *string    `bun:"code_challenge_method" json:"-"`
	RedirectURI         string     `bun:"redirect_uri,notnull" json:"redirect_uri"`
	ScopeNames          []string   `bun:"scope_names,type:text[],array" json:"scope_names,omitempty"`
	Used                bool       `bun:"used,notnull,default:false" json:"used"`
	UsedAt              *time.Time `bun:"used_at" json:"used_at,omitempty"`
	ExpiresAt           time.Time  `bun:"expires_at,notnull" json:"expires_at"`
	State               *string    `bun:"state" json:"state,omitempty"`
	Nonce               *string    `bun:"nonce" json:"nonce,omitempty"`
	UserAgent           *string    `bun:"user_agent" json:"user_agent,omitempty"`
	IPAddress           *string    `bun:"ip_address" json:"ip_address,omitempty"`

	// Relations
	Client *OAuthClient  `bun:"rel:belongs-to,join:client_id=id" json:"client,omitempty"`
	User   *User         `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	Scopes []*OAuthScope `bun:"rel:many-to-many,join:OAuthAuthorizationScopes" json:"scopes,omitempty"`
}

// OAuthScope model
type OAuthScope struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:oauth_scopes,alias:os"`

	Name         string `bun:"name,unique,notnull" json:"name"`
	Description  string `bun:"description,notnull" json:"description"`
	DefaultScope bool   `bun:"default_scope,notnull,default:false" json:"default_scope"`
	Public       bool   `bun:"public,notnull,default:true" json:"public"`

	// Relations
	Clients        []*OAuthClient        `bun:"rel:many-to-many,join:OAuthClientScopes" json:"clients,omitempty"`
	Tokens         []*OAuthToken         `bun:"rel:many-to-many,join:OAuthTokenScopes" json:"tokens,omitempty"`
	Authorizations []*OAuthAuthorization `bun:"rel:many-to-many,join:OAuthAuthorizationScopes" json:"authorizations,omitempty"`
}

// Join tables for OAuth many-to-many relationships
type OAuthClientScope struct {
	ClientID  string    `bun:"client_id,pk,type:varchar(20)"`
	ScopeID   string    `bun:"scope_id,pk,type:varchar(20)"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`
}

type OAuthTokenScope struct {
	TokenID   string    `bun:"token_id,pk,type:varchar(20)"`
	ScopeID   string    `bun:"scope_id,pk,type:varchar(20)"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`
}

type OAuthAuthorizationScope struct {
	AuthorizationID string    `bun:"authorization_id,pk,type:varchar(20)"`
	ScopeID         string    `bun:"scope_id,pk,type:varchar(20)"`
	CreatedAt       time.Time `bun:"created_at,notnull,default:current_timestamp"`
}
