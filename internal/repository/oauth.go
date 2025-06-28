package repository

import (
	"context"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/oauthauthorization"
	"github.com/xraph/frank/ent/oauthclient"
	"github.com/xraph/frank/ent/oauthscope"
	"github.com/xraph/frank/ent/oauthtoken"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// OAuthRepository defines the interface for OAuth data access
type OAuthRepository interface {
	// OAuth Client operations
	CreateClient(ctx context.Context, input CreateOAuthClientInput) (*ent.OAuthClient, error)
	GetClientByID(ctx context.Context, id xid.ID) (*ent.OAuthClient, error)
	GetClientByClientID(ctx context.Context, clientID string) (*ent.OAuthClient, error)
	UpdateClient(ctx context.Context, id xid.ID, input UpdateOAuthClientInput) (*ent.OAuthClient, error)
	DeleteClient(ctx context.Context, id xid.ID) error
	ListClients(ctx context.Context, params ListOAuthClientsParams) (*model.PaginatedOutput[*ent.OAuthClient], error)
	ListClientsByOrganization(ctx context.Context, organizationID xid.ID, params ListOAuthClientsParams) (*model.PaginatedOutput[*ent.OAuthClient], error)

	// OAuth Token operations
	CreateToken(ctx context.Context, input CreateOAuthTokenInput) (*ent.OAuthToken, error)
	GetTokenByAccessToken(ctx context.Context, accessToken string) (*ent.OAuthToken, error)
	GetTokenByRefreshToken(ctx context.Context, refreshToken string) (*ent.OAuthToken, error)
	GetTokenByID(ctx context.Context, id xid.ID) (*ent.OAuthToken, error)
	UpdateToken(ctx context.Context, id xid.ID, input UpdateOAuthTokenInput) (*ent.OAuthToken, error)
	DeleteToken(ctx context.Context, id xid.ID) error
	RevokeToken(ctx context.Context, accessToken string) error
	RevokeTokenByRefreshToken(ctx context.Context, refreshToken string) error
	ListTokens(ctx context.Context, params ListOAuthTokensParams) (*model.PaginatedOutput[*ent.OAuthToken], error)
	ListUserTokens(ctx context.Context, userID xid.ID, params ListOAuthTokensParams) (*model.PaginatedOutput[*ent.OAuthToken], error)
	ListClientTokens(ctx context.Context, clientID xid.ID, params ListOAuthTokensParams) (*model.PaginatedOutput[*ent.OAuthToken], error)

	// OAuth Authorization operations
	CreateAuthorization(ctx context.Context, input CreateOAuthAuthorizationInput) (*ent.OAuthAuthorization, error)
	GetAuthorizationByCode(ctx context.Context, code string) (*ent.OAuthAuthorization, error)
	DeleteAuthorization(ctx context.Context, id xid.ID) error
	DeleteAuthorizationByCode(ctx context.Context, code string) error
	ListAuthorizations(ctx context.Context, params ListOAuthAuthorizationsParams) (*model.PaginatedOutput[*ent.OAuthAuthorization], error)

	// OAuth Scope operations
	CreateScope(ctx context.Context, input CreateOAuthScopeInput) (*ent.OAuthScope, error)
	GetScopeByName(ctx context.Context, name string) (*ent.OAuthScope, error)
	ListScopes(ctx context.Context, params ListOAuthScopesParams) (*model.PaginatedOutput[*ent.OAuthScope], error)
	GetDefaultScopes(ctx context.Context) ([]*ent.OAuthScope, error)
	GetPublicScopes(ctx context.Context) ([]*ent.OAuthScope, error)
	UpdateScope(ctx context.Context, id xid.ID, input UpdateOAuthScopeInput) (*ent.OAuthScope, error)
	DeleteScope(ctx context.Context, id xid.ID) error

	// Token validation and cleanup
	ValidateAccessToken(ctx context.Context, accessToken string) (*ent.OAuthToken, error)
	ValidateRefreshToken(ctx context.Context, refreshToken string) (*ent.OAuthToken, error)
	CleanupExpiredTokens(ctx context.Context) (int, error)
	CleanupExpiredAuthorizations(ctx context.Context) (int, error)
	RevokeAllUserTokens(ctx context.Context, userID xid.ID) error
	RevokeAllClientTokens(ctx context.Context, clientID xid.ID) error

	// Analytics and statistics
	GetOAuthStats(ctx context.Context, organizationID *xid.ID) (*OAuthStats, error)
	GetClientUsageStats(ctx context.Context, clientID xid.ID, days int) (*ClientUsageStats, error)
	GetTokenUsageStats(ctx context.Context, userID *xid.ID, clientID *xid.ID, days int) (*TokenUsageStats, error)
}

// CreateOAuthClientInput represents input for creating an OAuth client
type CreateOAuthClientInput struct {
	ClientID                  string   `json:"client_id"`
	ClientSecret              string   `json:"client_secret"`
	ClientName                string   `json:"client_name"`
	ClientDescription         *string  `json:"client_description,omitempty"`
	ClientURI                 *string  `json:"client_uri,omitempty"`
	LogoURI                   *string  `json:"logo_uri,omitempty"`
	RedirectURIs              []string `json:"redirect_uris"`
	PostLogoutRedirectURIs    []string `json:"post_logout_redirect_uris,omitempty"`
	OrganizationID            *xid.ID  `json:"organization_id,omitempty"`
	Public                    bool     `json:"public"`
	Active                    bool     `json:"active"`
	AllowedCORSOrigins        []string `json:"allowed_cors_origins,omitempty"`
	AllowedGrantTypes         []string `json:"allowed_grant_types"`
	TokenExpirySeconds        int      `json:"token_expiry_seconds"`
	RefreshTokenExpirySeconds int      `json:"refresh_token_expiry_seconds"`
	AuthCodeExpirySeconds     int      `json:"auth_code_expiry_seconds"`
	RequiresPKCE              bool     `json:"requires_pkce"`
	RequiresConsent           bool     `json:"requires_consent"`
}

// UpdateOAuthClientInput represents input for updating an OAuth client
type UpdateOAuthClientInput struct {
	ClientName                *string  `json:"client_name,omitempty"`
	ClientDescription         *string  `json:"client_description,omitempty"`
	ClientSecret              *string  `json:"client_secret,omitempty"`
	ClientURI                 *string  `json:"client_uri,omitempty"`
	LogoURI                   *string  `json:"logo_uri,omitempty"`
	RedirectURIs              []string `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs    []string `json:"post_logout_redirect_uris,omitempty"`
	Active                    *bool    `json:"active,omitempty"`
	AllowedCORSOrigins        []string `json:"allowed_cors_origins,omitempty"`
	AllowedGrantTypes         []string `json:"allowed_grant_types,omitempty"`
	TokenExpirySeconds        *int     `json:"token_expiry_seconds,omitempty"`
	RefreshTokenExpirySeconds *int     `json:"refresh_token_expiry_seconds,omitempty"`
	AuthCodeExpirySeconds     *int     `json:"auth_code_expiry_seconds,omitempty"`
	RequiresPKCE              *bool    `json:"requires_pkce,omitempty"`
	RequiresConsent           *bool    `json:"requires_consent,omitempty"`
}

// CreateOAuthTokenInput represents input for creating an OAuth token
type CreateOAuthTokenInput struct {
	AccessToken           string     `json:"access_token"`
	RefreshToken          *string    `json:"refresh_token,omitempty"`
	TokenType             string     `json:"token_type"`
	ClientID              xid.ID     `json:"client_id"`
	UserID                xid.ID     `json:"user_id"`
	OrganizationID        *xid.ID    `json:"organization_id,omitempty"`
	ScopeNames            []string   `json:"scope_names,omitempty"`
	ExpiresIn             int        `json:"expires_in"`
	ExpiresAt             time.Time  `json:"expires_at"`
	RefreshTokenExpiresAt *time.Time `json:"refresh_token_expires_at,omitempty"`
	IPAddress             *string    `json:"ip_address,omitempty"`
	UserAgent             *string    `json:"user_agent,omitempty"`
}

// UpdateOAuthTokenInput represents input for updating an OAuth token
type UpdateOAuthTokenInput struct {
	AccessToken           *string    `json:"access_token"`
	RefreshToken          *string    `json:"refresh_token,omitempty"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"`
	RefreshTokenExpiresAt *time.Time `json:"refresh_token_expires_at,omitempty"`
	Revoked               *bool      `json:"revoked,omitempty"`
	RevokedAt             *time.Time `json:"revoked_at,omitempty"`
}

// CreateOAuthAuthorizationInput represents input for creating an OAuth authorization
type CreateOAuthAuthorizationInput struct {
	Code                string    `json:"code"`
	ClientID            xid.ID    `json:"client_id"`
	OrganizationID      *xid.ID   `json:"organization_id"`
	UserID              xid.ID    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	ScopeNames          []string  `json:"scope_names,omitempty"`
	State               string    `json:"state,omitempty"`
	CodeChallenge       *string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod *string   `json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	IPAddress           *string   `json:"ip_address,omitempty"`
	UserAgent           *string   `json:"user_agent,omitempty"`
	Nonce               *string   `json:"nonce,omitempty"`
}

// CreateOAuthScopeInput represents input for creating an OAuth scope
type CreateOAuthScopeInput struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	DefaultScope bool   `json:"default_scope"`
	Public       bool   `json:"public"`
}

// UpdateOAuthScopeInput represents input for updating an OAuth scope
type UpdateOAuthScopeInput struct {
	Description  *string `json:"description,omitempty"`
	DefaultScope *bool   `json:"default_scope,omitempty"`
	Public       *bool   `json:"public,omitempty"`
}

// List parameters structs
type ListOAuthClientsParams struct {
	model.PaginationParams
	OrganizationID *xid.ID `json:"organization_id,omitempty"`
	Active         *bool   `json:"active,omitempty"`
	Public         *bool   `json:"public,omitempty"`
	Search         *string `json:"search,omitempty"`
}

type ListOAuthTokensParams struct {
	model.PaginationParams
	ClientID       *xid.ID `json:"client_id,omitempty"`
	UserID         *xid.ID `json:"user_id,omitempty"`
	OrganizationID *xid.ID `json:"organization_id,omitempty"`
	Revoked        *bool   `json:"revoked,omitempty"`
	Scope          *string `json:"scope,omitempty"`
	Expired        *bool   `json:"expired,omitempty"`
}

type ListOAuthAuthorizationsParams struct {
	model.PaginationParams
	ClientID *xid.ID `json:"client_id,omitempty"`
	UserID   *xid.ID `json:"user_id,omitempty"`
}

type ListOAuthScopesParams struct {
	model.PaginationParams
	DefaultScope *bool `json:"default_scope,omitempty"`
	Public       *bool `json:"public,omitempty"`
}

// Statistics structs
type OAuthStats struct {
	TotalClients        int            `json:"total_clients"`
	ActiveClients       int            `json:"active_clients"`
	TotalTokens         int            `json:"total_tokens"`
	ActiveTokens        int            `json:"active_tokens"`
	RevokedTokens       int            `json:"revoked_tokens"`
	TotalAuthorizations int            `json:"total_authorizations"`
	ClientBreakdown     map[string]int `json:"client_breakdown"`
	ScopeUsage          map[string]int `json:"scope_usage"`
}

type ClientUsageStats struct {
	ClientID                xid.ID         `json:"client_id"`
	ClientName              string         `json:"client_name"`
	TotalTokens             int            `json:"total_tokens"`
	ActiveTokens            int            `json:"active_tokens"`
	TotalAuthorizations     int            `json:"total_authorizations"`
	UniqueUsers             int            `json:"unique_users"`
	DailyUsage              []DailyUsage   `json:"daily_usage"`
	ScopeUsage              map[string]int `json:"scope_usage"`
	AuthorizationsThisMonth int            `json:"authorizations_this_month"`
	TokensThisMonth         int            `json:"tokens_this_month"`
	SuccessRate             float64        `json:"success_rate"`
	LastUsed                *time.Time     `json:"last_used,omitempty"`
}

type TokenUsageStats struct {
	TotalTokens     int            `json:"total_tokens"`
	ActiveTokens    int            `json:"active_tokens"`
	ExpiredTokens   int            `json:"expired_tokens"`
	RevokedTokens   int            `json:"revoked_tokens"`
	DailyBreakdown  []DailyUsage   `json:"daily_breakdown"`
	ClientBreakdown map[string]int `json:"client_breakdown"`
	ScopeBreakdown  map[string]int `json:"scope_breakdown"`
}

// OAuthDailyUsage represents daily usage statistics
type DailyUsage struct {
	Date     time.Time `json:"date"`
	Messages int       `json:"messages"`
	Segments int       `json:"segments"`
	Cost     float64   `json:"cost"`
}

// oauthRepository implements OAuthRepository
type oauthRepository struct {
	client *ent.Client
	logger logging.Logger
}

// NewOAuthRepository creates a new OAuth repository
func NewOAuthRepository(client *ent.Client, logger logging.Logger) OAuthRepository {
	return &oauthRepository{
		client: client,
		logger: logger,
	}
}

// OAuth Client operations

func (r *oauthRepository) CreateClient(ctx context.Context, input CreateOAuthClientInput) (*ent.OAuthClient, error) {
	create := r.client.OAuthClient.Create().
		SetClientID(input.ClientID).
		SetClientSecret(input.ClientSecret).
		SetClientName(input.ClientName).
		SetRedirectUris(input.RedirectURIs).
		SetPublic(input.Public).
		SetAllowedGrantTypes(input.AllowedGrantTypes).
		SetTokenExpirySeconds(input.TokenExpirySeconds).
		SetRefreshTokenExpirySeconds(input.RefreshTokenExpirySeconds).
		SetAuthCodeExpirySeconds(input.AuthCodeExpirySeconds).
		SetRequiresPkce(input.RequiresPKCE).
		SetRequiresConsent(input.RequiresConsent)

	// Set optional fields
	if input.ClientDescription != nil {
		create.SetClientDescription(*input.ClientDescription)
	}
	if input.ClientURI != nil {
		create.SetClientURI(*input.ClientURI)
	}
	if input.LogoURI != nil {
		create.SetLogoURI(*input.LogoURI)
	}
	if len(input.PostLogoutRedirectURIs) > 0 {
		create.SetPostLogoutRedirectUris(input.PostLogoutRedirectURIs)
	}
	if input.OrganizationID != nil {
		create.SetOrganizationID(*input.OrganizationID)
	}
	if len(input.AllowedCORSOrigins) > 0 {
		create.SetAllowedCorsOrigins(input.AllowedCORSOrigins)
	}

	client, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "OAuth client with this client ID already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create OAuth client")
	}

	return client, nil
}

func (r *oauthRepository) GetClientByID(ctx context.Context, id xid.ID) (*ent.OAuthClient, error) {
	client, err := r.client.OAuthClient.Query().
		Where(oauthclient.ID(id)).
		WithScopes().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "OAuth client not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get OAuth client by ID")
	}
	return client, nil
}

func (r *oauthRepository) GetClientByClientID(ctx context.Context, clientID string) (*ent.OAuthClient, error) {
	client, err := r.client.OAuthClient.Query().
		Where(oauthclient.ClientID(clientID)).
		WithScopes().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "OAuth client not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get OAuth client by client ID")
	}
	return client, nil
}

func (r *oauthRepository) UpdateClient(ctx context.Context, id xid.ID, input UpdateOAuthClientInput) (*ent.OAuthClient, error) {
	update := r.client.OAuthClient.UpdateOneID(id)

	if input.ClientName != nil {
		update.SetClientName(*input.ClientName)
	}
	if input.ClientDescription != nil {
		update.SetClientDescription(*input.ClientDescription)
	}
	if input.ClientURI != nil {
		update.SetClientURI(*input.ClientURI)
	}
	if input.LogoURI != nil {
		update.SetLogoURI(*input.LogoURI)
	}
	if input.RedirectURIs != nil {
		update.SetRedirectUris(input.RedirectURIs)
	}
	if input.PostLogoutRedirectURIs != nil {
		update.SetPostLogoutRedirectUris(input.PostLogoutRedirectURIs)
	}
	if input.Active != nil {
		update.SetActive(*input.Active)
	}
	if input.AllowedCORSOrigins != nil {
		update.SetAllowedCorsOrigins(input.AllowedCORSOrigins)
	}
	if input.AllowedGrantTypes != nil {
		update.SetAllowedGrantTypes(input.AllowedGrantTypes)
	}
	if input.TokenExpirySeconds != nil {
		update.SetTokenExpirySeconds(*input.TokenExpirySeconds)
	}
	if input.RefreshTokenExpirySeconds != nil {
		update.SetRefreshTokenExpirySeconds(*input.RefreshTokenExpirySeconds)
	}
	if input.AuthCodeExpirySeconds != nil {
		update.SetAuthCodeExpirySeconds(*input.AuthCodeExpirySeconds)
	}
	if input.RequiresPKCE != nil {
		update.SetRequiresPkce(*input.RequiresPKCE)
	}
	if input.RequiresConsent != nil {
		update.SetRequiresConsent(*input.RequiresConsent)
	}

	client, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "OAuth client not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update OAuth client")
	}
	return client, nil
}

func (r *oauthRepository) DeleteClient(ctx context.Context, id xid.ID) error {
	err := r.client.OAuthClient.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "OAuth client not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete OAuth client")
	}
	return nil
}

func (r *oauthRepository) ListClients(ctx context.Context, params ListOAuthClientsParams) (*model.PaginatedOutput[*ent.OAuthClient], error) {
	query := r.client.OAuthClient.Query().
		WithScopes()

	// Apply filters
	if params.OrganizationID != nil {
		query = query.Where(oauthclient.OrganizationID(*params.OrganizationID))
	}
	if params.Active != nil {
		query = query.Where(oauthclient.Active(*params.Active))
	}
	if params.Public != nil {
		query = query.Where(oauthclient.Public(*params.Public))
	}

	return model.WithPaginationAndOptions[*ent.OAuthClient, *ent.OAuthClientQuery](ctx, query, params.PaginationParams)
}

func (r *oauthRepository) ListClientsByOrganization(ctx context.Context, organizationID xid.ID, params ListOAuthClientsParams) (*model.PaginatedOutput[*ent.OAuthClient], error) {
	params.OrganizationID = &organizationID
	return r.ListClients(ctx, params)
}

// OAuth Token operations

func (r *oauthRepository) CreateToken(ctx context.Context, input CreateOAuthTokenInput) (*ent.OAuthToken, error) {
	create := r.client.OAuthToken.Create().
		SetAccessToken(input.AccessToken).
		SetTokenType(input.TokenType).
		SetClientID(input.ClientID).
		SetUserID(input.UserID).
		SetExpiresIn(input.ExpiresIn).
		SetExpiresAt(input.ExpiresAt)

	// Set optional fields
	if input.RefreshToken != nil {
		create.SetRefreshToken(*input.RefreshToken)
	}
	if input.OrganizationID != nil {
		create.SetOrganizationID(*input.OrganizationID)
	}
	if len(input.ScopeNames) > 0 {
		create.SetScopeNames(input.ScopeNames)
	}
	if input.RefreshTokenExpiresAt != nil {
		create.SetRefreshTokenExpiresAt(*input.RefreshTokenExpiresAt)
	}
	if input.IPAddress != nil {
		create.SetIPAddress(*input.IPAddress)
	}
	if input.UserAgent != nil {
		create.SetUserAgent(*input.UserAgent)
	}

	token, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "OAuth token with this access token already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create OAuth token")
	}

	return token, nil
}

func (r *oauthRepository) GetTokenByAccessToken(ctx context.Context, accessToken string) (*ent.OAuthToken, error) {
	token, err := r.client.OAuthToken.Query().
		Where(oauthtoken.AccessToken(accessToken)).
		WithClient().
		WithUser().
		WithScopes().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "OAuth token not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get OAuth token by access token")
	}
	return token, nil
}

func (r *oauthRepository) GetTokenByRefreshToken(ctx context.Context, refreshToken string) (*ent.OAuthToken, error) {
	token, err := r.client.OAuthToken.Query().
		Where(oauthtoken.RefreshToken(refreshToken)).
		WithClient().
		WithUser().
		WithScopes().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "OAuth token not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get OAuth token by refresh token")
	}
	return token, nil
}

func (r *oauthRepository) GetTokenByID(ctx context.Context, id xid.ID) (*ent.OAuthToken, error) {
	token, err := r.client.OAuthToken.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "OAuth token not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get OAuth token by refresh token")
	}
	return token, nil
}

func (r *oauthRepository) UpdateToken(ctx context.Context, id xid.ID, input UpdateOAuthTokenInput) (*ent.OAuthToken, error) {
	update := r.client.OAuthToken.UpdateOneID(id)

	if input.ExpiresAt != nil {
		update.SetExpiresAt(*input.ExpiresAt)
	}
	if input.RefreshTokenExpiresAt != nil {
		update.SetRefreshTokenExpiresAt(*input.RefreshTokenExpiresAt)
	}
	if input.Revoked != nil {
		update.SetRevoked(*input.Revoked)
	}
	if input.RevokedAt != nil {
		update.SetRevokedAt(*input.RevokedAt)
	}

	token, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "OAuth token not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update OAuth token")
	}
	return token, nil
}

func (r *oauthRepository) DeleteToken(ctx context.Context, id xid.ID) error {
	err := r.client.OAuthToken.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "OAuth token not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete OAuth token")
	}
	return nil
}

func (r *oauthRepository) RevokeToken(ctx context.Context, accessToken string) error {
	now := time.Now()
	err := r.client.OAuthToken.Update().
		Where(oauthtoken.AccessToken(accessToken)).
		SetRevoked(true).
		SetRevokedAt(now).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to revoke OAuth token")
	}
	return nil
}

func (r *oauthRepository) RevokeTokenByRefreshToken(ctx context.Context, refreshToken string) error {
	now := time.Now()
	err := r.client.OAuthToken.Update().
		Where(oauthtoken.RefreshToken(refreshToken)).
		SetRevoked(true).
		SetRevokedAt(now).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to revoke OAuth token by refresh token")
	}
	return nil
}

func (r *oauthRepository) ListTokens(ctx context.Context, params ListOAuthTokensParams) (*model.PaginatedOutput[*ent.OAuthToken], error) {
	query := r.client.OAuthToken.Query().
		WithClient().
		WithUser().
		WithScopes()

	// Apply filters
	if params.ClientID != nil {
		query = query.Where(oauthtoken.ClientID(*params.ClientID))
	}
	if params.UserID != nil {
		query = query.Where(oauthtoken.UserID(*params.UserID))
	}
	if params.OrganizationID != nil {
		query = query.Where(oauthtoken.OrganizationID(*params.OrganizationID))
	}
	if params.Revoked != nil {
		query = query.Where(oauthtoken.Revoked(*params.Revoked))
	}
	if params.Scope != nil {
		query = query.Where(func(s *sql.Selector) {
			s.Where(sqljson.ValueContains(oauthtoken.FieldScopeNames, *params.Scope))
		})
	}

	return model.WithPaginationAndOptions[*ent.OAuthToken, *ent.OAuthTokenQuery](ctx, query, params.PaginationParams)
}

func (r *oauthRepository) ListUserTokens(ctx context.Context, userID xid.ID, params ListOAuthTokensParams) (*model.PaginatedOutput[*ent.OAuthToken], error) {
	params.UserID = &userID
	return r.ListTokens(ctx, params)
}

func (r *oauthRepository) ListClientTokens(ctx context.Context, clientID xid.ID, params ListOAuthTokensParams) (*model.PaginatedOutput[*ent.OAuthToken], error) {
	params.ClientID = &clientID
	return r.ListTokens(ctx, params)
}

// OAuth Authorization operations

func (r *oauthRepository) CreateAuthorization(ctx context.Context, input CreateOAuthAuthorizationInput) (*ent.OAuthAuthorization, error) {
	create := r.client.OAuthAuthorization.Create().
		SetCode(input.Code).
		SetClientID(input.ClientID).
		SetUserID(input.UserID).
		SetRedirectURI(input.RedirectURI).
		SetExpiresAt(input.ExpiresAt)

	// Set optional fields
	if len(input.ScopeNames) > 0 {
		create.SetScopeNames(input.ScopeNames)
	}
	if input.State != "" {
		create.SetState(input.State)
	}
	if input.CodeChallenge != nil {
		create.SetCodeChallenge(*input.CodeChallenge)
	}
	if input.CodeChallengeMethod != nil {
		create.SetCodeChallengeMethod(*input.CodeChallengeMethod)
	}
	if input.IPAddress != nil {
		create.SetIPAddress(*input.IPAddress)
	}
	if input.UserAgent != nil {
		create.SetUserAgent(*input.UserAgent)
	}

	authorization, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "OAuth authorization with this code already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create OAuth authorization")
	}

	return authorization, nil
}

func (r *oauthRepository) GetAuthorizationByCode(ctx context.Context, code string) (*ent.OAuthAuthorization, error) {
	authorization, err := r.client.OAuthAuthorization.Query().
		Where(oauthauthorization.Code(code)).
		WithClient().
		WithUser().
		WithScopes().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "OAuth authorization not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get OAuth authorization by code")
	}
	return authorization, nil
}

func (r *oauthRepository) DeleteAuthorization(ctx context.Context, id xid.ID) error {
	err := r.client.OAuthAuthorization.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "OAuth authorization not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete OAuth authorization")
	}
	return nil
}

func (r *oauthRepository) DeleteAuthorizationByCode(ctx context.Context, code string) error {
	_, err := r.client.OAuthAuthorization.Delete().
		Where(oauthauthorization.Code(code)).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete OAuth authorization by code")
	}
	return nil
}

func (r *oauthRepository) ListAuthorizations(ctx context.Context, params ListOAuthAuthorizationsParams) (*model.PaginatedOutput[*ent.OAuthAuthorization], error) {
	query := r.client.OAuthAuthorization.Query().
		WithClient().
		WithUser().
		WithScopes()

	// Apply filters
	if params.ClientID != nil {
		query = query.Where(oauthauthorization.ClientID(*params.ClientID))
	}
	if params.UserID != nil {
		query = query.Where(oauthauthorization.UserID(*params.UserID))
	}

	return model.WithPaginationAndOptions[*ent.OAuthAuthorization, *ent.OAuthAuthorizationQuery](ctx, query, params.PaginationParams)
}

// OAuth Scope operations

func (r *oauthRepository) CreateScope(ctx context.Context, input CreateOAuthScopeInput) (*ent.OAuthScope, error) {
	scope, err := r.client.OAuthScope.Create().
		SetName(input.Name).
		SetDescription(input.Description).
		SetDefaultScope(input.DefaultScope).
		SetPublic(input.Public).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "OAuth scope with this name already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create OAuth scope")
	}

	return scope, nil
}

func (r *oauthRepository) GetScopeByName(ctx context.Context, name string) (*ent.OAuthScope, error) {
	scope, err := r.client.OAuthScope.Query().
		Where(oauthscope.Name(name)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "OAuth scope not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get OAuth scope by name")
	}
	return scope, nil
}

func (r *oauthRepository) ListScopes(ctx context.Context, params ListOAuthScopesParams) (*model.PaginatedOutput[*ent.OAuthScope], error) {
	query := r.client.OAuthScope.Query()

	// Apply filters
	if params.DefaultScope != nil {
		query = query.Where(oauthscope.DefaultScope(*params.DefaultScope))
	}
	if params.Public != nil {
		query = query.Where(oauthscope.Public(*params.Public))
	}

	return model.WithPaginationAndOptions[*ent.OAuthScope, *ent.OAuthScopeQuery](ctx, query, params.PaginationParams)
}

func (r *oauthRepository) GetDefaultScopes(ctx context.Context) ([]*ent.OAuthScope, error) {
	scopes, err := r.client.OAuthScope.Query().
		Where(oauthscope.DefaultScope(true)).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get default OAuth scopes")
	}
	return scopes, nil
}

func (r *oauthRepository) GetPublicScopes(ctx context.Context) ([]*ent.OAuthScope, error) {
	scopes, err := r.client.OAuthScope.Query().
		Where(oauthscope.Public(true)).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get public OAuth scopes")
	}
	return scopes, nil
}

func (r *oauthRepository) UpdateScope(ctx context.Context, id xid.ID, input UpdateOAuthScopeInput) (*ent.OAuthScope, error) {
	update := r.client.OAuthScope.UpdateOneID(id)

	if input.Description != nil {
		update.SetDescription(*input.Description)
	}
	if input.DefaultScope != nil {
		update.SetDefaultScope(*input.DefaultScope)
	}
	if input.Public != nil {
		update.SetPublic(*input.Public)
	}

	scope, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "OAuth scope not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update OAuth scope")
	}
	return scope, nil
}

func (r *oauthRepository) DeleteScope(ctx context.Context, id xid.ID) error {
	err := r.client.OAuthScope.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "OAuth scope not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete OAuth scope")
	}
	return nil
}

// Token validation and cleanup

func (r *oauthRepository) ValidateAccessToken(ctx context.Context, accessToken string) (*ent.OAuthToken, error) {
	token, err := r.GetTokenByAccessToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	// Check if token is revoked
	if token.Revoked {
		return nil, errors.New(errors.CodeUnauthorized, "OAuth token has been revoked")
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		return nil, errors.New(errors.CodeUnauthorized, "OAuth token has expired")
	}

	return token, nil
}

func (r *oauthRepository) ValidateRefreshToken(ctx context.Context, refreshToken string) (*ent.OAuthToken, error) {
	token, err := r.GetTokenByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	// Check if token is revoked
	if token.Revoked {
		return nil, errors.New(errors.CodeUnauthorized, "OAuth refresh token has been revoked")
	}

	// Check if refresh token is expired
	if token.RefreshTokenExpiresAt != nil && time.Now().After(*token.RefreshTokenExpiresAt) {
		return nil, errors.New(errors.CodeUnauthorized, "OAuth refresh token has expired")
	}

	return token, nil
}

func (r *oauthRepository) CleanupExpiredTokens(ctx context.Context) (int, error) {
	deleted, err := r.client.OAuthToken.Delete().
		Where(oauthtoken.ExpiresAtLT(time.Now())).
		Exec(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to cleanup expired OAuth tokens")
	}
	return deleted, nil
}

func (r *oauthRepository) CleanupExpiredAuthorizations(ctx context.Context) (int, error) {
	deleted, err := r.client.OAuthAuthorization.Delete().
		Where(oauthauthorization.ExpiresAtLT(time.Now())).
		Exec(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to cleanup expired OAuth authorizations")
	}
	return deleted, nil
}

func (r *oauthRepository) RevokeAllUserTokens(ctx context.Context, userID xid.ID) error {
	now := time.Now()
	err := r.client.OAuthToken.Update().
		Where(oauthtoken.UserID(userID)).
		SetRevoked(true).
		SetRevokedAt(now).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to revoke all user OAuth tokens")
	}
	return nil
}

func (r *oauthRepository) RevokeAllClientTokens(ctx context.Context, clientID xid.ID) error {
	now := time.Now()
	err := r.client.OAuthToken.Update().
		Where(oauthtoken.ClientID(clientID)).
		SetRevoked(true).
		SetRevokedAt(now).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to revoke all client OAuth tokens")
	}
	return nil
}

// Analytics and statistics methods

func (r *oauthRepository) GetOAuthStats(ctx context.Context, organizationID *xid.ID) (*OAuthStats, error) {
	// Build base queries
	clientQuery := r.client.OAuthClient.Query()
	tokenQuery := r.client.OAuthToken.Query()
	authQuery := r.client.OAuthAuthorization.Query()

	if organizationID != nil {
		clientQuery = clientQuery.Where(oauthclient.OrganizationID(*organizationID))
		tokenQuery = tokenQuery.Where(oauthtoken.OrganizationID(*organizationID))
	}

	// Get counts
	totalClients, err := clientQuery.Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get total clients")
	}

	activeClients, err := clientQuery.Clone().Where(oauthclient.Active(true)).Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get active clients")
	}

	totalTokens, err := tokenQuery.Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get total tokens")
	}

	activeTokens, err := tokenQuery.Clone().
		Where(
			oauthtoken.Revoked(false),
			oauthtoken.ExpiresAtGT(time.Now()),
		).Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get active tokens")
	}

	revokedTokens, err := tokenQuery.Clone().Where(oauthtoken.Revoked(true)).Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get revoked tokens")
	}

	totalAuthorizations, err := authQuery.Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get total authorizations")
	}

	return &OAuthStats{
		TotalClients:        totalClients,
		ActiveClients:       activeClients,
		TotalTokens:         totalTokens,
		ActiveTokens:        activeTokens,
		RevokedTokens:       revokedTokens,
		TotalAuthorizations: totalAuthorizations,
		ClientBreakdown:     make(map[string]int),
		ScopeUsage:          make(map[string]int),
	}, nil
}

func (r *oauthRepository) GetClientUsageStats(ctx context.Context, clientID xid.ID, days int) (*ClientUsageStats, error) {
	client, err := r.GetClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// since := time.Now().AddDate(0, 0, -days)

	// Get token counts
	totalTokens, err := r.client.OAuthToken.Query().
		Where(oauthtoken.ClientID(clientID)).
		Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get total tokens")
	}

	activeTokens, err := r.client.OAuthToken.Query().
		Where(
			oauthtoken.ClientID(clientID),
			oauthtoken.Revoked(false),
			oauthtoken.ExpiresAtGT(time.Now()),
		).Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get active tokens")
	}

	// Get authorization count
	totalAuthorizations, err := r.client.OAuthAuthorization.Query().
		Where(oauthauthorization.ClientID(clientID)).
		Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get total authorizations")
	}

	// Get unique users count
	uniqueUsers, err := r.client.OAuthToken.Query().
		Where(oauthtoken.ClientID(clientID)).
		GroupBy(oauthtoken.FieldUserID).
		Strings(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get unique users")
	}

	return &ClientUsageStats{
		ClientID:            clientID,
		ClientName:          client.ClientName,
		TotalTokens:         totalTokens,
		ActiveTokens:        activeTokens,
		TotalAuthorizations: totalAuthorizations,
		UniqueUsers:         len(uniqueUsers),
		DailyUsage:          []DailyUsage{}, // Would need more complex queries for daily breakdown
		ScopeUsage:          make(map[string]int),
	}, nil
}

func (r *oauthRepository) GetTokenUsageStats(ctx context.Context, userID *xid.ID, clientID *xid.ID, days int) (*TokenUsageStats, error) {
	query := r.client.OAuthToken.Query()

	if userID != nil {
		query = query.Where(oauthtoken.UserID(*userID))
	}
	if clientID != nil {
		query = query.Where(oauthtoken.ClientID(*clientID))
	}

	since := time.Now().AddDate(0, 0, -days)
	query = query.Where(oauthtoken.CreatedAtGTE(since))

	// Get counts
	totalTokens, err := query.Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get total tokens")
	}

	activeTokens, err := query.Clone().
		Where(
			oauthtoken.Revoked(false),
			oauthtoken.ExpiresAtGT(time.Now()),
		).Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get active tokens")
	}

	expiredTokens, err := query.Clone().
		Where(oauthtoken.ExpiresAtLT(time.Now())).
		Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get expired tokens")
	}

	revokedTokens, err := query.Clone().
		Where(oauthtoken.Revoked(true)).
		Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get revoked tokens")
	}

	return &TokenUsageStats{
		TotalTokens:     totalTokens,
		ActiveTokens:    activeTokens,
		ExpiredTokens:   expiredTokens,
		RevokedTokens:   revokedTokens,
		DailyBreakdown:  []DailyUsage{}, // Would need more complex queries
		ClientBreakdown: make(map[string]int),
		ScopeBreakdown:  make(map[string]int),
	}, nil
}
