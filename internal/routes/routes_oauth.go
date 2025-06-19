package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/juicycleff/frank/pkg/services/audit"
	"github.com/rs/xid"
)

// RegisterOAuthAPI registers protected OAuth management endpoints
func RegisterOAuthAPI(group huma.API, di di.Container) {
	di.Logger().Info("Registering OAuth API routes")

	oauthCtrl := &oauthController{
		api: group,
		di:  di,
	}

	// OAuth Client Management
	registerListOAuthClients(group, oauthCtrl)
	registerCreateOAuthClient(group, oauthCtrl)
	registerGetOAuthClient(group, oauthCtrl)
	registerUpdateOAuthClient(group, oauthCtrl)
	registerDeleteOAuthClient(group, oauthCtrl)
	registerRegenerateClientSecret(group, oauthCtrl)
	registerActivateOAuthClient(group, oauthCtrl)
	registerDeactivateOAuthClient(group, oauthCtrl)

	// OAuth Token Management
	registerListOAuthTokens(group, oauthCtrl)
	registerGetOAuthToken(group, oauthCtrl)
	registerRevokeOAuthToken(group, oauthCtrl)
	registerListUserTokens(group, oauthCtrl)
	registerListClientTokens(group, oauthCtrl)
	registerBulkRevokeTokens(group, oauthCtrl)

	// OAuth Scope Management
	registerListOAuthScopes(group, oauthCtrl)
	registerCreateOAuthScope(group, oauthCtrl)
	registerGetOAuthScope(group, oauthCtrl)
	registerUpdateOAuthScope(group, oauthCtrl)
	registerDeleteOAuthScope(group, oauthCtrl)

	// OAuth Statistics and Analytics
	registerGetOAuthStats(group, oauthCtrl)
	registerGetClientStats(group, oauthCtrl)
	registerGetTokenStats(group, oauthCtrl)
}

// RegisterOAuthPublicAPI registers public OAuth endpoints (no authentication required)
func RegisterOAuthPublicAPI(group huma.API, di di.Container) {
	di.Logger().Info("Registering public OAuth API routes")

	oauthCtrl := &oauthController{
		api: group,
		di:  di,
	}

	// OAuth2 Authorization Flow
	registerOAuthAuthorize(group, oauthCtrl)
	registerOAuthToken(group, oauthCtrl)
	registerOAuthUserInfo(group, oauthCtrl)
	registerOAuthRevoke(group, oauthCtrl)
	registerOAuthIntrospect(group, oauthCtrl)

	// Well-known endpoints
	registerOAuthWellKnown(group, oauthCtrl)
	registerOAuthJWKS(group, oauthCtrl)
}

// Route Registration Functions

func registerListOAuthClients(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listOAuthClients",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/oauth/clients",
		Summary:       "List OAuth clients",
		Description:   "Get a paginated list of OAuth clients for the organization",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionReadOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.listOAuthClientsHandler)
}

func registerCreateOAuthClient(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "createOAuthClient",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/oauth/clients",
		Summary:       "Create OAuth client",
		Description:   "Create a new OAuth client for the organization",
		Tags:          []string{"OAuth"},
		DefaultStatus: 201,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid client configuration")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionWriteOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.createOAuthClientHandler)
}

func registerGetOAuthClient(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getOAuthClient",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/oauth/clients/{id}",
		Summary:       "Get OAuth client",
		Description:   "Get an OAuth client by ID",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth client not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionReadOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.getOAuthClientHandler)
}

func registerUpdateOAuthClient(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "updateOAuthClient",
		Method:        http.MethodPut,
		Path:          "/organizations/{orgId}/oauth/clients/{id}",
		Summary:       "Update OAuth client",
		Description:   "Update an OAuth client",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth client not found"), model.BadRequestError("Invalid client configuration")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionWriteOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.updateOAuthClientHandler)
}

func registerDeleteOAuthClient(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteOAuthClient",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/oauth/clients/{id}",
		Summary:       "Delete OAuth client",
		Description:   "Delete an OAuth client",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth client not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionWriteOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.deleteOAuthClientHandler)
}

func registerRegenerateClientSecret(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "regenerateClientSecret",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/oauth/clients/{id}/regenerate-secret",
		Summary:       "Regenerate client secret",
		Description:   "Regenerate the client secret for an OAuth client",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth client not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionWriteOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.regenerateClientSecretHandler)
}

func registerActivateOAuthClient(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "activateOAuthClient",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/oauth/clients/{id}/activate",
		Summary:       "Activate OAuth client",
		Description:   "Activate an OAuth client",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth client not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionWriteOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.activateOAuthClientHandler)
}

func registerDeactivateOAuthClient(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deactivateOAuthClient",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/oauth/clients/{id}/deactivate",
		Summary:       "Deactivate OAuth client",
		Description:   "Deactivate an OAuth client",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth client not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionWriteOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.deactivateOAuthClientHandler)
}

func registerListOAuthTokens(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listOAuthTokens",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/oauth/tokens",
		Summary:       "List OAuth tokens",
		Description:   "Get a paginated list of OAuth tokens for the organization",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionReadOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.listOAuthTokensHandler)
}

func registerGetOAuthToken(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getOAuthToken",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/oauth/tokens/{id}",
		Summary:       "Get OAuth token",
		Description:   "Get an OAuth token by ID",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth token not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionReadOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.getOAuthTokenHandler)
}

func registerRevokeOAuthToken(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "revokeOAuthToken",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/oauth/tokens/{id}/revoke",
		Summary:       "Revoke OAuth token",
		Description:   "Revoke an OAuth token",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth token not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionWriteOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.revokeOAuthTokenHandler)
}

func registerListUserTokens(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listUserTokens",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/users/{userId}/oauth/tokens",
		Summary:       "List user OAuth tokens",
		Description:   "Get a paginated list of OAuth tokens for a specific user",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionReadOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.listUserTokensHandler)
}

func registerListClientTokens(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listClientTokens",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/oauth/clients/{clientId}/tokens",
		Summary:       "List client OAuth tokens",
		Description:   "Get a paginated list of OAuth tokens for a specific client",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth client not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionReadOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.listClientTokensHandler)
}

func registerBulkRevokeTokens(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "bulkRevokeTokens",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/oauth/tokens/bulk-revoke",
		Summary:       "Bulk revoke OAuth tokens",
		Description:   "Revoke multiple OAuth tokens based on criteria",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionWriteOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.bulkRevokeTokensHandler)
}

func registerListOAuthScopes(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listOAuthScopes",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/oauth/scopes",
		Summary:       "List OAuth scopes",
		Description:   "Get a paginated list of OAuth scopes for the organization",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionReadOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.listOAuthScopesHandler)
}

func registerCreateOAuthScope(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "createOAuthScope",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/oauth/scopes",
		Summary:       "Create OAuth scope",
		Description:   "Create a new OAuth scope for the organization",
		Tags:          []string{"OAuth"},
		DefaultStatus: 201,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid scope configuration")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionWriteOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.createOAuthScopeHandler)
}

func registerGetOAuthScope(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getOAuthScope",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/oauth/scopes/{id}",
		Summary:       "Get OAuth scope",
		Description:   "Get an OAuth scope by ID",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth scope not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionReadOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.getOAuthScopeHandler)
}

func registerUpdateOAuthScope(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "updateOAuthScope",
		Method:        http.MethodPut,
		Path:          "/organizations/{orgId}/oauth/scopes/{id}",
		Summary:       "Update OAuth scope",
		Description:   "Update an OAuth scope",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth scope not found"), model.BadRequestError("Invalid scope configuration")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionWriteOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.updateOAuthScopeHandler)
}

func registerDeleteOAuthScope(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteOAuthScope",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/oauth/scopes/{id}",
		Summary:       "Delete OAuth scope",
		Description:   "Delete an OAuth scope",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth scope not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionWriteOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.deleteOAuthScopeHandler)
}

// Public OAuth Flow Registration

func registerOAuthAuthorize(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "oauthAuthorize",
		Method:        http.MethodGet,
		Path:          "/oauth/authorize",
		Summary:       "OAuth authorization endpoint",
		Description:   "OAuth 2.0 authorization endpoint for starting authorization flow",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, false, model.BadRequestError("Invalid authorization request")),
	}, oauthCtrl.oauthAuthorizeHandler)
}

func registerOAuthToken(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "oauthToken",
		Method:        http.MethodPost,
		Path:          "/oauth/token",
		Summary:       "OAuth token endpoint",
		Description:   "OAuth 2.0 token endpoint for exchanging authorization codes for access tokens",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, false, model.BadRequestError("Invalid token request")),
	}, oauthCtrl.oauthTokenHandler)
}

func registerOAuthUserInfo(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "oauthUserInfo",
		Method:        http.MethodGet,
		Path:          "/oauth/userinfo",
		Summary:       "OAuth user info endpoint",
		Description:   "OAuth 2.0 user info endpoint for getting user information from access token",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, false, model.UnauthorizedError()),
		Security: []map[string][]string{
			{"oauth2": {}},
		},
	}, oauthCtrl.oauthUserInfoHandler)
}

func registerOAuthRevoke(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "oauthRevoke",
		Method:        http.MethodPost,
		Path:          "/oauth/revoke",
		Summary:       "OAuth token revocation endpoint",
		Description:   "OAuth 2.0 token revocation endpoint for revoking access and refresh tokens",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, oauthCtrl.oauthRevokeHandler)
}

func registerOAuthIntrospect(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "oauthIntrospect",
		Method:        http.MethodPost,
		Path:          "/oauth/introspect",
		Summary:       "OAuth token introspection endpoint",
		Description:   "OAuth 2.0 token introspection endpoint for validating and getting information about tokens",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, oauthCtrl.oauthIntrospectHandler)
}

func registerOAuthWellKnown(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "oauthWellKnown",
		Method:        http.MethodGet,
		Path:          "/.well-known/oauth-authorization-server",
		Summary:       "OAuth well-known configuration",
		Description:   "OAuth 2.0 authorization server metadata endpoint",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, oauthCtrl.oauthWellKnownHandler)
}

func registerOAuthJWKS(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "oauthJWKS",
		Method:        http.MethodGet,
		Path:          "/.well-known/jwks.json",
		Summary:       "OAuth JWKS endpoint",
		Description:   "JSON Web Key Set endpoint for OAuth 2.0 token verification",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, oauthCtrl.oauthJWKSHandler)
}

func registerGetOAuthStats(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getOAuthStats",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/oauth/stats",
		Summary:       "Get OAuth statistics",
		Description:   "Get OAuth usage statistics for the organization",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionReadOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.getOAuthStatsHandler)
}

func registerGetClientStats(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getClientStats",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/oauth/clients/{id}/stats",
		Summary:       "Get OAuth client statistics",
		Description:   "Get usage statistics for a specific OAuth client",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("OAuth client not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionReadOAuth, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.getClientStatsHandler)
}

func registerGetTokenStats(api huma.API, oauthCtrl *oauthController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getTokenStats",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/oauth/tokens/stats",
		Summary:       "Get OAuth token statistics",
		Description:   "Get token usage statistics for the organization",
		Tags:          []string{"OAuth"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, oauthCtrl.di.AuthZ().Checker(), oauthCtrl.di.Logger())(
			authz.PermissionReadRole, authz.ResourceOrganization, "orgId",
		)},
	}, oauthCtrl.getTokenStatsHandler)
}

// oauthController handles OAuth-related HTTP requests
type oauthController struct {
	api huma.API
	di  di.Container
}

// OAuth Client Management Handlers

// ListOAuthClientsInput represents input for listing OAuth clients
type ListOAuthClientsInput struct {
	model.OrganisationPathParams
	model.OAuthClientListRequest
}

type ListOAuthClientsOutput = model.Output[*model.OAuthClientListResponse]

func (c *oauthController) listOAuthClientsHandler(ctx context.Context, input *ListOAuthClientsInput) (*ListOAuthClientsOutput, error) {
	clients, err := c.di.OAuthService().Client().ListClients(ctx, input.OAuthClientListRequest)
	if err != nil {
		return nil, err
	}

	return &ListOAuthClientsOutput{
		Body: clients,
	}, nil
}

// CreateOAuthClientInput represents input for creating an OAuth client
type CreateOAuthClientInput struct {
	model.OrganisationPathParams
	Body model.CreateOAuthClientRequest `json:"body"`
}

type CreateOAuthClientOutput = model.Output[*model.CreateOAuthClientResponse]

func (c *oauthController) createOAuthClientHandler(ctx context.Context, input *CreateOAuthClientInput) (*CreateOAuthClientOutput, error) {
	client, err := c.di.OAuthService().Client().CreateClient(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreateOAuthClientOutput{
		Body: client,
	}, nil
}

// GetOAuthClientInput represents input for getting an OAuth client
type GetOAuthClientInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"OAuth client ID"`
}

type GetOAuthClientOutput = model.Output[*model.OAuthClient]

func (c *oauthController) getOAuthClientHandler(ctx context.Context, input *GetOAuthClientInput) (*GetOAuthClientOutput, error) {
	client, err := c.di.OAuthService().Client().GetClient(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &GetOAuthClientOutput{
		Body: client,
	}, nil
}

// UpdateOAuthClientInput represents input for updating an OAuth client
type UpdateOAuthClientInput struct {
	model.OrganisationPathParams
	ID   xid.ID                         `path:"id" doc:"OAuth client ID"`
	Body model.UpdateOAuthClientRequest `json:"body"`
}

type UpdateOAuthClientOutput = model.Output[*model.OAuthClient]

func (c *oauthController) updateOAuthClientHandler(ctx context.Context, input *UpdateOAuthClientInput) (*UpdateOAuthClientOutput, error) {
	client, err := c.di.OAuthService().Client().UpdateClient(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateOAuthClientOutput{
		Body: client,
	}, nil
}

// DeleteOAuthClientInput represents input for deleting an OAuth client
type DeleteOAuthClientInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"OAuth client ID"`
}

type DeleteOAuthClientOutput = model.Output[map[string]interface{}]

func (c *oauthController) deleteOAuthClientHandler(ctx context.Context, input *DeleteOAuthClientInput) (*DeleteOAuthClientOutput, error) {
	err := c.di.OAuthService().Client().DeleteClient(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &DeleteOAuthClientOutput{
		Body: map[string]interface{}{
			"success": true,
			"message": "OAuth client deleted successfully",
		},
	}, nil
}

// RegenerateClientSecretInput represents input for regenerating client secret
type RegenerateClientSecretInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"OAuth client ID"`
}

type RegenerateClientSecretOutput = model.Output[*model.RegenerateClientSecretResponse]

func (c *oauthController) regenerateClientSecretHandler(ctx context.Context, input *RegenerateClientSecretInput) (*RegenerateClientSecretOutput, error) {
	response, err := c.di.OAuthService().Client().RegenerateClientSecret(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &RegenerateClientSecretOutput{
		Body: response,
	}, nil
}

// ActivateOAuthClientInput represents input for activating an OAuth client
type ActivateOAuthClientInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"OAuth client ID"`
}

type ActivateOAuthClientOutput = model.Output[map[string]interface{}]

func (c *oauthController) activateOAuthClientHandler(ctx context.Context, input *ActivateOAuthClientInput) (*ActivateOAuthClientOutput, error) {
	err := c.di.OAuthService().Client().ActivateClient(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &ActivateOAuthClientOutput{
		Body: map[string]interface{}{
			"success": true,
			"message": "OAuth client activated successfully",
		},
	}, nil
}

// DeactivateOAuthClientInput represents input for deactivating an OAuth client
type DeactivateOAuthClientInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"OAuth client ID"`
}

type DeactivateOAuthClientOutput = model.Output[map[string]interface{}]

func (c *oauthController) deactivateOAuthClientHandler(ctx context.Context, input *DeactivateOAuthClientInput) (*DeactivateOAuthClientOutput, error) {
	err := c.di.OAuthService().Client().DeactivateClient(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &DeactivateOAuthClientOutput{
		Body: map[string]interface{}{
			"success": true,
			"message": "OAuth client deactivated successfully",
		},
	}, nil
}

// OAuth Token Management Handlers

// ListOAuthTokensInput represents input for listing OAuth tokens
type ListOAuthTokensInput struct {
	model.OrganisationPathParams
	model.OAuthTokenListRequest
}

type ListOAuthTokensOutput = model.Output[*model.OAuthTokenListResponse]

func (c *oauthController) listOAuthTokensHandler(ctx context.Context, input *ListOAuthTokensInput) (*ListOAuthTokensOutput, error) {
	tokens, err := c.di.OAuthService().Token().ListTokens(ctx, input.OAuthTokenListRequest)
	if err != nil {
		return nil, err
	}

	return &ListOAuthTokensOutput{
		Body: tokens,
	}, nil
}

// GetOAuthTokenInput represents input for getting an OAuth token
type GetOAuthTokenInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"OAuth token ID"`
}

type GetOAuthTokenOutput = model.Output[*model.OAuthToken]

func (c *oauthController) getOAuthTokenHandler(ctx context.Context, input *GetOAuthTokenInput) (*GetOAuthTokenOutput, error) {
	token, err := c.di.OAuthService().Token().GetTokenInfo(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &GetOAuthTokenOutput{
		Body: token,
	}, nil
}

// RevokeOAuthTokenInput represents input for revoking an OAuth token
type RevokeOAuthTokenInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"OAuth token ID"`
}

type RevokeOAuthTokenOutput = model.Output[map[string]interface{}]

func (c *oauthController) revokeOAuthTokenHandler(ctx context.Context, input *RevokeOAuthTokenInput) (*RevokeOAuthTokenOutput, error) {
	err := c.di.OAuthService().Token().RevokeToken(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &RevokeOAuthTokenOutput{
		Body: map[string]interface{}{
			"success": true,
			"message": "OAuth token revoked successfully",
		},
	}, nil
}

// ListUserTokensInput represents input for listing user tokens
type ListUserTokensInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
	model.OAuthTokenListRequest
}

type ListUserTokensOutput = model.Output[*model.OAuthTokenListResponse]

func (c *oauthController) listUserTokensHandler(ctx context.Context, input *ListUserTokensInput) (*ListUserTokensOutput, error) {
	tokens, err := c.di.OAuthService().Token().ListUserTokens(ctx, input.UserID, input.OAuthTokenListRequest)
	if err != nil {
		return nil, err
	}

	return &ListUserTokensOutput{
		Body: tokens,
	}, nil
}

// ListClientTokensInput represents input for listing client tokens
type ListClientTokensInput struct {
	model.OrganisationPathParams
	ClientID xid.ID `path:"clientId" doc:"OAuth client ID"`
	model.OAuthTokenListRequest
}

type ListClientTokensOutput = model.Output[*model.OAuthTokenListResponse]

func (c *oauthController) listClientTokensHandler(ctx context.Context, input *ListClientTokensInput) (*ListClientTokensOutput, error) {
	tokens, err := c.di.OAuthService().Token().ListClientTokens(ctx, input.ClientID, input.OAuthTokenListRequest)
	if err != nil {
		return nil, err
	}

	return &ListClientTokensOutput{
		Body: tokens,
	}, nil
}

// BulkRevokeTokensInput represents input for bulk token revocation
type BulkRevokeTokensInput struct {
	model.OrganisationPathParams
	Body model.BulkRevokeTokensRequest `json:"body"`
}

type BulkRevokeTokensOutput = model.Output[*model.BulkRevokeTokensResponse]

func (c *oauthController) bulkRevokeTokensHandler(ctx context.Context, input *BulkRevokeTokensInput) (*BulkRevokeTokensOutput, error) {
	response, err := c.di.OAuthService().Client().BulkRevokeClientTokens(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &BulkRevokeTokensOutput{
		Body: response,
	}, nil
}

// OAuth Scope Management Handlers

// ListOAuthScopesInput represents input for listing OAuth scopes
type ListOAuthScopesInput struct {
	model.OrganisationPathParams
	model.PaginationParams
}

type ListOAuthScopesOutput = model.Output[*model.OAuthScopeListResponse]

func (c *oauthController) listOAuthScopesHandler(ctx context.Context, input *ListOAuthScopesInput) (*ListOAuthScopesOutput, error) {
	// This would need a scopes service method - simplified for now
	return &ListOAuthScopesOutput{
		Body: &model.OAuthScopeListResponse{
			Data:       []model.OAuthScope{},
			Pagination: &model.Pagination{},
		},
	}, nil
}

// CreateOAuthScopeInput represents input for creating an OAuth scope
type CreateOAuthScopeInput struct {
	model.OrganisationPathParams
	Body model.CreateOAuthScopeRequest `json:"body"`
}

type CreateOAuthScopeOutput = model.Output[*model.OAuthScope]

func (c *oauthController) createOAuthScopeHandler(ctx context.Context, input *CreateOAuthScopeInput) (*CreateOAuthScopeOutput, error) {
	// This would need a scopes service method - simplified for now
	return &CreateOAuthScopeOutput{
		Body: &model.OAuthScope{},
	}, nil
}

// GetOAuthScopeInput represents input for getting an OAuth scope
type GetOAuthScopeInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"OAuth scope ID"`
}

type GetOAuthScopeOutput = model.Output[*model.OAuthScope]

func (c *oauthController) getOAuthScopeHandler(ctx context.Context, input *GetOAuthScopeInput) (*GetOAuthScopeOutput, error) {
	// This would need a scopes service method - simplified for now
	return &GetOAuthScopeOutput{
		Body: &model.OAuthScope{},
	}, nil
}

// UpdateOAuthScopeInput represents input for updating an OAuth scope
type UpdateOAuthScopeInput struct {
	model.OrganisationPathParams
	ID   xid.ID                        `path:"id" doc:"OAuth scope ID"`
	Body model.UpdateOAuthScopeRequest `json:"body"`
}

type UpdateOAuthScopeOutput = model.Output[*model.OAuthScope]

func (c *oauthController) updateOAuthScopeHandler(ctx context.Context, input *UpdateOAuthScopeInput) (*UpdateOAuthScopeOutput, error) {
	// This would need a scopes service method - simplified for now
	return &UpdateOAuthScopeOutput{
		Body: &model.OAuthScope{},
	}, nil
}

// DeleteOAuthScopeInput represents input for deleting an OAuth scope
type DeleteOAuthScopeInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"OAuth scope ID"`
}

type DeleteOAuthScopeOutput = model.Output[map[string]interface{}]

func (c *oauthController) deleteOAuthScopeHandler(ctx context.Context, input *DeleteOAuthScopeInput) (*DeleteOAuthScopeOutput, error) {
	// This would need a scopes service method - simplified for now
	return &DeleteOAuthScopeOutput{
		Body: map[string]interface{}{
			"success": true,
			"message": "OAuth scope deleted successfully",
		},
	}, nil
}

// Public OAuth Flow Handlers

// OAuthAuthorizeInput represents input for OAuth authorization
type OAuthAuthorizeInput struct {
	model.AuthorizeRequest
}

type OAuthAuthorizeOutput = model.Output[*model.AuthorizeResponse]

func (c *oauthController) oauthAuthorizeHandler(ctx context.Context, input *OAuthAuthorizeInput) (*OAuthAuthorizeOutput, error) {
	response, err := c.di.OAuthService().OAuth().Authorize(ctx, input.AuthorizeRequest)
	if err != nil {
		return nil, err
	}

	return &OAuthAuthorizeOutput{
		Body: response,
	}, nil
}

// OAuthTokenInput represents input for OAuth token exchange
type OAuthTokenInput struct {
	Body model.TokenRequest `json:"body"`
}

type OAuthTokenOutput = model.Output[*model.TokenResponse]

func (c *oauthController) oauthTokenHandler(ctx context.Context, input *OAuthTokenInput) (*OAuthTokenOutput, error) {
	logger := c.di.Logger().Named("oauth-token")

	logger.Debug("Processing OAuth token exchange",
		logging.String("grant_type", input.Body.GrantType),
		logging.String("client_id", input.Body.ClientID))

	oauthService := c.di.OAuthService()
	if oauthService == nil {
		return nil, errors.New(errors.CodeInternalServer, "OAuth service not available")
	}

	// Validate required fields
	if input.Body.GrantType == "" {
		return nil, errors.New(errors.CodeBadRequest, "grant_type is required")
	}

	if input.Body.ClientID == "" {
		return nil, errors.New(errors.CodeBadRequest, "client_id is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionOAuthTokenExchange,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"grant_type": input.Body.GrantType,
			"client_id":  input.Body.ClientID,
		},
		Source: audit.SourceAPI,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	var response *model.TokenResponse
	var err error

	// Handle different grant types
	switch input.Body.GrantType {
	case "authorization_code":
		// Validate authorization code grant
		if input.Body.Code == "" {
			return nil, errors.New(errors.CodeBadRequest, "code is required for authorization_code grant")
		}
		if input.Body.RedirectURI == "" {
			return nil, errors.New(errors.CodeBadRequest, "redirect_uri is required for authorization_code grant")
		}

		// Exchange authorization code for tokens
		response, err = oauthService.OAuth().ExchangeCodeForToken(ctx, input.Body)
		if err != nil {
			logger.Error("Failed to exchange authorization code", logging.Error(err))
			return nil, errors.Wrap(err, errors.CodeBadRequest, "invalid authorization code")
		}

	case "refresh_token":
		// Validate refresh token grant
		if input.Body.RefreshToken == "" {
			return nil, errors.New(errors.CodeBadRequest, "refresh_token is required for refresh_token grant")
		}

		// Refresh access token
		response, err = oauthService.OAuth().RefreshToken(ctx, input.Body)
		if err != nil {
			logger.Error("Failed to refresh token", logging.Error(err))
			return nil, errors.Wrap(err, errors.CodeBadRequest, "invalid refresh token")
		}

	case "client_credentials":
		// Validate client credentials
		if input.Body.ClientSecret == "" {
			return nil, errors.New(errors.CodeBadRequest, "client_secret is required for client_credentials grant")
		}

		// Handle client credentials flow
		clientCredsReq := model.OAuthClientCredentials{
			ClientID:     input.Body.ClientID,
			ClientSecret: input.Body.ClientSecret,
			GrantType:    input.Body.GrantType,
			Scope:        input.Body.Scope,
		}

		clientResponse, err := oauthService.OAuth().ClientCredentials(ctx, clientCredsReq)
		if err != nil {
			logger.Error("Failed client credentials flow", logging.Error(err))
			return nil, errors.Wrap(err, errors.CodeUnauthorized, "invalid client credentials")
		}

		// Convert to standard token response
		response = &model.TokenResponse{
			AccessToken: clientResponse.AccessToken,
			TokenType:   clientResponse.TokenType,
			ExpiresIn:   clientResponse.ExpiresIn,
			Scope:       clientResponse.Scope,
		}

	default:
		return nil, errors.Newf(errors.CodeBadRequest, "unsupported grant type: %s", input.Body.GrantType)
	}

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Details["token_type"] = response.TokenType
	auditEvent.Details["expires_in"] = response.ExpiresIn

	logger.Info("OAuth token exchange successful",
		logging.String("grant_type", input.Body.GrantType),
		logging.String("client_id", input.Body.ClientID),
		logging.Int("expires_in", response.ExpiresIn))

	return &OAuthTokenOutput{
		Body: response,
	}, nil
}

// OAuthUserInfoInput represents input for OAuth user info
type OAuthUserInfoInput struct {
	Authorization string `header:"Authorization" doc:"Bearer token"`
}

type OAuthUserInfoOutput = model.Output[map[string]interface{}]

func (c *oauthController) oauthUserInfoHandler(ctx context.Context, input *OAuthUserInfoInput) (*OAuthUserInfoOutput, error) {
	logger := c.di.Logger().Named("oauth-userinfo")

	logger.Debug("Processing OAuth user info request")

	oauthService := c.di.OAuthService()
	if oauthService == nil {
		return nil, errors.New(errors.CodeInternalServer, "OAuth service not available")
	}

	// Extract access token from Authorization header
	accessToken := input.Authorization
	if accessToken == "" {
		return nil, errors.New(errors.CodeUnauthorized, "access token is required")
	}

	// Remove "Bearer " prefix if present
	if len(accessToken) > 7 && accessToken[:7] == "Bearer " {
		accessToken = accessToken[7:]
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionOAuthUserInfo,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"token_prefix": getTokenPrefix(accessToken),
		},
		Source: audit.SourceAPI,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	// Get user info using the access token
	userInfo, err := oauthService.OAuth().GetUserInfo(ctx, accessToken)
	if err != nil {
		logger.Error("Failed to get user info", logging.Error(err))
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "invalid access token")
	}

	auditEvent.Status = audit.StatusSuccess
	if userID, ok := userInfo["sub"].(string); ok {
		auditEvent.Details["user_id"] = userID
	}

	logger.Info("OAuth user info retrieved successfully")

	return &OAuthUserInfoOutput{
		Body: userInfo,
	}, nil
}

// OAuthRevokeInput represents input for OAuth token revocation
type OAuthRevokeInput struct {
	Body model.RevokeTokenRequest `json:"body"`
}

type OAuthRevokeOutput = model.Output[map[string]interface{}]

func (c *oauthController) oauthRevokeHandler(ctx context.Context, input *OAuthRevokeInput) (*OAuthRevokeOutput, error) {
	err := c.di.OAuthService().OAuth().RevokeToken(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &OAuthRevokeOutput{
		Body: map[string]interface{}{
			"success": true,
		},
	}, nil
}

// OAuthIntrospectInput represents input for OAuth token introspection
type OAuthIntrospectInput struct {
	Body model.IntrospectTokenRequest `json:"body"`
}

type OAuthIntrospectOutput = model.Output[*model.IntrospectTokenResponse]

func (c *oauthController) oauthIntrospectHandler(ctx context.Context, input *OAuthIntrospectInput) (*OAuthIntrospectOutput, error) {
	response, err := c.di.OAuthService().OAuth().IntrospectToken(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &OAuthIntrospectOutput{
		Body: response,
	}, nil
}

// OAuthWellKnownInput represents input for OAuth well-known configuration
type OAuthWellKnownInput struct{}

type OAuthWellKnownOutput = model.Output[map[string]interface{}]

func (c *oauthController) oauthWellKnownHandler(ctx context.Context, input *OAuthWellKnownInput) (*OAuthWellKnownOutput, error) {
	baseURL := c.di.Config().Server.BaseURL

	config := map[string]interface{}{
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/oauth/authorize",
		"token_endpoint":         baseURL + "/oauth/token",
		"userinfo_endpoint":      baseURL + "/oauth/userinfo",
		"revocation_endpoint":    baseURL + "/oauth/revoke",
		"introspection_endpoint": baseURL + "/oauth/introspect",
		"jwks_uri":               baseURL + "/.well-known/jwks.json",
		"response_types_supported": []string{
			"code",
		},
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
		},
		"code_challenge_methods_supported": []string{
			"S256",
			"plain",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},
	}

	return &OAuthWellKnownOutput{
		Body: config,
	}, nil
}

// OAuthJWKSInput represents input for OAuth JWKS endpoint
type OAuthJWKSInput struct{}

type OAuthJWKSBody = map[string]interface{}
type OAuthJWKSOutput = model.Output[OAuthJWKSBody]

func (c *oauthController) oauthJWKSHandler(ctx context.Context, input *OAuthJWKSInput) (*OAuthJWKSOutput, error) {
	// This would normally return the public keys used to verify JWT tokens
	// For now, return empty keys array
	jwks := map[string]interface{}{
		"keys": []interface{}{},
	}

	return &OAuthJWKSOutput{
		Body: jwks,
	}, nil
}

// Statistics Handlers

// GetOAuthStatsInput represents input for getting OAuth statistics
type GetOAuthStatsInput struct {
	model.OrganisationPathParams
	Days model.OptionalParam[int] `query:"days" doc:"Number of days for statistics (default: 30)"`
}

type GetOAuthStatsOutput = model.Output[*model.OAuthStats]

func (c *oauthController) getOAuthStatsHandler(ctx context.Context, input *GetOAuthStatsInput) (*GetOAuthStatsOutput, error) {
	// This would need a stats service method - simplified for now
	stats := &model.OAuthStats{
		TotalClients:        0,
		ActiveClients:       0,
		PublicClients:       0,
		TotalTokens:         0,
		ActiveTokens:        0,
		RevokedTokens:       0,
		ExpiredTokens:       0,
		TotalAuthorizations: 0,
		TotalScopes:         0,
		TokensToday:         0,
		AuthorizationsToday: 0,
	}

	return &GetOAuthStatsOutput{
		Body: stats,
	}, nil
}

// GetClientStatsInput represents input for getting client statistics
type GetClientStatsInput struct {
	model.OrganisationPathParams
	ID   xid.ID                   `path:"id" doc:"OAuth client ID"`
	Days model.OptionalParam[int] `query:"days" doc:"Number of days for statistics (default: 30)"`
}

type GetClientStatsOutput = model.Output[*model.OAuthClientStats]

func (c *oauthController) getClientStatsHandler(ctx context.Context, input *GetClientStatsInput) (*GetClientStatsOutput, error) {
	days := 30
	if input.Days.IsSet {
		days = input.Days.Value
	}

	stats, err := c.di.OAuthService().Client().GetClientUsage(ctx, input.ID, days)
	if err != nil {
		return nil, err
	}

	return &GetClientStatsOutput{
		Body: stats,
	}, nil
}

// GetTokenStatsInput represents input for getting token statistics
type GetTokenStatsInput struct {
	model.OrganisationPathParams
	Days     model.OptionalParam[int]    `query:"days" doc:"Number of days for statistics (default: 30)"`
	ClientID model.OptionalParam[xid.ID] `query:"clientId" doc:"Filter by client ID"`
	UserID   model.OptionalParam[xid.ID] `query:"userId" doc:"Filter by user ID"`
}

type GetTokenStatsOutput = model.Output[*model.TokenUsageStats]

func (c *oauthController) getTokenStatsHandler(ctx context.Context, input *GetTokenStatsInput) (*GetTokenStatsOutput, error) {
	days := 30
	if input.Days.IsSet {
		days = input.Days.Value
	}

	var userId *xid.ID
	if input.UserID.IsSet {
		userId = &input.UserID.Value
	}

	var clientId *xid.ID
	if input.UserID.IsSet {
		clientId = &input.ClientID.Value
	}

	stats, err := c.di.OAuthService().Token().GetTokenStats(ctx, userId, clientId, days)
	if err != nil {
		return nil, err
	}

	return &GetTokenStatsOutput{
		Body: stats,
	}, nil
}

func (c *oauthController) logAuditEvent(ctx context.Context, event audit.AuditEvent) {
	if event.Resource == "" {
		event.Resource = "oauth"
	}
	logAuditEvent(ctx, event, c.di.AuditService(), c.di.Logger())
}
