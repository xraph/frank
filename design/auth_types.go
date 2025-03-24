package design

import (
	. "goa.design/goa/v3/dsl"
)

var OAuth2Auth = OAuth2Security("oauth2", func() {
	Description("OAuth2 authentication")
	AuthorizationCodeFlow("/v1/oauth/authorize", "/v1/oauth/token", "/v1/oauth/refresh")

	Scope("profile", "View profile information")
	Scope("email", "View email information")
	Scope("openid", "OpenID Connect scope")
	Scope("offline_access", "Request refresh token")
	Scope("api", "API access")

	// Flow("authorization_code", func() {
	// 	AuthorizationURL("/oauth/authorize")
	// 	TokenURL("/oauth/token")
	// })
	// Flow("password", func() {
	// 	TokenURL("/oauth/token")
	// 	Scope("profile", "View profile information")
	// 	Scope("email", "View email information")
	// })
	// Flow("client_credentials", func() {
	// 	TokenURL("/oauth/token")
	// 	Scope("api", "API access")
	// })
})

var APIKeyAuth = APIKeySecurity("api_key", func() {
	Description("API key-based request authorization")
	// Header("X-API-Key")
})

var JWTAuth = JWTSecurity("jwt", func() {
	Description("JWT-based authentication and authorization")
	// Header("Authorization")

	Scope("api:read", "Read-only access")
	Scope("api:write", "Read and write access")
})
