package design

import (
	. "goa.design/goa/v3/dsl"
)

var OAuthClientResponse = Type("OAuthClientResponse", func() {
	Description("OAuth client information")
	Attribute("id", String, "Client ID")
	Attribute("client_id", String, "OAuth client ID")
	Attribute("client_name", String, "Client name")
	Attribute("client_description", String, "Client description")
	Attribute("client_uri", String, "Client URI")
	Attribute("logo_uri", String, "Logo URI")
	Attribute("redirect_uris", ArrayOf(String), "Authorized redirect URIs")
	Attribute("post_logout_redirect_uris", ArrayOf(String), "Authorized post-logout redirect URIs")
	Attribute("allowed_cors_origins", ArrayOf(String), "Allowed CORS origins")
	Attribute("allowed_grant_types", ArrayOf(String), "Allowed grant types")
	Attribute("public", Boolean, "Whether client is public")
	Attribute("active", Boolean, "Whether client is active")
	Attribute("organization_id", String, "Organization ID")
	Attribute("token_expiry_seconds", Int, "Access token expiry in seconds")
	Attribute("refresh_token_expiry_seconds", Int, "Refresh token expiry in seconds")
	Attribute("requires_pkce", Boolean, "Whether PKCE is required")
	Attribute("requires_consent", Boolean, "Whether user consent is required")
	Attribute("created_at", String, "Creation timestamp")
	Attribute("updated_at", String, "Last update timestamp")
	Required("id", "client_id", "client_name", "redirect_uris", "allowed_grant_types", "public", "active")
})

var OAuthClientWithSecretResponse = Type("OAuthClientWithSecretResponse", func() {
	Description("OAuth client information with client secret")
	Extend(OAuthClientResponse)
	Attribute("client_secret", String, "OAuth client secret")
	Required("client_secret")
})

var CreateOAuthClientRequest = Type("CreateOAuthClientRequest", func() {
	Description("Create OAuth client request")
	Attribute("client_name", String, "Client name", func() {
		Example("My App")
	})
	Attribute("client_description", String, "Client description")
	Attribute("client_uri", String, "Client URI")
	Attribute("logo_uri", String, "Logo URI")
	Attribute("redirect_uris", ArrayOf(String), "Authorized redirect URIs", func() {
		Example([]string{"https://example.com/callback"})
	})
	Attribute("post_logout_redirect_uris", ArrayOf(String), "Authorized post-logout redirect URIs")
	Attribute("allowed_cors_origins", ArrayOf(String), "Allowed CORS origins")
	Attribute("allowed_grant_types", ArrayOf(String), "Allowed grant types", func() {
		Example([]string{"authorization_code", "refresh_token"})
	})
	Attribute("public", Boolean, "Whether client is public", func() {
		Default(false)
	})
	Attribute("token_expiry_seconds", Int, "Access token expiry in seconds", func() {
		Default(3600)
	})
	Attribute("refresh_token_expiry_seconds", Int, "Refresh token expiry in seconds", func() {
		Default(2592000) // 30 days
	})
	Attribute("requires_pkce", Boolean, "Whether PKCE is required", func() {
		Default(true)
	})
	Attribute("requires_consent", Boolean, "Whether user consent is required", func() {
		Default(true)
	})
	Required("client_name", "redirect_uris")
})

var UpdateOAuthClientRequest = Type("UpdateOAuthClientRequest", func() {
	Description("Update OAuth client request")
	Attribute("client_name", String, "Client name")
	Attribute("client_description", String, "Client description")
	Attribute("client_uri", String, "Client URI")
	Attribute("logo_uri", String, "Logo URI")
	Attribute("redirect_uris", ArrayOf(String), "Authorized redirect URIs")
	Attribute("post_logout_redirect_uris", ArrayOf(String), "Authorized post-logout redirect URIs")
	Attribute("allowed_cors_origins", ArrayOf(String), "Allowed CORS origins")
	Attribute("allowed_grant_types", ArrayOf(String), "Allowed grant types")
	Attribute("public", Boolean, "Whether client is public")
	Attribute("active", Boolean, "Whether client is active")
	Attribute("token_expiry_seconds", Int, "Access token expiry in seconds")
	Attribute("refresh_token_expiry_seconds", Int, "Refresh token expiry in seconds")
	Attribute("requires_pkce", Boolean, "Whether PKCE is required")
	Attribute("requires_consent", Boolean, "Whether user consent is required")
})

var RotateClientSecretRequest = Type("RotateClientSecretRequest", func() {
	Description("Rotate client secret request")
	Attribute("client_id", String, "OAuth client ID")
	Required("client_id")
})

var OAuthScopeResponse = Type("OAuthScopeResponse", func() {
	Description("OAuth scope information")
	Attribute("id", String, "Scope ID")
	Attribute("name", String, "Scope name")
	Attribute("description", String, "Scope description")
	Attribute("default_scope", Boolean, "Whether this scope is included by default")
	Attribute("public", Boolean, "Whether this scope can be requested by any client")
	Required("id", "name", "description", "default_scope", "public")
})

var CreateOAuthScopeRequest = Type("CreateOAuthScopeRequest", func() {
	Description("Create OAuth scope request")
	Attribute("name", String, "Scope name", func() {
		Example("read:users")
	})
	Attribute("description", String, "Scope description", func() {
		Example("Read user information")
	})
	Attribute("default_scope", Boolean, "Whether this scope is included by default", func() {
		Default(false)
	})
	Attribute("public", Boolean, "Whether this scope can be requested by any client", func() {
		Default(true)
	})
	Required("name", "description")
})

var ConsentRequest = Type("ConsentRequest", func() {
	Description("OAuth consent request")
	Attribute("client_id", String, "OAuth client ID")
	Attribute("scope", String, "Requested scopes (space-separated)")
	Attribute("redirect_uri", String, "Redirect URI")
	Attribute("state", String, "OAuth state parameter")
	Attribute("approved", Boolean, "Whether consent is approved", func() {
		Default(false)
	})
	Required("client_id", "scope", "redirect_uri")
})

var _ = Service("oauth_provider", func() {
	Description("OAuth2 provider service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("conflict", ConflictError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Path("/v1/oauth")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("conflict", StatusConflict)
		Response("internal_error", StatusInternalServerError)
	})

	// OAuth authorization endpoints
	Method("authorize", func() {
		Description("OAuth2 authorization endpoint")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Attribute("client_id", String, "OAuth client identifier")
			Attribute("response_type", String, "OAuth response type")
			Attribute("redirect_uri", String, "Redirect URI after authorization")
			Attribute("scope", String, "Requested scopes (space-separated)")
			Attribute("state", String, "OAuth state parameter")
			Attribute("code_challenge", String, "PKCE code challenge")
			Attribute("code_challenge_method", String, "PKCE code challenge method")
			Required("client_id", "response_type", "redirect_uri")
		})
		// Change the result type from a struct to String
		Result(String, "HTML response")
		HTTP(func() {
			GET("/authorize")
			Params(func() {
				Param("client_id")
				Param("response_type")
				Param("redirect_uri")
				Param("scope")
				Param("state")
				Param("code_challenge")
				Param("code_challenge_method")
			})
			Response(StatusOK, func() {
				ContentType("text/html")
			})
		})
	})

	Method("token", func() {
		Description("OAuth2 token endpoint")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Attribute("grant_type", String, "Grant type")
			Attribute("code", String, "Authorization code (for authorization_code grant)")
			Attribute("redirect_uri", String, "Redirect URI (for authorization_code grant)")
			Attribute("client_id", String, "Client ID")
			Attribute("client_secret", String, "Client secret")
			Attribute("refresh_token", String, "Refresh token (for refresh_token grant)")
			Attribute("code_verifier", String, "PKCE code verifier (for authorization_code grant)")
			Attribute("username", String, "Resource owner username (for password grant)")
			Attribute("password", String, "Resource owner password (for password grant)")
			Attribute("scope", String, "Requested scopes (space-separated)")
			Required("grant_type")
		})
		Result(func() {
			Attribute("access_token", String, "Access token")
			Attribute("token_type", String, "Token type")
			Attribute("expires_in", Int, "Token expiry in seconds")
			Attribute("refresh_token", String, "Refresh token")
			Attribute("scope", String, "Granted scopes")
			Required("access_token", "token_type", "expires_in")
		})
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			POST("/token")
			// Instead of skipping encoding/decoding, define the params and form values
			Params(func() {
				Param("grant_type")
				Param("code")
				Param("redirect_uri")
				Param("client_id")
				Param("client_secret")
				Param("refresh_token")
				Param("code_verifier")
				Param("username")
				Param("password")
				Param("scope")
			})
			Response(StatusOK)
		})
	})

	Method("introspect", func() {
		Description("OAuth2 token introspection endpoint")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Attribute("token", String, "Token to introspect")
			Attribute("token_type_hint", String, "Token type hint")
			Required("token")
		})
		Result(func() {
			Attribute("active", Boolean, "Whether token is active")
			Attribute("scope", String, "Token scopes")
			Attribute("client_id", String, "Client ID")
			Attribute("username", String, "Resource owner username")
			Attribute("token_type", String, "Token type")
			Attribute("exp", Int, "Expiry timestamp")
			Attribute("iat", Int, "Issued at timestamp")
			Attribute("nbf", Int, "Not before timestamp")
			Attribute("sub", String, "Subject (user ID)")
			Attribute("aud", String, "Audience")
			Attribute("iss", String, "Issuer")
			Attribute("jti", String, "JWTAuth ID")
			Required("active")
		})
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			POST("/introspect")
			Params(func() {
				Param("token")
				Param("token_type_hint")
			})
			Response(StatusOK)
		})
	})

	Method("revoke", func() {
		Description("OAuth2 token revocation endpoint")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Attribute("token", String, "Token to revoke")
			Attribute("token_type_hint", String, "Token type hint")
			Attribute("client_id", String, "Client ID")
			Attribute("client_secret", String, "Client secret")
			Required("token")
		})
		HTTP(func() {
			POST("/revoke")
			Params(func() {
				Param("token")
				Param("token_type_hint")
				Param("client_id")
				Param("client_secret")
			})
			Response(StatusOK)
		})
	})

	Method("consent", func() {
		Description("Handle user consent for OAuth authorization")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(ConsentRequest)
		})
		Result(func() {
			Attribute("redirect_uri", String, "Redirect URI with authorization code")
			Required("redirect_uri")
		})
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			POST("/consent")
			// Use only Redirect or Response, not both
			Redirect("/redirect/dest", StatusTemporaryRedirect)
		})
	})

	Method("userinfo", func() {
		Description("OAuth2 UserInfo endpoint for OpenID Connect")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
		})
		Result(func() {
			Attribute("sub", String, "Subject (user ID)")
			Attribute("name", String, "Full name")
			Attribute("given_name", String, "First name")
			Attribute("family_name", String, "Last name")
			Attribute("middle_name", String, "Middle name")
			Attribute("nickname", String, "Nickname")
			Attribute("preferred_username", String, "Preferred username")
			Attribute("profile", String, "Profile URL")
			Attribute("picture", String, "Picture URL")
			Attribute("website", String, "Website URL")
			Attribute("email", String, "Email address")
			Attribute("email_verified", Boolean, "Whether email is verified")
			Attribute("gender", String, "Gender")
			Attribute("birthdate", String, "Birth date")
			Attribute("zoneinfo", String, "Time zone")
			Attribute("locale", String, "Locale")
			Attribute("phone_number", String, "Phone number")
			Attribute("phone_number_verified", Boolean, "Whether phone number is verified")
			Attribute("updated_at", Int, "Last update timestamp")
			Required("sub")
		})
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/userinfo")
			Response(StatusOK)
		})
	})

	// OAuth client management
	Method("list_clients", func() {
		Description("List OAuth clients")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("offset", Int, "Pagination offset", func() {
				Default(0)
				Minimum(0)
			})
			Attribute("limit", Int, "Number of items to return", func() {
				Default(20)
				Minimum(1)
				Maximum(100)
			})
			Attribute("organization_id", String, "Filter by organization ID")
		})
		Result(func() {
			Attribute("data", ArrayOf(OAuthClientResponse))
			Attribute("pagination", "Pagination")
			Required("data", "pagination")
		})
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			GET("/clients")
			Response(StatusOK)
			Params(func() {
				Param("offset")
				Param("limit")
				Param("organization_id")
			})
		})
	})

	Method("create_client", func() {
		Description("Create a new OAuth client")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(CreateOAuthClientRequest)
		})
		Result(OAuthClientWithSecretResponse)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			POST("/clients")
			Response(StatusCreated)
		})
	})

	Method("get_client", func() {
		Description("Get OAuth client by ID")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Client ID")
			Required("id")
		})
		Result(OAuthClientResponse)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			GET("/clients/{id}")
			Response(StatusOK)
		})
	})

	Method("update_client", func() {
		Description("Update OAuth client")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Client ID")
			Attribute("client", UpdateOAuthClientRequest)
			Required("id", "client")
		})
		Result(OAuthClientResponse)
		Error("bad_request", BadRequestError)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			PUT("/clients/{id}")
			Response(StatusOK)
		})
	})

	Method("delete_client", func() {
		Description("Delete OAuth client")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Client ID")
			Required("id")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			DELETE("/clients/{id}")
			Response(StatusNoContent)
		})
	})

	Method("rotate_client_secret", func() {
		Description("Rotate OAuth client secret")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Client ID")
			Required("id")
		})
		Result(func() {
			Attribute("client_id", String)
			Attribute("client_secret", String)
			Required("client_id", "client_secret")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			POST("/clients/{id}/rotate-secret")
			Response(StatusOK)
		})
	})

	// OAuth scope management
	Method("list_scopes", func() {
		Description("List OAuth scopes")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("offset", Int, "Pagination offset", func() {
				Default(0)
				Minimum(0)
			})
			Attribute("limit", Int, "Number of items to return", func() {
				Default(20)
				Minimum(1)
				Maximum(100)
			})
		})
		Result(func() {
			Attribute("data", ArrayOf(OAuthScopeResponse))
			Attribute("pagination", "Pagination")
			Required("data", "pagination")
		})
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/scopes")
			Response(StatusOK)
			Params(func() {
				Param("offset")
				Param("limit")
			})
		})
	})

	Method("create_scope", func() {
		Description("Create a new OAuth scope")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(CreateOAuthScopeRequest)
		})
		Result(OAuthScopeResponse)
		Error("bad_request", BadRequestError)
		Error("conflict", ConflictError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			POST("/scopes")
			Response(StatusCreated)
		})
	})

	Method("get_scope", func() {
		Description("Get OAuth scope by ID")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Scope ID")
			Required("id")
		})
		Result(OAuthScopeResponse)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/scopes/{id}")
			Response(StatusOK)
		})
	})

	Method("update_scope", func() {
		Description("Update OAuth scope")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Scope ID")
			Attribute("description", String, "Scope description")
			Attribute("default_scope", Boolean, "Whether this scope is included by default")
			Attribute("public", Boolean, "Whether this scope can be requested by any client")
			Required("id")
		})
		Result(OAuthScopeResponse)
		Error("bad_request", BadRequestError)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			PUT("/scopes/{id}")
			Response(StatusOK)
		})
	})

	Method("delete_scope", func() {
		Description("Delete OAuth scope")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Scope ID")
			Required("id")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			DELETE("/scopes/{id}")
			Response(StatusNoContent)
		})
	})

	// OpenID Connect metadata endpoints
	Method("oidc_configuration", func() {
		Description("OpenID Connect discovery configuration")
		NoSecurity()
		Result(func() {
			Attribute("issuer", String)
			Attribute("authorization_endpoint", String)
			Attribute("token_endpoint", String)
			Attribute("userinfo_endpoint", String)
			Attribute("jwks_uri", String)
			Attribute("registration_endpoint", String)
			Attribute("scopes_supported", ArrayOf(String))
			Attribute("response_types_supported", ArrayOf(String))
			Attribute("response_modes_supported", ArrayOf(String))
			Attribute("grant_types_supported", ArrayOf(String))
			Attribute("subject_types_supported", ArrayOf(String))
			Attribute("id_token_signing_alg_values_supported", ArrayOf(String))
			Attribute("token_endpoint_auth_methods_supported", ArrayOf(String))
			Attribute("claims_supported", ArrayOf(String))
			Required("issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri")
		})
		HTTP(func() {
			GET("/.well-known/openid-configuration")
			Response(StatusOK)
		})
	})

	Method("jwks", func() {
		Description("JSON Web Key Set")
		NoSecurity()
		Result(func() {
			Attribute("keys", ArrayOf(Any))
			Required("keys")
		})
		HTTP(func() {
			GET("/.well-known/jwks.json")
			Response(StatusOK)
		})
	})
})

var _ = Service("oauth_client", func() {
	Description("OAuth2 client service for authenticating with external providers")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Path("/v1/auth/oauth")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("internal_error", StatusInternalServerError)
	})

	Method("list_providers", func() {
		Description("List available OAuth providers")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
		})
		Result(func() {
			Attribute("providers", ArrayOf(SSOProvider))
			Required("providers")
		})
		HTTP(func() {
			GET("/providers")
			Response(StatusOK)
		})
	})

	Method("provider_auth", func() {
		Description("Initiate authentication with an OAuth provider")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Attribute("provider", String, "Provider ID")
			Attribute("redirect_uri", String, "Redirect URI after authentication")
			Required("provider")
		})
		Error("not_found", NotFoundError, "Provider not found")
		HTTP(func() {
			GET("/providers/{provider}")
			Param("redirect_uri")
			Response(StatusFound)
		})
	})

	Method("provider_callback", func() {
		Description("Handle OAuth provider callback")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Attribute("provider", String, "Provider ID")
			Attribute("code", String, "Authorization code")
			Attribute("state", String, "State parameter")
			Required("provider")
		})
		Result(func() {
			Attribute("authenticated", Boolean, "Whether authentication was successful")
			Attribute("user", "User", "User data if authentication successful")
			Attribute("message", String, "Success or error message")
			Required("authenticated", "message")
		})
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/callback/{provider}")
			Param("code")
			Param("state")
			Response(StatusOK)
			// Keep only one of Response or Redirect
			// Redirect("/redirect/dest", StatusTemporaryRedirect)
		})
	})
})
