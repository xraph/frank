package design

import (
	. "goa.design/goa/v3/dsl"
)

var IdentityProviderResponse = Type("IdentityProviderResponse", func() {
	Description("Identity provider information")
	Attribute("id", String, "Provider ID")
	Attribute("name", String, "Provider name")
	Attribute("organization_id", String, "Organization ID")
	Attribute("provider_type", String, "Provider type (oauth2, oidc, saml)")
	Attribute("client_id", String, "OAuth/OIDC client ID")
	Attribute("issuer", String, "OIDC issuer URL")
	Attribute("authorization_endpoint", String, "OAuth/OIDC authorization endpoint")
	Attribute("token_endpoint", String, "OAuth/OIDC token endpoint")
	Attribute("userinfo_endpoint", String, "OIDC userinfo endpoint")
	Attribute("jwks_uri", String, "OIDC JWKS URI")
	Attribute("metadata_url", String, "SAML metadata URL")
	Attribute("redirect_uri", String, "OAuth/OIDC redirect URI")
	Attribute("active", Boolean, "Whether provider is active")
	Attribute("primary", Boolean, "Whether this is the primary provider")
	Attribute("domains", ArrayOf(String), "Allowed email domains")
	Attribute("attributes_mapping", MapOf(String, String), "Attributes mapping")
	Attribute("created_at", String, "Creation timestamp")
	Attribute("updated_at", String, "Last update timestamp")
	Required("id", "name", "organization_id", "provider_type", "active", "created_at")
})

var CreateIdentityProviderRequest = Type("CreateIdentityProviderRequest", func() {
	Description("Create identity provider request")
	Attribute("name", String, "Provider name", func() {
		Example("Google")
	})
	Attribute("provider_type", String, "Provider type", func() {
		Enum("oauth2", "oidc", "saml")
		Example("oidc")
	})
	Attribute("client_id", String, "OAuth/OIDC client ID", func() {
		Example("client_id_123")
	})
	Attribute("client_secret", String, "OAuth/OIDC client secret", func() {
		Example("client_secret_456")
	})
	Attribute("issuer", String, "OIDC issuer URL", func() {
		Example("https://accounts.google.com")
	})
	Attribute("authorization_endpoint", String, "OAuth/OIDC authorization endpoint", func() {
		Example("https://accounts.google.com/o/oauth2/auth")
	})
	Attribute("token_endpoint", String, "OAuth/OIDC token endpoint", func() {
		Example("https://oauth2.googleapis.com/token")
	})
	Attribute("userinfo_endpoint", String, "OIDC userinfo endpoint", func() {
		Example("https://openidconnect.googleapis.com/v1/userinfo")
	})
	Attribute("jwks_uri", String, "OIDC JWKS URI", func() {
		Example("https://www.googleapis.com/oauth2/v3/certs")
	})
	Attribute("metadata_url", String, "SAML metadata URL")
	Attribute("redirect_uri", String, "OAuth/OIDC redirect URI", func() {
		Example("https://auth.example.com/callback")
	})
	Attribute("certificate", String, "SAML certificate")
	Attribute("private_key", String, "SAML private key")
	Attribute("active", Boolean, "Whether provider is active", func() {
		Default(true)
	})
	Attribute("primary", Boolean, "Whether this is the primary provider", func() {
		Default(false)
	})
	Attribute("domains", ArrayOf(String), "Allowed email domains", func() {
		Example([]string{"example.com"})
	})
	Attribute("attributes_mapping", MapOf(String, String), "Attributes mapping", func() {
		Example(map[string]string{
			"email": "email",
			"name":  "name",
		})
	})
	Required("name", "provider_type")
	// Conditional requirements checked in handler
})

var UpdateIdentityProviderRequest = Type("UpdateIdentityProviderRequest", func() {
	Description("Update identity provider request")
	Attribute("name", String, "Provider name")
	Attribute("client_id", String, "OAuth/OIDC client ID")
	Attribute("client_secret", String, "OAuth/OIDC client secret")
	Attribute("issuer", String, "OIDC issuer URL")
	Attribute("authorization_endpoint", String, "OAuth/OIDC authorization endpoint")
	Attribute("token_endpoint", String, "OAuth/OIDC token endpoint")
	Attribute("userinfo_endpoint", String, "OIDC userinfo endpoint")
	Attribute("jwks_uri", String, "OIDC JWKS URI")
	Attribute("metadata_url", String, "SAML metadata URL")
	Attribute("redirect_uri", String, "OAuth/OIDC redirect URI")
	Attribute("certificate", String, "SAML certificate")
	Attribute("private_key", String, "SAML private key")
	Attribute("active", Boolean, "Whether provider is active")
	Attribute("primary", Boolean, "Whether this is the primary provider")
	Attribute("domains", ArrayOf(String), "Allowed email domains")
	Attribute("attributes_mapping", MapOf(String, String), "Attributes mapping")
})

var SSOProvider = Type("SSOProvider", func() {
	Description("SSO Provider information")
	Attribute("id", String, "Provider ID")
	Attribute("name", String, "Provider name")
	Attribute("type", String, "Provider type (oauth2, oidc, saml)")
	Attribute("icon_url", String, "Provider icon URL")
	Required("id", "name", "type")
})

var _ = Service("sso", func() {
	Description("Single Sign-On service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("conflict", ConflictError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Path("/v1/auth/sso")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("conflict", StatusConflict)
		Response("internal_error", StatusInternalServerError)
	})

	Method("list_providers", func() {
		Description("List available SSO providers")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Attribute("organization_id", String, "Organization ID")
		})
		Result(func() {
			Attribute("providers", ArrayOf(SSOProvider))
			Required("providers")
		})
		HTTP(func() {
			GET("/providers")
			Response(StatusOK)
			Params(func() {
				Param("organization_id")
			})
		})
	})

	Method("provider_auth", func() {
		Description("Initiate SSO authentication with a provider")
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
			// Use only redirect, not response
			Redirect("/redirect/dest", StatusTemporaryRedirect)
		})
	})

	Method("provider_callback", func() {
		Description("Handle SSO provider callback")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Attribute("provider", String, "Provider ID")
			Attribute("code", String, "Authorization code")
			Attribute("state", String, "State parameter")
			Attribute("SAMLResponse", String, "SAML response")
			Attribute("RelayState", String, "SAML relay state")
			Required("provider")
		})
		Result(func() {
			Attribute("authenticated", Boolean, "Whether authentication was successful")
			Attribute("user", User, "User data if authentication successful")
			Required("authenticated")
		})
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/callback/{provider}")
			Params(func() {
				Param("code")
				Param("state")
				Param("SAMLResponse")
				Param("RelayState")
			})
			Response(StatusOK)
		})
	})

	// Identity provider management
	Method("list_identity_providers", func() {
		Description("List identity providers")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("organization_id", String, "Organization ID")
			Required("organization_id")
		})
		Result(func() {
			Attribute("providers", ArrayOf(IdentityProviderResponse))
			Required("providers")
		})
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			GET("/identity-providers")
			Response(StatusOK)
			Params(func() {
				Param("organization_id")
			})
		})
	})

	Method("create_identity_provider", func() {
		Description("Create a new identity provider")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("organization_id", String, "Organization ID")
			Attribute("provider", CreateIdentityProviderRequest)
			Required("organization_id", "provider")
		})
		Result(IdentityProviderResponse)
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			POST("/identity-providers")
			Response(StatusCreated)
		})
	})

	Method("get_identity_provider", func() {
		Description("Get identity provider by ID")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Provider ID")
			Required("id")
		})
		Result(IdentityProviderResponse)
		Error("not_found")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			GET("/identity-providers/{id}")
			Response(StatusOK)
		})
	})

	Method("update_identity_provider", func() {
		Description("Update identity provider")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Provider ID")
			Attribute("provider", UpdateIdentityProviderRequest)
			Required("id", "provider")
		})
		Result(IdentityProviderResponse)
		Error("bad_request")
		Error("not_found")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			PUT("/identity-providers/{id}")
			Response(StatusOK)
		})
	})

	Method("delete_identity_provider", func() {
		Description("Delete identity provider")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Provider ID")
			Required("id")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			DELETE("/identity-providers/{id}")
			Response(StatusNoContent)
		})
	})

	// SAML endpoints
	Method("saml_metadata", func() {
		Description("SAML metadata endpoint")
		NoSecurity()
		Payload(func() {
			Attribute("id", String, "Provider ID")
			Required("id")
		})
		Result(func() {
			Attribute("metadata", String, "SAML metadata XML")
			Required("metadata")
		})
		Error("not_found", NotFoundError)
		HTTP(func() {
			GET("/saml/{id}/metadata")
			Response(StatusOK, func() {
				ContentType("application/xml")
			})
		})
	})

	Method("saml_acs", func() {
		Description("SAML assertion consumer service")
		NoSecurity()
		Payload(func() {
			Attribute("id", String, "Provider ID")
			Required("id")
		})
		Result(String, "HTML response for browser redirection")
		Error("bad_request", BadRequestError)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			POST("/saml/{id}/acs")
			Response(StatusOK, func() {
				ContentType("text/html")
			})
		})
	})
})
