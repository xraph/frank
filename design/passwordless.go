package design

import (
	. "goa.design/goa/v3/dsl"
)

var PasswordlessEmailRequest = Type("PasswordlessEmailRequest", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Passwordless email login request")
	Attribute("email", String, "User email", func() {
		Format(FormatEmail)
		Example("user@example.com")
	})
	Attribute("redirect_url", String, "URL to redirect after successful authentication")
	Required("email")
})

var PasswordlessSMSRequest = Type("PasswordlessSMSRequest", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Passwordless SMS login request")
	Attribute("phone_number", String, "User phone number", func() {
		Example("+12345678901")
	})
	Attribute("redirect_url", String, "URL to redirect after successful authentication")
	Required("phone_number")
})

var PasswordlessVerifyRequest = Type("PasswordlessVerifyRequest", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Passwordless verification request")
	Attribute("token", String, "Verification token for email authentication")
	Attribute("phone_number", String, "Phone number for SMS authentication")
	Attribute("code", String, "Verification code for SMS authentication")
	Attribute("auth_type", String, "Authentication type", func() {
		Enum("email", "sms")
		Example("email")
	})
	Required("auth_type")
	// Dynamic requirements based on auth_type will be validated in the handler
})

var MagicLinkRequest = Type("MagicLinkRequest", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Magic link generation request")
	Attribute("email", String, "User email", func() {
		Format(FormatEmail)
		Example("user@example.com")
	})
	Attribute("user_id", String, "User ID", func() {
		Example("usr_123456789")
	})
	Attribute("redirect_url", String, "URL to redirect after authentication", func() {
		Example("https://example.com/dashboard")
	})
	Attribute("expires_in", Int, "Link expiry in seconds", func() {
		Default(86400)  // 24 hours
		Minimum(60)     // 1 minute minimum
		Maximum(604800) // 1 week maximum
	})
	Required("email", "user_id", "redirect_url")
})

var _ = Service("passwordless", func() {
	Description("Passwordless authentication service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Path("/v1/auth/passwordless")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("internal_error", StatusInternalServerError)
	})

	Method("email", func() {
		Description("Initiate passwordless email authentication")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Extend(PasswordlessEmailRequest)
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Attribute("verification_id", String, "Verification ID")
			Required("message", "verification_id")
		})
		Error("bad_request")
		HTTP(func() {
			POST("/email")
			Response(StatusOK)
		})
	})

	Method("sms", func() {
		Description("Initiate passwordless SMS authentication")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Extend(PasswordlessSMSRequest)
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Attribute("verification_id", String, "Verification ID")
			Required("message", "verification_id")
		})
		Error("bad_request")
		HTTP(func() {
			POST("/sms")
			Response(StatusOK)
		})
	})

	Method("verify", func() {
		Description("Verify passwordless authentication")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Extend(PasswordlessVerifyRequest)
		})
		Result(func() {
			Attribute("authenticated", Boolean, "Whether authentication was successful")
			Attribute("user_id", String, "User ID")
			Attribute("email", String, "User email")
			Attribute("user", "User", "User data if authentication successful")
			Required("authenticated", "user_id")
		})
		Error("bad_request")
		Error("unauthorized")
		HTTP(func() {
			POST("/verify")
			Response(StatusOK)
		})
	})

	Method("methods", func() {
		Description("Get available passwordless authentication methods")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
		})
		Result(func() {
			Attribute("enabled", Boolean, "Whether passwordless auth is enabled")
			Attribute("methods", ArrayOf(String), "Available methods")
			Required("enabled", "methods")
		})
		HTTP(func() {
			GET("/methods")
			Response(StatusOK)
		})
	})

	Method("magic_link", func() {
		Description("Generate magic link for passwordless login")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(MagicLinkRequest)
		})
		Result(func() {
			Attribute("magic_link", String, "Generated magic link")
			Attribute("expires_in", Int, "Expiry in seconds")
			Required("magic_link", "expires_in")
		})
		Error("bad_request")
		Error("unauthorized")
		HTTP(func() {
			POST("/magic-link")
			Response(StatusOK)
		})
	})
})
