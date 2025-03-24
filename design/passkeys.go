package design

import (
	. "goa.design/goa/v3/dsl"
)

var PasskeyRegisterBeginRequest = Type("PasskeyRegisterBeginRequest", func() {
	Description("Begin passkey registration request")
	Attribute("device_name", String, "Name of the device")
	Attribute("device_type", String, "Type of the device")
})

var PasskeyRegisterCompleteRequest = Type("PasskeyRegisterCompleteRequest", func() {
	Description("Complete passkey registration request")
	Attribute("session_id", String, "Registration session ID")
	Attribute("response", Any, "WebAuthn credential creation response")
	Attribute("device_name", String, "Name of the device")
	Attribute("device_type", String, "Type of the device")
	Required("session_id", "response")
})

var PasskeyLoginBeginRequest = Type("PasskeyLoginBeginRequest", func() {
	Description("Begin passkey authentication request")
})

var PasskeyLoginCompleteRequest = Type("PasskeyLoginCompleteRequest", func() {
	Description("Complete passkey authentication request")
	Attribute("session_id", String, "Authentication session ID")
	Attribute("response", Any, "WebAuthn assertion response")
	Required("session_id", "response")
})

var RegisteredPasskey = Type("RegisteredPasskey", func() {
	Description("Registered passkey information")
	Attribute("id", String, "Passkey ID")
	Attribute("name", String, "Passkey name")
	Attribute("device_type", String, "Device type")
	Attribute("registered_at", String, "Registration timestamp")
	Attribute("last_used", String, "Last usage timestamp")
	Required("id", "name", "device_type", "registered_at")
})

var UpdatePasskeyRequest = Type("UpdatePasskeyRequest", func() {
	Description("Update passkey request")
	Attribute("name", String, "New passkey name")
	Required("name")
})

var _ = Service("passkeys", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Passkey (WebAuthn) authentication service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("conflict", ConflictError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Path("/v1/auth/passkeys")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("conflict", StatusConflict)
		Response("internal_error", StatusInternalServerError)
	})

	Method("register_begin", func() {
		Description("Begin passkey registration")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(PasskeyRegisterBeginRequest)
		})
		Result(func() {
			Attribute("options", Any, "WebAuthn credential creation options")
			Attribute("session_id", String, "Registration session ID")
			Required("options", "session_id")
		})
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			POST("/register/begin")
			Response(StatusOK)
		})
	})

	Method("register_complete", func() {
		Description("Complete passkey registration")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(PasskeyRegisterCompleteRequest)
		})
		Result(RegisteredPasskey)
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		Error("conflict", ConflictError)
		HTTP(func() {
			POST("/register/complete")
			Response(StatusOK)
		})
	})

	Method("login_begin", func() {
		Description("Begin passkey authentication")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Extend(PasskeyLoginBeginRequest)
		})
		Result(func() {
			Attribute("options", Any, "WebAuthn credential request options")
			Attribute("session_id", String, "Authentication session ID")
			Required("options", "session_id")
		})
		Error("bad_request", BadRequestError)
		HTTP(func() {
			POST("/login/begin")
			Response(StatusOK)
		})
	})

	Method("login_complete", func() {
		Description("Complete passkey authentication")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Extend(PasskeyLoginCompleteRequest)
		})
		Result(func() {
			Attribute("authenticated", Boolean, "Whether authentication was successful")
			Attribute("user_id", String, "User ID")
			Required("authenticated", "user_id")
		})
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			POST("/login/complete")
			Response(StatusOK)
		})
	})

	Method("list", func() {
		Description("List registered passkeys")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
		})
		Result(func() {
			Attribute("passkeys", ArrayOf("RegisteredPasskey"))
			Required("passkeys")
		})
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("")
			Response(StatusOK)
		})
	})

	Method("update", func() {
		Description("Update passkey")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Passkey ID")
			Attribute("request", "UpdatePasskeyRequest")
			Required("id", "request")
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Required("message")
		})
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		Error("not_found", NotFoundError)
		HTTP(func() {
			PUT("/{id}")
			Response(StatusOK)
		})
	})

	Method("delete", func() {
		Description("Delete passkey")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Passkey ID")
			Required("id")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			DELETE("/{id}")
			Response(StatusNoContent)
		})
	})
})
