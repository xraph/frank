package design

import (
	. "goa.design/goa/v3/dsl"
)

var APIKeyResponse = Type("APIKeyResponse", func() {
	Description("API key information without the actual key")
	Attribute("id", String, "API key ID")
	Attribute("name", String, "API key name")
	Attribute("user_id", String, "User ID who owns the key")
	Attribute("organization_id", String, "Organization ID")
	Attribute("type", String, "API key type (client/server)")
	Attribute("active", Boolean, "Whether API key is active")
	Attribute("permissions", ArrayOf(String), "Key permissions")
	Attribute("scopes", ArrayOf(String), "Key scopes")
	Attribute("metadata", MetadataType, "Key metadata")
	Attribute("last_used", String, "Last used timestamp")
	Attribute("expires_at", String, "Expiry timestamp")
	Attribute("created_at", String, "Creation timestamp")
	Attribute("updated_at", String, "Last update timestamp")
	Required("id", "name", "type", "active", "created_at")
})

var APIKeyWithSecretResponse = Type("APIKeyWithSecretResponse", func() {
	Description("API key information with the actual key")
	Extend(APIKeyResponse)
	Attribute("key", String, "API key secret")
	Required("key")
})

var CreateAPIKeyRequest = Type("CreateAPIKeyRequest", func() {
	Description("Create API key request")
	Attribute("name", String, "API key name", func() {
		Example("My API Key")
	})
	Attribute("type", String, "API key type", func() {
		Enum("client", "server")
		Default("client")
	})
	Attribute("permissions", ArrayOf(String), "Key permissions", func() {
		Example([]string{"read:users", "write:organizations"})
	})
	Attribute("scopes", ArrayOf(String), "Key scopes", func() {
		Example([]string{"api:access"})
	})
	Attribute("metadata", MetadataType, "Key metadata")
	Attribute("expires_in", Int, "Expiry in seconds", func() {
		Example(2592000) // 30 days
	})
	Required("name")
})

var UpdateAPIKeyRequest = Type("UpdateAPIKeyRequest", func() {
	Description("Update API key request")
	Attribute("name", String, "API key name")
	Attribute("active", Boolean, "Whether API key is active")
	Attribute("permissions", ArrayOf(String), "Key permissions")
	Attribute("scopes", ArrayOf(String), "Key scopes")
	Attribute("metadata", MetadataType, "Key metadata")
	Attribute("expires_at", String, "Expiry timestamp")
})

var _ = Service("api_keys", func() {
	Description("API key management service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Path("/v1/api-keys")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("internal_error", StatusInternalServerError)
	})

	Method("list", func() {
		Description("List API keys")
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
			Attribute("type", String, "Filter by key type", func() {
				Enum("client", "server")
			})
			Attribute("organization_id", String, "Filter by organization ID")
		})
		Result(func() {
			Attribute("data", ArrayOf("APIKeyResponse"))
			Attribute("total", Int, "Total number of keys")
			Attribute("pagination", "Pagination")
			Required("data", "pagination", "total")
		})
		Error("unauthorized")
		HTTP(func() {
			GET("")
			Response(StatusOK)
			Params(func() {
				Param("offset")
				Param("limit")
				Param("type")
				Param("organization_id")
			})
		})
	})

	Method("create", func() {
		Description("Create a new API key")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("key", CreateAPIKeyRequest)
			Required("key")
		})
		Result(APIKeyWithSecretResponse)
		Error("bad_request")
		Error("unauthorized")
		HTTP(func() {
			POST("")
			Response(StatusCreated)
		})
	})

	Method("get", func() {
		Description("Get API key by ID")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "API key ID")
			Required("id")
		})
		Result(APIKeyResponse)
		Error("not_found")
		Error("unauthorized")
		HTTP(func() {
			GET("/{id}")
			Response(StatusOK)
		})
	})

	Method("update", func() {
		Description("Update API key")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "API key ID")
			Attribute("key", UpdateAPIKeyRequest)
			Required("id", "key")
		})
		Result(APIKeyResponse)
		Error("bad_request", BadRequestError)
		Error("not_found", NotFoundError, "API key not found")
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			PUT("/{id}")
			Response(StatusOK)
		})
	})

	Method("delete", func() {
		Description("Delete API key")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "API key ID")
			Required("id")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			DELETE("/{id}")
			Response(StatusNoContent)
		})
	})

	Method("validate", func() {
		Description("Validate API key")
		NoSecurity()
		Payload(func() {
			Attribute("api_key", String, "API key to validate", func() {
				Example("sk_12345678901234567890")
			})
			Required("api_key")
		})
		Result(func() {
			Attribute("valid", Boolean, "Whether key is valid")
			Attribute("key", "APIKeyResponse", "Key details if valid")
			Required("valid")
		})
		HTTP(func() {
			GET("/validate")
			Param("api_key")
			Response(StatusOK)
		})
	})
})
