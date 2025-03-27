package design

import (
	. "goa.design/goa/v3/dsl"
)

var Organization = Type("Organization", func() {
	Description("Organization information")
	Meta("struct:pkg:path", "designtypes")

	Attribute("id", String, "Organization ID")
	Attribute("name", String, "Organization name")
	Attribute("slug", String, "Organization slug")
	Attribute("domain", String, "Organization domain")
	Attribute("logo_url", String, "Organization logo URL")
	Attribute("plan", String, "Organization plan")
	Attribute("active", Boolean, "Whether organization is active")
	Attribute("metadata", MetadataType, "Organization metadata")
	Attribute("trial_ends_at", String, "Trial end date")
	Attribute("trial_used", Boolean, "Whether trial has been used")
	Attribute("created_at", String, "Creation timestamp")
	Attribute("updated_at", String, "Last update timestamp")
	Attribute("settings", OrganizationSettings, "Organization settings", func() {
		Meta("struct:tag:json", "settings")
	})
	Required("id", "name", "slug", "active", "created_at", "updated_at")
})

var OrganizationSettings = Type("OrganizationSettings", func() {
	Description("Organization information")
	Meta("struct:pkg:path", "designtypes")

	Field(1, "signupFields", ArrayOf(FormField), "Signup fields", func() {
		Meta("struct:tag:json", "signupFields")
	})
	Field(1, "verification", ArrayOf(OrganizationVerificationConfig), "Signup fields", func() {
		Meta("struct:tag:json", "verification")
	})
})

var OrganizationVerificationConfig = Type("OrganizationVerificationConfig", func() {
	Description("Configuration for organization verification")

	Field(1, "code_length", Int, func() {
		Description("Length of verification code")
		Default(6)
		Example(6)
	})

	Field(2, "method", String, func() {
		Description("Method used for verification")
		Default("email")
		Example("email")
		Enum("email", "sms", "phone") // Add other possible verification methods
	})
})

var CreateOrganizationRequest = Type("CreateOrganizationRequest", func() {
	Description("Create organization request")
	Attribute("name", String, "Organization name", func() {
		Example("Acme Inc.")
	})
	Attribute("slug", String, "Organization slug", func() {
		Example("acme")
	})
	Attribute("domain", String, "Organization domain", func() {
		Example("acme.com")
	})
	Attribute("logo_url", String, "Organization logo URL")
	Attribute("plan", String, "Organization plan", func() {
		Default("free")
		Example("enterprise")
	})
	Attribute("metadata", MetadataType, "Organization metadata")
	Attribute("trial_days", Int, "Number of trial days", func() {
		Minimum(0)
		Example(30)
	})
	Attribute("features", ArrayOf(String), "Features to enable", func() {
		Example([]string{"sso", "webhooks"})
	})
	Required("name")
})

var UpdateOrganizationRequest = Type("UpdateOrganizationRequest", func() {
	Description("Update organization request")
	Attribute("name", String, "Organization name")
	Attribute("domain", String, "Organization domain")
	Attribute("logo_url", String, "Organization logo URL")
	Attribute("plan", String, "Organization plan")
	Attribute("active", Boolean, "Whether organization is active")
	Attribute("metadata", MetadataType, "Organization metadata")
})

var OrganizationMemberResponse = Type("OrganizationMemberResponse", func() {
	Description("Organization member information")
	Attribute("id", String, "User ID")
	Attribute("email", String, "User email")
	Attribute("first_name", String, "User first name")
	Attribute("last_name", String, "User last name")
	Attribute("roles", ArrayOf(String), "User roles in organization")
	Attribute("joined_at", String, "When user joined the organization")
	Required("id", "email", "roles", "joined_at")
})

var AddOrganizationMemberRequest = Type("AddOrganizationMemberRequest", func() {
	Description("Add organization member request")
	Attribute("user_id", String, "User ID to add")
	Attribute("roles", ArrayOf(String), "Roles to assign", func() {
		Example([]string{"member"})
	})
	Required("user_id", "roles")
})

var UpdateOrganizationMemberRequest = Type("UpdateOrganizationMemberRequest", func() {
	Description("Update organization member request")
	Attribute("roles", ArrayOf(String), "Roles to assign")
	Required("roles")
})

var OrganizationFeatureResponse = Type("OrganizationFeatureResponse", func() {
	Description("Organization feature information")
	Attribute("id", String, "Feature ID")
	Attribute("key", String, "Feature key")
	Attribute("name", String, "Feature name")
	Attribute("description", String, "Feature description")
	Attribute("enabled", Boolean, "Whether feature is enabled")
	Attribute("is_premium", Boolean, "Whether feature is premium")
	Attribute("component", String, "Feature component category")
	Attribute("settings", MetadataType, "Feature settings")
	Required("id", "key", "name", "enabled")
})

var EnableFeatureRequest = Type("EnableFeatureRequest", func() {
	Description("Enable feature request")
	Attribute("feature_key", String, "Feature key to enable")
	Attribute("settings", MetadataType, "Feature settings")
	Required("feature_key")
})

var _ = Service("organizations", func() {
	Description("Organization management service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("conflict", ConflictError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Path("/v1/organizations")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("conflict", StatusConflict)
		Response("internal_error", StatusInternalServerError)
	})

	Method("list", func() {
		Description("List organizations")
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
			Attribute("search", String, "Search term")
		})
		Result(func() {
			Attribute("data", ArrayOf("Organization"))
			Attribute("pagination", "Pagination")
			Required("data", "pagination")
		})
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("")
			Response(StatusOK)
			Params(func() {
				Param("offset")
				Param("limit")
				Param("search")
			})
		})
	})

	Method("create", func() {
		Description("Create a new organization")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("organization", CreateOrganizationRequest)
			Required("organization")
		})
		Result(Organization)
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		Error("conflict", ConflictError, "Organization with this slug or domain already exists")
		HTTP(func() {
			POST("")
			Response(StatusCreated)
		})
	})

	Method("get", func() {
		Description("Get organization by ID")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Organization ID")
			Required("id")
		})
		Result(Organization)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/{id}")
			Response(StatusOK)
		})
	})

	Method("update", func() {
		Description("Update organization")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Organization ID")
			Attribute("organization", UpdateOrganizationRequest)
			Required("id", "organization")
		})
		Result(Organization)
		Error("bad_request", BadRequestError)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			PUT("/{id}")
			Response(StatusOK)
		})
	})

	Method("delete", func() {
		Description("Delete organization")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Organization ID")
			Required("id")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			DELETE("/{id}")
			Response(StatusNoContent)
		})
	})

	Method("list_members", func() {
		Description("List organization members")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Organization ID")
			Attribute("offset", Int, "Pagination offset", func() {
				Default(0)
				Minimum(0)
			})
			Attribute("limit", Int, "Number of items to return", func() {
				Default(20)
				Minimum(1)
				Maximum(100)
			})
			Attribute("search", String, "Search term")
			Required("id")
		})
		Result(func() {
			Attribute("data", ArrayOf(OrganizationMemberResponse))
			Attribute("pagination", Pagination)
			Required("data", "pagination")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			GET("/{id}/members")
			Response(StatusOK)
			Params(func() {
				Param("offset")
				Param("limit")
				Param("search")
			})
		})
	})

	Method("add_member", func() {
		Description("Add member to organization")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Organization ID")
			Attribute("member", AddOrganizationMemberRequest)
			Required("id", "member")
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Required("message")
		})
		Error("bad_request", BadRequestError)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			POST("/{id}/members")
			Response(StatusOK)
		})
	})

	Method("update_member", func() {
		Description("Update organization member")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Organization ID")
			Attribute("user_id", String, "User ID")
			Attribute("member", UpdateOrganizationMemberRequest)
			Required("id", "user_id", "member")
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Required("message")
		})
		Error("bad_request", BadRequestError)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			PUT("/{id}/members/{user_id}")
			Response(StatusOK)
		})
	})

	Method("remove_member", func() {
		Description("Remove member from organization")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Organization ID")
			Attribute("user_id", String, "User ID")
			Required("id", "user_id")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			DELETE("/{id}/members/{user_id}")
			Response(StatusNoContent)
		})
	})

	Method("list_features", func() {
		Description("List organization features")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Organization ID")
			Required("id")
		})
		Result(func() {
			Attribute("features", ArrayOf("OrganizationFeatureResponse"))
			Required("features")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			GET("/{id}/features")
			Response(StatusOK)
		})
	})

	Method("enable_feature", func() {
		Description("Enable a feature for an organization")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Organization ID")
			Attribute("feature", EnableFeatureRequest)
			Required("id", "feature")
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Required("message")
		})
		Error("bad_request", BadRequestError)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			POST("/{id}/features")
			Response(StatusOK)
		})
	})

	Method("disable_feature", func() {
		Description("Disable a feature for an organization")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Organization ID")
			Attribute("feature_key", String, "Feature key")
			Required("id", "feature_key")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			DELETE("/{id}/features/{feature_key}")
			Response(StatusNoContent)
		})
	})
})
