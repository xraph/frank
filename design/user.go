package design

import (
	. "goa.design/goa/v3/dsl"
)

var CreateUserRequest = Type("CreateUserRequest", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Create user request")

	Extend(BaseUserType)

	Attribute("password", String, "User password", func() {
		MinLength(8)
		Example("securepassword")
	})
	Attribute("organization_id", String, "Organization ID to add user to")
	Required("email")
})

var UpdateUserRequest = Type("UpdateUserRequest", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Update user request")

	Attribute("phone_number", String, "User phone number")
	Attribute("first_name", String, "User first name")
	Attribute("last_name", String, "User last name")
	Attribute("metadata", MetadataType, "User metadata")
	Attribute("profile_image_url", String, "Profile image URL")
	Attribute("locale", String, "User locale")
	Attribute("active", Boolean, "Whether user is active")
	Attribute("primary_organization_id", String, "Primary organization ID")
})

var UpdatePasswordRequest = Type("UpdatePasswordRequest", func() {
	Description("Update password request")
	Attribute("current_password", String, "Current password", func() {
		Example("oldpassword")
	})
	Attribute("new_password", String, "New password", func() {
		MinLength(8)
		Example("newpassword")
	})
	Required("current_password", "new_password")
})

var GetUserSessionResponse = Type("GetUserSessionResponse", func() {
	Extend(PaginationResponse)

	Description("Get user session response")

	Field(1, "data", ArrayOf(Session), "User sessions", func() {
	})

	Required("data")
})

var _ = Service("users", func() {
	Description("User management service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("conflict", ConflictError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Path("/v1/users")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("conflict", StatusConflict)
		Response("internal_error", StatusInternalServerError)
	})

	Method("list", func() {
		Description("List users")
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
			Attribute("organization_id", String, "Filter by organization ID")
		})
		Result(func() {
			Attribute("data", ArrayOf(User))
			Attribute("pagination", Pagination)
			Required("data", "pagination")
		})
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			GET("")
			Response(StatusOK)
			Params(func() {
				Param("offset", Int, "Pagination offset", func() {
					Default(0)
					Minimum(0)
				})
				Param("limit", Int, "Number of items to return", func() {
					Default(20)
					Minimum(1)
					Maximum(100)
				})
				Param("search", String, "Search term")
				Param("organization_id", String, "Filter by organization ID")
			})
		})
	})

	Method("create", func() {
		Description("Create a new user")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(CreateUserRequest)
		})
		Result(User)
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError, "User must be an admin to create users")
		Error("forbidden", ForbiddenError, "User must be an admin to create users")
		Error("conflict", ConflictError, "User with this email already exists")
		HTTP(func() {
			POST("")
			Response(StatusCreated)
		})
	})

	Method("get", func() {
		Description("Get user by ID")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "User ID")
			Required("id")
		})
		Result(User)
		Error("not_found")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			GET("/{id}")
			Response(StatusOK)
		})
	})

	Method("update", func() {
		Description("Update user")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "User ID")
			Attribute("user", UpdateUserRequest)
			Required("id", "user")
		})
		Result(User)
		Error("bad_request")
		Error("not_found")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			PUT("/{id}")
			Response(StatusOK)
		})
	})

	Method("delete", func() {
		Description("Delete user")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "User ID")
			Required("id")
		})
		Error("not_found")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			DELETE("/{id}")
			Response(StatusNoContent)
		})
	})

	Method("update_me", func() {
		Description("Update current user")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(UpdateUserRequest)
		})
		Result(User)
		Error("bad_request")
		Error("unauthorized")
		HTTP(func() {
			PUT("/me")
			Response(StatusOK)
		})
	})

	Method("update_password", func() {
		Description("Update current user password")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(UpdatePasswordRequest)
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Required("message")
		})
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError, "Invalid current password")
		Error("forbidden", ForbiddenError, "Password change not allowed")
		HTTP(func() {
			PUT("/me/password")
			Response(StatusOK)
		})
	})

	Method("get_sessions", func() {
		Description("Get current user sessions")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
		})
		Result(GetUserSessionResponse)
		Error("unauthorized")
		HTTP(func() {
			GET("/me/sessions")
			Response(StatusOK)
		})
	})

	Method("delete_session", func() {
		Description("Delete user session")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("session_id", String, "Session ID")
			Required("session_id")
		})
		Error("not_found")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			DELETE("/me/sessions/{session_id}")
			Response(StatusNoContent)
		})
	})

	Method("get_organizations", func() {
		Description("Get user organizations")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "User ID")
			Required("id")
		})
		Result(func() {
			Attribute("organizations", ArrayOf(Organization))
			Required("organizations")
		})
		Error("not_found")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			GET("/{id}/organizations")
			Response(StatusOK)
		})
	})
})
