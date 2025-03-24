package design

import (
	"github.com/juicycleff/frank/pkg/errors"
	. "goa.design/goa/v3/dsl"
)

var User = Type("User", func() {
	Description("User information")

	Meta("struct:pkg:path", "designtypes")

	Extend(BaseAuthUserType)

	Field(13, "active", Boolean, "Whether account is active")

	Required("active")
})

var LoginRequest = Type("LoginRequest", func() {
	Description("Login credentials")
	Attribute("email", String, "User email", func() {
		Format(FormatEmail)
		Example("user@example.com")
	})
	Attribute("password", String, "User password", func() {
		MinLength(1)
		Example("secure-password")
	})
	Attribute("organization_id", String, "Organization ID if logging into a specific organization")
	Attribute("remember_me", Boolean, "Whether to remember the user", func() {
		Default(false)
	})
	Attribute("captcha_response", String, "CAPTCHA response for protected login")
	Required("email", "password")
})

var LoginResponse = Type("LoginResponse", func() {
	Description("Successful login response")
	Attribute("user", User, "Authenticated user")
	Attribute("token", String, "JWTAuth access token")
	Attribute("refresh_token", String, "JWTAuth refresh token")
	Attribute("csrf_token", String, "CSRF token")
	Attribute("expires_at", Int64, "Token expiry timestamp")
	Attribute("mfa_required", Boolean, "Whether MFA is required to complete authentication")
	Attribute("mfa_types", ArrayOf(String), "Available MFA methods when MFA is required")
	Attribute("session_id", String, "Session ID", func() {
		Example("1234567890")
	})
	Required("user", "token", "csrf_token", "refresh_token", "expires_at", "mfa_required")
})

var RegisterRequest = Type("RegisterRequest", func() {
	Description("User registration data")
	Attribute("email", String, "User email", func() {
		Format(FormatEmail)
		Example("user@example.com")
	})
	Attribute("password", String, "User password", func() {
		MinLength(8)
		Example("secure-password")
	})
	Attribute("first_name", String, "User first name")
	Attribute("last_name", String, "User last name")
	Attribute("organization_id", String, "Organization ID if creating a user for a specific organization")
	Attribute("metadata", MetadataType, "Additional user metadata")
	Required("email", "password")
})

var RefreshTokenRequest = Type("RefreshTokenRequest", func() {
	Description("Refresh token request")
	Attribute("refresh_token", String, "JWTAuth refresh token")
	Required("refresh_token")
})

var RefreshTokenResponse = Type("RefreshTokenResponse", func() {
	Description("Refresh token response")
	Attribute("token", String, "New JWTAuth access token")
	Attribute("refresh_token", String, "New refresh token")
	Attribute("expires_at", Int64, "Token expiry timestamp")
	Required("token", "refresh_token", "expires_at")
})

var ForgotPasswordRequest = Type("ForgotPasswordRequest", func() {
	Description("Forgot password request")
	Attribute("email", String, "User email", func() {
		Format(FormatEmail)
		Example("user@example.com")
	})
	Required("email")
})

var ResetPasswordRequest = Type("ResetPasswordRequest", func() {
	Description("Reset password request")
	Attribute("token", String, "Password reset token")
	Attribute("new_password", String, "New password", func() {
		MinLength(8)
		Example("new-secure-password")
	})
	Required("token", "new_password")
})

var VerifyEmailRequest = Type("VerifyEmailRequest", func() {
	Description("Email verification request")
	Attribute("token", String, "Email verification token")
	Required("token")
})

var CSRFTokenResponse = Type("CSRFTokenResponse", func() {
	Description("CSRF token response")
	Attribute("csrf_token", String, "CSRF token")
	Required("csrf_token")
})

var _ = Service("auth", func() {
	Description("Authentication service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("conflict", ConflictError)
	Error("internal_error", InternalServerError)
	Error(errors.CodeInvalidCredentials, InternalServerError)

	HTTP(func() {
		Path("/v1/auth")
		Cookie("session_id:frank_sid")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("conflict", StatusConflict)
		Response("internal_error", StatusInternalServerError)
	})

	Method("login", func() {
		Description("Authenticate user with email and password")
		NoSecurity()
		ServerInterceptor(CSRFTokenInterceptor)
		Payload(func() {
			Extend(LoginRequest)
			Attribute("session_id", String)
		})
		Result(LoginResponse)
		Error("bad_request", BadRequestError)
		Error("forbidden", ForbiddenError, "Account is locked or email not verified")
		HTTP(func() {
			POST("/login")
			Response(StatusOK, func() {
				Cookie("session_id:frank_sid")
				CookieDomain("frank.com")
				CookieDomain("localhost")
				CookieMaxAge(3600) // Sessions last one hour
			})
		})
	})

	Method("register", func() {
		Description("Register a new user")
		NoSecurity()
		Payload(func() {
			Extend(RegisterRequest)
			Attribute("session_id", String)
		})
		Result(LoginResponse)
		Error("bad_request", BadRequestError)
		Error("conflict", ConflictError, "Email already exists")
		HTTP(func() {
			POST("/register")
			Response(StatusCreated, func() {
				Cookie("session_id:frank_sid")
				CookieDomain("frank.com")
				CookieDomain("localhost")
				CookieMaxAge(3600) // Sessions last one hour
			})
		})
	})

	Method("logout", func() {
		Description("Log out the current user")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("session_id", String)

		})
		Result(func() {
			Attribute("message", String, "Success message")
			Required("message")
		})
		HTTP(func() {
			POST("/logout")
			Response(StatusOK)

		})
	})

	Method("refresh_token", func() {
		Description("Refresh an access token")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Extend(RefreshTokenRequest)
			Attribute("session_id", String)
		})
		Result(RefreshTokenResponse)
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError, "Invalid refresh token")
		HTTP(func() {
			POST("/refresh")
			Response(StatusOK)

		})
	})

	Method("forgot_password", func() {
		Description("Initiate password reset process")
		Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		Payload(func() {
			AccessToken("oauth2", String, "OAuth2 access token")
			APIKey("api_key", "X-API-Key", String, "API key")
			Token("jwt", String, "JWT token")
			Extend(ForgotPasswordRequest)
			Attribute("redirect_url", String, "URL to redirect after password reset")
			Attribute("session_id", String)
		})
		Result(func() {
			Attribute("message", String)
			Required("message")
		})
		HTTP(func() {
			POST("/forgot-password")
			Param("redirect_url")
			Response(StatusAccepted)
		})
	})

	Method("reset_password", func() {
		Description("Reset password using token")
		NoSecurity()
		Payload(func() {
			Extend(ResetPasswordRequest)
			Attribute("session_id", String)
		})
		Result(func() {
			Attribute("message", String)
			Required("message")
		})
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError, "Invalid or expired token")
		HTTP(func() {
			POST("/reset-password")
			Response(StatusOK)
		})
	})

	Method("verify_email", func() {
		Description("Verify email using token")
		// Security(OAuth2Auth, APIKeyAuth, JWTAuth)
		NoSecurity()
		Payload(func() {
			// AccessToken("oauth2", String, "OAuth2 access token")
			// APIKey("api_key", "X-API-Key", String, "API key")
			// Token("jwt", String, "JWT token")
			Extend(VerifyEmailRequest)
			Attribute("session_id", String)

		})
		Result(func() {
			Attribute("message", String)
			Required("message")
		})
		Error("bad_request", BadRequestError)
		// Error("unauthorized", UnauthorizedError, "Invalid or expired token")
		HTTP(func() {
			POST("/verify-email")
			Response(StatusOK)
		})
	})

	Method("me", func() {
		Description("Get current user info")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("session_id", String)
		})
		Result(User)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/me")
			Response(StatusOK)
		})
	})

	Method("csrf", func() {
		Description("Generates a CSRF token")
		NoSecurity()
		Result(CSRFTokenResponse)
		Payload(func() {
			Attribute("session_id", String)
		})
		HTTP(func() {
			GET("/csrf-token")
			Response(StatusOK)
		})
	})
})
