package design

import (
	. "goa.design/goa/v3/dsl"
)

var MFAEnrollRequest = Type("MFAEnrollRequest", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("MFA enrollment request")
	Attribute("method", String, "MFA method to enroll", func() {
		Enum("totp", "sms", "email", "backup_codes")
		Example("totp")
	})
	Attribute("phone_number", String, "Phone number for SMS verification")
	Attribute("email", String, "Email for email verification", func() {
		Format(FormatEmail)
	})
	Required("method")
})

var TOTPEnrollResponse = Type("TOTPEnrollResponse", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("TOTP enrollment response")
	Attribute("secret", String, "TOTP secret key")
	Attribute("uri", String, "TOTP URI for QR code generation")
	Attribute("qr_code_data", String, "TOTP QR code as base64 image")
	Required("secret", "uri", "qr_code_data")
})

var BackupCodesResponse = Type("BackupCodesResponse", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("Backup codes response")
	Attribute("backup_codes", ArrayOf(String), "List of backup codes")
	Required("backup_codes")
})

var MFAVerifyRequest = Type("MFAVerifyRequest", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("MFA verification request")
	Attribute("method", String, "MFA method to verify", func() {
		Enum("totp", "sms", "email", "backup_codes")
		Example("totp")
	})
	Attribute("code", String, "Verification code", func() {
		Example("123456")
	})
	Attribute("phone_number", String, "Phone number for SMS verification")
	Required("method", "code")
})

var MFAUnEnrollRequest = Type("MFAUnEnrollRequest", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("MFA unenrollment request")
	Attribute("method", String, "MFA method to unenroll", func() {
		Enum("totp", "sms", "email", "backup_codes", "all")
		Example("totp")
	})
	Required("method")
})

var SendMFACodeRequest = Type("SendMFACodeRequest", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("Send MFA code request")
	Attribute("method", String, "MFA method", func() {
		Enum("sms", "email")
		Example("sms")
	})
	Required("method")
})

var _ = Service("mfa", func() {
	Description("Multi-Factor Authentication service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Path("/v1/auth/mfa")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("internal_error", StatusInternalServerError)
	})

	Method("enroll", func() {
		Description("Start MFA enrollment")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("request", MFAEnrollRequest)
			Required("request")
		})
		Result(func() {
			Attribute("totp", "TOTPEnrollResponse")
			Attribute("backup_codes", "BackupCodesResponse")
			Attribute("message", String, "Success message for SMS/Email enrollment")
		})
		Error("bad_request")
		Error("unauthorized")
		HTTP(func() {
			POST("/enroll")
			Response(StatusOK)
		})
	})

	Method("verify", func() {
		Description("Verify MFA code")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("request", MFAVerifyRequest)
			Required("request")
		})
		Result(func() {
			Attribute("verified", Boolean, "Whether verification was successful")
			Required("verified")
		})
		Error("bad_request")
		Error("unauthorized")
		HTTP(func() {
			POST("/verify")
			Response(StatusOK)
		})
	})

	Method("unenroll", func() {
		Description("Disable MFA method")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("request", MFAUnEnrollRequest)
			Required("request")
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Required("message")
		})
		Error("bad_request")
		Error("unauthorized")
		HTTP(func() {
			POST("/unenroll")
			Response(StatusOK)
		})
	})

	Method("methods", func() {
		Description("Get enabled MFA methods")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
		})
		Result(func() {
			Attribute("methods", ArrayOf(String), "Enabled MFA methods")
			Required("methods")
		})
		Error("unauthorized")
		HTTP(func() {
			GET("/methods")
			Response(StatusOK)
		})
	})

	Method("send_code", func() {
		Description("Send verification code")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("request", SendMFACodeRequest)
			Required("request")
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Attribute("expires_at", Int64, "When the code expires")
			Required("message", "expires_at")
		})
		Error("bad_request")
		Error("unauthorized")
		HTTP(func() {
			POST("/send-code")
			Response(StatusOK)
		})
	})
})
