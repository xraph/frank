package design

import (
	. "goa.design/goa/v3/dsl"
)

var EmailTemplateResponse = Type("EmailTemplateResponse", func() {
	Description("Email template information")

	Extend(BaseType)

	Attribute("name", String, "Template name")
	Attribute("subject", String, "Email subject")
	Attribute("type", String, "Template type")
	Attribute("html_content", String, "HTML content")
	Attribute("text_content", String, "Text content")
	Attribute("organization_id", String, "Organization ID")
	Attribute("active", Boolean, "Whether template is active")
	Attribute("system", Boolean, "Whether this is a system template")
	Attribute("locale", String, "Template locale")
	Attribute("metadata", MetadataType, "Template metadata")

	Required("id", "name", "subject", "type", "html_content", "active", "system", "locale")
})

var CreateEmailTemplateRequest = Type("CreateEmailTemplateRequest", func() {
	Description("Create email template request")
	Attribute("name", String, "Template name", func() {
		Example("Welcome Email")
	})
	Attribute("subject", String, "Email subject", func() {
		Example("Welcome to our platform")
	})
	Attribute("type", String, "Template type", func() {
		Example("welcome")
	})
	Attribute("html_content", String, "HTML content", func() {
		Example("<html><body><h1>Welcome!</h1><p>Hello {{name}}</p></body></html>")
	})
	Attribute("text_content", String, "Text content", func() {
		Example("Welcome! Hello {{name}}")
	})
	Attribute("organization_id", String, "Organization ID")
	Attribute("active", Boolean, "Whether template is active", func() {
		Default(true)
	})
	Attribute("system", Boolean, "Whether this is a system template", func() {
		Default(false)
	})
	Attribute("locale", String, "Template locale", func() {
		Default("en")
	})
	Attribute("metadata", MetadataType, "Template metadata")
	Required("name", "subject", "type", "html_content")
})

var UpdateEmailTemplateRequest = Type("UpdateEmailTemplateRequest", func() {
	Description("Update email template request")
	Attribute("name", String, "Template name")
	Attribute("subject", String, "Email subject")
	Attribute("html_content", String, "HTML content")
	Attribute("text_content", String, "Text content")
	Attribute("active", Boolean, "Whether template is active")
	Attribute("locale", String, "Template locale")
	Attribute("metadata", MetadataType, "Template metadata")
})

var SendEmailRequest = Type("SendEmailRequest", func() {
	// Generate in shared types package
	Meta("struct:pkg:path", "designtypes")

	Description("Send email request")
	Attribute("to", ArrayOf(String), "Recipients", func() {
		Example([]string{"user@example.com"})
	})
	Attribute("from", String, "Sender email", func() {
		Example("no-reply@example.com")
	})
	Attribute("subject", String, "Email subject", func() {
		Example("Important information")
	})
	Attribute("html_content", String, "HTML content")
	Attribute("text_content", String, "Text content")
	Attribute("cc", ArrayOf(String), "CC recipients")
	Attribute("bcc", ArrayOf(String), "BCC recipients")
	Attribute("reply_to", String, "Reply-to address")
	Attribute("headers", MapOf(String, String), "Custom headers")
	Attribute("metadata", MetadataType, "Email metadata")
	Required("to", "subject")
	// Required(func() {
	// 	AtLeastOne("html_content", "text_content")
	// })
})

var SendTemplateEmailRequest = Type("SendTemplateEmailRequest", func() {
	Description("Send template email request")
	Attribute("to", ArrayOf(String), "Recipients", func() {
		Example([]string{"user@example.com"})
	})
	Attribute("from", String, "Sender email", func() {
		Example("no-reply@example.com")
	})
	Attribute("subject", String, "Custom subject (overrides template subject)")
	Attribute("template_type", String, "Template type", func() {
		Example("welcome")
	})
	Attribute("template_data", MapOf(String, Any), "Template data", func() {
		Example(map[string]interface{}{
			"name": "John Doe",
		})
	})
	Attribute("organization_id", String, "Organization ID")
	Attribute("locale", String, "Template locale", func() {
		Default("en")
	})
	Attribute("cc", ArrayOf(String), "CC recipients")
	Attribute("bcc", ArrayOf(String), "BCC recipients")
	Attribute("reply_to", String, "Reply-to address")
	Attribute("headers", MapOf(String, String), "Custom headers")
	Attribute("metadata", MetadataType, "Email metadata")
	Required("to", "template_type", "template_data")
})

var _ = Service("email", func() {
	Description("Email template management and sending service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Path("/v1/email")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("internal_error", StatusInternalServerError)
	})

	Method("list_templates", func() {
		Description("List email templates")
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
			Attribute("type", String, "Filter by template type")
			Attribute("organization_id", String, "Filter by organization ID")
			Attribute("locale", String, "Filter by locale")
		})
		Result(func() {
			Attribute("data", ArrayOf("EmailTemplateResponse"))
			Attribute("pagination", "Pagination")
			Required("data", "pagination")
		})
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/templates")
			Response(StatusOK)
			Params(func() {
				Param("offset")
				Param("limit")
				Param("type")
				Param("organization_id")
				Param("locale")
			})
		})
	})

	Method("create_template", func() {
		Description("Create a new email template")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(CreateEmailTemplateRequest)
		})
		Result(EmailTemplateResponse)
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		Error("conflict", ConflictError, "Template with this type and locale already exists for this organization")
		HTTP(func() {
			POST("/templates")
			Response(StatusCreated)
		})
	})

	Method("get_template", func() {
		Description("Get email template by ID")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Template ID")
			Required("id")
		})
		Result(EmailTemplateResponse)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/templates/{id}")
			Response(StatusOK)
		})
	})

	Method("get_template_by_type", func() {
		Description("Get email template by type")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("type", String, "Template type")
			Attribute("organization_id", String, "Organization ID")
			Attribute("locale", String, "Template locale", func() {
				Default("en")
			})
			Required("type")
		})
		Result(EmailTemplateResponse)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/templates/by-type/{type}")
			Param("organization_id")
			Param("locale")
			Response(StatusOK)
		})
	})

	Method("update_template", func() {
		Description("Update email template")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Template ID")
			Attribute("template", UpdateEmailTemplateRequest)
			Required("id", "template")
		})
		Result(EmailTemplateResponse)
		Error("bad_request", BadRequestError)
		Error("not_found", NotFoundError, "Template not found")
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError, "Cannot modify system templates")
		HTTP(func() {
			PUT("/templates/{id}")
			Response(StatusOK)
		})
	})

	Method("delete_template", func() {
		Description("Delete email template")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Template ID")
			Required("id")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError, "Cannot delete system templates")
		HTTP(func() {
			DELETE("/templates/{id}")
			Response(StatusNoContent)
		})
	})

	Method("send", func() {
		Description("Send email")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(SendEmailRequest)
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Required("message")
		})
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		Error("internal_error", InternalServerError, "Failed to send email")
		HTTP(func() {
			POST("/send")
			Response(StatusOK)
		})
	})

	Method("send_template", func() {
		Description("Send email using a template")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Extend(SendTemplateEmailRequest)
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Required("message")
		})
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		Error("not_found", NotFoundError, "Template not found")
		Error("internal_error", InternalServerError, "Failed to send email")
		HTTP(func() {
			POST("/send-template")
			Response(StatusOK)
		})
	})
})
