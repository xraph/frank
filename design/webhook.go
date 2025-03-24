package design

import (
	. "goa.design/goa/v3/dsl"
)

var WebhookResponse = Type("WebhookResponse", func() {
	// Meta("struct:pkg:path", "designtypes")

	Description("Webhook information")
	Attribute("id", String, "Webhook ID")
	Attribute("name", String, "Webhook name")
	Attribute("url", String, "Webhook URL")
	Attribute("organization_id", String, "Organization ID")
	Attribute("active", Boolean, "Whether webhook is active")
	Attribute("event_types", ArrayOf(String), "Event types webhook subscribes to")
	Attribute("version", String, "Webhook version")
	Attribute("retry_count", Int, "Number of retries on failure")
	Attribute("timeout_ms", Int, "Timeout in milliseconds")
	Attribute("format", String, "Payload format (json/form)")
	Attribute("metadata", MetadataType, "Webhook metadata")
	Attribute("created_at", String, "Creation timestamp")
	Attribute("updated_at", String, "Last update timestamp")
	Required("id", "name", "url", "organization_id", "active", "event_types", "created_at")
})

var WebhookSecretResponse = Type("WebhookSecretResponse", func() {
	Description("Webhook creation response with secret")
	Extend(WebhookResponse)
	Attribute("secret", String, "Webhook secret for signature verification")
	Required("secret")
})

var CreateWebhookRequest = Type("CreateWebhookRequest", func() {
	Description("Create webhook request")
	Attribute("name", String, "Webhook name", func() {
		Example("User Events")
	})
	Attribute("url", String, "Webhook URL", func() {
		Format(FormatURI)
		Example("https://example.com/webhooks/receive")
	})
	Attribute("event_types", ArrayOf(String), "Event types to subscribe to", func() {
		Example([]string{"user.created", "user.updated"})
	})
	Attribute("retry_count", Int, "Number of retries on failure", func() {
		Default(3)
		Minimum(0)
		Maximum(10)
	})
	Attribute("timeout_ms", Int, "Timeout in milliseconds", func() {
		Default(5000)
		Minimum(1000)
		Maximum(30000)
	})
	Attribute("format", String, "Payload format", func() {
		Enum("json", "form")
		Default("json")
	})
	Attribute("metadata", MetadataType, "Webhook metadata")
	Required("name", "url", "event_types")
})

var UpdateWebhookRequest = Type("UpdateWebhookRequest", func() {
	Description("Update webhook request")
	Attribute("name", String, "Webhook name")
	Attribute("url", String, "Webhook URL", func() {
		Format(FormatURI)
	})
	Attribute("active", Boolean, "Whether webhook is active")
	Attribute("event_types", ArrayOf(String), "Event types to subscribe to")
	Attribute("retry_count", Int, "Number of retries on failure", func() {
		Minimum(0)
		Maximum(10)
	})
	Attribute("timeout_ms", Int, "Timeout in milliseconds", func() {
		Minimum(1000)
		Maximum(30000)
	})
	Attribute("format", String, "Payload format", func() {
		Enum("json", "form")
	})
	Attribute("metadata", MetadataType, "Webhook metadata")
})

var WebhookEventResponse = Type("WebhookEventResponse", func() {
	Description("Webhook event information")
	Attribute("id", String, "Event ID")
	Attribute("webhook_id", String, "Webhook ID")
	Attribute("event_type", String, "Event type")
	Attribute("payload", Any, "Event payload")
	Attribute("headers", MapOf(String, String), "Event headers")
	Attribute("delivered", Boolean, "Whether event was delivered")
	Attribute("delivered_at", String, "Delivery timestamp")
	Attribute("attempts", Int, "Number of delivery attempts")
	Attribute("next_retry", String, "Next retry timestamp")
	Attribute("status_code", Int, "HTTP status code from last attempt")
	Attribute("response_body", String, "Response from last attempt")
	Attribute("error", String, "Error from last attempt")
	Attribute("created_at", String, "Creation timestamp")
	Attribute("updated_at", String, "Last update timestamp")
	Required("id", "webhook_id", "event_type", "delivered", "attempts", "created_at")
})

var TriggerEventRequest = Type("TriggerEventRequest", func() {
	Description("Trigger webhook event request")
	Attribute("event_type", String, "Event type", func() {
		Example("user.created")
	})
	Attribute("payload", Any, "Event payload", func() {
		Example(map[string]interface{}{"user_id": "123", "email": "user@example.com"})
	})
	Attribute("headers", MapOf(String, String), "Custom headers")
	Required("event_type", "payload")
})

var _ = Service("webhooks", func() {
	Description("Webhook management service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Path("/v1/webhooks")
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("internal_error", StatusInternalServerError)
	})

	Method("list", func() {
		Description("List webhooks")
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
			Attribute("organization_id", String, "Organization ID")
			Attribute("event_types", ArrayOf(String), "Filter by event types")
		})
		Result(func() {
			Attribute("data", ArrayOf("WebhookResponse"))
			Attribute("pagination", "Pagination")
			Required("data", "pagination")
		})
		Error("unauthorized")
		HTTP(func() {
			GET("")
			Response(StatusOK)
			Param("offset")
			Param("limit")
			Param("organization_id")
			Param("event_types")
		})
	})

	Method("create", func() {
		Description("Create a new webhook")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("organization_id", String, "Organization ID")
			Attribute("webhook", CreateWebhookRequest)
			Required("organization_id", "webhook")
		})
		Result(WebhookSecretResponse)
		Error("bad_request")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			POST("")
			Response(StatusCreated)
		})
	})

	Method("get", func() {
		Description("Get webhook by ID")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Webhook ID")
			Required("id")
		})
		Result(WebhookResponse)
		Error("not_found")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			GET("/{id}")
			Response(StatusOK)
		})
	})

	Method("update", func() {
		Description("Update webhook")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Webhook ID")
			Attribute("webhook", UpdateWebhookRequest)
			Required("id", "webhook")
		})
		Result(WebhookResponse)
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
		Description("Delete webhook")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Webhook ID")
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

	Method("trigger_event", func() {
		Description("Manually trigger a webhook event")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("organization_id", String, "Organization ID")
			Attribute("event", TriggerEventRequest)
			Required("organization_id", "event")
		})
		Result(WebhookEventResponse)
		Error("bad_request")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			POST("/trigger")
			Response(StatusOK)
		})
	})

	Method("list_events", func() {
		Description("List webhook events")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Webhook ID")
			Attribute("offset", Int, "Pagination offset", func() {
				Default(0)
				Minimum(0)
			})
			Attribute("limit", Int, "Number of items to return", func() {
				Default(20)
				Minimum(1)
				Maximum(100)
			})
			Attribute("event_type", String, "Filter by event type")
			Attribute("delivered", Boolean, "Filter by delivery status")
			Required("id")
		})
		Result(func() {
			Attribute("data", ArrayOf(WebhookEventResponse))
			Attribute("pagination", Pagination)
			Required("data", "pagination")
		})
		Error("not_found")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			GET("/{id}/events")
			Response(StatusOK)
			Param("offset")
			Param("limit")
			Param("event_type")
			Param("delivered")
		})
	})

	Method("replay_event", func() {
		Description("Replay a webhook event")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Webhook ID")
			Attribute("event_id", String, "Event ID")
			Required("id", "event_id")
		})
		Result(WebhookEventResponse)
		Error("not_found")
		Error("unauthorized")
		Error("forbidden")
		HTTP(func() {
			POST("/{id}/events/{event_id}/replay")
			Response(StatusOK)
		})
	})

	Method("receive", func() {
		Description("Receive webhook callbacks from external sources")
		NoSecurity()
		Payload(func() {
			Attribute("id", String, "Webhook receiver ID")
			Required("id")
			// Body is received as raw bytes and processed based on content type
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Required("message")
		})
		HTTP(func() {
			POST("/external/receive/{id}")
			Response(StatusOK)
		})
	})
})
