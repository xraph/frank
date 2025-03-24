package design

import (
	. "goa.design/goa/v3/dsl"
)

var CSRFTokenInterceptor = Interceptor("CSRFToken", func() {
	Description("CSRF token interceptor")

	// // Track retry attempts in result
	ReadPayload(func() {
	})

	// WritePayload(func() {
	// 	Attribute("csrf_token", String, "CSRF token")
	// })

	// Cookie("csrf_token:frank_csrf")
	// Track retry attempts in result
	ReadResult(func() {
		// Cookie("csrf_token:csrf_token")
		Attribute("csrf_token", String, "CSRF token")
	})
	WriteResult(func() {
		// Cookie("csrf_token:csrf_token")
		Attribute("csrf_token", String, "CSRF token")
	})
})
