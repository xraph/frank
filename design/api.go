package design

import (
	. "goa.design/goa/v3/dsl"
	cors "goa.design/plugins/v3/cors/dsl"
	_ "goa.design/plugins/v3/docs"
)

// API defines the main API design
var _ = API("frank", func() {
	Title("Frank Authentication Server")
	Description("A comprehensive authentication server with OAuth2, MFA, Passkeys, SSO, and more")

	Version("1.0.0")

	// Terms of service - legal requirements and usage terms
	TermsOfService("https://frank.com/terms")
	Contact(func() {
		Name("API Support")
		Email("support@frank.com")
		URL("https://frank.com/support")
	})

	// License information - how the API can be used
	License(func() {
		Name("Apache 2.0")
		URL("https://www.apache.org/licenses/LICENSE-2.0.html")
	})

	// Documentation - detailed guides and references
	Docs(func() {
		Description(`Comprehensive API documentation including:
- Getting started guides
- Authentication details
- API reference
- Best practices
- Example code`)
		URL("https://frank.com/docs")
	})

	Server("frank", func() {
		Description("Frank server")

		Host("localhost", func() {
			URI("http://localhost:{port}")
			URI("grpc://localhost:{grpcPort}")

			// Define the version variable
			Variable("port", String, "API port", func() {
				Default("8998")
			})
			Variable("grpcPort", String, "API port", func() {
				Default("8999")
			})
		})

		Host("production", func() {
			Description("Production host")
			// Variables in URIs are replaced at runtime
			URI("https://{version}.{domain}")
			URI("grpcs://{version}.{grpcDomain}")

			// Define the version variable
			Variable("version", String, "API version", func() {
				Default("v1")
				Enum("v1", "v2")
			})
			Variable("domain", String, "API domain", func() {
				Default("api.frank.com")
			})
			Variable("grpcDomain", String, "GRPC domain", func() {
				Default("grpc.frank.com")
			})
		})

		Host("staging", func() {
			Description("Staging host")
			// Variables in URIs are replaced at runtime
			URI("https://{version}.{domain}")
			URI("grpcs://{version}.{grpcDomain}")

			// Define the version variable
			Variable("version", String, "API version", func() {
				Default("v1")
				Enum("v1", "v2")
			})
			Variable("domain", String, "API domain", func() {
				Default("api.staging.frank.com")
			})
			Variable("grpcDomain", String, "GRPC domain", func() {
				Default("grpc.staging.frank.com")
			})
		})
	})

	// Define error response format
	Error("FrankError", func() {
		Description("Standard error response format")
		Field(1, "code", String, "Error code")
		Field(2, "message", String, "Error message")
		Field(3, "data", MapOf(String, Any), "Additional error data")
		Required("code", "message")
	})

	// Define security schemes
	Security(OAuth2Auth, JWTAuth, APIKeyAuth)

	// Allow requests only from "localhost"
	cors.Origin("localhost")

	// Allow requests from any subdomain of domain.com
	cors.Origin("*.frank.com", func() {
		cors.Headers("X-Shared-Secret", "X-Api-Version")
		cors.MaxAge(100)
		cors.Credentials()
	})

	// Define CORS policy
	cors.Origin("/.*localhost.*/", func() {
		cors.Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")
		cors.Headers("Authorization", "Content-Type")
		cors.Expose("X-Request-Id")
		cors.MaxAge(600)
		cors.Credentials()
	})

	// Create common CORS middleware for all services
	HTTP(func() {
		Path("/")
	})
})
