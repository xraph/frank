package design

import (
	. "goa.design/goa/v3/dsl"
)

// HealthResponse defines the health check response
var HealthResponse = Type("HealthResponse", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("Health check response")
	Field(1, "status", String, "Overall health status", func() {
		Enum("healthy", "unhealthy")
		Example("healthy")
	})
	Field(2, "timestamp", String, "Timestamp of health check", func() {
		Format("date-time")
		Example("2023-01-01T12:00:00Z")
	})
	Field(3, "services", ArrayOf(HealthStatus), "Status of individual services")

	Required("status", "timestamp")
})

// HealthStatus defines the individual service health status
var HealthStatus = Type("HealthStatus", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("Service health status")
	Field(1, "service", String, "Service name")
	Field(2, "status", String, "Service status", func() {
		Enum("healthy", "unhealthy")
		Example("healthy")
	})
	Field(3, "message", String, "Additional message")

	Required("service", "status")
})

// ReadyResponse defines the health check response
var ReadyResponse = Type("ReadyResponse", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("Readiness check response")
	Field(1, "status", String, "Readiness status", func() {
		Enum("ready", "not_ready")
		Example("ready")
	})
	Field(2, "timestamp", String, "Timestamp of health check", func() {
		Format("date-time")
		Example("2023-01-01T12:00:00Z")
	})

	Required("status", "timestamp")
})

// HealthService defines the health check service
var _ = Service("health", func() {
	Description("Health check service for monitoring system status")

	// No security for health checks

	Method("check", func() {
		Description("Check system health")
		NoSecurity()
		Payload(func() {
			// Explicitly mark this method with no security
		})
		Result(HealthResponse)
		HTTP(func() {
			GET("/__health")
			Response(StatusOK, func() {
				ContentType("application/json")
			})
			Response(StatusServiceUnavailable, func() {
				ContentType("application/json")
			})
		})
	})

	Method("ready", func() {
		Description("Check if the system is ready to receive traffic")
		NoSecurity()
		Payload(func() {
			// Explicitly mark this method with no security
		})
		Result(ReadyResponse)
		HTTP(func() {
			GET("/__ready")
			Response(StatusOK, func() {
				ContentType("application/json")
			})
			Response(StatusServiceUnavailable, func() {
				ContentType("application/json")
			})
		})
	})

	Method("version", func() {
		Description("Get system version information")
		NoSecurity()
		Payload(func() {
			// Explicitly mark this method with no security
		})
		Result(func() {
			Attribute("version", String, "System version", func() {
				Example("1.0.0")
			})
			Attribute("build_date", String, "Build date", func() {
				Format("date-time")
				Example("2023-01-01T12:00:00Z")
			})
			Attribute("git_commit", String, "Git commit hash", func() {
				Example("a1b2c3d4e5f6")
			})
			Attribute("go_version", String, "Go version", func() {
				Example("go1.18.3")
			})
			Required("version", "build_date")
		})
		HTTP(func() {
			GET("/__version")
			Response(StatusOK)
		})
	})

	Method("metrics", func() {
		Description("Get system metrics")
		NoSecurity()
		// This method already has NoSecurity()
		NoSecurity()
		Payload(func() {
			// Explicitly mark this method with no security
		})
		Result(func() {
			Attribute("uptime", Int64, "System uptime in seconds", func() {
				Example(86400)
			})
			Attribute("memory_usage", Int64, "Memory usage in bytes", func() {
				Example(104857600)
			})
			Attribute("goroutines", Int, "Number of goroutines", func() {
				Example(42)
			})
			Attribute("requests", Int64, "Total request count", func() {
				Example(1000000)
			})
			Attribute("errors", Int64, "Total error count", func() {
				Example(1000)
			})
			Attribute("request_rate", Float32, "Requests per second", func() {
				Example(100.5)
			})
			Required("uptime", "memory_usage", "goroutines")
		})
		HTTP(func() {
			GET("/__metrics")
			Response(StatusOK)
		})
	})

	Method("debug", func() {
		NoSecurity()
		Description("Debug information (only available in development mode)")
		Payload(func() {
			// Explicitly mark this method with no security
		})
		Result(Any)
		HTTP(func() {
			GET("/__debug")
			Response(StatusOK)
		})
	})
})
