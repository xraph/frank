# Frank Authentication Server Development Guide

## Overview

This guide provides detailed information for developers working on the Frank Authentication Server. It covers the project structure, development workflow, testing strategies, and guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Go 1.21 or higher
- PostgreSQL 14 or higher
- Redis 6 or higher
- Docker and Docker Compose (for development environment)
- Make

### Setting Up the Development Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/juicycleff/frank.git
   cd frank
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Set up the development database:
   ```bash
   docker-compose up -d postgres redis
   ```

4. Run database migrations:
   ```bash
   make migrate-up
   ```

5. Start the development server:
   ```bash
   make dev
   ```

The server should now be running at `http://localhost:8080`.

## Project Structure

The Frank Authentication Server follows a clean, modular project structure:

```
frank/
├── cmd/                  # Command-line applications
│   └── server/           # Main server application
├── config/               # Configuration handling
├── docs/                 # Documentation
├── ent/                  # EntGo schema definitions and generated code
│   ├── schema/           # EntGo entity schema definitions
│   ├── generate.go       # EntGo code generation
│   └── ...               # Generated code
├── internal/             # Internal packages
│   ├── apikeys/          # API key management
│   ├── auth/             # Authentication core
│   │   ├── mfa/          # Multi-factor authentication
│   │   ├── oauth2/       # OAuth2 implementation
│   │   ├── passkeys/     # WebAuthn/Passkeys implementation
│   │   ├── passwordless/ # Passwordless authentication
│   │   ├── session/      # Session management
│   │   └── sso/          # Single Sign-On implementation
│   ├── email/            # Email service
│   ├── handlers/         # HTTP request handlers
│   ├── middleware/       # HTTP middleware
│   ├── organization/     # Organization management
│   ├── sms/              # SMS service
│   ├── user/             # User management
│   └── webhook/          # Webhook service
├── migrations/           # Database migrations
├── pkg/                  # Public packages
│   ├── crypto/           # Cryptographic utilities
│   ├── errors/           # Error handling
│   ├── logging/          # Logging utilities
│   └── utils/            # Utility functions
├── scripts/              # Utility scripts
├── .env.example          # Environment variable example
├── .gitignore            # Git ignore file
├── docker-compose.yml    # Docker Compose configuration
├── go.mod                # Go module definition
├── go.sum                # Go module checksums
├── LICENSE               # License file
├── Makefile              # Makefile for common tasks
└── README.md             # Project README
```

## Key Components

### EntGo Schema

Frank uses [EntGo](https://entgo.io/) as an entity framework for database operations. Entity schemas are defined in the `ent/schema` directory.

Example schema definition:

```go
// User schema
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/edge"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			Unique().
			Immutable().
			StorageKey("id"),
		field.String("email").
			Unique().
			NotEmpty(),
		field.String("password_hash").
			Sensitive().
			Optional(),
		field.String("first_name").
			Optional(),
		field.String("last_name").
			Optional(),
		field.String("profile_image_url").
			Optional(),
		field.String("phone_number").
			Optional(),
		field.Bool("email_verified").
			Default(false),
		field.Bool("phone_verified").
			Default(false),
		field.String("locale").
			Optional().
			Default("en"),
		field.Bool("active").
			Default(true),
		field.Time("created_at").
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
		field.JSON("metadata", map[string]interface{}{}).
			Optional(),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("organizations", Organization.Type),
		edge.To("passkeys", Passkey.Type).Annotations(),
		edge.To("sessions", Session.Type),
	}
}
```

### Configuration

Configuration is handled with environment variables and configuration files. The `config` package provides a structured way to access configuration values.

Example configuration loading:

```go
package config

import (
	"time"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Auth     AuthConfig
	Security SecurityConfig
	Email    EmailConfig
	SMS      SMSConfig
	Features FeatureConfig
}

type ServerConfig struct {
	Host            string
	Port            int
	BaseURL         string
	ShutdownTimeout time.Duration
}

// Load loads the configuration from environment variables and files
func Load() (*Config, error) {
	// Implementation details...
}
```

### Middleware

HTTP middleware functions are defined in the `internal/middleware` package. They handle cross-cutting concerns like authentication, logging, and error handling.

Example middleware:

```go
package middleware

import (
	"net/http"

	"github.com/juicycleff/frank/pkg/logging"
)

// Recovery is a middleware that recovers from panics and returns a 500 response
func Recovery(logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					// Handle the panic and log it
					logger.Error("Panic recovered", logging.Any("error", rec))
					// Return 500 response
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error": "Internal server error"}`))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
```

### Authentication Flows

Authentication flows are implemented in the various packages under `internal/auth`. Each authentication method has its own package with a clear separation of concerns.

## Development Workflow

### Code Generation

Frank uses code generation for database entities, OpenAPI documentation, and other aspects. Use the following commands:

```bash
# Generate EntGo code
make generate-ent

# Generate OpenAPI documentation
make generate-openapi
```

### Database Migrations

Database migrations are managed using a migration tool. Use the following commands:

```bash
# Create a new migration
make migrate-create name=add_new_table

# Apply all pending migrations
make migrate-up

# Roll back the last migration
make migrate-down
```

### Running Tests

Tests are organized by package. Use the following commands:

```bash
# Run all tests
make test

# Run tests for a specific package
make test-pkg PKG=./internal/auth/oauth2

# Run tests with coverage
make test-coverage
```

### Linting and Formatting

Frank follows Go best practices for code quality. Use the following commands:

```bash
# Run linters
make lint

# Format code
make fmt
```

## Testing Strategy

### Unit Tests

Unit tests focus on testing individual functions and components in isolation. They should be fast and have no external dependencies.

Example unit test:

```go
package crypto

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "securepassword"
	
	// Test password hashing
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	
	// Test password verification
	err = VerifyPassword(hash, password)
	if err != nil {
		t.Fatalf("Failed to verify password: %v", err)
	}
	
	// Test incorrect password
	err = VerifyPassword(hash, "wrongpassword")
	if err == nil {
		t.Fatal("Expected error when verifying incorrect password")
	}
}
```

### Integration Tests

Integration tests verify that different components work together correctly. They may involve database access and other external services.

Example integration test:

```go
package auth_test

import (
	"context"
	"testing"
	
	"github.com/juicycleff/frank/internal/auth"
	"github.com/juicycleff/frank/internal/user"
)

func TestAuthFlow(t *testing.T) {
	// Set up test environment
	ctx := context.Background()
	db := setupTestDatabase(t)
	userService := user.NewService(db)
	authService := auth.NewService(db, userService)
	
	// Create a test user
	testUser, err := userService.Create(ctx, user.CreateUserInput{
		Email:    "test@example.com",
		Password: "testpassword",
	})
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	
	// Test authentication
	authenticatedUser, err := authService.Authenticate(ctx, "test@example.com", "testpassword")
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}
	
	if authenticatedUser.ID != testUser.ID {
		t.Fatalf("Expected user ID %s, got %s", testUser.ID, authenticatedUser.ID)
	}
}
```

### API Tests

API tests verify the HTTP endpoints and their responses. They should be run against a test server.

Example API test:

```go
package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	
	"github.com/juicycleff/frank/internal/handlers"
)

func TestLoginEndpoint(t *testing.T) {
	// Set up test server
	handler := setupTestHandler(t)
	server := httptest.NewServer(handler)
	defer server.Close()
	
	// Test valid login
	loginJSON := `{"email":"test@example.com","password":"testpassword"}`
	resp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json", strings.NewReader(loginJSON))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %v", resp.Status)
	}
	
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	
	// Check response has expected fields
	if _, ok := result["token"]; !ok {
		t.Fatal("Response missing token field")
	}
}
```

## Deployment

### Docker Deployment

Frank can be deployed using Docker. A Dockerfile is provided in the repository:

```dockerfile
FROM golang:1.21-alpine as builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o frank ./cmd/server

FROM alpine:3.18

WORKDIR /app

COPY --from=builder /app/frank .
COPY --from=builder /app/configs ./configs

EXPOSE 8080

CMD ["./frank"]
```

### Kubernetes Deployment

For production environments, Kubernetes deployment is recommended. Example manifests are provided in the `deployments/kubernetes` directory.

### Environment Variables

The following environment variables should be set in production:

```
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
SERVER_BASE_URL=https://auth.example.com

# Database Configuration
DATABASE_HOST=postgres
DATABASE_PORT=5432
DATABASE_NAME=frank
DATABASE_USER=frank
DATABASE_PASSWORD=secret

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=secret

# Security Configuration
AUTH_TOKEN_SECRET_KEY=your-secure-token-secret
AUTH_COOKIE_SECRET=your-secure-cookie-secret
AUTH_ACCESS_TOKEN_DURATION=1h
AUTH_REFRESH_TOKEN_DURATION=30d

# Email Configuration
EMAIL_PROVIDER=smtp
EMAIL_SMTP_HOST=smtp.example.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USER=user
EMAIL_SMTP_PASSWORD=password
EMAIL_FROM=auth@example.com

# SMS Configuration
SMS_PROVIDER=twilio
SMS_TWILIO_ACCOUNT_SID=your-account-sid
SMS_TWILIO_AUTH_TOKEN=your-auth-token
SMS_TWILIO_FROM_NUMBER=+1234567890
```

## Contributing

### Coding Standards

1. Follow Go's [Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
2. Use meaningful variable and function names
3. Write comprehensive comments, especially for exported functions
4. Keep functions small and focused on a single responsibility
5. Use interfaces for dependency injection and testing

### Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests, linters, and formatting: `make test lint fmt`
5. Commit your changes: `git commit -m "Add my feature"`
6. Push to your fork: `git push origin feature/my-feature`
7. Create a pull request with a detailed description

### Documentation

All new features should include:

1. Code comments that explain "why" not just "what"
2. Updates to relevant documentation in the `docs` directory
3. Example usage if applicable

## Debugging

### Logging

Frank uses structured logging with different log levels. Set the following environment variable to control the log level:

```
LOG_LEVEL=debug|info|warn|error
```

Example log output:

```
{"level":"info","time":"2023-01-01T00:00:00Z","message":"Server started","host":"0.0.0.0","port":8080}
```

### Troubleshooting Common Issues

1. **Database connection issues**:
    - Check database credentials and connection parameters
    - Ensure the database is running and accessible
    - Check for firewall or network issues

2. **Authentication failures**:
    - Verify that the correct token secret keys are set
    - Check for clock skew between services
    - Ensure cookies are configured correctly for the domain

3. **Performance issues**:
    - Enable debug logging to identify bottlenecks
    - Check database query performance
    - Monitor resource usage (CPU, memory, database connections)

## API Versioning

Frank uses a versioned API to ensure backward compatibility. The current version is v1, accessible at `/api/v1/`.

When making changes:
1. Non-breaking changes can be added to the current version
2. Breaking changes should be introduced in a new version
3. Deprecated endpoints should be marked with `@deprecated` in the documentation

## Security Guidelines

### Secure Coding Practices

1. Never store sensitive data in plain text
2. Always validate and sanitize user input
3. Use parameterized queries to prevent SQL injection
4. Set appropriate security headers in HTTP responses
5. Implement proper error handling without exposing sensitive information

### Security Checks

Regular security checks should be performed:

1. Run vulnerability scanning tools
2. Conduct code reviews with security focus
3. Update dependencies to address security vulnerabilities
4. Perform penetration testing

## Performance Optimization

### Database Optimization

1. Use appropriate indexes for frequently queried fields
2. Optimize complex queries
3. Use database connection pooling
4. Consider caching for frequently accessed data

### API Performance

1. Use pagination for list endpoints
2. Implement rate limiting to prevent abuse
3. Optimize response payloads (include only necessary fields)
4. Use compression for HTTP responses