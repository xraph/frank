#!/bin/bash

# Script to generate the folder structure and placeholder files for the Frank Auth Server

set -e

PROJECT_ROOT="$1"
if [ -z "$PROJECT_ROOT" ]; then
  PROJECT_ROOT="frank"
  echo "No project root specified, using default: $PROJECT_ROOT"
fi

# Create project root
mkdir -p "$PROJECT_ROOT"
cd "$PROJECT_ROOT"

# Initialize go module
go mod init github.com/juicycleff/frank

# Create directory structure with placeholder files
echo "Creating directory structure and placeholder files..."

# Create cmd directory
mkdir -p cmd/server
touch cmd/server/main.go

# Create config directory
mkdir -p config
touch config/config.go
touch config/defaults.go
touch config/environment.go

# Create ent directory with schema subdirectory
mkdir -p ent/schema
# Create ent schema files
ENT_SCHEMA_FILES=(
  "user.go"
  "organization.go"
  "session.go"
  "apikey.go"
  "mfa.go"
  "passkey.go"
  "oauth_client.go"
  "oauth_scope.go"
  "oauth_token.go"
  "oauth_authorization.go"
  "webhook.go"
  "webhook_event.go"
  "identity_provider.go"
  "permission.go"
  "role.go"
  "email_template.go"
  "verification.go"
  "feature_flag.go"
  "organization_feature.go"
)
for file in "${ENT_SCHEMA_FILES[@]}"; do
  touch "ent/schema/$file"
done

# Create internal directory
mkdir -p internal

# Create auth subdirectories and files
mkdir -p internal/auth/oauth2
touch internal/auth/oauth2/provider.go
touch internal/auth/oauth2/server.go
touch internal/auth/oauth2/client.go
touch internal/auth/oauth2/token.go
touch internal/auth/oauth2/handlers.go
touch internal/auth/oauth2/storage.go

mkdir -p internal/auth/passwordless
touch internal/auth/passwordless/email.go
touch internal/auth/passwordless/sms.go
touch internal/auth/passwordless/magic_link.go
touch internal/auth/passwordless/service.go

mkdir -p internal/auth/mfa
touch internal/auth/mfa/totp.go
touch internal/auth/mfa/backup_codes.go
touch internal/auth/mfa/sms.go
touch internal/auth/mfa/email.go
touch internal/auth/mfa/service.go

mkdir -p internal/auth/passkeys
touch internal/auth/passkeys/webauthn.go
touch internal/auth/passkeys/authenticator.go
touch internal/auth/passkeys/service.go

mkdir -p internal/auth/sso
touch internal/auth/sso/provider.go
touch internal/auth/sso/saml.go
touch internal/auth/sso/oidc.go
touch internal/auth/sso/service.go

mkdir -p internal/auth/session
touch internal/auth/session/manager.go
touch internal/auth/session/store.go
touch internal/auth/session/cookie.go

# Create middleware directory
mkdir -p internal/middleware
touch internal/middleware/auth.go
touch internal/middleware/logging.go
touch internal/middleware/cors.go
touch internal/middleware/rate_limiter.go
touch internal/middleware/recovery.go
touch internal/middleware/organization.go

# Create handlers directory
mkdir -p internal/handlers
touch internal/handlers/auth.go
touch internal/handlers/users.go
touch internal/handlers/organizations.go
touch internal/handlers/oauth.go
touch internal/handlers/webhooks.go
touch internal/handlers/apikeys.go
touch internal/handlers/mfa.go
touch internal/handlers/passkeys.go
touch internal/handlers/sso.go
touch internal/handlers/passwordless.go

# Create organization directory
mkdir -p internal/organization
touch internal/organization/service.go
touch internal/organization/repository.go
touch internal/organization/features.go
touch internal/organization/membership.go

# Create user directory
mkdir -p internal/user
touch internal/user/service.go
touch internal/user/repository.go
touch internal/user/password.go
touch internal/user/verification.go

# Create apikeys directory
mkdir -p internal/apikeys
touch internal/apikeys/service.go
touch internal/apikeys/repository.go
touch internal/apikeys/validator.go

# Create webhook directory
mkdir -p internal/webhook
touch internal/webhook/service.go
touch internal/webhook/repository.go
touch internal/webhook/event.go
touch internal/webhook/delivery.go

# Create email directory
mkdir -p internal/email
touch internal/email/service.go
touch internal/email/templates.go
touch internal/email/sender.go

# Create sms directory
mkdir -p internal/sms
touch internal/sms/service.go
touch internal/sms/sender.go

# Create server directory
mkdir -p internal/server
touch internal/server/http.go
touch internal/server/router.go
touch internal/server/health.go

# Create rbac directory
mkdir -p internal/rbac
touch internal/rbac/service.go
touch internal/rbac/repository.go
touch internal/rbac/enforcer.go

# Create pkg directory
mkdir -p pkg/errors
touch pkg/errors/errors.go
touch pkg/errors/codes.go

mkdir -p pkg/logging
touch pkg/logging/logger.go
touch pkg/logging/middleware.go

mkdir -p pkg/crypto
touch pkg/crypto/jwt.go
touch pkg/crypto/hash.go
touch pkg/crypto/random.go

mkdir -p pkg/validator
touch pkg/validator/validator.go

mkdir -p pkg/utils
touch pkg/utils/http.go
touch pkg/utils/strings.go
touch pkg/utils/time.go

# Create migrations directory
mkdir -p migrations
touch migrations/20250101000000_initial_schema.up.sql
touch migrations/20250101000000_initial_schema.down.sql

# Create scripts directory
mkdir -p scripts
touch scripts/setup.sh
touch scripts/generate.sh
touch scripts/migrate.sh
chmod +x scripts/setup.sh
chmod +x scripts/generate.sh
chmod +x scripts/migrate.sh

# Create api directory
mkdir -p api/proto
touch api/proto/auth.proto
touch api/proto/user.proto
touch api/proto/organization.proto

mkdir -p api/swagger
touch api/swagger/openapi.yaml

# Create web directory
mkdir -p web/templates/email
touch web/templates/email/verification.html
touch web/templates/email/magic_link.html
touch web/templates/email/password_reset.html

mkdir -p web/templates/auth
touch web/templates/auth/login.html
touch web/templates/auth/register.html
touch web/templates/auth/mfa.html

mkdir -p web/static/css
mkdir -p web/static/js
mkdir -p web/static/images

mkdir -p web/views/components
mkdir -p web/views/layouts

# Create tests directory
mkdir -p tests/integration
touch tests/integration/auth_test.go
touch tests/integration/organization_test.go
touch tests/integration/oauth_test.go

mkdir -p tests/unit
touch tests/unit/auth_test.go
touch tests/unit/crypto_test.go
touch tests/unit/validation_test.go

mkdir -p tests/mocks
touch tests/mocks/repositories.go
touch tests/mocks/services.go

# Create docs directory
mkdir -p docs
touch docs/architecture.md
touch docs/api.md
touch docs/oauth2.md
touch docs/development.md

# Create root files
touch go.mod
touch go.sum
touch Makefile
touch Dockerfile
touch docker-compose.yml
touch .gitignore
touch .golangci.yml
touch .env.example
touch README.md

# Initialize git repository
git init

# Create basic .gitignore
cat > .gitignore << EOF
# Binaries for programs and plugins
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary, built with 'go test -c'
*.test

# Output of the go coverage tool, specifically when used with LiteIDE
*.out

# Dependency directories (remove the comment below to include it)
# vendor/

# Environment variables
.env

# IDE specific files
.idea/
.vscode/
*.swp
*.swo

# Mac OS X hidden files
.DS_Store

# Build directory
bin/
build/
dist/

# Logs
logs/
*.log
EOF

# Create basic README
cat > README.md << EOF
# Frank Auth Server

A comprehensive authentication server implemented in Golang with EntGO, featuring:

- OAuth2 provider and client
- Passwordless authentication
- Multi-factor authentication (MFA)
- Passkeys (WebAuthn)
- Single Sign-On (SSO) including Enterprise SSO
- Webhooks
- Organization management
- API Key management for machine-to-machine authentication
- Customizable features per organization

## Getting Started

### Prerequisites

- Go 1.21+
- PostgreSQL
- Redis (optional, for session storage)

### Installation

1. Clone the repository:
   \`\`\`
   git clone https://github.com/juicycleff/frank.git
   cd frank
   \`\`\`

2. Install dependencies:
   \`\`\`
   go mod download
   \`\`\`

3. Generate EntGO code:
   \`\`\`
   go run -mod=mod entgo.io/ent/cmd/ent generate ./ent/schema
   \`\`\`

4. Run database migrations:
   \`\`\`
   ./scripts/migrate.sh
   \`\`\`

5. Start the server:
   \`\`\`
   go run cmd/server/main.go
   \`\`\`

## Documentation

For more detailed information, please refer to the docs directory:

- [Architecture](docs/architecture.md)
- [API Documentation](docs/api.md)
- [OAuth2 Implementation](docs/oauth2.md)
- [Development Guide](docs/development.md)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
EOF

# Create basic Makefile
cat > Makefile << EOF
.PHONY: build run test lint generate migrate clean

# Go parameters
GOCMD=go
GOBUILD=\$(GOCMD) build
GORUN=\$(GOCMD) run
GOTEST=\$(GOCMD) test
GOGET=\$(GOCMD) get
BINARY_NAME=frank
MAIN_PATH=./cmd/frank

all: generate test lint build

build:
	\$(GOBUILD) -o ./bin/\$(BINARY_NAME) \$(MAIN_PATH)

run:
	\$(GORUN) \$(MAIN_PATH)

test:
	\$(GOTEST) -v ./...

lint:
	golangci-lint run

generate:
	go run -mod=mod entgo.io/ent/cmd/ent generate ./ent/schema

migrate:
	./scripts/migrate.sh

clean:
	rm -f ./bin/\$(BINARY_NAME)

deps:
	\$(GOGET) -u ./...
EOF

# Create Docker file
cat > Dockerfile << EOF
# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Generate Ent code
RUN go run -mod=mod entgo.io/ent/cmd/ent generate ./ent/schema

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o frank ./cmd/frank

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/frank .

# Copy web resources and migrations
COPY --from=builder /app/web ./web
COPY --from=builder /app/migrations ./migrations

# Set environment variables
ENV GIN_MODE=release

# Expose port
EXPOSE 8080

# Run the binary
CMD ["./frank"]
EOF

# Create Docker Compose file
cat > docker-compose.yml << EOF
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://postgres:postgres@db:5432/frank
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - ./config:/app/config

  db:
    image: postgres:14
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=frank
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
EOF

# Create .env.example file
cat > .env.example << EOF
# Server Configuration
PORT=8080
ENV=development

# Database Configuration
DATABASE_URL=postgres://postgres:postgres@localhost:5432/frank

# Redis Configuration
REDIS_URL=redis://localhost:6379

# Security Configuration
JWT_SECRET=your-jwt-secret-key
SESSION_SECRET=your-session-secret-key
ENCRYPTION_KEY=your-encryption-key

# SMTP Configuration
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user@example.com
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=noreply@example.com

# SMS Configuration
TWILIO_ACCOUNT_SID=your-account-sid
TWILIO_AUTH_TOKEN=your-auth-token
TWILIO_PHONE_NUMBER=+1234567890

# OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
EOF

echo "Project structure created successfully at: $(pwd)"
echo "You can start by running: cd $(pwd) && go mod tidy"