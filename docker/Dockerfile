# Frank Auth SaaS - Multi-stage Docker Build
# This Dockerfile creates a production-ready image for the Frank Auth SaaS platform

# Build stage
FROM golang:1.21-alpine AS builder

# Build arguments
ARG VERSION=1.0.0
ARG BUILD_TIME
ARG GIT_COMMIT
ARG ENVIRONMENT=production

# Set build metadata
LABEL maintainer="Frank Auth Team <support@frankauth.com>"
LABEL version=${VERSION}
LABEL description="Multi-tenant authentication SaaS platform with Clerk.js compatibility"

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    make \
    gcc \
    musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files first (for better caching)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Generate code (Ent ORM, Wire DI, etc.)
RUN make generate

# Build the application
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w \
    -X 'main.Version=${VERSION}' \
    -X 'main.BuildTime=${BUILD_TIME}' \
    -X 'main.GitCommit=${GIT_COMMIT}' \
    -X 'main.Environment=${ENVIRONMENT}'" \
    -a -installsuffix cgo \
    -o frank-auth \
    ./cmd/server

# Verify the binary
RUN ./frank-auth --version

# Production stage
FROM alpine:3.18 AS production

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    jq \
    && rm -rf /var/cache/apk/*

# Create a non-root user
RUN addgroup -g 1001 -S frankauth && \
    adduser -u 1001 -S frankauth -G frankauth

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/frank-auth .

# Copy configuration files
COPY --from=builder /app/configs ./configs

# Copy migration files
COPY --from=builder /app/migrations ./migrations

# Copy templates
COPY --from=builder /app/templates ./templates

# Create necessary directories
RUN mkdir -p /var/log/frank-auth && \
    mkdir -p /tmp/frank-auth && \
    chown -R frankauth:frankauth /app && \
    chown -R frankauth:frankauth /var/log/frank-auth && \
    chown -R frankauth:frankauth /tmp/frank-auth

# Set executable permissions
RUN chmod +x ./frank-auth

# Switch to non-root user
USER frankauth

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 9090

# Set environment variables
ENV GIN_MODE=release
ENV ENVIRONMENT=production
ENV LOG_LEVEL=info
ENV CONFIG_PATH=/app/configs

# Default command
CMD ["./frank-auth"]

# Development stage (for development builds)
FROM golang:1.21-alpine AS development

# Install development tools
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    make \
    gcc \
    musl-dev \
    curl \
    bash \
    vim \
    jq

# Install air for hot reloading
RUN go install github.com/cosmtrek/air@latest

# Install migrate tool
RUN go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Install other development tools
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install golang.org/x/tools/cmd/goimports@latest && \
    go install github.com/google/wire/cmd/wire@latest

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Create non-root user for development
RUN addgroup -g 1001 -S frankauth && \
    adduser -u 1001 -S frankauth -G frankauth -s /bin/bash

# Create necessary directories
RUN mkdir -p /var/log/frank-auth && \
    mkdir -p /tmp/frank-auth && \
    chown -R frankauth:frankauth /app && \
    chown -R frankauth:frankauth /var/log/frank-auth && \
    chown -R frankauth:frankauth /tmp/frank-auth

# Switch to non-root user
USER frankauth

# Set environment variables for development
ENV GIN_MODE=debug
ENV ENVIRONMENT=development
ENV LOG_LEVEL=debug
ENV CONFIG_PATH=/app/configs

# Expose ports (including debugging ports)
EXPOSE 8080 9090 2345

# Default command for development (with hot reloading)
CMD ["air", "-c", ".air.toml"]

# Testing stage (for running tests)
FROM golang:1.21-alpine AS testing

# Install test dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    make \
    gcc \
    musl-dev \
    curl \
    postgresql-client

# Install testing tools
RUN go install github.com/onsi/ginkgo/v2/ginkgo@latest && \
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install gotest.tools/gotestsum@latest

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Download dependencies
RUN go mod download

# Set environment for testing
ENV ENVIRONMENT=test
ENV LOG_LEVEL=error
ENV CONFIG_PATH=/app/configs

# Run tests by default
CMD ["make", "test"]

# Migrations stage (for running database migrations)
FROM alpine:3.18 AS migrations

# Install dependencies
RUN apk add --no-cache \
    ca-certificates \
    postgresql-client \
    curl

# Install migrate tool
COPY --from=builder /go/bin/migrate /usr/local/bin/migrate

# Copy migration files
COPY migrations /migrations

# Create migration script
RUN echo '#!/bin/sh' > /migrate.sh && \
    echo 'migrate -path /migrations -database "$DATABASE_URL" up' >> /migrate.sh && \
    chmod +x /migrate.sh

# Default command
CMD ["/migrate.sh"]

# CLI stage (for CLI tools)
FROM alpine:3.18 AS cli

# Install dependencies
RUN apk add --no-cache \
    ca-certificates \
    curl \
    jq \
    bash

# Copy CLI binary
COPY --from=builder /app/frank-auth .

# Create CLI wrapper script
RUN echo '#!/bin/bash' > /frank-cli.sh && \
    echo './frank-auth cli "$@"' >> /frank-cli.sh && \
    chmod +x /frank-cli.sh

# Default command
ENTRYPOINT ["/frank-cli.sh"]

# Nginx stage (for serving static files and reverse proxy)
FROM nginx:alpine AS nginx

# Copy nginx configuration
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/default.conf /etc/nginx/conf.d/default.conf

# Copy static files (if any)
COPY --from=builder /app/web/static /usr/share/nginx/html/static

# Expose port
EXPOSE 80 443

# Health check for nginx
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

# Default stage - production
FROM production AS default