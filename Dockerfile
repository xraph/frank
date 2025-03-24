# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux && make build-prod

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
EXPOSE 8998

# Run the binary
CMD ["./bin/frank"]
