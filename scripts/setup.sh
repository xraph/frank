#!/bin/bash
set -e

# Frank Authentication Server Setup Script

echo "🚀 Setting up Frank Authentication Server..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go before continuing."
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
MIN_VERSION="1.18"
if [[ "$(printf '%s\n' "$MIN_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]]; then
    echo "❌ Go version $GO_VERSION detected. Frank requires Go $MIN_VERSION or higher."
    exit 1
fi

# Check if ent CLI is installed
if ! command -v ent &> /dev/null; then
    echo "📦 Installing ent CLI..."
    go install entgo.io/ent/cmd/ent@latest
fi

# Go to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

# Initialize Go modules if not already done
if [ ! -f go.mod ]; then
    echo "📝 Initializing Go modules..."
    go mod init github.com/juicycleff/frank
fi

# Install dependencies
echo "📦 Installing dependencies..."
go mod tidy

# Setup environment
if [ ! -f .env ]; then
    echo "📝 Creating .env file from example..."
    cp .env.example .env 2>/dev/null || echo "# Frank Authentication Server Environment Variables" > .env
    echo "# Generated on $(date)" >> .env
    echo "PORT=8000" >> .env
    echo "ENV=development" >> .env
    echo "LOG_LEVEL=debug" >> .env
    echo "DATABASE_URL=postgres://postgres:postgres@localhost:5432/frank?sslmode=disable" >> .env
    echo "REDIS_URL=redis://localhost:6379" >> .env
    echo "SESSION_SECRET=$(openssl rand -hex 32)" >> .env
    echo "TOKEN_SECRET=$(openssl rand -hex 32)" >> .env
    echo "API_KEY_SECRET=$(openssl rand -hex 32)" >> .env
    echo "BASE_URL=http://localhost:8000" >> .env
    echo "SMTP_HOST=localhost" >> .env
    echo "SMTP_PORT=1025" >> .env
    echo "SMTP_USERNAME=" >> .env
    echo "SMTP_PASSWORD=" >> .env
    echo "SMTP_FROM=noreply@example.com" >> .env
    echo "ENABLE_SWAGGER=true" >> .env
fi

# Generate code
echo "🔧 Generating ent code..."
bash "${SCRIPT_DIR}/generate.sh"

# Setup development database
if command -v docker &> /dev/null; then
    if ! docker ps | grep -q "frank-postgres"; then
        echo "🐘 Setting up PostgreSQL database..."
        docker run --name frank-postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=frank -p 5432:5432 -d postgres:14
    fi
    if ! docker ps | grep -q "frank-redis"; then
        echo "🔴 Setting up Redis..."
        docker run --name frank-redis -p 6379:6379 -d redis:7
    fi
else
    echo "⚠️ Docker not found. Please set up PostgreSQL and Redis manually."
fi

# Run migrations
echo "🔄 Running database migrations..."
bash "${SCRIPT_DIR}/migrate.sh"

echo "✅ Setup complete! You can now start the server with 'go run cmd/api/main.go'"