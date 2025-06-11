.PHONY: help dev build clean test lint docker ngrok

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GORUN=$(GOCMD) run
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

BINARY_NAME=frank
MAIN_PATH=./cmd/frank
CLI_BINARY_NAME=frank_cli
CLI_MAIN_PATH=./cmd/frank_cli

# Default target
help: ## Show this help message
	@echo "Frank Auth - Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development
dev: ## Start development environment
	@./scripts/dev.sh

dev-frontend: ## Start only frontend development server
	@echo "🚀 Starting frontend development server with live reload..."
	@cd web && pnpm dev

dev-backend: ## Start only backend development server with live reload
	@echo "🚀 Starting backend development server with live reload..."
	@if command -v air > /dev/null 2>&1; then \
		air -c .air.toml; \
	else \
		echo "⚠️  Air not found. Installing air for live reload..."; \
		go install github.com/cosmtrek/air@latest; \
		air -c .air.toml; \
	fi


dev-cli: ## Start only backend development cli
	@go run cmd/cli/main.go

dev-backend-simple: ## Start backend without live reload
	@echo "🚀 Starting backend development server (no live reload)..."
	@go run cmd/frank/main.go

ngrok: ## Start ngrok tunnel
	@sh scripts/start-ngrok.sh

# Building
build: ## Build for production
	@./scripts/build.sh

build-frontend: ## Build only frontend
	@cd web && pnpm build

build-backend: ## Build only backend
	@go build -o dist/frank-auth cmd/frank/main.go

build-cli: ## Build only cli
	@go build -o bin/frank-cli cmd/cli/main.go

# Testing
test: ## Run all tests
	@go test -v ./...
	@cd web && pnpm test

test-backend: ## Run backend tests
	@go test -v ./...

test-frontend: ## Run frontend tests
	@cd web && pnpm test

test-watch: ## Run backend tests in watch mode
	@if command -v air > /dev/null 2>&1; then \
		air -c .air.test.toml; \
	else \
		echo "Installing air for test watching..."; \
		go install github.com/cosmtrek/air@latest; \
		air -c .air.test.toml; \
	fi

# Linting
lint: ## Lint all code
	@golangci-lint run
	@cd web && pnpm lint

lint-fix: ## Fix linting issues
	@golangci-lint run --fix
	@cd web && pnpm lint --fix

lint-watch: ## Run linter in watch mode
	@golangci-lint run --watch

# Database
migrate-up: ## Run database migrations
	@go run cmd/migrate/main.go up

migrate-down: ## Rollback database migrations
	@go run cmd/migrate/main.go down

migrate-create: ## Create new migration (usage: make migrate-create name=migration_name)
	@go generate ./ent

# Docker
docker-build: ## Build Docker image
	@docker build -t frank-auth:latest .

docker-run: ## Run Docker container
	@docker run -p 8998:8998 frank-auth:latest

docker-compose-up: ## Start with docker-compose
	@docker-compose up -d

docker-compose-down: ## Stop docker-compose
	@docker-compose down

docker-logs: ## Show docker-compose logs
	@docker-compose logs -f

# Cleanup
clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf dist
	@rm -rf tmp
	@rm -rf web/apps/dashboard/out
	@rm -rf web/apps/dashboard/.next
	@rm -rf web/node_modules
	@go clean
	@echo "✅ Clean completed"

clean-all: clean ## Clean everything including Docker volumes
	@echo "🧹 Cleaning Docker volumes..."
	@docker-compose down -v
	@docker system prune -f

# Installation
install-tools: ## Install development tools
	@echo "📦 Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/pressly/goose/v3/cmd/goose@latest
	@go install github.com/cosmtrek/air@latest
	@npm install -g pnpm
	@echo "✅ Development tools installed"

# Production deployment
deploy: build ## Deploy to production
	@echo "🚀 Deploying Frank Auth..."
	@scp -r dist/* production-server:/opt/frank-auth/
	@ssh production-server 'cd /opt/frank-auth && ./deploy.sh'

# Development utilities
logs: ## Show application logs
	@tail -f tmp/app.log 2>/dev/null || echo "No log file found. Start the application first."

ps: ## Show running processes
	@echo "Backend processes:"
	@ps aux | grep -E "(air|frank|go run)" | grep -v grep || echo "No backend processes found"
	@echo "\nFrontend processes:"
	@ps aux | grep -E "(next|pnpm)" | grep -v grep || echo "No frontend processes found"

stop: ## Stop all development processes
	@echo "🛑 Stopping development processes..."
	@pkill -f "air" 2>/dev/null || true
	@pkill -f "go run" 2>/dev/null || true
	@pkill -f "next dev" 2>/dev/null || true
	@pkill -f "pnpm dev" 2>/dev/null || true
	@echo "✅ All processes stopped"