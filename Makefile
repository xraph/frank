.PHONY: help dev build clean test lint docker ngrok migrate-help

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
MIGRATE_BINARY_NAME=frank_migrate
MIGRATE_MAIN_PATH=./cmd/migrate

# Migration parameters (can be overridden via command line)
MIGRATION_ENV?=development

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

build-migrate: ## Build migration tool
	@echo "🔨 Building migration tool..."
	@mkdir -p bin
	@go build -o bin/$(MIGRATE_BINARY_NAME) $(MIGRATE_MAIN_PATH)/main.go
	@echo "✅ Migration tool built: bin/$(MIGRATE_BINARY_NAME)"

# Migration Management (entgo versioned migrations)
migrate-help: ## Show migration help
	@echo "📚 Frank Auth Migration Commands:"
	@echo ""
	@echo "🔧 Basic Operations:"
	@echo "  make migrate-create name=add_users       # Create new migration"
	@echo "  make migrate-up                          # Apply all pending migrations"
	@echo "  make migrate-down                        # Rollback last migration"
	@echo "  make migrate-status                      # Show migration status"
	@echo ""
	@echo "🎯 Advanced Operations:"
	@echo "  make migrate-to version=20231201120001   # Migrate to specific version"
	@echo "  make migrate-rollback steps=3            # Rollback N migrations (default: 1)"
	@echo "  make migrate-seed                        # Seed database with default data"
	@echo "  make migrate-seed file=custom.sql        # Seed with custom file"
	@echo "  make migrate-validate                    # Validate schema integrity"
	@echo ""
	@echo "🏢 Multi-tenant & Environment:"
	@echo "  make migrate-up env=staging            # Run in staging environment"
	@echo "  make migrate-seed tenant=01FZS6TV...   # Tenant-specific seeding"
	@echo ""
	@echo "⚠️  Dangerous Operations:"
	@echo "  make migrate-reset                     # Reset database (DANGEROUS)"
	@echo "  make migrate-drop                      # Drop all tables (DANGEROUS)"
	@echo "  make migrate-force-unlock              # Force unlock migration lock"
	@echo ""
	@echo "🔍 Debugging:"
	@echo "  make migrate-dry-run                   # Dry run migrations"
	@echo "  make migrate-version                   # Show current version"
	@echo ""
	@echo "💡 Examples:"
	@echo "  make migrate-create name=\"add_user_preferences\""
	@echo "  make migrate-rollback steps=2"
	@echo "  make migrate-to version=20231201120001"
	@echo "  make migrate-seed file=custom_seed.sql"
	@echo "  make migrate-seed env=staging"

migrate-create: ## Create new migration (usage: make migrate-create name=migration_name)
	@if [ -z "$(name)" ]; then \
		echo "❌ Migration name is required"; \
		echo "Usage: make migrate-create name=add_users"; \
		exit 1; \
	fi
	@echo "📝 Creating migration: $(name)"
	@go run -mod=mod ent/migrate/main.go "$(name)"
	@echo "✅ Migration created successfully"
	@echo "📁 Check migrations/ for generated files"

migrate-up: ## Apply all pending migrations
	@echo "⬆️  Applying database migrations..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) migrate
	@echo "✅ Migrations applied successfully"

migrate-down: ## Rollback last migration
	@echo "⬇️  Rolling back last migration..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) rollback --steps 1
	@echo "✅ Rollback completed"

migrate-status: ## Show migration status
	@echo "📊 Migration Status:"
	@./scripts/migrate.sh --env $(MIGRATION_ENV) status

migrate-version: ## Show current migration version
	@echo "🏷️  Current Migration Version:"
	@./scripts/migrate.sh --env $(MIGRATION_ENV) version

migrate-to: ## Migrate to specific version (usage: make migrate-to version=20231201120001)
	@if [ -z "$(version)" ]; then \
		echo "❌ Migration version is required"; \
		echo "Usage: make migrate-to version=20231201120001"; \
		exit 1; \
	fi
	@echo "🎯 Migrating to version: $(version)"
	@./scripts/migrate.sh --env $(MIGRATION_ENV) migrate --version $(version)
	@echo "✅ Migration to version $(version) completed"

migrate-rollback: ## Rollback N migrations (usage: make migrate-rollback steps=3, defaults to 1)
	@STEPS=${steps:-1}; \
	echo "⬇️  Rolling back $STEPS migration(s)..."; \
	./scripts/migrate.sh --env $(MIGRATION_ENV) rollback --steps $STEPS; \
	echo "✅ Rollback of $STEPS migration(s) completed"

migrate-rollback-to: ## Rollback to specific version (usage: make migrate-rollback-to version=20231201120001)
	@if [ -z "$(version)" ]; then \
		echo "❌ Migration version is required"; \
		echo "Usage: make migrate-rollback-to version=20231201120001"; \
		exit 1; \
	fi
	@echo "⬇️  Rolling back to version: $(version)"
	@./scripts/migrate.sh --env $(MIGRATION_ENV) rollback --version $(version)
	@echo "✅ Rollback to version $(version) completed"

migrate-seed: ## Seed database with default data (usage: make migrate-seed [file=path/to/seed.sql])
	@echo "🌱 Seeding database with default data..."
	@if [ -n "$(file)" ]; then \
		./scripts/migrate.sh --env $(MIGRATION_ENV) seed --seed-file $(file); \
	else \
		./scripts/migrate.sh --env $(MIGRATION_ENV) seed; \
	fi
	@echo "✅ Database seeding completed"

migrate-validate: ## Validate database schema integrity
	@echo "🔍 Validating database schema..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) validate
	@echo "✅ Schema validation completed"

migrate-dry-run: ## Show what migrations would be applied (dry run)
	@echo "🔍 Dry run - showing what would be migrated:"
	@./scripts/migrate.sh --env $(MIGRATION_ENV) --dry-run migrate

migrate-reset: ## Reset database (DANGEROUS - removes all data)
	@echo "⚠️  WARNING: This will PERMANENTLY DELETE all data!"
	@echo "This action cannot be undone."
	@read -p "Are you absolutely sure? Type 'yes' to confirm: " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		echo "🗑️  Resetting database..."; \
		./scripts/migrate.sh --env $(MIGRATION_ENV) reset --yes; \
		echo "✅ Database reset completed"; \
	else \
		echo "❌ Reset cancelled"; \
	fi

migrate-drop: ## Drop all database tables (DANGEROUS)
	@echo "⚠️  WARNING: This will DROP ALL TABLES!"
	@echo "This action cannot be undone."
	@read -p "Are you absolutely sure? Type 'yes' to confirm: " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		echo "🗑️  Dropping all tables..."; \
		./scripts/migrate.sh --env $(MIGRATION_ENV) drop --yes; \
		echo "✅ All tables dropped"; \
	else \
		echo "❌ Drop cancelled"; \
	fi

migrate-force-unlock: ## Force unlock migration lock (use with caution)
	@echo "🔓 Force unlocking migration lock..."
	@echo "⚠️  Only use this if you're sure no migration is running!"
	@read -p "Continue? (y/N): " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		./scripts/migrate.sh --env $(MIGRATION_ENV) force-unlock --yes; \
		echo "✅ Migration lock removed"; \
	else \
		echo "❌ Force unlock cancelled"; \
	fi

# Migration shortcuts for different environments
migrate-dev: ## Run migrations in development
	@MIGRATION_ENV=development $(MAKE) migrate-up

migrate-test: ## Run migrations in test environment
	@MIGRATION_ENV=testing $(MAKE) migrate-up

migrate-staging: ## Run migrations in staging
	@MIGRATION_ENV=staging $(MAKE) migrate-up

migrate-prod: ## Run migrations in production (with confirmation)
	@echo "🚨 PRODUCTION MIGRATION WARNING 🚨"
	@echo "You are about to run migrations in PRODUCTION!"
	@echo "Make sure you have:"
	@echo "  ✅ Backed up the database"
	@echo "  ✅ Tested migrations in staging"
	@echo "  ✅ Reviewed all migration files"
	@echo "  ✅ Have a rollback plan ready"
	@echo ""
	@read -p "Proceed with production migration? Type 'MIGRATE' to confirm: " confirm; \
	if [ "$confirm" = "MIGRATE" ]; then \
		echo "🚀 Running production migration..."; \
		MIGRATION_ENV=production $(MAKE) migrate-up; \
	else \
		echo "❌ Production migration cancelled"; \
	fi

# Migration with Docker
migrate-docker: ## Run migrations using Docker
	@echo "🐳 Running migrations in Docker..."
	@./scripts/migrate.sh --docker migrate

migrate-docker-build: ## Build migration Docker image
	@echo "🐳 Building migration Docker image..."
	@docker build -f docker/Dockerfile.migrate -t frank-migrate:latest .

db-generate:
	@echo "💻 Generating ent schema for database."
	@go generate ./ent

# Database utilities
db-console: ## Open database console
	@echo "💻 Opening database console..."
	@if command -v psql > /dev/null 2>&1; then \
		psql -h localhost -U frank -d frank; \
	else \
		echo "❌ psql not found. Install PostgreSQL client tools."; \
	fi

db-backup: ## Create database backup
	@echo "💾 Creating database backup..."
	@mkdir -p backups
	@pg_dump -h localhost -U frank -d frank > backups/frank_backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo "✅ Backup created in backups/ directory"

db-restore: ## Restore database from backup (usage: make db-restore file=backup.sql)
	@if [ -z "$(file)" ]; then \
		echo "❌ Backup file is required"; \
		echo "Usage: make db-restore file=backups/frank_backup_20231201_120000.sql"; \
		exit 1; \
	fi
	@echo "📥 Restoring database from $(file)..."
	@psql -h localhost -U frank -d frank < $(file)
	@echo "✅ Database restored from $(file)"

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

test-migration: ## Test migration system
	@echo "🧪 Testing migration system..."
	@go test -v ./migration/...
	@echo "✅ Migration tests completed"

# Linting
lint: ## Lint all code
	@golangci-lint run
	@cd web && pnpm lint

lint-fix: ## Fix linting issues
	@golangci-lint run --fix
	@cd web && pnpm lint --fix

lint-watch: ## Run linter in watch mode
	@golangci-lint run --watch

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
	@rm -rf bin
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

clean-migrations: ## Clean migration lock (use with caution)
	@echo "🧹 Cleaning migration locks..."
	@./scripts/migrate.sh force-unlock --yes

# Installation
install-tools: ## Install development tools
	@echo "📦 Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/cosmtrek/air@latest
	@go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	@npm install -g pnpm
	@echo "✅ Development tools installed"

install-migration-deps: ## Install migration dependencies
	@echo "📦 Installing migration dependencies..."
	@go get entgo.io/ent@latest
	@go get ariga.io/atlas@latest
	@go get github.com/golang-migrate/migrate/v4@latest
	@go get github.com/lib/pq@latest
	@go get github.com/go-sql-driver/mysql@latest
	@go get github.com/mattn/go-sqlite3@latest
	@go mod tidy
	@echo "✅ Migration dependencies installed"

# Production deployment
deploy: build ## Deploy to production
	@echo "🚀 Deploying Frank Auth..."
	@scp -r dist/* production-server:/opt/frank-auth/
	@ssh production-server 'cd /opt/frank-auth && ./deploy.sh'

deploy-migrations: ## Deploy only migrations to production
	@echo "🚀 Deploying migrations to production..."
	@scp -r migrations/* production-server:/opt/frank-auth/migrations/
	@ssh production-server 'cd /opt/frank-auth && make migrate-prod'

# Development utilities
logs: ## Show application logs
	@tail -f tmp/app.log 2>/dev/null || echo "No log file found. Start the application first."

migration-logs: ## Show migration logs
	@if [ -f tmp/migration.log ]; then \
		tail -f tmp/migration.log; \
	else \
		echo "No migration log file found."; \
	fi

# Client Generation
client-generate: ## Generate TypeScript and Go API clients from OpenAPI spec
	@echo "🔧 Generating API clients..."
	@chmod +x scripts/client.sh
	@./scripts/client.sh
	@echo "✅ API clients generated successfully"

client-generate-ts: ## Generate only TypeScript client
	@echo "🔧 Generating TypeScript API client..."
	@chmod +x scripts/client.sh
	@./scripts/client.sh --skip-go
	@echo "✅ TypeScript client generated successfully"

client-generate-go: ## Generate only Go client
	@echo "🔧 Generating Go API client..."
	@chmod +x scripts/client.sh
	@./scripts/client.sh --skip-ts
	@echo "✅ Go client generated successfully"

client-install-deps: ## Install client generation dependencies
	@echo "📦 Installing client generation dependencies..."
	@if ! command -v openapi-generator-cli > /dev/null 2>&1; then \
		echo "Installing OpenAPI Generator CLI..."; \
		npm install -g @openapitools/openapi-generator-cli; \
	fi
	@if ! command -v oapi-codegen > /dev/null 2>&1; then \
		echo "Installing oapi-codegen..."; \
		go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest; \
	fi
	@echo "✅ Client generation dependencies installed"

client-clean: ## Clean generated client files
	@echo "🧹 Cleaning generated client files..."
	@rm -rf web/packages/client/typescript
	@rm -rf pkg/client/*.go
	@rm -rf pkg/client/go.mod
	@rm -rf pkg/client/go.sum
	@echo "✅ Client files cleaned"

client-build-ts: ## Build TypeScript client
	@echo "🔨 Building TypeScript client..."
	@if [ -d "web/packages/client/typescript" ]; then \
		cd web/packages/client/typescript && npm install && npm run build; \
		echo "✅ TypeScript client built successfully"; \
	else \
		echo "❌ TypeScript client not found. Run 'make client-generate' first"; \
		exit 1; \
	fi

client-test-ts: ## Test TypeScript client
	@echo "🧪 Testing TypeScript client..."
	@if [ -d "web/packages/client/typescript" ]; then \
		cd web/packages/client/typescript && npm test; \
		echo "✅ TypeScript client tests passed"; \
	else \
		echo "❌ TypeScript client not found. Run 'make client-generate' first"; \
		exit 1; \
	fi

client-test-go: ## Test Go client
	@echo "🧪 Testing Go client..."
	@if [ -f "pkg/client/client.go" ]; then \
		cd pkg/client && go test -v .; \
		echo "✅ Go client tests passed"; \
	else \
		echo "❌ Go client not found. Run 'make client-generate' first"; \
		exit 1; \
	fi

client-publish-ts: ## Publish TypeScript client to npm (requires npm login)
	@echo "📦 Publishing TypeScript client to npm..."
	@if [ -d "web/packages/client/typescript" ]; then \
		cd web/packages/client/typescript && npm publish; \
		echo "✅ TypeScript client published to npm"; \
	else \
		echo "❌ TypeScript client not found. Run 'make client-generate' first"; \
		exit 1; \
	fi

client-generate-debug: ## Generate clients with debug logging
	@echo "🔧 Generating API clients (debug mode)..."
	@chmod +x scripts/client.sh
	@./scripts/client.sh --debug
	@echo "✅ API clients generated successfully"

client-generate-ts-debug: ## Generate only TypeScript client with debug logging
	@echo "🔧 Generating TypeScript API client (debug mode)..."
	@chmod +x scripts/client.sh
	@./scripts/client.sh --skip-go --debug
	@echo "✅ TypeScript client generated successfully"

client-generate-go-debug: ## Generate only Go client with debug logging
	@echo "🔧 Generating Go API client (debug mode)..."
	@chmod +x scripts/client.sh
	@./scripts/client.sh --skip-ts --debug
	@echo "✅ Go client generated successfully"

client-dev: ## Generate clients and start development with live reload
	@echo "🚀 Starting client development mode..."
	@$(MAKE) client-generate
	@$(MAKE) dev

client-help: ## Show client generation help
	@echo "📚 Frank Auth Client Generation Commands:"
	@echo ""
	@echo "🔧 Generation:"
	@echo "  make client-generate        # Generate both TypeScript and Go clients"
	@echo "  make client-generate-ts     # Generate only TypeScript client"
	@echo "  make client-generate-go     # Generate only Go client"
	@echo ""
	@echo "🐛 Debug Generation:"
	@echo "  make client-generate-debug     # Generate both clients with debug logging"
	@echo "  make client-generate-ts-debug  # Generate TypeScript client with debug logging"
	@echo "  make client-generate-go-debug  # Generate Go client with debug logging"
	@echo ""
	@echo "🛠️  Development:"
	@echo "  make client-install-deps    # Install client generation dependencies"
	@echo "  make client-clean           # Clean generated client files"
	@echo "  make client-build-ts        # Build TypeScript client"
	@echo "  make client-dev             # Generate clients and start dev mode"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  make client-test-ts         # Test TypeScript client"
	@echo "  make client-test-go         # Test Go client"
	@echo ""
	@echo "📦 Publishing:"
	@echo "  make client-publish-ts      # Publish TypeScript client to npm"
	@echo ""
	@echo "🎯 Examples:"
	@echo "  make client-generate                    # Generate both clients"
	@echo "  make client-clean && make client-generate  # Clean and regenerate"
	@echo "  make client-generate-ts-debug           # Debug TypeScript generation issues"
	@echo "  ./scripts/client.sh --skip-server      # Generate without starting server"
	@echo "  ./scripts/client.sh --port 3000        # Use custom port"
	@echo "  DEBUG=true ./scripts/client.sh         # Enable debug via environment"

# Test parameter passing (for debugging)
test-params: ## Test parameter passing (usage: make test-params name=test steps=2 version=123)
	@echo "Testing parameter values:"
	@echo "  name: '$(name)'"
	@echo "  steps: '$(steps)' (default: ${steps:-1})"
	@echo "  version: '$(version)'"
	@echo "  file: '$(file)'"
	@echo "  env: '$(env)' (MIGRATION_ENV: '$(MIGRATION_ENV)')"

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

# Setup and initialization
setup: ## Setup development environment
	@echo "🚀 Setting up Frank Auth development environment..."
	@$(MAKE) install-tools
	@$(MAKE) install-migration-deps
	@$(MAKE) build-migrate
	@echo "📋 Next steps:"
	@echo "  1. Configure your database in config/config.yaml"
	@echo "  2. Run: make migrate-create name=initial_schema"
	@echo "  3. Run: make migrate-up"
	@echo "  4. Run: make migrate-seed"
	@echo "  5. Run: make dev"
	@echo "✅ Setup completed!"

init-db: ## Initialize database with schema and seed data
	@echo "🗄️  Initializing database..."
	@$(MAKE) migrate-up
	@$(MAKE) migrate-seed
	@echo "✅ Database initialized successfully"

# Quick development workflow
quick-start: ## Quick start for new developers
	@echo "⚡ Quick start for Frank Auth..."
	@$(MAKE) setup
	@$(MAKE) init-db
	@echo "🎉 Frank Auth is ready!"
	@echo "Run 'make dev' to start the development server"