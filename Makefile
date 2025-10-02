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


# Migration State Synchronization Commands
migrate-sync: ## Synchronize migration state with database schema
	@echo "🔄 Synchronizing migration state..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) sync
	@echo "✅ Migration state synchronized"

migrate-sync-dry: ## Show what migration sync would do (dry run)
	@echo "🔍 Analyzing migration synchronization plan..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) --dry-run sync

migrate-sync-force: ## Force synchronize migration state (use with caution)
	@echo "⚠️  Force synchronizing migration state..."
	@read -p "This will force synchronization of migration state. Continue? (y/N): " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		./scripts/migrate.sh --env $(MIGRATION_ENV) --force --create-missing --update-existing sync; \
		echo "✅ Force synchronization completed"; \
	else \
		echo "❌ Force synchronization cancelled"; \
	fi

migrate-analyze: ## Analyze current database state and migration status
	@echo "🔍 Analyzing database migration state..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) analyze

migrate-analyze-json: ## Analyze database state and output as JSON
	@echo "🔍 Analyzing database migration state (JSON output)..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) --output json analyze

migrate-repair: ## Repair corrupted migration state
	@echo "🔧 Repairing migration state..."
	@echo "⚠️  This will attempt to fix corrupted migration state"
	@read -p "Continue with migration repair? (y/N): " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		./scripts/migrate.sh --env $(MIGRATION_ENV) repair; \
		echo "✅ Migration state repair completed"; \
	else \
		echo "❌ Migration repair cancelled"; \
	fi

migrate-repair-force: ## Force repair migration state without confirmation
	@echo "🔧 Force repairing migration state..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) --yes --force repair
	@echo "✅ Force migration repair completed"

# Migration Troubleshooting Commands
migrate-check-state: ## Check for migration state inconsistencies
	@echo "🔍 Checking migration state consistency..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) analyze | grep -E "(Error|Warning|Inconsistent)" || echo "✅ No obvious state issues detected"

migrate-fix-format-change: ## Fix migration state after format change
	@echo "🔄 Fixing migration state after format change..."
	@echo "This will:"
	@echo "  1. Analyze current database state"
	@echo "  2. Identify missing migration entries"
	@echo "  3. Synchronize state with actual schema"
	@echo ""
	@read -p "Continue with format change fix? (y/N): " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		echo "📊 Step 1: Analyzing current state..."; \
		./scripts/migrate.sh --env $(MIGRATION_ENV) analyze; \
		echo ""; \
		echo "🔄 Step 2: Running sync (dry run)..."; \
		./scripts/migrate.sh --env $(MIGRATION_ENV) --dry-run --create-missing sync; \
		echo ""; \
		read -p "Apply the synchronization plan above? (y/N): " apply; \
		if [ "$$apply" = "y" ] || [ "$$apply" = "Y" ]; then \
			echo "🚀 Step 3: Applying synchronization..."; \
			./scripts/migrate.sh --env $(MIGRATION_ENV) --create-missing sync; \
			echo "✅ Format change fix completed"; \
		else \
			echo "❌ Synchronization cancelled"; \
		fi; \
	else \
		echo "❌ Format change fix cancelled"; \
	fi

# Enhanced Migration Commands with Sync Support
migrate-up-safe: ## Apply migrations with safety checks
	@echo "🔍 Pre-migration analysis..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) analyze
	@echo ""
	@read -p "Proceed with migration? (y/N): " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		./scripts/migrate.sh --env $(MIGRATION_ENV) migrate; \
		echo "🔍 Post-migration analysis..."; \
		./scripts/migrate.sh --env $(MIGRATION_ENV) analyze; \
	else \
		echo "❌ Migration cancelled"; \
	fi

migrate-rollback-safe: ## Rollback migrations with safety checks
	@echo "🔍 Pre-rollback analysis..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) analyze
	@echo ""
	@STEPS=${steps:-1}; \
	echo "⚠️  WARNING: Rolling back $$STEPS migration(s)"; \
	read -p "Continue with rollback? (y/N): " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		./scripts/migrate.sh --env $(MIGRATION_ENV) rollback --steps $$STEPS; \
		echo "🔍 Post-rollback analysis..."; \
		./scripts/migrate.sh --env $(MIGRATION_ENV) analyze; \
	else \
		echo "❌ Rollback cancelled"; \
	fi

# Development workflow with sync
migrate-dev-reset: ## Reset development database and resync (DANGEROUS)
	@echo "🚨 DEVELOPMENT DATABASE RESET 🚨"
	@echo "This will:"
	@echo "  1. Drop all tables"
	@echo "  2. Re-run all migrations"
	@echo "  3. Seed with default data"
	@echo "  4. Synchronize state"
	@echo ""
	@read -p "Are you sure? This will DELETE ALL DATA! (type 'dev-reset' to confirm): " confirm; \
	if [ "$$confirm" = "dev-reset" ]; then \
		echo "🗑️  Dropping tables..."; \
		./scripts/migrate.sh --env development drop --yes || true; \
		echo "⬆️  Running migrations..."; \
		./scripts/migrate.sh --env development migrate; \
		echo "🌱 Seeding database..."; \
		./scripts/migrate.sh --env development seed; \
		echo "🔄 Synchronizing state..."; \
		./scripts/migrate.sh --env development sync; \
		echo "✅ Development database reset completed"; \
	else \
		echo "❌ Reset cancelled"; \
	fi

# Environment-specific sync commands
migrate-sync-dev: ## Sync migration state in development
	@MIGRATION_ENV=development $(MAKE) migrate-sync

migrate-sync-test: ## Sync migration state in test environment
	@MIGRATION_ENV=testing $(MAKE) migrate-sync

migrate-sync-staging: ## Sync migration state in staging
	@MIGRATION_ENV=staging $(MAKE) migrate-sync

migrate-sync-prod: ## Sync migration state in production (with extra confirmation)
	@echo "🚨 PRODUCTION MIGRATION SYNC WARNING 🚨"
	@echo "You are about to synchronize migration state in PRODUCTION!"
	@echo "Make sure you have:"
	@echo "  ✅ Backed up the database"
	@echo "  ✅ Tested sync in staging"
	@echo "  ✅ Analyzed the sync plan"
	@echo "  ✅ Have a rollback plan ready"
	@echo ""
	@read -p "Proceed with production migration sync? Type 'SYNC-PROD' to confirm: " confirm; \
	if [ "$confirm" = "SYNC-PROD" ]; then \
		echo "🔍 Analyzing production state..."; \
		MIGRATION_ENV=production $(MAKE) migrate-analyze; \
		echo ""; \
		read -p "Continue with sync? Type 'YES' to confirm: " final; \
		if [ "$final" = "YES" ]; then \
			echo "🚀 Running production migration sync..."; \
			MIGRATION_ENV=production $(MAKE) migrate-sync; \
		else \
			echo "❌ Production sync cancelled at final confirmation"; \
		fi; \
	else \
		echo "❌ Production sync cancelled"; \
	fi

# Updated help with sync commands
migrate-help: ## Show enhanced migration help including sync commands
	@echo "📚 Enhanced Migration Management with Sync Support"
	@echo ""
	@echo "🔧 Basic Operations:"
	@echo "  make migrate-up                      # Apply all pending migrations"
	@echo "  make migrate-down                    # Rollback last migration"
	@echo "  make migrate-status                  # Show migration status"
	@echo "  make migrate-create name=migration   # Create new migration"
	@echo ""
	@echo "🔄 Synchronization Operations:"
	@echo "  make migrate-sync                    # Sync migration state with schema"
	@echo "  make migrate-sync-dry                # Show what sync would do"
	@echo "  make migrate-sync-force              # Force sync (dangerous)"
	@echo "  make migrate-analyze                 # Analyze database state"
	@echo "  make migrate-analyze-json            # Analyze state (JSON output)"
	@echo "  make migrate-repair                  # Repair corrupted state"
	@echo ""
	@echo "🩹 Troubleshooting:"
	@echo "  make migrate-check-state             # Check for inconsistencies"
	@echo "  make migrate-fix-format-change       # Fix state after format change"
	@echo "  make migrate-repair-force            # Force repair without prompts"
	@echo ""
	@echo "🛡️  Safe Operations:"
	@echo "  make migrate-up-safe                 # Migrate with pre/post analysis"
	@echo "  make migrate-rollback-safe           # Rollback with safety checks"
	@echo ""
	@echo "🏢 Environment-Specific Sync:"
	@echo "  make migrate-sync-dev                # Sync in development"
	@echo "  make migrate-sync-staging            # Sync in staging"
	@echo "  make migrate-sync-prod               # Sync in production (with extra safety)"
	@echo ""
	@echo "⚡ Quick Fixes:"
	@echo "  # Schema exists but migrations not tracked:"
	@echo "  make migrate-sync-force"
	@echo ""
	@echo "  # After migration format change:"
	@echo "  make migrate-fix-format-change"
	@echo ""
	@echo "  # Corrupted migration state:"
	@echo "  make migrate-repair"
	@echo ""
	@echo "  # Reset development environment:"
	@echo "  make migrate-dev-reset"
	@echo ""
	@echo "🎯 Common Scenarios:"
	@echo ""
	@echo "  📋 Moving from old to new migration format:"
	@echo "    1. make migrate-analyze"
	@echo "    2. make migrate-sync-dry"
	@echo "    3. make migrate-sync"
	@echo ""
	@echo "  🔧 Database exists but no migration history:"
	@echo "    1. make migrate-analyze"
	@echo "    2. make migrate-sync-force"
	@echo ""
	@echo "  ⚠️  Dirty/corrupted migration state:"
	@echo "    1. make migrate-check-state"
	@echo "    2. make migrate-repair"
	@echo ""
	@echo "  🧪 Setting up clean development environment:"
	@echo "    make migrate-dev-reset"


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
	@echo "💡 Run 'make migrate-analyze' to check state after applying"

migrate-up: ## Apply all pending migrations with post-sync check
	@echo "⬆️  Applying database migrations..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) migrate
	@echo "🔍 Checking migration state consistency..."
	@./scripts/migrate.sh --env $(MIGRATION_ENV) analyze | grep -E "(Warning|Error)" || echo "✅ Migration state looks good"
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
	@docker build -f docker/Dockerfile.migrate -t wakflo-migrate:latest .


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