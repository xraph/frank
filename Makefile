.PHONY: build run test lint generate migrate clean ngrok

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

COMMIT_FLAGS=-ldflags="-s -w -X 'github.com/juicycleff/frank/cmd/frank/main.buildDate=$(date -u +%Y%m%d%H%M%S)' -X 'github.com/juicycleff/frank/cmd/frank/main.gitCommit=$(git rev-parse --short HEAD)'"

all: generate test lint build

build:
	$(GOBUILD) $(COMMIT_FLAGS) -o ./bin/$(BINARY_NAME) $(MAIN_PATH)

build-client-prod:
	npm install -g pnpm@latest-10 && cd web/sdk && pnpm i && pnpm build && cd ../client && pnpm i && pnpm build && cd ../..

build-prod:
	make generate-db & $(GOBUILD) -a -installsuffix cgo $(COMMIT_FLAGS) -o ./bin/$(BINARY_NAME) $(MAIN_PATH)

#build-cli:
#	$(GOBUILD) -o ./bin/$(CLI_BINARY_NAME) $(CLI_MAIN_PATH)

build-all:
	$(GOBUILD) -o ./bin/$(BINARY_NAME) $(MAIN_PATH)
	$(GOBUILD) -o ./bin/$(CLI_BINARY_NAME) $(CLI_MAIN_PATH)

run:
	$(GORUN) $(COMMIT_FLAGS)  -o ./tmp/frank $(MAIN_PATH)

test:
	$(GOTEST) -v ./...

lint:
	golangci-lint run

generate-db:
	go generate ./ent

swag:
	swag2op init --output api/swagger -g cmd/server/main.go --parseDependency --overridesFile .swaggo --generatedTime --parseInternal

migrate:
	./scripts/migrate.sh

clean:
	rm -f ./bin/$(BINARY_NAME)
	rm -rf web/client/dist

ngrok:
	sh scripts/start-ngrok.sh

# Run the web client development server
dev-client:
	cd web/client && pnpm run dev

# Run both backend and frontend in development mode
dev-all:
	make -j 2 dev dev-client

# Development target with file watching
dev:
	air -c .air.toml

setup:
	sh scripts/setup.sh

generate:
	sh scripts/generate.sh

generate-goa:
	goa gen github.com/juicycleff/frank/design -o .

setup-client:
	cd web/js-sdk && pnpm i && cd ../..
	cd web/client && pnpm i && cd ../..

# Install development dependencies
dev-deps:
	$(GOGET) -u github.com/cosmtrek/air
	$(GOGET) -u github.com/golang/mock/mockgen
	$(GOGET) -u github.com/golangci/golangci-lint/cmd/golangci-lint
	$(GOGET) -u entgo.io/ent/cmd/ent


deps:
	$(GOGET) -u ./...

# Default target
help:
	@echo "Available targets:"
	@echo "  make generate-openapi	- Generate OpenAPI specification"
	@echo "  make generate-docs	   - Generate OpenAPI spec and Swagger UI"
	@echo "  make install-tools	   - Install required tools"

	@echo "  build	   - Build the application with the web client"
	@echo "  run		 - Run the built application in production mode"
	@echo "  dev		 - Run the application in development mode"
	@echo "  dev-client  - Run the web client development server"
	@echo "  dev-all	 - Run both backend and frontend in development mode"
	@echo "  gen-client  - Generate (build) the web client"
	@echo "  clean	   - Clean build artifacts"
	@echo "  test		- Run tests"
	@echo "  setup	   - Setup project (download dependencies)"
	@echo "  gen-ent	 - Generate Ent models"

# Install required tools
install-tools:
	@echo "Installing required tools..."
	go get -u github.com/getkin/kin-openapi/openapi3
	go get -u gopkg.in/yaml.v3

# Build the CLI tool
build-cli:
	@echo "Building OpenAPI CLI generator..."
	$(GOBUILD) -o ./bin/$(CLI_BINARY_NAME) $(CLI_MAIN_PATH)

# Generate OpenAPI specification
generate-openapi: build-cli
	@echo "Generating OpenAPI specification..."
	./bin/openapi-generator \
		--pkg github.com/juicycleff/frank/internal/routes \
		--func NewRouter \
		--output api/swagger/openapi \
		--title "Frank API" \
		--desc "API for Frank authentication and authorization service" \
		--version "1.0.0" \
		--contact-name "API Support" \
		--contact-email "support@example.com" \
		--contact-url "https://example.com/support" \
		--license "MIT" \
		--license-url "https://opensource.org/licenses/MIT" \
		--json \
		--yaml \
		--servers "https://api.example.com,https://staging-api.example.com"

# Generate OpenAPI specification and Swagger UI
generate-docs: build-cli
	@echo "Generating OpenAPI specification and Swagger UI..."
	./bin/openapi-generator \
		--pkg github.com/juicycleff/frank/internal/routes \
		--func NewRouter \
		--output api/swagger/openapi \
		--title "Frank API" \
		--desc "API for Frank authentication and authorization service" \
		--version "1.0.0" \
		--contact-name "API Support" \
		--contact-email "support@example.com" \
		--contact-url "https://example.com/support" \
		--license "MIT" \
		--license-url "https://opensource.org/licenses/MIT" \
		--json \
		--yaml \
		--servers "https://api.example.com,https://staging-api.example.com" \
		--swagger-ui api/swagger/ui