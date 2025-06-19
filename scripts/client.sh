#!/bin/bash

# scripts/client.sh - OpenAPI Client Generator for Frank Auth
# Generates TypeScript and Go clients from Huma OpenAPI specification

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WEB_DIR="$PROJECT_ROOT/web"
PACKAGES_DIR="$WEB_DIR/packages"
CLIENT_DIR="$PACKAGES_DIR/client"
GO_CLIENT_DIR="$PROJECT_ROOT/pkg/client"
TEMP_DIR=$(mktemp -d)
SERVER_PORT="${SERVER_PORT:-8998}"
SERVER_HOST="${SERVER_HOST:-localhost}"
API_BASE_URL="http://${SERVER_HOST}:${SERVER_PORT}"
DEBUG="${DEBUG:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Logging functions
log_debug() {
    if [ "$DEBUG" = "true" ]; then
        echo -e "${PURPLE}[DEBUG]${NC} $1"
    fi
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    local exit_code=$?
    log_debug "Cleanup function called with exit code: $exit_code"

    if [ -d "$TEMP_DIR" ]; then
        log_debug "Cleaning up temporary directory: $TEMP_DIR"
        rm -rf "$TEMP_DIR"
    fi

    # Kill any background processes we might have started
    if [ -n "${SERVER_PID:-}" ]; then
        log_debug "Cleaning up server process: $SERVER_PID"
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi

    exit $exit_code
}

trap cleanup EXIT

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install dependencies
install_dependencies() {
    local generate_ts="$1"
    local generate_go="$2"

    log_info "Checking and installing dependencies..."

    # Check for Node.js and npm (only if generating TypeScript)
    if [ "$generate_ts" = true ]; then
        if ! command_exists node; then
            log_error "Node.js is not installed. Please install Node.js 18+ from https://nodejs.org/"
            exit 1
        fi

        if ! command_exists npm; then
            log_error "npm is not installed. Please install npm"
            exit 1
        fi

        # Install OpenAPI Generator CLI if not present
        if ! command_exists openapi-generator-cli; then
            log_info "Installing OpenAPI Generator CLI..."
            npm install -g @openapitools/openapi-generator-cli
        fi
    fi

    # Check for Go (only if generating Go client)
    if [ "$generate_go" = true ]; then
        if ! command_exists go; then
            log_error "Go is not installed. Please install Go 1.21+ from https://golang.org/"
            exit 1
        fi

        # Install oapi-codegen for Go client generation
        if ! command_exists oapi-codegen; then
            log_info "Installing oapi-codegen for Go client generation..."
            go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest
        fi
    fi
}

# Wait for server to be ready
wait_for_server() {
    local max_attempts=30
    local attempt=1

    log_info "Waiting for server to be ready at $API_BASE_URL..."

    while [ $attempt -le $max_attempts ]; do
        if curl -s -o /dev/null -w "%{http_code}" "$API_BASE_URL/health" | grep -q "200"; then
            log_success "Server is ready!"
            return 0
        fi

        log_info "Attempt $attempt/$max_attempts: Server not ready, waiting 2 seconds..."
        sleep 2
        ((attempt++))
    done

    log_error "Server failed to start after $max_attempts attempts"
    return 1
}

# Generate OpenAPI spec from running server
generate_openapi_spec() {
    local spec_file="$TEMP_DIR/openapi.json"

    log_info "Generating OpenAPI specification from server..." >&2
    log_debug "Trying endpoints: $API_BASE_URL/docs/openapi.json and $API_BASE_URL/openapi.json" >&2

    # Try to fetch the OpenAPI spec from the server
    local curl_output
    if curl_output=$(curl -s -w "HTTP %{http_code}" "$API_BASE_URL/docs/openapi.json" -o "$spec_file" 2>&1); then
        if echo "$curl_output" | grep -q "HTTP 200"; then
            log_success "OpenAPI spec downloaded successfully from /docs/openapi.json" >&2
        else
            log_warn "First endpoint failed: $curl_output" >&2
            if curl_output=$(curl -s -w "HTTP %{http_code}" "$API_BASE_URL/openapi.json" -o "$spec_file" 2>&1); then
                if echo "$curl_output" | grep -q "HTTP 200"; then
                    log_success "OpenAPI spec downloaded successfully from /openapi.json" >&2
                else
                    log_error "Second endpoint also failed: $curl_output" >&2
                    log_error "Failed to download OpenAPI specification from server" >&2
                    log_info "Make sure the server is running with: make dev" >&2
                    log_info "Try accessing these URLs in your browser:" >&2
                    log_info "  - $API_BASE_URL/docs/openapi.json" >&2
                    log_info "  - $API_BASE_URL/openapi.json" >&2
                    return 1
                fi
            else
                log_error "Curl command failed: $curl_output" >&2
                return 1
            fi
        fi
    else
        log_error "Curl command failed: $curl_output" >&2
        return 1
    fi

    # Check if file exists and has content
    if [ ! -f "$spec_file" ] || [ ! -s "$spec_file" ]; then
        log_error "OpenAPI spec file is empty or doesn't exist" >&2
        return 1
    fi

    # Validate the spec with better error reporting
    if ! command_exists jq; then
        log_warn "jq not found, skipping JSON validation" >&2
    else
        if ! jq empty "$spec_file" 2>/dev/null; then
            log_error "Invalid OpenAPI specification (not valid JSON)" >&2
            log_info "First 200 characters of downloaded file:" >&2
            head -c 200 "$spec_file" >&2 || true
            return 1
        fi

        # Check if it's a valid OpenAPI spec
        if ! jq -e '.openapi' "$spec_file" >/dev/null 2>&1; then
            log_error "Invalid OpenAPI specification (missing openapi field)" >&2
            log_info "Available top-level keys:" >&2
            jq -r 'keys[]' "$spec_file" 2>/dev/null >&2 || echo "Could not parse JSON keys" >&2
            return 1
        fi
    fi

    log_success "OpenAPI specification generated and validated" >&2
    log_debug "Spec file location: $spec_file" >&2

    # Return only the file path (to stdout)
    echo "$spec_file"
}

# Generate TypeScript client
generate_typescript_client() {
    local spec_file="$1"

    # Validate input
    if [ -z "$spec_file" ]; then
        log_error "No spec file provided to generate_typescript_client"
        return 1
    fi

    # Verify spec file exists and is readable
    if [ ! -f "$spec_file" ]; then
        log_error "Spec file does not exist: $spec_file"
        return 1
    fi

    if [ ! -r "$spec_file" ]; then
        log_error "Spec file is not readable: $spec_file"
        return 1
    fi

    local spec_size
    spec_size=$(wc -c < "$spec_file" 2>/dev/null || echo "0")
    if [ "$spec_size" -eq 0 ]; then
        log_error "Spec file is empty: $spec_file"
        return 1
    fi

    log_info "Generating TypeScript client..."
    log_debug "Using OpenAPI spec: $spec_file"
    log_debug "Spec file size: $spec_size bytes"

    # Create client directory
    log_info "Creating client directory: $CLIENT_DIR"
    if ! mkdir -p "$CLIENT_DIR"; then
        log_error "Failed to create client directory: $CLIENT_DIR"
        return 1
    fi

    # Check if openapi-generator-cli is available
    if ! command_exists openapi-generator-cli; then
        log_error "openapi-generator-cli not found. Installing..."
        if ! npm install -g @openapitools/openapi-generator-cli; then
            log_error "Failed to install OpenAPI Generator CLI"
            return 1
        fi
    fi

    # Remove existing TypeScript client if it exists
    if [ -d "$CLIENT_DIR" ]; then
        log_info "Removing existing TypeScript client directory..."
        rm -rf "$CLIENT_DIR"
    fi

    log_info "Running OpenAPI Generator for TypeScript client..."
    log_debug "Output directory: $CLIENT_DIR"

    # Create a temporary script to avoid shell escaping issues
    local temp_script="$TEMP_DIR/generate_ts.sh"
    cat > "$temp_script" << EOF
#!/bin/bash
set -e
openapi-generator-cli generate \\
    -i "$spec_file" \\
    -g typescript-fetch \\
    -o "$CLIENT_DIR" \\
    --additional-properties=npmName=@frank-auth/client,npmVersion=1.0.0,supportsES6=true,typescriptThreePlus=true,withSeparateModelsAndApi=true,modelPackage=models,apiPackage=api,srcDir=src \\
    --skip-validate-spec
EOF

    chmod +x "$temp_script"

    log_debug "Generated temporary script: $temp_script"
    if [ "$DEBUG" = "true" ]; then
        log_debug "Script contents:"
        cat "$temp_script"
    fi

    # Execute the generation
    if ! bash "$temp_script" 2>&1; then
        log_error "Failed to generate TypeScript client"
        log_info "Debugging information:"
        log_info "  Spec file path: $spec_file"
        log_info "  Spec file exists: $([ -f "$spec_file" ] && echo "yes" || echo "no")"
        log_info "  Spec file size: $spec_size bytes"
        if [ -f "$spec_file" ]; then
            log_info "  First few lines of spec file:"
            head -3 "$spec_file" 2>/dev/null || echo "  Could not read spec file"
        fi
        return 1
    fi

    log_success "TypeScript client generated successfully"

    # Verify the generated files
    if [ ! -d "$CLIENT_DIR" ]; then
        log_error "TypeScript client directory was not created"
        return 1
    fi

    log_info "Generated TypeScript client files:"
    find "$CLIENT_DIR/src" -type f -name "*.ts" | head -5 || true

    # Create package.json for the TypeScript client
    log_info "Creating package.json..."
    cat > "$CLIENT_DIR/package.json" << EOF
{
  "name": "@frank-auth/client",
  "version": "1.0.0",
  "description": "TypeScript client for Frank Authentication API",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc",
    "build:watch": "tsc --watch",
    "test": "jest",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix"
  },
  "keywords": [
    "frank-auth",
    "authentication",
    "typescript",
    "api-client",
    "fetch"
  ],
  "author": "Frank Auth Team",
  "license": "MIT",
  "dependencies": {},
  "devDependencies": {
    "@types/node": "^20.0.0",
    "typescript": "^5.0.0",
    "jest": "^29.0.0",
    "@types/jest": "^29.0.0",
    "eslint": "^8.0.0",
    "@typescript-eslint/eslint-plugin": "^6.0.0",
    "@typescript-eslint/parser": "^6.0.0"
  },
  "peerDependencies": {},
  "files": [
    "dist",
    "src",
    "README.md"
  ]
}
EOF

    # Create TypeScript configuration
    cat > "$CLIENT_DIR/tsconfig.json" << EOF
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020", "DOM"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "moduleResolution": "node",
    "allowSyntheticDefaultImports": true,
    "resolveJsonModule": true
  },
  "include": [
    "src/**/*.ts"
  ],
  "exclude": [
    "node_modules",
    "dist",
    "**/*.test.ts",
    "**/*.spec.ts"
  ]
}
EOF

    # Create README for TypeScript client
    cat > "$CLIENT_DIR/README.md" << EOF
# Frank Auth TypeScript Client

Official TypeScript client for the Frank Authentication API. Uses native fetch API for HTTP requests.

## Installation

\`\`\`bash
npm install @frank-auth/client
\`\`\`

## Usage

\`\`\`typescript
import { Configuration, AuthApi, UsersApi } from '@frank-auth/client';

// Configure the client
const config = new Configuration({
  basePath: 'https://api.frankauth.com/v1',
  apiKey: 'your-api-key',
  // or use Bearer token
  // accessToken: 'your-access-token',
});

// Create API instances
const authApi = new AuthApi(config);
const usersApi = new UsersApi(config);

// Example: Login
try {
  const response = await authApi.login({
    loginRequest: {
      email: 'user@example.com',
      password: 'password123'
    }
  });
  console.log('Login successful:', response);
} catch (error) {
  console.error('Login failed:', error);
}

// Example: Get user profile
try {
  const profile = await usersApi.getCurrentUser();
  console.log('User profile:', profile);
} catch (error) {
  console.error('Failed to get user profile:', error);
}
\`\`\`

## Advanced Configuration

\`\`\`typescript
import { Configuration, AuthApi } from '@frank-auth/client';

const config = new Configuration({
  basePath: 'https://api.frankauth.com/v1',
  apiKey: 'your-api-key',
  fetchApi: fetch, // Use custom fetch implementation if needed
  middleware: [
    {
      pre: async (context) => {
        // Custom request middleware
        console.log('Making request to:', context.url);
        return Promise.resolve(context);
      },
      post: async (context) => {
        // Custom response middleware
        console.log('Response status:', context.response.status);
        return Promise.resolve(context.response);
      }
    }
  ]
});

const authApi = new AuthApi(config);
\`\`\`

## API Reference

This client provides full access to the Frank Authentication API. See the [API documentation](https://docs.frankauth.com) for detailed information about available endpoints and operations.

## Error Handling

The client uses the native fetch API for HTTP requests. All API methods return promises that resolve to the response data or reject with an error.

\`\`\`typescript
try {
  const result = await authApi.login({
    loginRequest: {
      email: 'user@example.com',
      password: 'password123'
    }
  });
  // Handle success
  console.log('Login successful:', result);
} catch (error) {
  if (error instanceof Response) {
    // HTTP error response
    console.error('HTTP Error:', error.status, error.statusText);
    const errorBody = await error.text();
    console.error('Error body:', errorBody);
  } else {
    // Network error or other issue
    console.error('Network/Other error:', error.message);
  }
}
\`\`\`

## Configuration Options

- \`basePath\`: API base URL (default: 'https://api.frankauth.com/v1')
- \`apiKey\`: API key for authentication
- \`accessToken\`: Bearer token for authentication
- \`username\`: Username for basic auth
- \`password\`: Password for basic auth
- \`fetchApi\`: Custom fetch implementation (defaults to global fetch)
- \`middleware\`: Array of middleware for request/response processing

## Browser Compatibility

This client uses the native fetch API, which is supported in:
- Chrome 42+
- Firefox 39+
- Safari 10.1+
- Edge 14+

For older browsers, you may need to include a fetch polyfill:

\`\`\`bash
npm install whatwg-fetch
\`\`\`

\`\`\`typescript
import 'whatwg-fetch';
import { Configuration, AuthApi } from '@frank-auth/client';
\`\`\`

## Development

\`\`\`bash
# Install dependencies
npm install

# Build the client
npm run build

# Run tests
npm test

# Lint code
npm run lint
\`\`\`

## Project Structure

\`\`\`
typescript/
├── src/           # Generated TypeScript source files
│   ├── apis/      # API endpoint classes
│   ├── models/    # Type definitions and models
│   └── runtime.ts # Runtime utilities
├── dist/          # Compiled JavaScript output
├── package.json
├── tsconfig.json
└── README.md
\`\`\`

## TypeScript Support

This client is written in TypeScript and provides full type safety:

\`\`\`typescript
import { User, Organization, LoginRequest } from '@frank-auth/client';

// All types are automatically inferred
const loginRequest: LoginRequest = {
  email: 'user@example.com',
  password: 'password123'
};

// Response types are strongly typed
const user: User = await usersApi.getCurrentUser();
const org: Organization = await orgApi.getOrganization({ orgId: user.organizationId });
\`\`\`
EOF

    log_success "TypeScript client generated successfully"
}

# Generate Go client
# Generate Go client using OpenAPI Generator instead of oapi-codegen
generate_go_client() {
    local spec_file="$1"

    # Validate input
    if [ -z "$spec_file" ]; then
        log_error "No spec file provided to generate_go_client"
        return 1
    fi

    if [ ! -f "$spec_file" ]; then
        log_error "Spec file does not exist: $spec_file"
        return 1
    fi

    log_info "Generating Go client using OpenAPI Generator..."
    log_debug "Using OpenAPI spec: $spec_file"

    # Create Go client directory
    if ! mkdir -p "$GO_CLIENT_DIR"; then
        log_error "Failed to create Go client directory: $GO_CLIENT_DIR"
        return 1
    fi

    # Check if OpenAPI Generator is available (prefer this over oapi-codegen)
    local generator_cmd=""
    if command_exists openapi-generator-cli; then
        generator_cmd="openapi-generator-cli"
        log_info "Using openapi-generator-cli for Go client generation"
    elif command_exists openapi-generator; then
        generator_cmd="openapi-generator"
        log_info "Using openapi-generator for Go client generation"
    elif command_exists oapi-codegen; then
        log_warn "OpenAPI Generator not found, falling back to oapi-codegen (may have issues with complex types)"
        return generate_go_client_with_oapi_codegen "$spec_file"
    else
        log_error "No Go client generator found. Please install OpenAPI Generator:"
        log_info "  npm install -g @openapitools/openapi-generator-cli"
        log_info "  # or"
        log_info "  brew install openapi-generator"
        return 1
    fi

    # Remove existing Go client if it exists
    if [ -d "$GO_CLIENT_DIR" ]; then
        log_info "Removing existing Go client directory..."
        rm -rf "$GO_CLIENT_DIR"/*
    fi

    # Create configuration for OpenAPI Generator
    local config_file="$TEMP_DIR/openapi-generator-config.yaml"
    cat > "$config_file" << EOF
packageName: client
packageVersion: 0.0.1
packageUrl: github.com/juicycleff/frank/pkg/client
clientPackage: client
generateInterfaces: true
structPrefix: true
enumClassPrefix: true
useOneOfDiscriminatorLookup: true
legacyDiscriminatorBehavior: false
prependFormOrBodyParameters: false
# Single model file configuration
singleModelFile: true
modelFilename: models.go
modelPackage: client
# Additional Go-specific configurations
withGoCodegenComment: true
withXml: false
hideGenerationTimestamp: true
EOF

    log_debug "OpenAPI Generator config file: $config_file"
    if [ "$DEBUG" = "true" ]; then
        log_debug "Config contents:"
        cat "$config_file"
    fi

    # Generate Go client using OpenAPI Generator
    log_info "Running OpenAPI Generator for Go client..."
    if ! $generator_cmd generate \
        -i "$spec_file" \
        -g go \
        -o "$GO_CLIENT_DIR" \
        -c "$config_file" \
        --additional-properties=packageName=client,generateInterfaces=true,structPrefix=true,singleModelFile=true,modelFilename=models.go \
        --skip-validate-spec \
        --global-property=models,apis,supportingFiles 2>&1; then

        log_error "Failed to generate Go client with OpenAPI Generator"
        log_info "Debugging information:"
        log_info "  Spec file path: $spec_file"
        log_info "  Spec file exists: $([ -f "$spec_file" ] && echo "yes" || echo "no")"
        log_info "  Config file: $config_file"
        log_info "  Output directory: $GO_CLIENT_DIR"
        return 1
    fi

    log_success "Go client generated successfully with OpenAPI Generator"

    # Create Go module if it doesn't exist
    if [ ! -f "$GO_CLIENT_DIR/go.mod" ]; then
        cd "$GO_CLIENT_DIR"
        go mod init github.com/juicycleff/frank/pkg/client
        go mod tidy
        cd "$PROJECT_ROOT"
    fi

    # Create Frank-specific client wrapper
    create_frank_client_wrapper_openapi_gen

    log_success "Go client with Frank wrapper generated successfully"
}

# Fallback function for oapi-codegen (keeps your existing implementation)
generate_go_client_with_oapi_codegen() {
    local spec_file="$1"

    log_warn "Using oapi-codegen fallback - may have issues with complex array types"

    # Your existing oapi-codegen implementation here...
    # (keep the existing code from your current script)
}

# Create Frank-specific wrapper for OpenAPI Generator output
create_frank_client_wrapper_openapi_gen() {
    # This creates a more user-friendly wrapper around the generated client
    cat > "$GO_CLIENT_DIR/frank_client.go" << 'EOF'
package client

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// FrankClient wraps the generated OpenAPI client with Frank-specific functionality
type FrankClient struct {
	*APIClient
	cfg *Configuration
}

// Config holds configuration for the Frank Auth client
type Config struct {
	BaseURL     string
	APIKey      string
	AccessToken string
	Timeout     time.Duration
	UserAgent   string
	HTTPClient  *http.Client
}

// NewFrankClient creates a new Frank Auth client using OpenAPI Generator
func NewFrankClient(config *Config) *FrankClient {
	if config == nil {
		config = &Config{}
	}

	// Set defaults
	if config.BaseURL == "" {
		config.BaseURL = "https://api.frankauth.com/v1"
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "frank-auth-go-client/1.0.0"
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: config.Timeout}
	}

	// Create OpenAPI client configuration
	cfg := NewConfiguration()
	cfg.Servers = ServerConfigurations{{URL: config.BaseURL}}
	cfg.HTTPClient = config.HTTPClient
	cfg.UserAgent = config.UserAgent

	// Set up authentication
	if config.APIKey != "" {
		cfg.DefaultHeader["X-API-Key"] = config.APIKey
	}
	if config.AccessToken != "" {
		cfg.DefaultHeader["Authorization"] = "Bearer " + config.AccessToken
	}

	apiClient := NewAPIClient(cfg)

	return &FrankClient{
		APIClient: apiClient,
		cfg:       cfg,
	}
}

// WithAPIKey sets the API key for authentication
func (c *FrankClient) WithAPIKey(apiKey string) *FrankClient {
	c.cfg.DefaultHeader["X-API-Key"] = apiKey
	return c
}

// WithAccessToken sets the access token for authentication
func (c *FrankClient) WithAccessToken(token string) *FrankClient {
	c.cfg.DefaultHeader["Authorization"] = "Bearer " + token
	return c
}

// Convenience methods for common operations

// Login authenticates a user
func (c *FrankClient) Login(ctx context.Context, email, password string) (*LoginResponse, *http.Response, error) {
	req := LoginRequest{Email: email, Password: password}
	return c.AuthenticationAPI.Login(ctx).LoginRequest(req).Execute()
}

// GetCurrentUser retrieves the current authenticated user
func (c *FrankClient) GetCurrentUser(ctx context.Context) (*User, *http.Response, error) {
	return c.UsersAPI.GetCurrentUser(ctx).Execute()
}

// ListUserPasskeys lists passkeys for the current user
func (c *FrankClient) ListUserPasskeys(ctx context.Context) (*PasskeyListResponse, *http.Response, error) {
	return c.PasskeysAPI.ListPasskeys(ctx).Execute()
}
EOF

    # Create comprehensive README
    cat > "$GO_CLIENT_DIR/README.md" << 'EOF'
# Frank Auth Go Client

Official Go client for the Frank Authentication API, generated using OpenAPI Generator.

## Why OpenAPI Generator?

This client is generated using OpenAPI Generator instead of oapi-codegen because:

- ✅ **Better Type Support**: Handles complex schema types including nullable arrays
- ✅ **More Mature**: Battle-tested with thousands of APIs
- ✅ **Feature Complete**: Supports all OpenAPI 3.0 features
- ✅ **Active Development**: Regular updates and bug fixes
- ✅ **Consistent Output**: Same generator used for TypeScript, Java, Python clients

## Installation

```bash
go get github.com/juicycleff/frank/pkg/client
```

## Quick Start

```go
package main

import (
    "context"
    "log"

    "github.com/juicycleff/frank/pkg/client"
)

func main() {
    // Create client
    frankClient := client.NewFrankClient(&client.Config{
        BaseURL: "https://api.frankauth.com/v1",
        APIKey:  "your-api-key",
    })

    ctx := context.Background()

    // Login
    login, _, err := frankClient.Login(ctx, "user@example.com", "password")
    if err != nil {
        log.Fatal(err)
    }

    // Get user info
    user, _, err := frankClient.GetCurrentUser(ctx)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Welcome %s!", user.GetEmail())
}
```

## Features

- Full Frank Auth API coverage
- Type-safe operations
- Proper error handling
- Built-in pagination support
- Authentication methods (API Key, Bearer Token)
- Configurable HTTP client
- Request/response middleware support

## Generated vs Manual Code

- **Generated Code**: All API operations, models, and core client functionality
- **Manual Code**: Frank-specific convenience methods and configuration helpers
- **Best of Both**: Type safety + ease of use
EOF
}

# Start server if not running
start_server() {
    log_info "Checking if server is running..."

    if curl -s -o /dev/null -w "%{http_code}" "$API_BASE_URL/health" | grep -q "200"; then
        log_success "Server is already running"
        return 0
    fi

    log_info "Starting server for OpenAPI spec generation..."

    # Check if make command exists and Makefile has run target
    if command_exists make && grep -q "^run:" Makefile 2>/dev/null; then
        log_info "Starting server using make run..."
        make run &
        SERVER_PID=$!
    elif [ -f "cmd/server/main.go" ]; then
        log_info "Starting server using go run..."
        go run cmd/server/main.go &
        SERVER_PID=$!
    else
        log_error "Cannot find a way to start the server"
        log_info "Please start the server manually and run this script again"
        exit 1
    fi

    # Wait for server to be ready
    if wait_for_server; then
        log_success "Server started successfully"
        return 0
    else
        log_error "Failed to start server"
        if [ -n "${SERVER_PID:-}" ]; then
            kill $SERVER_PID 2>/dev/null || true
        fi
        exit 1
    fi
}

# Stop server if we started it
stop_server() {
    if [ -n "${SERVER_PID:-}" ]; then
        log_info "Stopping server..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        log_success "Server stopped"
    fi
}

# Main function
main() {
    local server_started=false
    local generate_ts=true
    local generate_go=true

    log_info "🚀 Starting Frank Auth OpenAPI client generation..."

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-server)
                SKIP_SERVER=true
                shift
                ;;
            --skip-ts)
                generate_ts=false
                log_info "Skipping TypeScript client generation"
                shift
                ;;
            --skip-go)
                generate_go=false
                log_info "Skipping Go client generation"
                shift
                ;;
            --debug)
                DEBUG=true
                log_debug "Debug mode enabled"
                shift
                ;;
            --port)
                SERVER_PORT="$2"
                API_BASE_URL="http://${SERVER_HOST}:${SERVER_PORT}"
                shift 2
                ;;
            --host)
                SERVER_HOST="$2"
                API_BASE_URL="http://${SERVER_HOST}:${SERVER_PORT}"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --skip-server    Skip starting the server (assumes it's already running)"
                echo "  --skip-ts        Skip TypeScript client generation"
                echo "  --skip-go        Skip Go client generation"
                echo "  --debug          Enable debug logging"
                echo "  --port PORT      Server port (default: 8998)"
                echo "  --host HOST      Server host (default: localhost)"
                echo "  --help           Show this help message"
                echo ""
                echo "Environment variables:"
                echo "  DEBUG=true       Enable debug logging"
                echo "  SERVER_PORT      Server port"
                echo "  SERVER_HOST      Server host"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    log_debug "Configuration:"
    log_debug "  Project root: $PROJECT_ROOT"
    log_debug "  Client dir: $CLIENT_DIR"
    log_debug "  Go client dir: $GO_CLIENT_DIR"
    log_debug "  API base URL: $API_BASE_URL"
    log_debug "  Generate TS: $generate_ts"
    log_debug "  Generate Go: $generate_go"
    log_debug "  Skip server: ${SKIP_SERVER:-false}"

    # Install dependencies
    log_info "Installing dependencies for selected generators..."
    if ! install_dependencies "$generate_ts" "$generate_go"; then
        log_error "Failed to install dependencies"
        exit 1
    fi

    # Start server if needed
    if [ "${SKIP_SERVER:-false}" != "true" ]; then
        if ! start_server; then
            log_error "Failed to start server"
            exit 1
        fi
        server_started=true
    else
        log_info "Skipping server start (assuming it's already running)"
        if ! wait_for_server; then
            log_error "Server is not running. Please start it or remove --skip-server flag"
            exit 1
        fi
    fi

    # Generate OpenAPI spec
    log_info "Generating OpenAPI specification..."
    local spec_file
    if ! spec_file=$(generate_openapi_spec); then
        log_error "Failed to generate OpenAPI specification"
        if [ "$server_started" = true ]; then
            stop_server
        fi
        exit 1
    fi

    # Validate spec file was returned
    if [ -z "$spec_file" ] || [ ! -f "$spec_file" ]; then
        log_error "OpenAPI spec generation returned invalid file path: '$spec_file'"
        if [ "$server_started" = true ]; then
            stop_server
        fi
        exit 1
    fi

    log_debug "OpenAPI spec file ready: $spec_file"

    # Generate clients based on flags
    local generation_success=true

    if [ "$generate_ts" = true ]; then
        log_info "Starting TypeScript client generation..."
        if ! generate_typescript_client "$spec_file"; then
            log_error "Failed to generate TypeScript client"
            generation_success=false
        else
            log_success "TypeScript client generated successfully"
        fi
    else
        log_info "Skipping TypeScript client generation"
    fi

    if [ "$generate_go" = true ]; then
        log_info "Starting Go client generation..."
        if ! generate_go_client "$spec_file"; then
            log_error "Failed to generate Go client"
            generation_success=false
        else
            log_success "Go client generated successfully"
        fi
    else
        log_info "Skipping Go client generation"
    fi

    # Stop server if we started it
    if [ "$server_started" = true ]; then
        stop_server
    fi

    # Check if any generation failed
    if [ "$generation_success" = false ]; then
        log_error "One or more client generations failed"
        exit 1
    fi

    log_success "🎉 Client generation completed successfully!"
    log_info ""
    log_info "Generated files:"
    if [ "$generate_ts" = true ]; then
        log_info "  📁 TypeScript client: $CLIENT_DIR/"
    fi
    if [ "$generate_go" = true ]; then
        log_info "  📁 Go client: $GO_CLIENT_DIR/"
    fi
    log_info ""
    log_info "Next steps:"
    if [ "$generate_ts" = true ]; then
        log_info "  1. TypeScript: cd $CLIENT_DIR && npm install && npm run build"
    fi
    if [ "$generate_go" = true ]; then
        log_info "  2. Go: The client is ready to use, check $GO_CLIENT_DIR/README.md for usage"
    fi
}

# Run main function
main "$@"