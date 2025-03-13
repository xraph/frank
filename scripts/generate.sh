#!/bin/bash
set -e

# Frank Authentication Server Generate Script

echo "🔧 Generating code for Frank Authentication Server..."

# Go to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

# Check if ent CLI is installed
if ! command -v ent &> /dev/null; then
    echo "❌ ent CLI is not installed. Please run setup.sh first."
    exit 1
fi

# Generate Ent code
echo "🧩 Generating Ent code..."
go generate ./ent

# Install protoc and plugins if needed
if ! command -v protoc &> /dev/null; then
    echo "⚠️ protoc not found. Installing protobuf tooling..."

    # Check OS
    OS=$(uname -s)
    ARCH=$(uname -m)

    if [ "$OS" = "Linux" ]; then
        echo "🐧 Linux detected..."
        PROTOC_ZIP="protoc-24.4-linux-x86_64.zip"
        curl -OL "https://github.com/protocolbuffers/protobuf/releases/download/v24.4/$PROTOC_ZIP"
        sudo unzip -o $PROTOC_ZIP -d /usr/local bin/protoc
        sudo unzip -o $PROTOC_ZIP -d /usr/local 'include/*'
        rm -f $PROTOC_ZIP
    elif [ "$OS" = "Darwin" ]; then
        echo "🍎 macOS detected..."
        brew install protobuf
    else
        echo "❌ Unsupported OS for automatic protoc installation. Please install manually."
        exit 1
    fi

    # Install Go plugins for protoc
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
fi

# Check and install OpenAPI Generator if needed
if ! command -v openapi-generator &> /dev/null; then
    echo "⚠️ openapi-generator not found. Installing OpenAPI Generator..."

    # Check OS
    OS=$(uname -s)

    if [ "$OS" = "Linux" ]; then
        echo "🐧 Linux detected..."
        # Check if npm is available
        if command -v npm &> /dev/null; then
            npm install @openapitools/openapi-generator-cli -g
        else
            # Manual installation using Java
            if command -v java &> /dev/null; then
                echo "Installing via JAR download..."
                mkdir -p "$HOME/bin"
                curl -L "https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/6.6.0/openapi-generator-cli-6.6.0.jar" -o "$HOME/bin/openapi-generator-cli.jar"
                echo '#!/bin/bash' > "$HOME/bin/openapi-generator"
                echo 'java -jar "'$HOME'/bin/openapi-generator-cli.jar" "$@"' >> "$HOME/bin/openapi-generator"
                chmod +x "$HOME/bin/openapi-generator"
                export PATH="$HOME/bin:$PATH"
                echo "Please add $HOME/bin to your PATH permanently in your shell profile."
            else
                echo "❌ Java not found. Please install Java and OpenAPI Generator manually."
                echo "You can download OpenAPI Generator from https://github.com/OpenAPITools/openapi-generator"
            fi
        fi
    elif [ "$OS" = "Darwin" ]; then
        echo "🍎 macOS detected..."
        brew install openapi-generator
    else
        echo "❌ Unsupported OS for automatic OpenAPI Generator installation. Please install manually."
        echo "You can download OpenAPI Generator from https://github.com/OpenAPITools/openapi-generator"
    fi

    # Verify installation
    if ! command -v openapi-generator &> /dev/null; then
        echo "⚠️ OpenAPI Generator installation may have failed. Continuing without it."
        echo "Please install manually from https://github.com/OpenAPITools/openapi-generator"
    else
        echo "✅ OpenAPI Generator installed successfully!"
    fi
fi

# Generate protocol buffers
echo "📄 Generating protocol buffer code..."
mkdir -p internal/pb

# Generate each proto file
for proto_file in api/proto/*.proto; do
    echo "Processing $proto_file..."
    protoc --proto_path=api/proto \
           --go_out=internal/pb --go_opt=paths=source_relative \
           --go-grpc_out=internal/pb --go-grpc_opt=paths=source_relative \
           "$proto_file"
done

# Generate OpenAPI code
if command -v openapi-generator &> /dev/null; then
    echo "📚 Generating OpenAPI GO client code..."
    openapi-generator generate -i api/swagger/swagger.yaml -g go -o client \
        --package-name client \
        --skip-validate-spec \
        --additional-properties=removeOperationIdPrefix=true

    echo "📚 Generating OpenAPI TypeScript client code..."
    # Create a config file for TypeScript generator
    cat > scripts/openapi-ts-config.json << EOF
{
  "supportsES6": true,
  "npmName": "frank-client",
  "npmVersion": "1.0.0",
  "withInterfaces": true,
  "modelPropertyNaming": "camelCase",
  "enumPropertyNaming": "camelCase",
  "removeOperationIdPrefix": true
}
EOF
    
    # Generate TypeScript client with prefix removal for models and operation IDs
    openapi-generator generate -i api/swagger/swagger.yaml -g typescript-fetch -o web/js-sdk \
        -c scripts/openapi-ts-config.json \
        --skip-validate-spec \
        --global-property models,apis,supportingFiles \
        --global-property modelNamePrefix= \
        --global-property fileNaming=kebab-case \
        --additional-properties=removeOperationIdPrefix=true
    
    # Optional: Find and replace "Ent" prefix in generated TypeScript files (in case the global property doesn't work)
    if command -v find &> /dev/null && command -v sed &> /dev/null; then
        echo "Removing 'Ent' prefix from model names in generated TypeScript files..."

        # Check if the necessary directories exist
        if [ ! -d "web/js-sdk/src/models" ]; then
            echo "⚠️ Directory web/js-sdk/src/models does not exist. Skipping TypeScript modifications."
        else
            # Use temporary files instead of in-place editing for compatibility
            if [ "$OS" = "Darwin" ]; then
                echo "Using macOS compatible commands..."

                # Replace in model files
                echo "Processing model interface definitions..."
                for file in web/js-sdk/src/models/*.ts; do
                    if [ -f "$file" ]; then
                        # Use temporary file to avoid in-place editing issues
                        sed 's/export interface Ent\([A-Z][a-zA-Z0-9]*\)/export interface \1/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/export class Ent\([A-Z][a-zA-Z0-9]*\)/export class \1/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/export type Ent\([A-Z][a-zA-Z0-9]*\)/export type \1/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/export function Ent\([A-Z][a-zA-Z0-9]*\)FromJSON/export function \1FromJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/export function Ent\([A-Z][a-zA-Z0-9]*\)FromJSONTyped/export function \1FromJSONTyped/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/export function Ent\([A-Z][a-zA-Z0-9]*\)ToJSON/export function \1ToJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"
                    fi
                done

                # Process source files for imports and references
                echo "Processing import statements and references..."
                for file in web/js-sdk/src/*.ts; do
                    if [ -f "$file" ]; then
                        sed 's/from "\.\/Ent\([A-Z][a-zA-Z0-9]*\)"/from "\.\/\1"/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/import type { Ent\([A-Z][a-zA-Z0-9]*\) } from/import type { \1 } from/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)FromJSON/\1FromJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)FromJSONTyped/\1FromJSONTyped/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)ToJSON/\1ToJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)ToJSONTyped/\1ToJSONTyped/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"
                    fi
                done

                # Recursively process all TypeScript files in subdirectories
                echo "Processing TypeScript files in subdirectories..."
                find web/js-sdk/src -type f -name "*.ts" | while read file; do
                    if [ -f "$file" ]; then
                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)FromJSON/\1FromJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)ToJSON/\1ToJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"
                    fi
                done

                # Rename files from EntXxx.ts to Xxx.ts
                echo "Renaming Ent* files..."
                for file in web/js-sdk/src/models/Ent*.ts; do
                    if [ -f "$file" ]; then
                        newname=$(echo "$file" | sed 's/Ent//')
                        echo "Renaming $file to $newname"
                        mv "$file" "$newname"
                    fi
                done

            else
                # For Linux and other systems
                echo "Using Linux compatible commands..."

                # Replace in model files
                echo "Processing model interface definitions..."
                for file in web/js-sdk/src/models/*.ts; do
                    if [ -f "$file" ]; then
                        # Create a temp file for each transformation to avoid stdin issues
                        sed 's/export interface Ent\([A-Z][a-zA-Z0-9]*\)/export interface \1/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/export class Ent\([A-Z][a-zA-Z0-9]*\)/export class \1/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/export type Ent\([A-Z][a-zA-Z0-9]*\)/export type \1/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/export function Ent\([A-Z][a-zA-Z0-9]*\)FromJSON/export function \1FromJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/export function Ent\([A-Z][a-zA-Z0-9]*\)FromJSONTyped/export function \1FromJSONTyped/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/export function Ent\([A-Z][a-zA-Z0-9]*\)ToJSON/export function \1ToJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"
                    fi
                done

                # Process source files for imports and references
                echo "Processing import statements and references..."
                for file in web/js-sdk/src/*.ts; do
                    if [ -f "$file" ]; then
                        sed 's/from "\.\/Ent\([A-Z][a-zA-Z0-9]*\)"/from "\.\/\1"/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/import type { Ent\([A-Z][a-zA-Z0-9]*\) } from/import type { \1 } from/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)FromJSON/\1FromJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)FromJSONTyped/\1FromJSONTyped/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)ToJSON/\1ToJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)ToJSONTyped/\1ToJSONTyped/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"
                    fi
                done

                # Recursively process all TypeScript files in subdirectories
                echo "Processing TypeScript files in subdirectories..."
                find web/js-sdk/src -type f -name "*.ts" | while read file; do
                    if [ -f "$file" ]; then
                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)FromJSON/\1FromJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"

                        sed 's/Ent\([A-Z][a-zA-Z0-9]*\)ToJSON/\1ToJSON/g' "$file" > "$file.tmp"
                        mv "$file.tmp" "$file"
                    fi
                done

                # Rename files from EntXxx.ts to Xxx.ts
                echo "Renaming Ent* files..."
                for file in web/js-sdk/src/models/Ent*.ts; do
                    if [ -f "$file" ]; then
                        newname=$(echo "$file" | sed 's/Ent//')
                        echo "Renaming $file to $newname"
                        mv "$file" "$newname"
                    fi
                done
            fi
        fi
    fi
else
    echo "⚠️ openapi-generator still not found. Skipping OpenAPI client generation."
fi

# Generate mock files for testing
echo "🧪 Generating mocks for testing..."
go install github.com/golang/mock/mockgen@latest

# List of interfaces to mock
INTERFACES_TO_MOCK=(
    "internal/user.Service"
    "internal/auth/session.Store"
    "internal/auth/oauth2.Storage"
    "internal/organization.Service"
    "internal/webhook.Service"
    "internal/auth/mfa.Service"
    "internal/auth/passkeys.Service"
    "internal/auth/passwordless.Service"
    "internal/auth/sso.Service"
    "internal/apikeys.Service"

    "internal/apikeys.Repository"
    "internal/user.Repository"
    "internal/auth/session.Store"
    "internal/organization.Repository"
    "internal/webhook.Repository"
    "internal/auth/passkeys.Repository"
    "internal/email.TemplateRepository"
)

# Generate mocks
mkdir -p internal/mocks
for interface in "${INTERFACES_TO_MOCK[@]}"; do
    # Extract package and interface name
    PKG=$(echo $interface | cut -d. -f1)
    INTF=$(echo $interface | cut -d. -f2)

    # Extract the actual package name (last component of the path)
    PKG_NAME=$(basename $PKG)

    # Capitalize first letter of package name using tr (more compatible than ^ operator)
    PKG_NAME_CAP=$(echo $PKG_NAME | tr '[:lower:]' '[:upper:]' | cut -c1)$(echo $PKG_NAME | cut -c2-)

    echo "Generating mock for $INTF with mock name Mock${PKG_NAME_CAP}${INTF}..."

    # Generate mocks with mock name prefixed by package name
    mockgen -destination tests/mocks/${PKG_NAME_CAP}${INTF}_mock.go -package mocks -mock_names "${INTF}=Mock${PKG_NAME_CAP}${INTF}" github.com/juicycleff/frank/$PKG $INTF
done

echo "✅ Code generation complete!"