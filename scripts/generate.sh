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

# Generate OpenAPI code (if swagger-codegen is installed)
if command -v swagger-codegen &> /dev/null; then
    echo "📚 Generating OpenAPI client code..."
    swagger-codegen generate -i api/swagger/openapi.yaml -l go -o internal/api/client
else
    echo "⚠️ swagger-codegen not found. Skipping OpenAPI client generation."
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
)

# Generate mocks
mkdir -p internal/mocks
for interface in "${INTERFACES_TO_MOCK[@]}"; do
    # Extract package and interface name
    PKG=$(echo $interface | cut -d. -f1)
    INTF=$(echo $interface | cut -d. -f2)

    echo "Generating mock for $INTF in $PKG..."
    mockgen -destination internal/mocks/${INTF}_mock.go -package mocks github.com/juicycleff/frank/$PKG $INTF
done

echo "✅ Code generation complete!"