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

# Check and install Swagger Codegen if needed
if ! command -v swagger-codegen &> /dev/null; then
    echo "⚠️ swagger-codegen not found. Installing Swagger Codegen..."

    # Check OS
    OS=$(uname -s)

    if [ "$OS" = "Linux" ]; then
        echo "🐧 Linux detected..."
        # Check if apt is available (Debian/Ubuntu)
        if command -v apt &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y swagger-codegen
        # Check if dnf is available (Fedora/RHEL)
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y swagger-codegen
        # Check if yum is available (older RHEL/CentOS)
        elif command -v yum &> /dev/null; then
            sudo yum install -y swagger-codegen
        else
            # Manual installation using Java
            if command -v java &> /dev/null; then
                echo "Installing via JAR download..."
                mkdir -p "$HOME/bin"
                curl -L "https://repo1.maven.org/maven2/io/swagger/codegen/v3/swagger-codegen-cli/3.0.36/swagger-codegen-cli-3.0.36.jar" -o "$HOME/bin/swagger-codegen-cli.jar"
                echo '#!/bin/bash' > "$HOME/bin/swagger-codegen"
                echo 'java -jar "'$HOME'/bin/swagger-codegen-cli.jar" "$@"' >> "$HOME/bin/swagger-codegen"
                chmod +x "$HOME/bin/swagger-codegen"
                export PATH="$HOME/bin:$PATH"
                echo "Please add $HOME/bin to your PATH permanently in your shell profile."
            else
                echo "❌ Java not found. Please install Java and Swagger Codegen manually."
                echo "You can download Swagger Codegen from https://github.com/swagger-api/swagger-codegen"
            fi
        fi
    elif [ "$OS" = "Darwin" ]; then
        echo "🍎 macOS detected..."
        brew install swagger-codegen
    else
        echo "❌ Unsupported OS for automatic Swagger Codegen installation. Please install manually."
        echo "You can download Swagger Codegen from https://github.com/swagger-api/swagger-codegen"
    fi

    # Verify installation
    if ! command -v swagger-codegen &> /dev/null; then
        echo "⚠️ Swagger Codegen installation may have failed. Continuing without it."
        echo "Please install manually from https://github.com/swagger-api/swagger-codegen"
    else
        echo "✅ Swagger Codegen installed successfully!"
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
if command -v swagger-codegen &> /dev/null; then
    echo "📚 Generating OpenAPI client code..."
    swagger-codegen generate -i api/swagger/openapi.yaml -l go -o internal/api/client
else
    echo "⚠️ swagger-codegen still not found. Skipping OpenAPI client generation."
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
    # This changes the interface name within the mock code (e.g., MockService → MockUserService)
    mockgen -destination internal/mocks/${INTF}_mock.go -package mocks -mock_names "${INTF}=Mock${PKG_NAME_CAP}${INTF}" github.com/juicycleff/frank/$PKG $INTF
    mockgen -destination tests/mocks/${INTF}_mock.go -package mocks -mock_names "${INTF}=Mock${PKG_NAME_CAP}${INTF}" github.com/juicycleff/frank/$PKG $INTF
done

echo "✅ Code generation complete!"