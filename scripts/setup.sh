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

# Install or update ngrok
install_ngrok() {
    echo "📦 Installing/updating ngrok..."

    # Determine system architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64) NGROK_ARCH="amd64" ;;
        arm64|aarch64) NGROK_ARCH="arm64" ;;
        arm*) NGROK_ARCH="arm" ;;
        *) echo "❌ Unsupported architecture: $ARCH"; return 1 ;;
    esac

    # Determine OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        # Try the package manager method first
        if command -v apt-get &> /dev/null; then
            curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && \
            echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list && \
            sudo apt update && sudo apt install ngrok -y
            return $?
        elif command -v yum &> /dev/null; then
            echo "Using binary installation for yum-based systems..."
        else
            echo "Using binary installation method..."
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="darwin"
        if command -v brew &> /dev/null; then
            brew install --cask ngrok
            return $?
        else
            echo "Homebrew not found, using binary installation method..."
        fi
    elif [[ "$OSTYPE" == "cygwin" || "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        OS="windows"
    else
        echo "❌ Unsupported OS: $OSTYPE"
        return 1
    fi

    # Binary installation method as fallback
    TEMP_DIR=$(mktemp -d)
    NGROK_ZIP="$TEMP_DIR/ngrok.zip"
    DOWNLOAD_URL="https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-${OS}-${NGROK_ARCH}.zip"

    echo "Downloading ngrok from $DOWNLOAD_URL..."
    if command -v curl &> /dev/null; then
        curl -L -o "$NGROK_ZIP" "$DOWNLOAD_URL"
    elif command -v wget &> /dev/null; then
        wget -O "$NGROK_ZIP" "$DOWNLOAD_URL"
    else
        echo "❌ Neither curl nor wget found. Please install one of them."
        return 1
    fi

    # Extract and install
    echo "Extracting ngrok..."
    if [[ "$OS" == "windows" ]]; then
        INSTALL_DIR="$HOME/bin"
    else
        INSTALL_DIR="/usr/local/bin"
    fi

    mkdir -p "$INSTALL_DIR"
    unzip -o "$NGROK_ZIP" -d "$TEMP_DIR"

    if [[ "$OSTYPE" == "linux-gnu"* || "$OSTYPE" == "darwin"* ]]; then
        sudo mv "$TEMP_DIR/ngrok" "$INSTALL_DIR/"
        sudo chmod +x "$INSTALL_DIR/ngrok"
    else
        mv "$TEMP_DIR/ngrok.exe" "$INSTALL_DIR/"
    fi

    # Clean up
    rm -rf "$TEMP_DIR"

    echo "ngrok installed successfully to $INSTALL_DIR"
    return 0
}

# Check if ngrok is installed, and install if not
if ! command -v ngrok &> /dev/null; then
    install_ngrok || { echo "❌ Failed to install ngrok. Please install it manually from https://ngrok.com/download"; exit 1; }
else
    echo "✅ ngrok is already installed. Checking for updates..."
    # Check ngrok version
    CURRENT_VERSION=$(ngrok --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)

    # For demonstration, we'll update if it exists. In a real script, you might want to check the version number
    # against a minimum required version
    install_ngrok || { echo "⚠️ Failed to update ngrok, but continuing with existing installation."; }
fi

# Configure ngrok if not already configured
if ! ngrok config check &> /dev/null; then
    echo "⚙️ ngrok is not configured. Please run 'ngrok config add-authtoken YOUR_AUTH_TOKEN' after this script completes."
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
    # Add ngrok configuration
    echo "NGROK_ENABLED=false" >> .env
    echo "NGROK_DOMAIN=" >> .env  # If you have a reserved domain with ngrok
fi

# Add a helper script for starting ngrok tunnel
NGROK_SCRIPT="${SCRIPT_DIR}/start-ngrok.sh"
cat > "$NGROK_SCRIPT" << 'EOF'
#!/bin/bash
# Start ngrok tunnel for Frank Authentication Server

PORT=$(grep -E "^PORT=" .env | cut -d= -f2)
PORT=${PORT:-8000}  # Default to 8000 if not found

DOMAIN=$(grep -E "^NGROK_DOMAIN=" .env | cut -d= -f2)

echo "🚇 Starting ngrok tunnel to port $PORT..."

if [ -n "$DOMAIN" ]; then
    echo "Using custom domain: $DOMAIN"
    ngrok http --domain="$DOMAIN" "$PORT"
else
    ngrok http "$PORT"
fi
EOF

chmod +x "$NGROK_SCRIPT"

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


echo "✅ Setup complete! You can now:"
echo "  • Start the server with 'go run cmd/api/main.go'"
echo "  • Start an ngrok tunnel with './scripts/start-ngrok.sh'"
echo ""
echo "💡 To configure ngrok with your authtoken, run: ngrok config add-authtoken YOUR_AUTH_TOKEN"