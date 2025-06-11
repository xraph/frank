#!/bin/bash
# setup.sh - Complete development environment setup for Frank Auth

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[SETUP]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if command -v apt-get &> /dev/null; then
            DISTRO="ubuntu"
        elif command -v yum &> /dev/null; then
            DISTRO="centos"
        else
            DISTRO="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi

    print_info "Detected OS: $OS ($DISTRO)"
}

# Install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."

    case "$OS" in
        "linux")
            case "$DISTRO" in
                "ubuntu")
                    sudo apt-get update
                    sudo apt-get install -y curl wget git build-essential software-properties-common apt-transport-https ca-certificates gnupg lsb-release
                    ;;
                "centos")
                    sudo yum update -y
                    sudo yum install -y curl wget git gcc gcc-c++ make
                    ;;
            esac
            ;;
        "macos")
            if ! command -v brew &> /dev/null; then
                print_status "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew update
            ;;
    esac
}

# Install Go
install_go() {
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | cut -d' ' -f3 | cut -d'o' -f2)
        print_info "Go $GO_VERSION is already installed"
        return
    fi

    print_status "Installing Go..."

    GO_VERSION="1.21.5"

    case "$OS" in
        "linux")
            wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
            sudo rm -rf /usr/local/go
            sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
            rm go${GO_VERSION}.linux-amd64.tar.gz

            # Add to PATH
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
            export PATH=$PATH:/usr/local/go/bin
            export PATH=$PATH:$HOME/go/bin
            ;;
        "macos")
            brew install go
            ;;
    esac

    print_status "Go installed successfully ✅"
}

# Install Node.js and pnpm
install_nodejs() {
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version)
        print_info "Node.js $NODE_VERSION is already installed"
    else
        print_status "Installing Node.js..."

        case "$OS" in
            "linux")
                curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
                sudo apt-get install -y nodejs
                ;;
            "macos")
                brew install node
                ;;
        esac
    fi

    # Install pnpm
    if ! command -v pnpm &> /dev/null; then
        print_status "Installing pnpm..."
        npm install -g pnpm
    else
        print_info "pnpm is already installed"
    fi

    print_status "Node.js and pnpm installed successfully ✅"
}

# Install Docker and Docker Compose
install_docker() {
    if command -v docker &> /dev/null; then
        print_info "Docker is already installed"
        return
    fi

    print_status "Installing Docker..."

    case "$OS" in
        "linux")
            case "$DISTRO" in
                "ubuntu")
                    # Add Docker's official GPG key
                    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

                    # Add Docker repository
                    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

                    # Install Docker
                    sudo apt-get update
                    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

                    # Add user to docker group
                    sudo usermod -aG docker $USER
                    ;;
            esac
            ;;
        "macos")
            print_warning "Please install Docker Desktop for Mac from https://www.docker.com/products/docker-desktop"
            print_warning "After installation, run this script again"
            return
            ;;
    esac

    print_status "Docker installed successfully ✅"
    print_warning "You may need to log out and log back in for Docker group changes to take effect"
}

# Install development tools
install_dev_tools() {
    print_status "Installing development tools..."

    # Go tools
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    go install github.com/cosmtrek/air@latest
    go install github.com/pressly/goose/v3/cmd/goose@latest

    # Atlas CLI for database migrations
    case "$OS" in
        "linux")
            curl -sSf https://atlasgo.sh | sh
            ;;
        "macos")
            brew install ariga/tap/atlas
            ;;
    esac

    print_status "Development tools installed successfully ✅"
}

# Setup Docker containers
setup_docker_containers() {
    print_status "Setting up Docker containers..."

    # Create docker-compose.yml if it doesn't exist
    if [ ! -f docker-compose.yml ]; then
        cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15
    container_name: frank-postgres
    environment:
      POSTGRES_DB: frank_auth
      POSTGRES_USER: frank
      POSTGRES_PASSWORD: frank_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U frank -d frank_auth"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: frank-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  mailhog:
    image: mailhog/mailhog:latest
    container_name: frank-mailhog
    ports:
      - "1025:1025"  # SMTP
      - "8025:8025"  # Web UI
    logging:
      driver: none

volumes:
  postgres_data:
  redis_data:
EOF
        print_status "Created docker-compose.yml"
    fi

    # Start containers
    docker-compose up -d

    print_status "Docker containers started successfully ✅"
    print_info "PostgreSQL: localhost:5432 (user: frank, password: frank_password, db: frank_auth)"
    print_info "Redis: localhost:6379"
    print_info "MailHog UI: http://localhost:8025"
}

# Fix script permissions
fix_permissions() {
    print_status "Fixing script permissions..."

    # Make all scripts executable
    chmod +x scripts/*.sh 2>/dev/null || true
    chmod +x dev.sh 2>/dev/null || true
    chmod +x build.sh 2>/dev/null || true
    chmod +x setup.sh 2>/dev/null || true

    print_status "Script permissions fixed ✅"
}

# Setup project dependencies
setup_project() {
    print_status "Setting up project dependencies..."

    # Backend dependencies
    if [ -f go.mod ]; then
        go mod download
        go mod tidy
    else
        print_warning "go.mod not found. Initializing Go module..."
        go mod init frank-auth
    fi

    # Frontend dependencies
    if [ -d web ]; then
        cd web
        pnpm install
        cd ..
    else
        print_warning "web directory not found. Skipping frontend setup."
    fi

    print_status "Project dependencies installed ✅"
}

# Create environment and configuration files
create_env_files() {
    print_status "Creating environment and configuration files..."

    # Backend .env
    if [ ! -f .env ]; then
        cat > .env << 'EOF'
# Database
DATABASE_URL=postgres://frank:frank_password@localhost:5432/frank_auth?sslmode=disable

# Redis
REDIS_URL=redis://localhost:6379

# Server
PORT=8998
HOST=localhost
DEBUG=true

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# Email (using MailHog for development)
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=noreply@frankauth.dev

# OAuth Providers (configure as needed)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
EOF
        print_status "Created .env file"
    fi

    # Frontend .env.local
    if [ -d web ] && [ ! -f web/.env.local ]; then
        cat > web/.env.local << 'EOF'
NEXT_PUBLIC_API_URL=http://localhost:8998
NEXT_PUBLIC_APP_URL=http://localhost:3000
EOF
        print_status "Created web/.env.local file"
    fi

    # Air configuration for live reload
    if [ ! -f .air.toml ]; then
        cat > .air.toml << 'EOF'
# .air.toml - Air configuration for live reload
root = "."
testdata_dir = "testdata"
tmp_dir = "tmp"

[build]
  args_bin = []
  bin = "./tmp/main"
  cmd = "go build -o ./tmp/main ./cmd/server/main.go"
  delay = 1000
  exclude_dir = ["assets", "tmp", "vendor", "testdata", "web", "dist", "node_modules", ".git", ".vscode", ".idea"]
  exclude_file = []
  exclude_regex = ["_test.go"]
  exclude_unchanged = false
  follow_symlink = false
  full_bin = ""
  include_dir = []
  include_ext = ["go", "tpl", "tmpl", "html", "yaml", "yml", "json"]
  include_file = []
  kill_delay = "0s"
  log = "build-errors.log"
  poll = false
  poll_interval = 0
  rerun = false
  rerun_delay = 500
  send_interrupt = false
  stop_on_root = false

[color]
  app = ""
  build = "yellow"
  main = "magenta"
  runner = "green"
  watcher = "cyan"

[log]
  main_only = false
  time = false

[misc]
  clean_on_exit = false

[screen]
  clear_on_rebuild = true
  keep_scroll = true
EOF
        print_status "Created .air.toml file"
    fi

    # Air test configuration
    if [ ! -f .air.test.toml ]; then
        cat > .air.test.toml << 'EOF'
# .air.test.toml - Air configuration for test watching
root = "."
testdata_dir = "testdata"
tmp_dir = "tmp"

[build]
  args_bin = []
  bin = ""
  cmd = "go test -v ./..."
  delay = 1000
  exclude_dir = ["assets", "tmp", "vendor", "testdata", "web", "dist", "node_modules", ".git", ".vscode", ".idea"]
  exclude_file = []
  exclude_regex = []
  exclude_unchanged = false
  follow_symlink = false
  full_bin = ""
  include_dir = []
  include_ext = ["go"]
  include_file = []
  kill_delay = "0s"
  log = "test-errors.log"
  poll = false
  poll_interval = 0
  rerun = false
  rerun_delay = 500
  send_interrupt = false
  stop_on_root = false

[color]
  app = ""
  build = "yellow"
  main = "magenta"
  runner = "green"
  watcher = "cyan"

[log]
  main_only = false
  time = true

[misc]
  clean_on_exit = false

[screen]
  clear_on_rebuild = true
  keep_scroll = false
EOF
        print_status "Created .air.test.toml file"
    fi

    # Create tmp directory for air
    mkdir -p tmp
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."

    local failed=0

    # Check Go
    if command -v go &> /dev/null; then
        print_info "✅ Go: $(go version | cut -d' ' -f3)"
    else
        print_error "❌ Go not found"
        failed=1
    fi

    # Check Node.js
    if command -v node &> /dev/null; then
        print_info "✅ Node.js: $(node --version)"
    else
        print_error "❌ Node.js not found"
        failed=1
    fi

    # Check pnpm
    if command -v pnpm &> /dev/null; then
        print_info "✅ pnpm: $(pnpm --version)"
    else
        print_error "❌ pnpm not found"
        failed=1
    fi

    # Check Docker
    if command -v docker &> /dev/null; then
        print_info "✅ Docker: $(docker --version | cut -d' ' -f3 | cut -d',' -f1)"
    else
        print_error "❌ Docker not found"
        failed=1
    fi

    # Check Atlas
    if command -v atlas &> /dev/null; then
        print_info "✅ Atlas: $(atlas version)"
    else
        print_error "❌ Atlas not found"
        failed=1
    fi

    # Check Docker containers
    if docker-compose ps | grep -q "Up"; then
        print_info "✅ Docker containers are running"
    else
        print_warning "⚠️  Some Docker containers may not be running"
    fi

    if [ $failed -eq 0 ]; then
        print_status "All dependencies installed successfully! 🎉"
    else
        print_error "Some dependencies failed to install. Please check the errors above."
        exit 1
    fi
}

# Display next steps
show_next_steps() {
    echo ""
    echo "🎉 Setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Review and update .env files with your configuration"
    echo "2. Run database migrations: make migrate-up"
    echo "3. Start development with live reload: make dev"
    echo ""
    echo "Available commands:"
    echo "  make help          - Show all available commands"
    echo "  make dev           - Start full development environment with live reload"
    echo "  make dev-backend   - Start only backend with live reload"
    echo "  make dev-frontend  - Start only frontend with live reload"
    echo "  make test          - Run all tests"
    echo "  make test-watch    - Run tests in watch mode"
    echo "  make build         - Build for production"
    echo "  make stop          - Stop all development processes"
    echo ""
    echo "Services:"
    echo "  PostgreSQL:   localhost:5432"
    echo "  Redis:        localhost:6379"
    echo "  MailHog UI:   http://localhost:8025"
    echo "  Backend API:  http://localhost:8998 (with live reload)"
    echo "  Frontend:     http://localhost:3000 (with live reload)"
    echo ""
    echo "🔄 Live reload features:"
    echo "  - Backend: Automatically rebuilds and restarts on Go file changes"
    echo "  - Frontend: Hot module replacement for instant updates"
    echo "  - Tests: Run 'make test-watch' for continuous testing"
    echo ""
    echo "If you're on Linux, you may need to log out and log back in for Docker group changes to take effect."
}

# Main setup function
main() {
    echo "🚀 Setting up Frank Auth development environment..."
    echo ""

    detect_os
    install_system_deps
    install_go
    install_nodejs
    install_docker
    install_dev_tools
    fix_permissions
    setup_docker_containers
    setup_project
    create_env_files
    verify_installation
    show_next_steps
}

# Run if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi