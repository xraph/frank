#!/bin/bash
# scripts/dev.sh - Enhanced development workflow script with Docker and migration support

set -e

echo "🚀 Starting Frank Auth development environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
DOCKER_COMPOSE_FILE="${DOCKER_COMPOSE_FILE:-docker-compose.yml}"
DOCKER_COMPOSE_DEV_FILE="${DOCKER_COMPOSE_DEV_FILE:-docker-compose.dev.yml}"
SKIP_DOCKER="${SKIP_DOCKER:-false}"
SKIP_MIGRATION="${SKIP_MIGRATION:-false}"
SKIP_FRONTEND="${SKIP_FRONTEND:-false}"
AUTO_MIGRATE="${AUTO_MIGRATE:-true}"
ENVIRONMENT="${ENVIRONMENT:-development}"

# Service health check timeouts
POSTGRES_TIMEOUT=30
REDIS_TIMEOUT=15
SERVICE_CHECK_INTERVAL=2

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[DEV]${NC} $1"
}

print_docker() {
    echo -e "${PURPLE}[DOCKER]${NC} $1"
}

print_migration() {
    echo -e "${CYAN}[MIGRATE]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Frank Auth Development Script

Usage: $0 [options]

Options:
  --skip-docker          Skip Docker container management
  --skip-migration       Skip database migrations
  --skip-frontend        Skip frontend development server
  --no-auto-migrate      Don't automatically run migrations
  --env ENV             Environment (development|testing|staging)
  --compose-file FILE   Docker Compose file to use
  --help                Show this help message

Environment Variables:
  SKIP_DOCKER           Skip Docker container management (true/false)
  SKIP_MIGRATION        Skip database migrations (true/false)
  SKIP_FRONTEND         Skip frontend development server (true/false)
  AUTO_MIGRATE          Automatically run migrations (true/false)
  ENVIRONMENT           Environment (development|testing|staging)
  DOCKER_COMPOSE_FILE   Docker Compose file to use

Examples:
  $0                              # Full development setup
  $0 --skip-docker               # Skip Docker, use external services
  $0 --skip-frontend             # Backend only
  $0 --env testing               # Use testing environment
  $0 --no-auto-migrate           # Don't run migrations automatically

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-docker)
                SKIP_DOCKER=true
                shift
                ;;
            --skip-migration)
                SKIP_MIGRATION=true
                shift
                ;;
            --skip-frontend)
                SKIP_FRONTEND=true
                shift
                ;;
            --no-auto-migrate)
                AUTO_MIGRATE=false
                shift
                ;;
            --env)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --compose-file)
                DOCKER_COMPOSE_FILE="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Check if required tools are installed
check_dependencies() {
    print_status "Checking dependencies..."

    # Check Go
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed. Please install Go 1.21+ from https://golang.org/dl/"
        exit 1
    fi

    # Verify Go version
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ $(echo "$GO_VERSION 1.21" | tr " " "\n" | sort -V | head -n1) != "1.21" ]]; then
        print_warning "Go version $GO_VERSION detected. Recommended: 1.21+"
    fi

    # Check Node.js if frontend is enabled
    if [[ "$SKIP_FRONTEND" != "true" ]]; then
        if ! command -v node &> /dev/null; then
            print_error "Node.js is not installed. Please install Node.js 18+ from https://nodejs.org/"
            exit 1
        fi

        # Verify Node.js version
        NODE_VERSION=$(node --version | sed 's/v//')
        if [[ $(echo "$NODE_VERSION 18.0.0" | tr " " "\n" | sort -V | head -n1) != "18.0.0" ]]; then
            print_warning "Node.js version $NODE_VERSION detected. Recommended: 18+"
        fi

        # Check pnpm
        if ! command -v pnpm &> /dev/null; then
            print_info "pnpm is not installed. Installing pnpm..."
            npm install -g pnpm
        fi
    fi

    # Check Docker if not skipped
    if [[ "$SKIP_DOCKER" != "true" ]]; then
        if ! command -v docker &> /dev/null; then
            print_error "Docker is not installed. Please install Docker from https://docker.com/"
            print_info "Or use --skip-docker to use external services"
            exit 1
        fi

        if ! command -v docker-compose &> /dev/null; then
            print_error "Docker Compose is not installed."
            exit 1
        fi

        # Check if Docker daemon is running
        if ! docker info &> /dev/null; then
            print_error "Docker daemon is not running. Please start Docker."
            exit 1
        fi
    fi

    # Check air for live reload
    if ! command -v air &> /dev/null; then
        print_info "Air not found. Installing air for live reload..."
        go install github.com/cosmtrek/air@latest
    fi

    print_status "All dependencies are installed ✅"
}

# Setup frontend dependencies
setup_frontend() {
    if [[ "$SKIP_FRONTEND" == "true" ]]; then
        print_info "Skipping frontend setup"
        return
    fi

    print_status "Setting up frontend dependencies..."

    if [ ! -d "web" ]; then
        print_warning "web directory not found. Skipping frontend setup."
        SKIP_FRONTEND=true
        return
    fi

    cd web

    # Install dependencies if needed
    if [ ! -d "node_modules" ] || [ ! -f "pnpm-lock.yaml" ]; then
        print_info "Installing frontend dependencies..."
        pnpm install
    else
        print_info "Frontend dependencies already installed"
    fi

    cd ..

    print_status "Frontend dependencies ready ✅"
}

# Setup backend dependencies
setup_backend() {
    print_status "Setting up backend dependencies..."

    # Download and tidy Go modules
    go mod download
    go mod tidy

    # Create necessary directories
    mkdir -p tmp
    mkdir -p logs
    mkdir -p bin

    # Build migration tool if needed
    if [ ! -f "bin/frank-migrate" ]; then
        print_info "Building migration tool..."
        go build -o bin/frank-migrate ./cmd/migrate
    fi

    print_status "Backend dependencies ready ✅"
}

# Check and start Docker services
manage_docker_services() {
    if [[ "$SKIP_DOCKER" == "true" ]]; then
        print_info "Skipping Docker service management"
        return
    fi

    print_docker "Managing Docker services..."

    # Check if compose file exists
    if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
        print_warning "Docker Compose file not found: $DOCKER_COMPOSE_FILE"
        print_info "Creating basic docker-compose.yml..."
        create_basic_compose_file
    fi

    # Check if services are already running
    if docker-compose -f "$DOCKER_COMPOSE_FILE" ps | grep -q "Up"; then
        print_docker "Some services are already running"
        print_info "Checking service health..."
    else
        print_docker "Starting Docker services..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" up -d
    fi

    # Wait for services to be ready
    wait_for_services

    print_docker "Docker services are ready ✅"
}

# Create a basic docker-compose file if it doesn't exist
create_basic_compose_file() {
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: frank_postgres
    environment:
      POSTGRES_DB: frank
      POSTGRES_USER: frank
      POSTGRES_PASSWORD: frank
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U frank -d frank"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: frank_redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  mailhog:
    image: mailhog/mailhog:latest
    container_name: frank_mailhog
    ports:
      - "1025:1025"  # SMTP server
      - "8025:8025"  # Web UI
    environment:
      MH_STORAGE: maildir
      MH_MAILDIR_PATH: /maildir

volumes:
  postgres_data:
  redis_data:

networks:
  default:
    name: frank_network
EOF

    print_docker "Created basic docker-compose.yml"
}

# Wait for Docker services to be ready
wait_for_services() {
    print_docker "Waiting for services to be ready..."

    # Check PostgreSQL
    if docker-compose -f "$DOCKER_COMPOSE_FILE" ps postgres &> /dev/null; then
        print_info "Waiting for PostgreSQL..."
        local postgres_ready=false
        local count=0

        while [ $count -lt $POSTGRES_TIMEOUT ] && [ "$postgres_ready" = false ]; do
            if docker-compose -f "$DOCKER_COMPOSE_FILE" exec -T postgres pg_isready -U frank -d frank &> /dev/null; then
                postgres_ready=true
                print_docker "PostgreSQL is ready ✅"
            else
                sleep $SERVICE_CHECK_INTERVAL
                count=$((count + SERVICE_CHECK_INTERVAL))
                echo -n "."
            fi
        done

        if [ "$postgres_ready" = false ]; then
            print_error "PostgreSQL failed to start within ${POSTGRES_TIMEOUT}s"
            exit 1
        fi
    fi

    # Check Redis
    if docker-compose -f "$DOCKER_COMPOSE_FILE" ps redis &> /dev/null; then
        print_info "Waiting for Redis..."
        local redis_ready=false
        local count=0

        while [ $count -lt $REDIS_TIMEOUT ] && [ "$redis_ready" = false ]; do
            if docker-compose -f "$DOCKER_COMPOSE_FILE" exec -T redis redis-cli ping &> /dev/null; then
                redis_ready=true
                print_docker "Redis is ready ✅"
            else
                sleep $SERVICE_CHECK_INTERVAL
                count=$((count + SERVICE_CHECK_INTERVAL))
                echo -n "."
            fi
        done

        if [ "$redis_ready" = false ]; then
            print_error "Redis failed to start within ${REDIS_TIMEOUT}s"
            exit 1
        fi
    fi

    # Check MailHog
    if docker-compose -f "$DOCKER_COMPOSE_FILE" ps mailhog &> /dev/null; then
        print_docker "MailHog is ready ✅"
    fi
}

# Run database migrations
run_migrations() {
    if [[ "$SKIP_MIGRATION" == "true" ]]; then
        print_info "Skipping database migrations"
        return
    fi

    if [[ "$AUTO_MIGRATE" != "true" ]]; then
        print_info "Auto-migration disabled"
        return
    fi

    print_migration "Running database migrations..."

    # Check if migration tool exists
    if [ ! -f "bin/frank-migrate" ]; then
        print_error "Migration tool not found. Run 'make build-migrate' first."
        return 1
    fi

    # Run migrations using our migration tool
    if ./bin/frank-migrate --env "$ENVIRONMENT" migrate; then
        print_migration "Migrations completed successfully ✅"
    else
        print_error "Migration failed"
        print_info "You can run migrations manually with: make migrate-up"
        return 1
    fi

    # Check if database needs seeding
    if ./bin/frank-migrate --env "$ENVIRONMENT" status | grep -q "Current Version: No migrations applied"; then
        print_migration "Database appears to be empty. Running seed data..."
        if ./bin/frank-migrate --env "$ENVIRONMENT" seed; then
            print_migration "Database seeded successfully ✅"
        else
            print_warning "Database seeding failed"
        fi
    fi
}

# Start development servers
start_dev_servers() {
    print_status "Starting development servers with live reload..."

    # Start frontend in background if enabled
    if [[ "$SKIP_FRONTEND" != "true" ]] && [ -d "web" ]; then
        print_info "Starting frontend development server..."
        cd web
        pnpm dev &
        FRONTEND_PID=$!
        cd ..

        # Store PID for cleanup
        echo $FRONTEND_PID > .frontend.pid
        print_status "Frontend server started with live reload ✅"
        print_info "Frontend: http://localhost:3000"
    else
        print_info "Frontend server skipped"
    fi

    # Wait a moment for frontend to start
    sleep 3

    # Start backend with Air for live reload
    print_info "Starting backend development server with live reload..."

    # Set environment variables for backend
    export ENVIRONMENT="$ENVIRONMENT"
    export LOG_LEVEL="debug"

    air -c .air.toml &
    BACKEND_PID=$!

    # Store PID for cleanup
    echo $BACKEND_PID > .backend.pid

    print_status "Development servers started with live reload! 🎉"
    print_info "Backend API: http://localhost:8998"
    print_info "API Docs: http://localhost:8998/docs"
    print_info "Health Check: http://localhost:8998/health"

    if [[ "$SKIP_FRONTEND" != "true" ]] && [ -d "web" ]; then
        print_info "Frontend: http://localhost:3000"
    fi

    if [[ "$SKIP_DOCKER" != "true" ]]; then
        print_info "MailHog UI: http://localhost:8025 (email testing)"
    fi

    echo ""
    print_status "🔄 Live reload is active - changes will be automatically detected!"
    print_info "📊 Logs are saved to logs/ directory"
    print_info "🗄️  Database: postgresql://frank:frank@localhost:5432/frank"
    print_info "💡 Press Ctrl+C to stop all servers"
    echo ""

    # Show helpful commands
    show_dev_commands

    # Wait for interrupt
    trap cleanup INT TERM
    wait
}

# Show helpful development commands
show_dev_commands() {
    echo -e "${BLUE}📋 Helpful Development Commands:${NC}"
    echo ""
    echo "  Migration Commands:"
    echo "    make migrate-status           # Check migration status"
    echo "    make migrate-create name=...  # Create new migration"
    echo "    make migrate-up               # Apply pending migrations"
    echo "    make migrate-seed             # Seed database"
    echo ""
    echo "  Database Commands:"
    echo "    make db-console               # Open database console"
    echo "    make db-backup                # Create database backup"
    echo ""
    echo "  Development Commands:"
    echo "    make logs                     # Show application logs"
    echo "    make test                     # Run tests"
    echo "    make lint                     # Run linting"
    echo ""
    echo "  Docker Commands:"
    echo "    docker-compose logs -f        # Show Docker logs"
    echo "    docker-compose restart        # Restart services"
    echo ""
}

# Enhanced cleanup function
cleanup() {
    print_status "Shutting down development servers..."

    # Kill frontend
    if [ -f .frontend.pid ]; then
        local frontend_pid=$(cat .frontend.pid)
        if kill -0 $frontend_pid 2>/dev/null; then
            kill $frontend_pid 2>/dev/null || true
            print_info "Frontend server stopped"
        fi
        rm -f .frontend.pid
    fi

    # Kill backend (air process)
    if [ -f .backend.pid ]; then
        local backend_pid=$(cat .backend.pid)
        if kill -0 $backend_pid 2>/dev/null; then
            kill $backend_pid 2>/dev/null || true
            print_info "Backend server stopped"
        fi
        rm -f .backend.pid
    fi

    # Kill any remaining processes
    pkill -f "air" 2>/dev/null || true
    pkill -f "go run.*cmd/frank" 2>/dev/null || true
    pkill -f "pnpm dev" 2>/dev/null || true
    pkill -f "next dev" 2>/dev/null || true

    # Clean up tmp directory
    rm -rf tmp/main 2>/dev/null || true

    # Optionally stop Docker services
    if [[ "$SKIP_DOCKER" != "true" ]]; then
        echo ""
        read -p "Stop Docker services? (y/N): " -t 5 stop_docker || stop_docker="N"
        if [[ "$stop_docker" =~ ^[Yy]$ ]]; then
            print_docker "Stopping Docker services..."
            docker-compose -f "$DOCKER_COMPOSE_FILE" stop
            print_docker "Docker services stopped"
        else
            print_info "Docker services left running"
        fi
    fi

    print_status "Development environment stopped ✅"
    exit 0
}

# Show development environment info
show_dev_info() {
    echo ""
    print_info "🛠️  Development Environment Info:"
    print_info "Environment: $ENVIRONMENT"
    print_info "Go version: $(go version | cut -d' ' -f3)"

    if [[ "$SKIP_FRONTEND" != "true" ]] && command -v node &> /dev/null; then
        print_info "Node.js version: $(node --version)"
    fi

    if [[ "$SKIP_FRONTEND" != "true" ]] && command -v pnpm &> /dev/null; then
        print_info "pnpm version: $(pnpm --version)"
    fi

    if command -v air &> /dev/null; then
        print_info "Air version: $(air -v 2>/dev/null | head -n1 || echo 'installed')"
    fi

    if [[ "$SKIP_DOCKER" != "true" ]]; then
        print_info "Docker version: $(docker --version | cut -d' ' -f3 | sed 's/,//')"
        print_info "Docker Compose file: $DOCKER_COMPOSE_FILE"
    fi

    print_info "Auto-migrate: $AUTO_MIGRATE"
    print_info "Skip Docker: $SKIP_DOCKER"
    print_info "Skip Frontend: $SKIP_FRONTEND"
    print_info "Skip Migration: $SKIP_MIGRATION"
    echo ""
}

# Health check for services
health_check() {
    print_status "Running health checks..."

    local all_healthy=true

    # Check backend health
    if curl -s http://localhost:8998/health &> /dev/null; then
        print_status "Backend: Healthy ✅"
    else
        print_warning "Backend: Not responding ❌"
        all_healthy=false
    fi

    # Check frontend health
    if [[ "$SKIP_FRONTEND" != "true" ]] && curl -s http://localhost:3000 &> /dev/null; then
        print_status "Frontend: Healthy ✅"
    elif [[ "$SKIP_FRONTEND" != "true" ]]; then
        print_warning "Frontend: Not responding ❌"
        all_healthy=false
    fi

    # Check Docker services
    if [[ "$SKIP_DOCKER" != "true" ]]; then
        if docker-compose -f "$DOCKER_COMPOSE_FILE" ps | grep -q "Up"; then
            print_status "Docker Services: Running ✅"
        else
            print_warning "Docker Services: Not all running ❌"
            all_healthy=false
        fi
    fi

    if [ "$all_healthy" = true ]; then
        print_status "All services are healthy! 🎉"
    else
        print_warning "Some services may need attention"
    fi
}

# Main execution
main() {
    parse_args "$@"
    check_dependencies
    setup_backend
    setup_frontend
    manage_docker_services
    run_migrations
    show_dev_info
    start_dev_servers
}

# Run if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi