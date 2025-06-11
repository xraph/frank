#!/bin/bash
# scripts/dev.sh - Development workflow script with live reload

set -e

echo "🚀 Starting Frank Auth development environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if required tools are installed
check_dependencies() {
    print_status "Checking dependencies..."

    # Check Go
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed. Please install Go 1.21+ from https://golang.org/dl/"
        exit 1
    fi

    # Check Node.js
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed. Please install Node.js 18+ from https://nodejs.org/"
        exit 1
    fi

    # Check pnpm
    if ! command -v pnpm &> /dev/null; then
        print_error "pnpm is not installed. Installing pnpm..."
        npm install -g pnpm
    fi

    # Check air for live reload
    if ! command -v air &> /dev/null; then
        print_warning "Air not found. Installing air for live reload..."
        go install github.com/cosmtrek/air@latest
    fi

    print_status "All dependencies are installed ✅"
}

# Setup frontend dependencies
setup_frontend() {
    print_status "Setting up frontend dependencies..."

    if [ ! -d "web" ]; then
        print_warning "web directory not found. Skipping frontend setup."
        return
    fi

    cd web
    pnpm install
    cd ..

    print_status "Frontend dependencies installed ✅"
}

# Setup backend dependencies
setup_backend() {
    print_status "Setting up backend dependencies..."

    go mod download
    go mod tidy

    # Create tmp directory for air
    mkdir -p tmp

    print_status "Backend dependencies installed ✅"
}

# Check if Docker services are running
check_docker_services() {
    print_status "Checking Docker services..."

    if ! command -v docker &> /dev/null; then
        print_warning "Docker not found. Database services may not be available."
        return
    fi

    if ! docker-compose ps | grep -q "Up"; then
        print_warning "Docker services are not running. Starting them..."
        docker-compose up -d

        # Wait for services to be ready
        print_info "Waiting for services to be ready..."
        sleep 5

        # Check PostgreSQL
        if docker-compose exec -T postgres pg_isready -U frank -d frank_auth &> /dev/null; then
            print_status "PostgreSQL is ready ✅"
        else
            print_warning "PostgreSQL may not be ready yet"
        fi

        # Check Redis
        if docker-compose exec -T redis redis-cli ping &> /dev/null; then
            print_status "Redis is ready ✅"
        else
            print_warning "Redis may not be ready yet"
        fi
    else
        print_status "Docker services are already running ✅"
    fi
}

# Start development servers
start_dev_servers() {
    print_status "Starting development servers with live reload..."

    # Start frontend in background if web directory exists
    if [ -d "web" ]; then
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
        print_warning "web directory not found. Skipping frontend server."
    fi

    # Wait a moment for frontend to start
    sleep 3

    # Start backend with Air for live reload
    print_info "Starting backend development server with live reload..."
    air -c .air.toml &
    BACKEND_PID=$!

    # Store PID for cleanup
    echo $BACKEND_PID > .backend.pid

    print_status "Development servers started with live reload! 🎉"
    print_info "Backend API: http://localhost:8998"
    print_info "Combined: http://localhost:8998 (production-like)"

    if [ -d "web" ]; then
        print_info "Frontend: http://localhost:3000"
    fi

    print_info "MailHog UI: http://localhost:8025 (email testing)"
    echo ""
    print_status "🔄 Live reload is active - changes will be automatically detected!"
    print_info "💡 Press Ctrl+C to stop all servers"
    echo ""

    # Wait for interrupt
    trap cleanup INT TERM
    wait
}

# Enhanced cleanup function
cleanup() {
    print_status "Shutting down development servers..."

    # Kill frontend
    if [ -f .frontend.pid ]; then
        kill $(cat .frontend.pid) 2>/dev/null || true
        rm .frontend.pid
    fi

    # Kill backend (air process)
    if [ -f .backend.pid ]; then
        kill $(cat .backend.pid) 2>/dev/null || true
        rm .backend.pid
    fi

    # Kill any remaining air processes
    pkill -f "air" 2>/dev/null || true
    pkill -f "go run" 2>/dev/null || true

    # Clean up tmp directory
    rm -rf tmp/main 2>/dev/null || true

    print_status "Development servers stopped ✅"
    exit 0
}

# Show development info
show_dev_info() {
    echo ""
    print_info "🛠️  Development Environment Info:"
    print_info "Go version: $(go version | cut -d' ' -f3)"
    if command -v node &> /dev/null; then
        print_info "Node.js version: $(node --version)"
    fi
    if command -v pnpm &> /dev/null; then
        print_info "pnpm version: $(pnpm --version)"
    fi
    if command -v air &> /dev/null; then
        print_info "Air version: $(air -v 2>/dev/null | head -n1 || echo 'installed')"
    fi
    echo ""
}

# Main execution
main() {
    check_dependencies
    setup_backend
    setup_frontend
    check_docker_services
    show_dev_info
    start_dev_servers
}

# Run if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi