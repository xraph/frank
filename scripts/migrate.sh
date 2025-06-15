#!/bin/bash

# Frank Auth SaaS - Database Migration Script
# This script provides a convenient interface for managing database migrations
# in the Frank Auth SaaS platform, supporting multi-tenant operations.

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MIGRATE_CMD="$PROJECT_ROOT/cmd/migrate"
MIGRATE_BINARY="$PROJECT_ROOT/bin/migrate"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default configuration
DEFAULT_CONFIG_PATH="$PROJECT_ROOT/config/config.yaml"
DEFAULT_TIMEOUT="5m"
DEFAULT_ENV="development"
DEFAULT_MIGRATE_DIR="migrations"

# Global variables
CONFIG_PATH=""
ENVIRONMENT=""
DRY_RUN=false
FORCE=false
VERBOSE=false
TIMEOUT="$DEFAULT_TIMEOUT"
SKIP_CONFIRM=false
BUILD_BINARY=true
DOCKER_MODE=false
DOCKER_COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"
MIGRATE_DIR="$DEFAULT_MIGRATE_DIR"

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ ${1}${NC}"
}

print_success() {
    echo -e "${GREEN}✓ ${1}${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ ${1}${NC}"
}

print_error() {
    echo -e "${RED}✗ ${1}${NC}" >&2
}

print_header() {
    echo -e "${PURPLE}================================${NC}"
    echo -e "${PURPLE} Frank Auth SaaS - Migration${NC}"
    echo -e "${PURPLE}================================${NC}"
}

# Function to show usage
show_usage() {
    cat << EOF
Frank Auth SaaS - Database Migration Script

Usage: $0 [options] <command> [command-options]

COMMANDS:
  migrate         Apply pending migrations
  rollback        Rollback applied migrations
  status          Show migration status
  create          Create a new migration file (uses entgo generator)
  seed            Seed database with initial data
  reset           Reset database (DANGEROUS)
  validate        Validate database schema
  version         Show current migration version
  force-unlock    Remove migration lock
  drop            Drop all database tables
  build           Build migration binary
  docker-migrate  Run migrations in Docker
  help            Show this help message

GLOBAL OPTIONS:
  -c, --config PATH        Configuration file path
  -e, --env ENV           Environment (development|staging|production)
  -d, --dry-run           Show what would be done without executing
  -f, --force             Force the operation
  -v, --verbose           Enable verbose logging
  -t, --timeout DURATION  Operation timeout (default: 5m)
  -y, --yes               Skip confirmation prompts
  -h, --help              Show this help message
      --no-build          Skip building migration binary
      --docker            Use Docker for migrations
      --docker-compose FILE  Docker compose file path
      --migrate-dir PATH  Migration directory path

MIGRATION OPTIONS:
      --version VERSION   Target migration version
      --steps N           Number of rollback steps
      --name NAME         Migration name (for create)
      --seed-file PATH    Seed data file path
      --tenant ID         Tenant ID for tenant-specific operations
      --migrate-dir PATH  Migration directory path (default: migrations)

EXAMPLES:
  # Apply all pending migrations
  $0 migrate

  # Create a new migration (uses entgo generator)
  $0 create --name "add_user_preferences"
  # This will run: go run -mod=mod ent/migrate/main.go add_user_preferences

  # Check migration status
  $0 status

  # Rollback last 3 migrations with confirmation
  $0 rollback --steps 3

  # Migrate to specific version
  $0 migrate --version 20231201120000

  # Run migrations in staging environment
  $0 -e staging migrate

  # Dry run to see what would happen
  $0 -d migrate

  # Run migrations using Docker
  $0 --docker migrate

  # Reset database (with confirmation)
  $0 reset

  # Seed database with default data
  $0 seed

  # Drop all tables (DANGEROUS)
  $0 drop

  # Show current migration version
  $0 version

ENVIRONMENT VARIABLES:
  FRANK_CONFIG_PATH       Configuration file path
  FRANK_ENVIRONMENT       Application environment
  DATABASE_URL            Database connection string
  DOCKER_BUILDKIT         Enable Docker BuildKit (recommended)

MIGRATION SYSTEM:
  This tool uses entgo's versioned migrations with Atlas support.
  Migration files are stored in migrations/ in golang-migrate format.
  Use 'create' command to generate new migrations using entgo's Atlas integration.

EOF
}

# Function to parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--config)
                CONFIG_PATH="$2"
                shift 2
                ;;
            -e|--env)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -y|--yes)
                SKIP_CONFIRM=true
                shift
                ;;
            --no-build)
                BUILD_BINARY=false
                shift
                ;;
            --docker)
                DOCKER_MODE=true
                BUILD_BINARY=false
                shift
                ;;
            --docker-compose)
                DOCKER_COMPOSE_FILE="$2"
                shift 2
                ;;
            --migrate-dir)
                MIGRATE_DIR="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                # Unknown option, pass to command
                break
                ;;
        esac
    done

    # Set defaults
    if [[ -z "$CONFIG_PATH" ]]; then
        CONFIG_PATH="${FRANK_CONFIG_PATH:-$DEFAULT_CONFIG_PATH}"
    fi

    if [[ -z "$ENVIRONMENT" ]]; then
        ENVIRONMENT="${FRANK_ENVIRONMENT:-$DEFAULT_ENV}"
    fi

    # Remaining arguments are the command and its options
    COMMAND_ARGS=("$@")
}

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."

    # Check if Go is installed (for building)
    if [[ "$BUILD_BINARY" == true ]] && ! command -v go &> /dev/null; then
        print_error "Go is not installed or not in PATH"
        exit 1
    fi

    # Check if Docker is available (for Docker mode)
    if [[ "$DOCKER_MODE" == true ]] && ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi

    # Check if project root exists
    if [[ ! -d "$PROJECT_ROOT" ]]; then
        print_error "Project root directory not found: $PROJECT_ROOT"
        exit 1
    fi

    # Check if config file exists
    if [[ ! -f "$CONFIG_PATH" ]] && [[ "$DOCKER_MODE" == false ]]; then
        print_warning "Configuration file not found: $CONFIG_PATH"
        print_info "Will use environment variables for configuration"
    fi

    print_success "Prerequisites check passed"
}

# Function to build migration binary
build_migration_binary() {
    if [[ "$BUILD_BINARY" == false ]]; then
        return 0
    fi

    print_info "Building migration binary..."

    local binary_dir="$PROJECT_ROOT/bin"
    mkdir -p "$binary_dir"

    # Build the migration binary
    cd "$PROJECT_ROOT"
    if ! go build -o "$MIGRATE_BINARY" ./cmd/migrate; then
        print_error "Failed to build migration binary"
        exit 1
    fi

    print_success "Migration binary built successfully"
}

# Function to run migration command
run_migration_command() {
    local cmd_args=()

    # Add global flags
    if [[ -n "$CONFIG_PATH" ]] && [[ -f "$CONFIG_PATH" ]]; then
        cmd_args+=("--config" "$CONFIG_PATH")
    fi

    if [[ -n "$ENVIRONMENT" ]]; then
        cmd_args+=("--env" "$ENVIRONMENT")
    fi

    if [[ "$DRY_RUN" == true ]]; then
        cmd_args+=("--dry-run")
    fi

    if [[ "$FORCE" == true ]]; then
        cmd_args+=("--force")
    fi

    if [[ "$VERBOSE" == true ]]; then
        cmd_args+=("--verbose")
    fi

    if [[ -n "$TIMEOUT" ]]; then
        cmd_args+=("--timeout" "$TIMEOUT")
    fi

    if [[ "$SKIP_CONFIRM" == true ]]; then
        cmd_args+=("--yes")
    fi

    if [[ -n "$MIGRATE_DIR" ]]; then
        cmd_args+=("--migrate-dir" "$MIGRATE_DIR")
    fi

    # Add command and its arguments
    cmd_args+=("${COMMAND_ARGS[@]}")

    # Execute the command
    print_info "Executing migration command: ${cmd_args[*]}"

    if [[ "$DOCKER_MODE" == true ]]; then
        run_docker_migration "${cmd_args[@]}"
    else
        "$MIGRATE_BINARY" "${cmd_args[@]}"
    fi
}

# Function to run migration in Docker
run_docker_migration() {
    print_info "Running migration in Docker..."

    # Check if docker-compose file exists
    if [[ ! -f "$DOCKER_COMPOSE_FILE" ]]; then
        print_error "Docker Compose file not found: $DOCKER_COMPOSE_FILE"
        exit 1
    fi

    # Build and run migration in Docker
    local docker_args=(
        "run"
        "--rm"
        "-v" "$PROJECT_ROOT:/app"
        "-w" "/app"
        "--network" "host"
    )

    # Add environment variables
    if [[ -n "$ENVIRONMENT" ]]; then
        docker_args+=("-e" "ENVIRONMENT=$ENVIRONMENT")
    fi

    # Use project's Go image or build one
    docker_args+=("golang:1.21-alpine")
    docker_args+=("sh" "-c" "go build -o /tmp/migrate ./cmd/migrate && /tmp/migrate $*")

    docker "${docker_args[@]}"
}

# Function to handle specific commands
handle_command() {
    local command="${COMMAND_ARGS[0]:-}"

    case "$command" in
        "build")
            print_header
            build_migration_binary
            print_success "Build completed successfully"
            ;;
        "docker-migrate")
            print_header
            DOCKER_MODE=true
            BUILD_BINARY=false
            # Remove 'docker-migrate' from args and run migrate
            COMMAND_ARGS=("migrate" "${COMMAND_ARGS[@]:1}")
            check_prerequisites
            run_migration_command
            ;;
        "migrate"|"rollback"|"status"|"create"|"seed"|"reset"|"validate"|"version"|"force-unlock"|"drop")
            print_header
            check_prerequisites
            build_migration_binary
            run_migration_command
            print_success "Migration operation completed successfully"
            ;;
        "help"|"")
            show_usage
            ;;
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Function to handle cleanup
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        print_error "Migration script failed with exit code $exit_code"
    fi
    exit $exit_code
}

# Function to handle interruption
handle_interrupt() {
    print_warning "Migration interrupted by user"
    exit 130
}

# Main execution
main() {
    # Set up signal handlers
    trap cleanup EXIT
    trap handle_interrupt INT TERM

    # Parse command line arguments
    parse_args "$@"

    # Handle the command
    handle_command
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi