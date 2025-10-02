#!/bin/bash

# Wakflo SaaS - Enhanced Database Migration Script with Synchronization Support
# This script provides a comprehensive interface for managing database migrations
# in the Wakflo SaaS platform, supporting multi-tenant operations and state synchronization.

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
BOLD='\033[1m'
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
OUTPUT_FORMAT="text"

# Function to print colored output with enhanced formatting
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
    echo -e "${PURPLE} Wakflo SaaS - Enhanced Migration${NC}"
    echo -e "${PURPLE}================================${NC}"
}

print_sync_header() {
    echo -e "${CYAN}🔄 Migration State Synchronization${NC}"
    echo -e "${CYAN}====================================${NC}"
}

# Function to show enhanced usage
show_usage() {
    cat << EOF
Wakflo SaaS - Enhanced Database Migration Script with Synchronization

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

SYNC COMMANDS:
  sync            Synchronize migration state with database schema
  analyze         Analyze current database state and migration status
  repair          Repair corrupted migration state

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
      --output FORMAT     Output format (text|json)

MIGRATION OPTIONS:
      --version VERSION   Target migration version
      --steps N           Number of rollback steps
      --name NAME         Migration name (for create)
      --seed-file PATH    Seed data file path
      --tenant ID         Tenant ID for tenant-specific operations

SYNC OPTIONS:
      --create-missing    Create missing migration entries during sync
      --update-existing   Update existing migration entries during sync
      --skip-validation   Skip schema validation during sync

EXAMPLES:

  Basic Operations:
    $0 migrate                    # Apply all pending migrations
    $0 create --name "add_users"  # Create new migration
    $0 status                     # Show migration status

  State Synchronization:
    $0 analyze                    # Analyze database state
    $0 --dry-run sync            # Show what sync would do
    $0 --force --create-missing sync  # Force sync with missing entries
    $0 repair                     # Repair corrupted state

  Troubleshooting:
    $0 analyze --output json      # Detailed analysis in JSON
    $0 --force repair            # Force repair without prompts
    $0 --create-missing --update-existing sync  # Complete sync

  Environment-Specific:
    $0 -e staging sync           # Sync in staging environment
    $0 -e production analyze     # Analyze production state

COMMON SCENARIOS:

  🔄 After Migration Format Change:
    1. $0 analyze                 # Check current state
    2. $0 --dry-run sync         # See what would be synced
    3. $0 --create-missing sync  # Apply synchronization

  🏗️  Schema Exists, No Migration History:
    1. $0 analyze                # Understand current state
    2. $0 --force --create-missing sync  # Mark existing as applied

  ⚠️  Corrupted Migration State:
    1. $0 repair                 # Attempt automatic repair
    2. $0 analyze                # Verify repair worked
    3. $0 sync                   # Synchronize if needed

ENVIRONMENT VARIABLES:
  WAKFLO_CONFIG_PATH       Configuration file path
  WAKFLO_ENVIRONMENT       Application environment
  DATABASE_URL            Database connection string
  DOCKER_BUILDKIT         Enable Docker BuildKit (recommended)

For detailed documentation on migration state synchronization, see:
https://docs.wakflo.com/migrations/synchronization

EOF
}

# Enhanced argument parsing with sync options
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
            --output)
                OUTPUT_FORMAT="$2"
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
        CONFIG_PATH="${WAKFLO_CONFIG_PATH:-$DEFAULT_CONFIG_PATH}"
    fi

    if [[ -z "$ENVIRONMENT" ]]; then
        ENVIRONMENT="${WAKFLO_ENVIRONMENT:-$DEFAULT_ENV}"
    fi

    # Remaining arguments are the command and its options
    COMMAND_ARGS=("$@")
}

# Enhanced prerequisite checks
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

    # Check if config file exists (more flexible)
    if [[ ! -f "$CONFIG_PATH" ]] && [[ "$DOCKER_MODE" == false ]]; then
        print_warning "Configuration file not found: $CONFIG_PATH"
        print_info "Will use environment variables for configuration"
    fi

    # Check migration directory
    if [[ ! -d "$PROJECT_ROOT/$MIGRATE_DIR" ]]; then
        print_warning "Migration directory not found: $PROJECT_ROOT/$MIGRATE_DIR"
        print_info "Will create migration directory if needed"
        mkdir -p "$PROJECT_ROOT/$MIGRATE_DIR"
    fi

    print_success "Prerequisites check passed"
}

# Enhanced migration command runner
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

    if [[ -n "$OUTPUT_FORMAT" ]]; then
        cmd_args+=("--output" "$OUTPUT_FORMAT")
    fi

    # Add command and its arguments
    cmd_args+=("${COMMAND_ARGS[@]}")

    # Execute the command
    if [[ "$VERBOSE" == true ]]; then
        print_info "Executing migration command: ${cmd_args[*]}"
    fi

    if [[ "$DOCKER_MODE" == true ]]; then
        run_docker_migration "${cmd_args[@]}"
    else
        "$MIGRATE_BINARY" "${cmd_args[@]}"
    fi
}

# Enhanced command handler with sync support
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
        # Enhanced sync commands
        "sync")
            print_sync_header
            handle_sync_command
            ;;
        "analyze")
            print_header
            echo -e "${CYAN}🔍 Database State Analysis${NC}"
            echo -e "${CYAN}===========================${NC}"
            handle_analyze_command
            ;;
        "repair")
            print_header
            echo -e "${YELLOW}🔧 Migration State Repair${NC}"
            echo -e "${YELLOW}==========================${NC}"
            handle_repair_command
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

# New sync command handlers
handle_sync_command() {
    check_prerequisites
    build_migration_binary

    if [[ "$DRY_RUN" == true ]]; then
        print_info "DRY RUN: Analyzing synchronization plan..."
    else
        print_info "Starting migration state synchronization..."

        if [[ "$FORCE" == false ]] && [[ "$SKIP_CONFIRM" == false ]]; then
            echo
            print_warning "This will synchronize migration state with database schema"
            echo -e "Environment: ${BOLD}$ENVIRONMENT${NC}"
            echo -e "Database Config: ${BOLD}$CONFIG_PATH${NC}"
            echo
            read -p "Continue with synchronization? (y/N): " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                print_info "Synchronization cancelled"
                return 0
            fi
        fi
    fi

    run_migration_command

    if [[ "$DRY_RUN" == false ]]; then
        print_success "Migration state synchronization completed"
        echo
        print_info "💡 Run 'analyze' command to verify the synchronized state"
    else
        echo
        print_info "💡 Run without --dry-run to apply the synchronization plan"
    fi
}

handle_analyze_command() {
    check_prerequisites
    build_migration_binary

    print_info "Analyzing database state and migration history..."

    run_migration_command

    echo
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        print_info "💡 Analysis completed in JSON format"
    else
        print_info "💡 Use --output json for machine-readable analysis"
        print_info "💡 Run 'sync' command if synchronization is needed"
    fi
}

handle_repair_command() {
    check_prerequisites
    build_migration_binary

    if [[ "$FORCE" == false ]] && [[ "$SKIP_CONFIRM" == false ]]; then
        echo
        print_warning "This will attempt to repair corrupted migration state"
        echo "This operation will:"
        echo "  • Clear any dirty migration flags"
        echo "  • Unlock any locked migrations"
        echo "  • Fix inconsistent state entries"
        echo
        echo -e "Environment: ${BOLD}$ENVIRONMENT${NC}"
        echo
        read -p "Continue with repair? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            print_info "Repair cancelled"
            return 0
        fi
    fi

    print_info "Attempting to repair migration state..."

    run_migration_command

    print_success "Migration state repair completed"
    echo
    print_info "💡 Run 'analyze' command to verify the repair was successful"
}

# Enhanced build function
build_migration_binary() {
    if [[ "$BUILD_BINARY" == false ]]; then
        return 0
    fi

    print_info "Building enhanced migration binary..."

    local binary_dir="$PROJECT_ROOT/bin"
    mkdir -p "$binary_dir"

    # Build the migration binary
    cd "$PROJECT_ROOT"
    if ! go build -o "$MIGRATE_BINARY" ./cmd/migrate; then
        print_error "Failed to build migration binary"
        exit 1
    fi

    print_success "Enhanced migration binary built successfully"
}

# Enhanced Docker support
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

# Enhanced cleanup with better error handling
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo
        print_error "Migration script failed with exit code $exit_code"

        # Provide helpful troubleshooting suggestions
        echo
        print_info "Troubleshooting suggestions:"
        echo "  • Check database connection and credentials"
        echo "  • Verify migration files exist and are valid"
        echo "  • Try running 'analyze' command to check database state"
        echo "  • Use 'repair' command if migration state is corrupted"
        echo "  • Run with --verbose flag for detailed output"
        echo
        print_info "For more help: $0 --help"
    fi
    exit $exit_code
}

# Enhanced interrupt handler
handle_interrupt() {
    echo
    print_warning "Migration interrupted by user"
    echo
    print_info "If migration was in progress, you may need to:"
    echo "  • Check migration state with: $0 analyze"
    echo "  • Repair state if needed with: $0 repair"
    exit 130
}

# Main execution with enhanced error handling
main() {
    # Set up signal handlers
    trap cleanup EXIT
    trap handle_interrupt INT TERM

    # Parse command line arguments
    parse_args "$@"

    # Validate environment
    if [[ "$ENVIRONMENT" == "production" ]] && [[ "$FORCE" == false ]] && [[ "$SKIP_CONFIRM" == false ]]; then
        echo
        print_warning "🚨 PRODUCTION ENVIRONMENT DETECTED 🚨"
        echo
        echo "You are about to run migration operations in PRODUCTION!"
        echo "Make sure you have:"
        echo "  ✅ Backed up the database"
        echo "  ✅ Tested the operation in staging"
        echo "  ✅ Analyzed the current state"
        echo "  ✅ Have a rollback plan ready"
        echo
        read -p "Proceed with production operation? Type 'PRODUCTION' to confirm: " confirm
        if [[ "$confirm" != "PRODUCTION" ]]; then
            print_info "Production operation cancelled for safety"
            exit 0
        fi
        echo
    fi

    # Handle the command
    handle_command
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi