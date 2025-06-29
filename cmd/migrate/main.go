// Package main provides a command-line interface for managing database migrations
// in the Frank Auth SaaS platform using entgo's versioned migrations with Atlas support.
// This tool handles entgo schema migrations, data seeding, and database management operations
// for the multi-tenant authentication system.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/database/sqlite3"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/rs/xid"
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/internal/migration"
	"github.com/xraph/frank/pkg/data"
	"github.com/xraph/frank/pkg/logging"
)

const (
	// Migration commands
	cmdMigrate     = "migrate"
	cmdRollback    = "rollback"
	cmdStatus      = "status"
	cmdCreate      = "create"
	cmdSeed        = "seed"
	cmdReset       = "reset"
	cmdValidate    = "validate"
	cmdVersion     = "version"
	cmdForceUnlock = "force-unlock"
	cmdDrop        = "drop"

	// Default timeout for migration operations
	defaultTimeout = 5 * time.Minute

	// Migration directory
	migrationDir = "migrations"
)

// CLI represents the migration command-line interface
type CLI struct {
	config      *config.Config
	logger      logging.Logger
	migrator    *migration.Migrator
	dataClients *data.Clients
	migrate     *migrate.Migrate
}

// Command line flags
var (
	configPath  = flag.String("config", "", "Path to configuration file")
	environment = flag.String("env", "", "Environment (development, staging, production)")
	dryRun      = flag.Bool("dry-run", false, "Show what would be done without executing")
	force       = flag.Bool("force", false, "Force the operation (use with caution)")
	timeout     = flag.Duration("timeout", defaultTimeout, "Timeout for migration operations")
	verbose     = flag.Bool("verbose", false, "Enable verbose logging")
	version     = flag.String("version", "", "Target migration version")
	steps       = flag.Int("steps", 0, "Number of steps to rollback")
	name        = flag.String("name", "", "Name for new migration")
	seedFile    = flag.String("seed-file", "", "Path to seed data file")
	tenantID    = flag.String("tenant", "", "Tenant ID for tenant-specific operations")
	skipConfirm = flag.Bool("yes", false, "Skip confirmation prompts")
	migrateDir  = flag.String("migrate-dir", migrationDir, "Migration directory path")
)

func main() {
	flag.Parse()

	if len(flag.Args()) == 0 {
		printUsage()
		os.Exit(1)
	}

	command := flag.Args()[0]

	// Initialize CLI
	cli, err := newCLI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing CLI: %v\n", err)
		os.Exit(1)
	}
	defer cli.cleanup()

	// Set timeout context
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Execute command
	if err := cli.executeCommand(ctx, command, flag.Args()[1:]); err != nil {
		cli.logger.Error("Command failed", logging.Error(err))
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// newCLI creates a new CLI instance with proper initialization
func newCLI() (*CLI, error) {
	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize logger
	logLevel := cfg.Logging.Level
	if *verbose {
		logLevel = "debug"
	}

	logger := logging.NewLogger(&logging.LoggerConfig{
		Level:       logLevel,
		Environment: cfg.App.Environment,
		// Output:      "stdout",
		// Format:      "text", // Use text format for CLI
	})

	// Initialize data clients
	dataClients := data.NewClients(cfg, logger, nil, nil)
	if dataClients == nil {
		return nil, fmt.Errorf("failed to initialize data clients")
	}

	// Initialize custom migrator for seeding and additional operations
	migrator := migration.NewMigrator(dataClients, logger)

	// Initialize golang-migrate instance
	migrateInstance, err := initializeGolangMigrate(cfg)
	if err != nil {
		logger.Warn("Failed to initialize golang-migrate, some operations may not be available", logging.Error(err))
	}

	return &CLI{
		config:      cfg,
		logger:      logger,
		migrator:    migrator,
		dataClients: dataClients,
		migrate:     migrateInstance,
	}, nil
}

// initializeGolangMigrate initializes the golang-migrate instance
func initializeGolangMigrate(cfg *config.Config) (*migrate.Migrate, error) {
	// Build source URL for migration files
	sourceURL := fmt.Sprintf("file://%s", *migrateDir)

	// Build database URL
	var databaseURL string
	switch cfg.Database.Driver {
	case "postgres":
		if cfg.Database.DSN != "" {
			databaseURL = cfg.Database.DSN
		} else {
			databaseURL = fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
				cfg.Database.User,
				cfg.Database.Password,
				cfg.Database.Host,
				cfg.Database.Port,
				cfg.Database.Database,
				cfg.Database.SSLMode,
			)
		}
	case "mysql":
		if cfg.Database.DSN != "" {
			databaseURL = "mysql://" + cfg.Database.DSN
		} else {
			databaseURL = fmt.Sprintf("mysql://%s:%s@tcp(%s:%d)/%s",
				cfg.Database.User,
				cfg.Database.Password,
				cfg.Database.Host,
				cfg.Database.Port,
				cfg.Database.Database,
			)
		}
	case "sqlite", "sqlite3":
		databaseURL = "sqlite3://" + cfg.Database.Database
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Database.Driver)
	}

	// Create migrate instance
	m, err := migrate.New(sourceURL, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create migrate instance: %w", err)
	}

	return m, nil
}

// loadConfig loads configuration from file or environment
func loadConfig() (*config.Config, error) {
	if *configPath != "" {
		return config.Load(*configPath)
	}

	if *environment != "" {
		os.Setenv("ENVIRONMENT", *environment)
	}

	return config.Load("")
}

// cleanup performs cleanup operations
func (c *CLI) cleanup() {
	if c.migrate != nil {
		sourceErr, databaseErr := c.migrate.Close()
		if sourceErr != nil {
			c.logger.Error("Failed to close migration source", logging.Error(sourceErr))
		}
		if databaseErr != nil {
			c.logger.Error("Failed to close migration database", logging.Error(databaseErr))
		}
	}

	if c.dataClients != nil {
		if err := c.dataClients.Close(); err != nil {
			c.logger.Error("Failed to close data clients", logging.Error(err))
		}
	}
}

// executeCommand executes the specified migration command
func (c *CLI) executeCommand(ctx context.Context, command string, args []string) error {
	switch command {
	case cmdMigrate:
		return c.handleMigrate(ctx)
	case cmdRollback:
		return c.handleRollback(ctx)
	case cmdStatus:
		return c.handleStatus(ctx)
	case cmdCreate:
		return c.handleCreate(ctx)
	case cmdSeed:
		return c.handleSeed(ctx)
	case cmdReset:
		return c.handleReset(ctx)
	case cmdValidate:
		return c.handleValidate(ctx)
	case cmdVersion:
		return c.handleVersion(ctx)
	case cmdForceUnlock:
		return c.handleForceUnlock(ctx)
	case cmdDrop:
		return c.handleDrop(ctx)
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

// handleMigrate handles the migrate command
func (c *CLI) handleMigrate(ctx context.Context) error {
	if c.migrate == nil {
		return fmt.Errorf("migration instance not available")
	}

	c.logger.Info("Starting database migration")

	if *dryRun {
		c.logger.Info("DRY RUN: Showing pending migrations")
		return c.showPendingMigrations()
	}

	var err error
	if *version != "" {
		// Migrate to specific version
		targetVersion, parseErr := parseVersion(*version)
		if parseErr != nil {
			return fmt.Errorf("invalid version format: %w", parseErr)
		}
		err = c.migrate.Migrate(targetVersion)
	} else {
		// Migrate to latest
		err = c.migrate.Up()
	}

	if err != nil {
		if err == migrate.ErrNoChange {
			fmt.Println("No migrations to apply - database is up to date")
			c.logger.Info("No migrations to apply")
			return nil
		}
		return fmt.Errorf("migration failed: %w", err)
	}

	c.logger.Info("Migration completed successfully")
	fmt.Println("✓ Migration completed successfully")
	return nil
}

// handleRollback handles the rollback command
func (c *CLI) handleRollback(ctx context.Context) error {
	if c.migrate == nil {
		return fmt.Errorf("migration instance not available")
	}

	if *steps == 0 && *version == "" {
		return fmt.Errorf("rollback requires either --steps or --version flag")
	}

	if !*skipConfirm {
		if !confirmRollback() {
			fmt.Println("Rollback cancelled")
			return nil
		}
	}

	c.logger.Info("Starting database rollback")

	if *dryRun {
		c.logger.Info("DRY RUN: Would rollback database")
		return nil
	}

	var err error
	if *version != "" {
		// Rollback to specific version
		targetVersion, parseErr := parseVersion(*version)
		if parseErr != nil {
			return fmt.Errorf("invalid version format: %w", parseErr)
		}
		err = c.migrate.Migrate(targetVersion)
	} else if *steps > 0 {
		// Rollback specific number of steps
		err = c.migrate.Steps(-*steps)
	}

	if err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	c.logger.Info("Rollback completed successfully")
	fmt.Println("✓ Rollback completed successfully")
	return nil
}

// handleStatus handles the status command
func (c *CLI) handleStatus(ctx context.Context) error {
	if c.migrate == nil {
		return fmt.Errorf("migration instance not available")
	}

	// Get current version
	currentVersion, dirty, err := c.migrate.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	fmt.Printf("Migration Status\n")
	fmt.Printf("================\n")
	fmt.Printf("Database:        %s\n", c.config.Database.Database)
	fmt.Printf("Driver:          %s\n", c.config.Database.Driver)
	fmt.Printf("Migration Dir:   %s\n", *migrateDir)

	if err == migrate.ErrNilVersion {
		fmt.Printf("Current Version: No migrations applied\n")
	} else {
		fmt.Printf("Current Version: %d\n", currentVersion)
	}

	if dirty {
		fmt.Printf("Status:          DIRTY (migration failed, manual intervention required)\n")
		fmt.Printf("⚠️  Database is in a dirty state. Use 'force-unlock' if you're sure no migration is running.\n")
	} else {
		fmt.Printf("Status:          CLEAN\n")
	}

	// Show available migrations
	if err := c.showAvailableMigrations(); err != nil {
		c.logger.Warn("Failed to show available migrations", logging.Error(err))
	}

	return nil
}

// handleCreate handles the create command
func (c *CLI) handleCreate(ctx context.Context) error {
	if *name == "" {
		return fmt.Errorf("migration name is required (use --name flag)")
	}

	c.logger.Info("Creating new migration", logging.String("name", *name))

	// Use entgo's migration generator
	cmd := fmt.Sprintf("go run -mod=mod ent/migrate/main.go %s", *name)
	fmt.Printf("Generating migration using: %s\n", cmd)
	fmt.Printf("Please run this command from your project root directory.\n")

	return nil
}

// handleSeed handles the seed command
func (c *CLI) handleSeed(ctx context.Context) error {
	c.logger.Info("Starting database seeding")

	opts := migration.SeedOptions{
		SeedFile: *seedFile,
		TenantID: parseTenantID(*tenantID),
		Force:    *force,
	}

	if err := c.migrator.Seed(ctx, opts); err != nil {
		return fmt.Errorf("seeding failed: %w", err)
	}

	c.logger.Info("Database seeding completed successfully")
	fmt.Println("✓ Database seeded successfully")
	return nil
}

// handleReset handles the reset command
func (c *CLI) handleReset(ctx context.Context) error {
	if !*skipConfirm {
		if !confirmReset() {
			fmt.Println("Reset cancelled")
			return nil
		}
	}

	c.logger.Warn("Starting database reset - ALL DATA WILL BE LOST")

	if *dryRun {
		c.logger.Info("DRY RUN: Would reset database")
		return nil
	}

	if err := c.migrator.Reset(ctx, *force); err != nil {
		return fmt.Errorf("database reset failed: %w", err)
	}

	c.logger.Info("Database reset completed successfully")
	fmt.Println("✓ Database reset completed - all data has been removed")
	return nil
}

// handleValidate handles the validate command
func (c *CLI) handleValidate(ctx context.Context) error {
	c.logger.Info("Validating database schema")

	result, err := c.migrator.Validate(ctx, parseTenantID(*tenantID))
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if result.Valid {
		fmt.Println("✓ Database schema is valid")
		c.logger.Info("Database schema validation passed")
	} else {
		fmt.Println("✗ Database schema validation failed")
		for _, issue := range result.Issues {
			fmt.Printf("  • %s: %s\n", issue.Type, issue.Message)
		}
		return fmt.Errorf("schema validation failed with %d issues", len(result.Issues))
	}

	return nil
}

// handleVersion handles the version command
func (c *CLI) handleVersion(ctx context.Context) error {
	if c.migrate == nil {
		return fmt.Errorf("migration instance not available")
	}

	currentVersion, dirty, err := c.migrate.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get version: %w", err)
	}

	if err == migrate.ErrNilVersion {
		fmt.Println("No migrations applied")
	} else {
		fmt.Printf("Current version: %d", currentVersion)
		if dirty {
			fmt.Printf(" (dirty)")
		}
		fmt.Println()
	}

	return nil
}

// handleForceUnlock handles the force-unlock command
func (c *CLI) handleForceUnlock(ctx context.Context) error {
	if c.migrate == nil {
		return fmt.Errorf("migration instance not available")
	}

	if !*skipConfirm {
		if !confirmForceUnlock() {
			fmt.Println("Force unlock cancelled")
			return nil
		}
	}

	if err := c.migrate.Force(-1); err != nil {
		return fmt.Errorf("failed to force unlock: %w", err)
	}

	fmt.Println("✓ Migration lock forcefully removed")
	c.logger.Info("Migration lock forcefully removed")
	return nil
}

// handleDrop handles the drop command
func (c *CLI) handleDrop(ctx context.Context) error {
	if c.migrate == nil {
		return fmt.Errorf("migration instance not available")
	}

	if !*skipConfirm {
		if !confirmDrop() {
			fmt.Println("Drop cancelled")
			return nil
		}
	}

	c.logger.Warn("Dropping database schema")

	if err := c.migrate.Drop(); err != nil {
		return fmt.Errorf("failed to drop database: %w", err)
	}

	fmt.Println("✓ Database schema dropped successfully")
	c.logger.Info("Database schema dropped successfully")
	return nil
}

// Helper functions

// parseVersion parses version string to uint
func parseVersion(versionStr string) (uint, error) {
	if versionStr == "" {
		return 0, fmt.Errorf("version cannot be empty")
	}
	var version uint
	if _, err := fmt.Sscanf(versionStr, "%d", &version); err != nil {
		return 0, fmt.Errorf("invalid version format: %s", versionStr)
	}
	return version, nil
}

// showPendingMigrations shows pending migrations for dry run
func (c *CLI) showPendingMigrations() error {
	fmt.Println("Pending migrations would be applied:")
	// This is a simplified version - in practice you'd iterate through available migrations
	// and compare with current version
	return nil
}

// showAvailableMigrations shows available migration files
func (c *CLI) showAvailableMigrations() error {
	files, err := os.ReadDir(*migrateDir)
	if err != nil {
		return fmt.Errorf("failed to read migration directory: %w", err)
	}

	fmt.Printf("\nAvailable Migrations:\n")
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".sql") {
			fmt.Printf("  • %s\n", file.Name())
		}
	}

	return nil
}

// parseTenantID parses tenant ID from string
func parseTenantID(tenantIDStr string) *xid.ID {
	if tenantIDStr == "" {
		return nil
	}

	tenantID, err := xid.FromString(tenantIDStr)
	if err != nil {
		return nil
	}

	return &tenantID
}

// Confirmation functions

// confirmRollback asks for confirmation before rollback
func confirmRollback() bool {
	fmt.Print("This will rollback your database. Are you sure? (y/N): ")
	var response string
	fmt.Scanln(&response)
	return strings.ToLower(response) == "y" || strings.ToLower(response) == "yes"
}

// confirmReset asks for confirmation before reset
func confirmReset() bool {
	fmt.Print("This will PERMANENTLY DELETE ALL DATA in your database. Are you absolutely sure? (type 'yes' to confirm): ")
	var response string
	fmt.Scanln(&response)
	return response == "yes"
}

// confirmForceUnlock asks for confirmation before force unlock
func confirmForceUnlock() bool {
	fmt.Print("This will forcefully remove the migration lock. Only do this if you're sure no migration is running. Continue? (y/N): ")
	var response string
	fmt.Scanln(&response)
	return strings.ToLower(response) == "y" || strings.ToLower(response) == "yes"
}

// confirmDrop asks for confirmation before dropping database
func confirmDrop() bool {
	fmt.Print("This will DROP ALL TABLES in your database. Are you absolutely sure? (type 'yes' to confirm): ")
	var response string
	fmt.Scanln(&response)
	return response == "yes"
}

// printUsage prints command usage information
func printUsage() {
	fmt.Printf(`Frank Auth SaaS - Database Migration Tool (entgo versioned migrations)

Usage: %s [flags] <command> [command-flags]

Commands:
  migrate      Apply pending migrations
  rollback     Rollback applied migrations
  status       Show migration status
  create       Create a new migration file (uses entgo generator)
  seed         Seed the database with initial data
  reset        Reset the database (DANGEROUS - removes all data)
  validate     Validate database schema integrity
  version      Show current migration version
  force-unlock Remove migration lock (use with caution)
  drop         Drop all database tables

Global Flags:
  --config PATH       Path to configuration file
  --env ENV          Environment (development, staging, production)
  --dry-run          Show what would be done without executing
  --force            Force the operation (use with caution)
  --timeout DURATION Timeout for migration operations (default: 5m)
  --verbose          Enable verbose logging
  --yes              Skip confirmation prompts
  --migrate-dir PATH Migration directory path (default: ent/migrate/migrations)

Migration Flags:
  --version VERSION  Target migration version
  --steps N          Number of steps to rollback
  --name NAME        Name for new migration
  --seed-file PATH   Path to seed data file
  --tenant ID        Tenant ID for tenant-specific operations

Examples:
  # Apply all pending migrations
  %s migrate

  # Create a new migration (runs entgo generator)
  %s --name "add_user_preferences" create

  # Check migration status
  %s status

  # Rollback last 3 migrations
  %s --steps 3 rollback

  # Migrate to specific version
  %s --version 20231201120000 migrate

  # Seed database with initial data
  %s seed

  # Dry run migration to see what would happen
  %s --dry-run migrate

Environment Variables:
  DATABASE_URL       Database connection string
  DATABASE_DRIVER    Database driver (postgres, mysql, sqlite)
  ENVIRONMENT        Application environment
  LOG_LEVEL          Logging level (debug, info, warn, error)

Migration Files:
  Migrations are stored in %s/ directory
  Files follow golang-migrate format: {version}_{name}.up.sql and {version}_{name}.down.sql
  Use 'create' command to generate new migrations using entgo's Atlas integration

`, filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), *migrateDir)
}
