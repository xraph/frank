// Package main provides a command-line interface for managing database migrations
// in the Frank Auth SaaS platform using entgo's versioned migrations with Atlas support.
// Enhanced with migration state synchronization capabilities for handling format changes.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
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
	// New synchronization commands
	cmdSync    = "sync"
	cmdAnalyze = "analyze"
	cmdRepair  = "repair"

	// Default timeout for migration operations
	defaultTimeout = 5 * time.Minute

	// Migration directory
	migrationDir = "../migrations"
)

// CLI represents the migration command-line interface
type CLI struct {
	config      *config.Config
	logger      logging.Logger
	migrator    *migration.Migrator
	syncer      *migration.MigrationSyncer
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
	// New sync flags
	createMissing  = flag.Bool("create-missing", false, "Create missing migration entries")
	updateExisting = flag.Bool("update-existing", false, "Update existing migration entries")
	skipValidation = flag.Bool("skip-validation", false, "Skip schema validation during sync")
	outputFormat   = flag.String("output", "text", "Output format (text, json)")
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
		Level: logLevel,
		// Environment: cfg.Environment,
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

	// Initialize migration syncer
	syncer := migration.NewMigrationSyncer(dataClients, logger, migrateInstance)

	return &CLI{
		config:      cfg,
		logger:      logger,
		migrator:    migrator,
		syncer:      syncer,
		dataClients: dataClients,
		migrate:     migrateInstance,
	}, nil
}

// initializeGolangMigrate initializes the golang-migrate instance
// Enhanced to automatically create public schema if it doesn't exist
func initializeGolangMigrate(cfg *config.Config) (*migrate.Migrate, error) {
	// Build database URL first
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

		// For PostgreSQL, ensure public schema exists before initializing migrate
		if err := ensurePublicSchemaExists(cfg); err != nil {
			return nil, fmt.Errorf("failed to ensure public schema exists: %w", err)
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

	// Build source URL for migration files
	sourceURL := fmt.Sprintf("file://%s", *migrateDir)

	// Create migrate instance
	m, err := migrate.New(sourceURL, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create migrate instance: %w", err)
	}

	return m, nil
}

// ensurePublicSchemaExists ensures the public schema exists for PostgreSQL databases
func ensurePublicSchemaExists(cfg *config.Config) error {
	if cfg.Database.Driver != "postgres" {
		return nil // Only needed for PostgreSQL
	}

	// Build connection string without specifying search_path
	var connStr string
	if cfg.Database.DSN != "" {
		connStr = cfg.Database.DSN
	} else {
		connStr = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			cfg.Database.Host,
			cfg.Database.Port,
			cfg.Database.User,
			cfg.Database.Password,
			cfg.Database.Database,
			cfg.Database.SSLMode,
		)
	}

	// Open direct database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database connection: %w", err)
	}
	defer db.Close()

	// Test the connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Check if public schema exists
	var schemaExists bool
	checkQuery := "SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = 'public')"

	err = db.QueryRow(checkQuery).Scan(&schemaExists)
	if err != nil {
		return fmt.Errorf("failed to check if public schema exists: %w", err)
	}

	if !schemaExists {
		fmt.Println("ℹ️  Public schema not found, creating it...")

		// Create public schema
		createSchemaQuery := "CREATE SCHEMA IF NOT EXISTS public"
		if _, err := db.Exec(createSchemaQuery); err != nil {
			return fmt.Errorf("failed to create public schema: %w", err)
		}

		// Grant permissions on public schema
		grantQueries := []string{
			fmt.Sprintf("GRANT ALL ON SCHEMA public TO %s", cfg.Database.User),
			"GRANT ALL ON SCHEMA public TO public",
		}

		for _, query := range grantQueries {
			if _, err := db.Exec(query); err != nil {
				// Log warning but don't fail - permissions might already exist
				fmt.Printf("⚠️  Warning: failed to grant permissions: %v\n", err)
			}
		}

		fmt.Println("✅ Public schema created successfully")
	}

	return nil
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
	// New synchronization commands
	case cmdSync:
		return c.handleSync(ctx)
	case cmdAnalyze:
		return c.handleAnalyze(ctx)
	case cmdRepair:
		return c.handleRepair(ctx)
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

// handleSync handles the sync command for migration state synchronization
func (c *CLI) handleSync(ctx context.Context) error {
	if c.syncer == nil {
		return fmt.Errorf("migration syncer not available")
	}

	c.logger.Info("Starting migration state synchronization")

	opts := migration.SyncOptions{
		DryRun:         *dryRun,
		Force:          *force,
		SkipValidation: *skipValidation,
		CreateMissing:  *createMissing,
		UpdateExisting: *updateExisting,
	}

	if *version != "" {
		targetVersion, parseErr := parseVersion(*version)
		if parseErr != nil {
			return fmt.Errorf("invalid version format: %w", parseErr)
		}
		opts.TargetVersion = &targetVersion
	}

	result, err := c.syncer.SyncMigrationState(ctx, opts)
	if err != nil {
		return fmt.Errorf("migration sync failed: %w", err)
	}

	// Output results
	if err := c.outputSyncResult(result); err != nil {
		return fmt.Errorf("failed to output sync result: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("migration sync completed with errors")
	}

	c.logger.Info("Migration state synchronization completed successfully")
	return nil
}

// handleAnalyze handles the analyze command for database state analysis
func (c *CLI) handleAnalyze(ctx context.Context) error {
	if c.syncer == nil {
		return fmt.Errorf("migration syncer not available")
	}

	c.logger.Info("Analyzing database state")

	// Create a sync with dry-run to get analysis
	opts := migration.SyncOptions{
		DryRun:         true,
		SkipValidation: *skipValidation,
	}

	result, err := c.syncer.SyncMigrationState(ctx, opts)
	if err != nil {
		return fmt.Errorf("database analysis failed: %w", err)
	}

	// Output analysis results
	if err := c.outputAnalysisResult(result); err != nil {
		return fmt.Errorf("failed to output analysis result: %w", err)
	}

	c.logger.Info("Database state analysis completed")
	return nil
}

// handleRepair handles the repair command for fixing corrupted migration state
func (c *CLI) handleRepair(ctx context.Context) error {
	if c.syncer == nil {
		return fmt.Errorf("migration syncer not available")
	}

	if !*skipConfirm && !*force {
		if !confirmRepair() {
			fmt.Println("Repair cancelled")
			return nil
		}
	}

	c.logger.Info("Starting migration state repair")

	if *dryRun {
		fmt.Println("DRY RUN: Would repair migration state")
		return nil
	}

	err := c.syncer.RepairMigrationState(ctx, *force)
	if err != nil {
		return fmt.Errorf("migration repair failed: %w", err)
	}

	fmt.Println("✓ Migration state repaired successfully")
	c.logger.Info("Migration state repair completed successfully")
	return nil
}

// Output formatting methods

func (c *CLI) outputSyncResult(result *migration.SyncResult) error {
	switch *outputFormat {
	case "json":
		return c.outputSyncResultJSON(result)
	default:
		return c.outputSyncResultText(result)
	}
}

func (c *CLI) outputSyncResultText(result *migration.SyncResult) error {
	fmt.Printf("Migration Synchronization Result\n")
	fmt.Printf("=================================\n")
	fmt.Printf("Success:         %t\n", result.Success)
	fmt.Printf("Current Version: %d\n", result.CurrentVersion)
	fmt.Printf("Target Version:  %d\n", result.TargetVersion)
	fmt.Printf("Duration:        %v\n", result.Duration)

	if len(result.SyncedMigrations) > 0 {
		fmt.Printf("\nSynced Migrations:\n")
		for _, mig := range result.SyncedMigrations {
			status := "✓"
			if mig.Status == migration.SyncStatusFailed {
				status = "✗"
			} else if mig.Status == migration.SyncStatusSkipped {
				status = "⊝"
			}
			fmt.Printf("  %s %05d - %s (%s)\n", status, mig.Version, mig.Name, mig.Action)
			if mig.Error != "" {
				fmt.Printf("      Error: %s\n", mig.Error)
			}
		}
	}

	if len(result.SkippedMigrations) > 0 {
		fmt.Printf("\nSkipped Migrations:\n")
		for _, migration := range result.SkippedMigrations {
			fmt.Printf("  ⊝ %05d - %s (skipped)\n", migration.Version, migration.Name)
			if migration.Error != "" {
				fmt.Printf("      Reason: %s\n", migration.Error)
			}
		}
	}

	if len(result.Errors) > 0 {
		fmt.Printf("\nErrors:\n")
		for _, err := range result.Errors {
			fmt.Printf("  ✗ %s\n", err)
		}
	}

	return nil
}

func (c *CLI) outputSyncResultJSON(result *migration.SyncResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func (c *CLI) outputAnalysisResult(result *migration.SyncResult) error {
	switch *outputFormat {
	case "json":
		return c.outputAnalysisResultJSON(result)
	default:
		return c.outputAnalysisResultText(result)
	}
}

func (c *CLI) outputAnalysisResultText(result *migration.SyncResult) error {
	fmt.Printf("Database State Analysis\n")
	fmt.Printf("=======================\n")

	if result.DatabaseState != nil {
		state := result.DatabaseState
		fmt.Printf("Current Version: %d\n", state.Version)
		fmt.Printf("Dirty State:     %t\n", state.Dirty)
		fmt.Printf("Tables:          %d\n", len(state.Tables))
		fmt.Printf("Indexes:         %d\n", len(state.Indexes))
		fmt.Printf("Constraints:     %d\n", len(state.Constraints))
		fmt.Printf("Migrations:      %d\n", len(state.Migrations))
		fmt.Printf("Last Updated:    %v\n", state.LastUpdated.Format(time.RFC3339))

		if len(state.Tables) > 0 {
			fmt.Printf("\nTables:\n")
			for _, table := range state.Tables {
				fmt.Printf("  • %s (%d columns)\n", table.Name, len(table.Columns))
			}
		}

		if len(state.Migrations) > 0 {
			fmt.Printf("\nApplied Migrations:\n")
			for _, migration := range state.Migrations {
				status := "✓"
				if migration.Dirty {
					status = "⚠"
				}
				fmt.Printf("  %s %05d (applied: %v)\n", status, migration.Version, migration.AppliedAt.Format("2006-01-02 15:04:05"))
			}
		}
	}

	// Show what would be synchronized
	if len(result.SyncedMigrations) > 0 || len(result.SkippedMigrations) > 0 {
		fmt.Printf("\nSynchronization Plan:\n")
		allMigrations := append(result.SyncedMigrations, result.SkippedMigrations...)
		for _, mig := range allMigrations {
			action := string(mig.Action)
			if mig.Action == migration.SyncActionSkip {
				action = "skip"
			}
			fmt.Printf("  • %05d - %s (%s)\n", mig.Version, mig.Name, action)
			if mig.Error != "" {
				fmt.Printf("      Note: %s\n", mig.Error)
			}
		}
	}

	return nil
}

func (c *CLI) outputAnalysisResultJSON(result *migration.SyncResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
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
		targetVersion, parseErr := parseVersion(*version)
		if parseErr != nil {
			return fmt.Errorf("invalid version format: %w", parseErr)
		}
		err = c.migrate.Migrate(targetVersion)
	} else {
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
func confirmRepair() bool {
	fmt.Print("This will attempt to repair the migration state. This may clear dirty flags and unlock migrations. Continue? (y/N): ")
	var response string
	fmt.Scanln(&response)
	return strings.ToLower(response) == "y" || strings.ToLower(response) == "yes"
}

// Updated usage function
func printUsage() {
	fmt.Printf(`Frank Auth SaaS - Enhanced Database Migration Tool

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

Synchronization Commands:
  sync         Synchronize migration state with database schema
  analyze      Analyze current database state and migration status
  repair       Repair corrupted migration state

Global Flags:
  --config PATH       Path to configuration file
  --env ENV          Environment (development, staging, production)
  --dry-run          Show what would be done without executing
  --force            Force the operation (use with caution)
  --timeout DURATION Timeout for migration operations (default: 5m)
  --verbose          Enable verbose logging
  --yes              Skip confirmation prompts
  --migrate-dir PATH Migration directory path (default: migrations)
  --output FORMAT    Output format: text, json (default: text)

Migration Flags:
  --version VERSION     Target migration version
  --steps N            Number of steps to rollback
  --name NAME          Name for new migration
  --seed-file PATH     Path to seed data file
  --tenant ID          Tenant ID for tenant-specific operations

Sync Flags:
  --create-missing     Create missing migration entries during sync
  --update-existing    Update existing migration entries during sync
  --skip-validation    Skip schema validation during sync

Examples:
  # Apply all pending migrations
  %s migrate

  # Analyze current database state
  %s analyze

  # Synchronize migration state (dry run)
  %s --dry-run sync

  # Force synchronize with missing migrations
  %s --force --create-missing sync

  # Repair corrupted migration state
  %s repair

  # Check what sync would do without applying
  %s --dry-run --output json sync

  # Create a new migration (runs entgo generator)
  %s --name "add_user_preferences" create

Environment Variables:
  DATABASE_URL       Database connection string
  DATABASE_DRIVER    Database driver (postgres, mysql, sqlite)
  ENVIRONMENT        Application environment
  LOG_LEVEL          Logging level (debug, info, warn, error)

Migration State Synchronization:
  The sync command helps resolve issues when:
  - Migration files have been reformatted or restructured
  - Database schema exists but migration history is incomplete
  - Migration state is corrupted or inconsistent
  - Moving between different migration tools or formats

  Use 'analyze' to inspect current state before running 'sync'.
  Always run with --dry-run first to see what changes would be made.

`, filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]))
}
