package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/file"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/logging"
	_ "github.com/lib/pq"           // PostgreSQL driver
	_ "github.com/mattn/go-sqlite3" // SQLite driver
	"github.com/rs/xid"
	"go.uber.org/zap"
)

// MigrationConfig holds migration-specific configuration
type MigrationConfig struct {
	DatabaseURL     string
	MigrationsDir   string
	Driver          string
	AutoMigrate     bool
	CreateDatabase  bool
	DropDatabase    bool
	ResetDatabase   bool
	ForceMigration  bool
	MigrationNumber int
	Command         string
	ConfigPath      string
}

// Available commands
const (
	CmdUp       = "up"
	CmdDown     = "down"
	CmdDrop     = "drop"
	CmdForce    = "force"
	CmdVersion  = "version"
	CmdGoto     = "goto"
	CmdCreate   = "create"
	CmdStatus   = "status"
	CmdReset    = "reset"
	CmdSeed     = "seed"
	CmdValidate = "validate"
)

func main() {
	var migrationConfig MigrationConfig

	// Parse command line flags
	flag.StringVar(&migrationConfig.Command, "command", "up", "Migration command (up, down, drop, force, version, goto, create, status, reset, seed, validate)")
	flag.StringVar(&migrationConfig.DatabaseURL, "database-url", "", "Database connection URL")
	flag.StringVar(&migrationConfig.MigrationsDir, "migrations-dir", "./migrations", "Path to migrations directory")
	flag.StringVar(&migrationConfig.Driver, "driver", "postgres", "Database driver (postgres, sqlite3)")
	flag.StringVar(&migrationConfig.ConfigPath, "config", "", "Path to config file")
	flag.BoolVar(&migrationConfig.AutoMigrate, "auto-migrate", false, "Automatically run migrations")
	flag.BoolVar(&migrationConfig.CreateDatabase, "create-db", false, "Create database if it does not exist")
	flag.BoolVar(&migrationConfig.DropDatabase, "drop-db", false, "Drop database (use with caution)")
	flag.BoolVar(&migrationConfig.ResetDatabase, "reset-db", false, "Drop and recreate database (use with caution)")
	flag.BoolVar(&migrationConfig.ForceMigration, "force", false, "Force migration to specific version")
	flag.IntVar(&migrationConfig.MigrationNumber, "number", 0, "Migration number for force/goto commands")

	flag.Parse()

	// Initialize logger
	logger := logging.NewLogger(&logging.LoggerConfig{
		Level: "info",
	})

	// Load configuration if config path is provided
	var cfg *config.Config
	var err error
	if migrationConfig.ConfigPath != "" {
		cfg, err = config.Load(migrationConfig.ConfigPath)
		if err != nil {
			logger.Error("Failed to load config", zap.Error(err))
			os.Exit(1)
		}
	} else {
		// Try to load default config
		cfg, err = config.Load()
		if err != nil {
			logger.Warn("Failed to load default config, using flags", zap.Error(err))
		}
	}

	// Use config values if available, otherwise use flags
	if cfg != nil && migrationConfig.DatabaseURL == "" {
		migrationConfig.DatabaseURL = cfg.Database.GetFullAddress()
		migrationConfig.MigrationsDir = cfg.Database.MigrationsDir
		migrationConfig.Driver = cfg.Database.Driver
		migrationConfig.AutoMigrate = cfg.Database.AutoMigrate
	}

	// Validate required parameters
	if migrationConfig.DatabaseURL == "" {
		logger.Error("Database URL is required")
		printUsage()
		os.Exit(1)
	}

	if migrationConfig.MigrationsDir == "" {
		migrationConfig.MigrationsDir = "./migrations"
	}

	// Ensure migrations directory exists
	if err := ensureMigrationsDir(migrationConfig.MigrationsDir); err != nil {
		logger.Error("Failed to ensure migrations directory", "error", err)
		os.Exit(1)
	}

	// Execute the specified command
	ctx := context.Background()
	migrator := NewMigrator(migrationConfig, logger)

	switch migrationConfig.Command {
	case CmdUp:
		err = migrator.Up(ctx)
	case CmdDown:
		err = migrator.Down(ctx)
	case CmdDrop:
		err = migrator.Drop(ctx)
	case CmdForce:
		if migrationConfig.MigrationNumber == 0 {
			logger.Error("Migration number is required for force command")
			os.Exit(1)
		}
		err = migrator.Force(ctx, migrationConfig.MigrationNumber)
	case CmdVersion:
		err = migrator.Version(ctx)
	case CmdGoto:
		if migrationConfig.MigrationNumber == 0 {
			logger.Error("Migration number is required for goto command")
			os.Exit(1)
		}
		err = migrator.Goto(ctx, uint(migrationConfig.MigrationNumber))
	case CmdCreate:
		if len(flag.Args()) == 0 {
			logger.Error("Migration name is required for create command")
			os.Exit(1)
		}
		err = migrator.Create(ctx, strings.Join(flag.Args(), "_"))
	case CmdStatus:
		err = migrator.Status(ctx)
	case CmdReset:
		err = migrator.Reset(ctx)
	case CmdSeed:
		err = migrator.Seed(ctx)
	case CmdValidate:
		err = migrator.Validate(ctx)
	default:
		logger.Error("Unknown command", zap.String("command", migrationConfig.Command))
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		logger.Error("Migration failed", zap.String("command", migrationConfig.Command), zap.Error(err))
		os.Exit(1)
	}

	logger.Info("Migration completed successfully", zap.String("command", migrationConfig.Command))
}

// Migrator handles database migrations
type Migrator struct {
	config MigrationConfig
	logger logging.Logger
	db     *sql.DB
	m      *migrate.Migrate
}

// NewMigrator creates a new migrator instance
func NewMigrator(config MigrationConfig, logger logging.Logger) *Migrator {
	return &Migrator{
		config: config,
		logger: logger,
	}
}

// initializeDB initializes the database connection
func (m *Migrator) initializeDB(ctx context.Context) error {
	if m.db != nil {
		return nil
	}

	db, err := sql.Open(m.config.Driver, m.config.DatabaseURL)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	m.db = db
	return nil
}

// initializeMigrate initializes the migrate instance
func (m *Migrator) initializeMigrate(ctx context.Context) error {
	if m.m != nil {
		return nil
	}

	if err := m.initializeDB(ctx); err != nil {
		return err
	}

	// Initialize the file source
	sourceURL := fmt.Sprintf("file://%s", m.config.MigrationsDir)
	source, err := (&file.File{}).Open(sourceURL)
	if err != nil {
		return fmt.Errorf("failed to open migration source: %w", err)
	}

	// Initialize database driver
	var driver migrate.Database
	switch m.config.Driver {
	case "postgres":
		driver, err = postgres.WithInstance(m.db, &postgres.Config{})
	case "sqlite3":
		driver, err = sqlite3.WithInstance(m.db, &sqlite3.Config{})
	default:
		return fmt.Errorf("unsupported database driver: %s", m.config.Driver)
	}

	if err != nil {
		return fmt.Errorf("failed to initialize database driver: %w", err)
	}

	// Create migrate instance
	migrator, err := migrate.NewWithSourceAndDatabaseInstance("file", source, m.config.Driver, driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	m.m = migrator
	return nil
}

// Up runs all pending migrations
func (m *Migrator) Up(ctx context.Context) error {
	m.logger.Info("Running up migrations")

	if err := m.initializeMigrate(ctx); err != nil {
		return err
	}

	if err := m.m.Up(); err != nil {
		if err == migrate.ErrNoChange {
			m.logger.Info("No migrations to run")
			return nil
		}
		return fmt.Errorf("failed to run up migrations: %w", err)
	}

	return nil
}

// Down runs one down migration
func (m *Migrator) Down(ctx context.Context) error {
	m.logger.Info("Running down migration")

	if err := m.initializeMigrate(ctx); err != nil {
		return err
	}

	if err := m.m.Steps(-1); err != nil {
		if err == migrate.ErrNoChange {
			m.logger.Info("No migrations to rollback")
			return nil
		}
		return fmt.Errorf("failed to run down migration: %w", err)
	}

	return nil
}

// Drop drops all tables
func (m *Migrator) Drop(ctx context.Context) error {
	m.logger.Warn("Dropping all database tables")

	if err := m.initializeMigrate(ctx); err != nil {
		return err
	}

	if err := m.m.Drop(); err != nil {
		return fmt.Errorf("failed to drop database: %w", err)
	}

	return nil
}

// Force forces the migration version
func (m *Migrator) Force(ctx context.Context, version int) error {
	m.logger.Info("Forcing migration version", zap.Int("version", version))

	if err := m.initializeMigrate(ctx); err != nil {
		return err
	}

	if err := m.m.Force(version); err != nil {
		return fmt.Errorf("failed to force migration version: %w", err)
	}

	return nil
}

// Version prints the current migration version
func (m *Migrator) Version(ctx context.Context) error {
	if err := m.initializeMigrate(ctx); err != nil {
		return err
	}

	version, dirty, err := m.m.Version()
	if err != nil {
		if err == migrate.ErrNilVersion {
			m.logger.Info("No migrations have been run")
			return nil
		}
		return fmt.Errorf("failed to get migration version: %w", err)
	}

	status := "clean"
	if dirty {
		status = "dirty"
	}

	m.logger.Info("Current migration version", zap.Int("version", int(version)), zap.String("status", status))
	return nil
}

// Goto migrates to a specific version
func (m *Migrator) Goto(ctx context.Context, version uint) error {
	m.logger.Info("Migrating to specific version", zap.Int("version", int(version)))

	if err := m.initializeMigrate(ctx); err != nil {
		return err
	}

	if err := m.m.Migrate(version); err != nil {
		if err == migrate.ErrNoChange {
			m.logger.Info("Already at specified version", zap.Int("version", int(version)))
			return nil
		}
		return fmt.Errorf("failed to migrate to version %d: %w", version, err)
	}

	return nil
}

// Create creates a new migration file
func (m *Migrator) Create(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("migration name cannot be empty")
	}

	// Generate timestamp
	timestamp := time.Now().Unix()

	// Create up migration file
	upFilename := fmt.Sprintf("%d_%s.up.sql", timestamp, name)
	upPath := filepath.Join(m.config.MigrationsDir, upFilename)

	// Create down migration file
	downFilename := fmt.Sprintf("%d_%s.down.sql", timestamp, name)
	downPath := filepath.Join(m.config.MigrationsDir, downFilename)

	// Create up file
	upFile, err := os.Create(upPath)
	if err != nil {
		return fmt.Errorf("failed to create up migration file: %w", err)
	}
	defer upFile.Close()

	// Write template to up file
	upTemplate := fmt.Sprintf(`-- Migration: %s
-- Created: %s
-- Description: Add your up migration here

BEGIN;

-- Add your SQL statements here
-- Example:
-- CREATE TABLE example_table (
--     id BIGSERIAL PRIMARY KEY,
--     name VARCHAR(255) NOT NULL,
--     created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
-- );

COMMIT;
`, name, time.Now().Format(time.RFC3339))

	if _, err := upFile.WriteString(upTemplate); err != nil {
		return fmt.Errorf("failed to write up migration template: %w", err)
	}

	// Create down file
	downFile, err := os.Create(downPath)
	if err != nil {
		return fmt.Errorf("failed to create down migration file: %w", err)
	}
	defer downFile.Close()

	// Write template to down file
	downTemplate := fmt.Sprintf(`-- Migration: %s (DOWN)
-- Created: %s
-- Description: Add your down migration here

BEGIN;

-- Add your rollback SQL statements here
-- Example:
-- DROP TABLE IF EXISTS example_table;

COMMIT;
`, name, time.Now().Format(time.RFC3339))

	if _, err := downFile.WriteString(downTemplate); err != nil {
		return fmt.Errorf("failed to write down migration template: %w", err)
	}

	m.logger.Info("Migration files created",
		zap.String("up_file", upPath),
		zap.String("down_file", downPath),
	)

	return nil
}

// Status shows the migration status
func (m *Migrator) Status(ctx context.Context) error {
	if err := m.initializeMigrate(ctx); err != nil {
		return err
	}

	version, dirty, err := m.m.Version()
	if err != nil {
		if err == migrate.ErrNilVersion {
			m.logger.Info("Migration Status: No migrations have been run")
			return nil
		}
		return fmt.Errorf("failed to get migration version: %w", err)
	}

	status := "clean"
	if dirty {
		status = "dirty"
	}

	m.logger.Info("Migration Status",
		zap.Int("current_version", int(version)),
		zap.String("status", status),
		zap.String("migrations_dir", m.config.MigrationsDir),
	)

	// List migration files
	files, err := filepath.Glob(filepath.Join(m.config.MigrationsDir, "*.up.sql"))
	if err != nil {
		return fmt.Errorf("failed to list migration files: %w", err)
	}

	m.logger.Info("Available migrations", zap.Int("count", len(files)))
	for _, file := range files {
		filename := filepath.Base(file)
		versionStr := strings.Split(filename, "_")[0]
		fileVersion, _ := strconv.Atoi(versionStr)

		status := "pending"
		if uint(fileVersion) <= version {
			status = "applied"
		}
		m.logger.Info("Migration file", zap.String("filename", filename), zap.Int("status", status))
	}

	return nil
}

// Reset drops all tables and reruns all migrations
func (m *Migrator) Reset(ctx context.Context) error {
	m.logger.Warn("Resetting database (drop + up)")

	if err := m.Drop(ctx); err != nil {
		return fmt.Errorf("failed to drop database: %w", err)
	}

	if err := m.Up(ctx); err != nil {
		return fmt.Errorf("failed to run migrations after reset: %w", err)
	}

	return nil
}

// Seed runs database seeding
func (m *Migrator) Seed(ctx context.Context) error {
	m.logger.Info("Running database seeding")

	if err := m.initializeDB(ctx); err != nil {
		return err
	}

	// Create platform organization if it doesn't exist
	if err := m.createPlatformOrganization(ctx); err != nil {
		return fmt.Errorf("failed to create platform organization: %w", err)
	}

	// Create default admin user if it doesn't exist
	if err := m.createDefaultAdminUser(ctx); err != nil {
		return fmt.Errorf("failed to create default admin user: %w", err)
	}

	// Create default roles if they don't exist
	if err := m.createDefaultRoles(ctx); err != nil {
		return fmt.Errorf("failed to create default roles: %w", err)
	}

	m.logger.Info("Database seeding completed")
	return nil
}

// Validate validates migration files
func (m *Migrator) Validate(ctx context.Context) error {
	m.logger.Info("Validating migration files")

	files, err := filepath.Glob(filepath.Join(m.config.MigrationsDir, "*.sql"))
	if err != nil {
		return fmt.Errorf("failed to list migration files: %w", err)
	}

	if len(files) == 0 {
		m.logger.Warn("No migration files found")
		return nil
	}

	validCount := 0
	for _, file := range files {
		if err := m.validateMigrationFile(file); err != nil {
			m.logger.Error("Invalid migration file", zap.String("file", file), zap.Error(err))
		} else {
			validCount++
		}
	}

	m.logger.Info("Migration validation completed",
		zap.Int("valid_count", validCount),
		zap.Int("valid_files", validCount),
		zap.Int("invalid_files", len(files)-validCount),
	)

	if validCount < len(files) {
		return fmt.Errorf("found %d invalid migration files", len(files)-validCount)
	}

	return nil
}

// Helper functions

func ensureMigrationsDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return nil
}

func (m *Migrator) createPlatformOrganization(ctx context.Context) error {
	orgID := xid.New()
	query := `
		INSERT INTO organizations (id, name, slug, org_type, is_platform_organization, active, created_at, updated_at)
		VALUES ($1, 'Frank Platform', 'frank-platform', 'platform', true, true, NOW(), NOW())
		ON CONFLICT (slug) DO NOTHING`

	_, err := m.db.ExecContext(ctx, query, orgID.String())
	return err
}

func (m *Migrator) createDefaultAdminUser(ctx context.Context) error {
	userID := xid.New()
	query := `
		INSERT INTO users (id, email, username, first_name, last_name, user_type, email_verified, active, created_at, updated_at)
		VALUES ($1, 'admin@frankauth.dev', 'admin', 'Frank', 'Admin', 'internal', true, true, NOW(), NOW())
		ON CONFLICT (email) DO NOTHING`

	_, err := m.db.ExecContext(ctx, query, userID.String())
	return err
}

func (m *Migrator) createDefaultRoles(ctx context.Context) error {
	roles := []struct {
		name        string
		displayName string
		roleType    string
		system      bool
	}{
		{"super_admin", "Super Administrator", "system", true},
		{"platform_admin", "Platform Administrator", "system", true},
		{"org_admin", "Organization Administrator", "organization", false},
		{"org_member", "Organization Member", "organization", false},
		{"user", "User", "application", false},
	}

	for _, role := range roles {
		roleID := xid.New()
		query := `
			INSERT INTO roles (id, name, display_name, role_type, system, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
			ON CONFLICT (name, role_type) DO NOTHING`

		_, err := m.db.ExecContext(ctx, query, roleID.String(), role.name, role.displayName, role.roleType, role.system)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Migrator) validateMigrationFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Basic validation - check if file is readable and not empty
	stat, err := file.Stat()
	if err != nil {
		return err
	}

	if stat.Size() == 0 {
		return fmt.Errorf("migration file is empty")
	}

	// Additional validation could include SQL syntax checking
	// For now, just basic file validation
	return nil
}

func printUsage() {
	fmt.Println(`
Frank Auth Migration Tool

Usage:
  migrate [options] [command]

Commands:
  up          Run all pending migrations (default)
  down        Rollback one migration
  drop        Drop all tables (destructive)
  force N     Force migration to version N
  version     Show current migration version
  goto N      Migrate to specific version N
  create NAME Create new migration files
  status      Show migration status
  reset       Drop all tables and re-run migrations (destructive)
  seed        Run database seeding
  validate    Validate migration files

Options:
  -database-url     Database connection URL
  -migrations-dir   Path to migrations directory (default: ./migrations)
  -driver          Database driver (postgres, sqlite3) (default: postgres)
  -config          Path to config file
  -auto-migrate    Automatically run migrations (default: false)
  -create-db       Create database if it doesn't exist (default: false)
  -drop-db         Drop database (use with caution) (default: false)
  -reset-db        Drop and recreate database (use with caution) (default: false)
  -force           Force migration to specific version (default: false)
  -number          Migration number for force/goto commands (default: 0)

Examples:
  migrate up
  migrate down
  migrate create add_users_table
  migrate force -number=123
  migrate goto -number=5
  migrate status
  migrate -database-url="postgres://user:pass@localhost/db" up
  migrate -config=config.yaml up
`)
}
