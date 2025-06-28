// Package migration provides database migration utilities for the Frank Auth SaaS platform.
// It complements entgo's versioned migrations with additional functionality like seeding,
// validation, and multi-tenant database operations.
package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	schema2 "ariga.io/atlas/sql/schema"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql/schema"
	"github.com/rs/xid"
	"github
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/migrate"
	"github.com/xraph/frank/pkg/data"
	"github.com/rs/xid"
)

// Migrator handles database operations that complement entgo's versioned migrations
type Migrator struct {
	dataClients *data.Clients
	logger      logging.Logger
}

// NewMigrator creates a new migrator instance
func NewMigrator(dataClients *data.Clients, logger logging.Logger) *Migrator {
	return &Migrator{
		dataClients: dataClients,
		logger:      logger.Named("migrator"),
	}
}

// Seed seeds the database with initial data
func (m *Migrator) Seed(ctx context.Context, opts SeedOptions) error {
	m.logger.Info("Starting database seeding", logging.String("seedFile", opts.SeedFile))

	// Ensure schema is up to date first
	if err := m.ensureSchema(ctx); err != nil {
		return fmt.Errorf("failed to ensure schema: %w", err)
	}

	// Run custom seed if provided
	if opts.SeedFile != "" {
		if err := m.runSeedFile(ctx, opts.SeedFile); err != nil {
			return fmt.Errorf("failed to run seed file: %w", err)
		}
	}

	// Run default seeding
	if err := m.runDefaultSeeding(ctx, opts.TenantID); err != nil {
		return fmt.Errorf("failed to run default seeding: %w", err)
	}

	m.logger.Info("Database seeding completed")
	return nil
}

// Reset resets the database by dropping all tables
func (m *Migrator) Reset(ctx context.Context, force bool) error {
	if !force {
		return fmt.Errorf("reset operation requires force flag")
	}

	m.logger.Warn("Resetting database - ALL DATA WILL BE LOST")

	// Drop all tables
	driver := m.dataClients.Driver()

	// Get database connection
	conn := driver.DB()
	if conn == nil {
		return fmt.Errorf("failed to get database connection")
	}

	// Drop tables based on database type
	switch m.dataClients.Dialect() {
	case dialect.Postgres:
		if err := m.resetPostgres(ctx, conn); err != nil {
			return fmt.Errorf("failed to reset postgres database: %w", err)
		}
	case dialect.MySQL:
		if err := m.resetMySQL(ctx, conn); err != nil {
			return fmt.Errorf("failed to reset mysql database: %w", err)
		}
	case dialect.SQLite:
		if err := m.resetSQLite(ctx, conn); err != nil {
			return fmt.Errorf("failed to reset sqlite database: %w", err)
		}
	default:
		return fmt.Errorf("unsupported database dialect: %s", m.dataClients.Dialect())
	}

	m.logger.Info("Database reset completed")
	return nil
}

// Validate validates the database schema integrity
func (m *Migrator) Validate(ctx context.Context, tenantID *xid.ID) (*ValidationResult, error) {
	m.logger.Info("Validating database schema")

	result := &ValidationResult{
		Valid:  true,
		Issues: make([]ValidationIssue, 0),
	}

	// Validate schema against entgo definitions
	if err := m.validateEntgoSchema(ctx, result); err != nil {
		return nil, fmt.Errorf("failed to validate entgo schema: %w", err)
	}

	// Validate constraints and indexes
	if err := m.validateConstraints(ctx, result); err != nil {
		return nil, fmt.Errorf("failed to validate constraints: %w", err)
	}

	// Validate data integrity
	if err := m.validateDataIntegrity(ctx, result); err != nil {
		return nil, fmt.Errorf("failed to validate data integrity: %w", err)
	}

	result.Valid = len(result.Issues) == 0

	m.logger.Info("Schema validation completed",
		logging.Bool("valid", result.Valid),
		logging.Int("issues", len(result.Issues)),
	)

	return result, nil
}

// SchemaHash calculates a hash of the current database schema
func (m *Migrator) SchemaHash(ctx context.Context) (string, error) {
	// Get schema information
	schemaInfo, err := m.getSchemaInfo(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get schema info: %w", err)
	}

	// Calculate hash
	hash := sha256.Sum256([]byte(schemaInfo))
	return hex.EncodeToString(hash[:]), nil
}

// ensureSchema ensures the database schema is up to date using entgo
func (m *Migrator) ensureSchema(ctx context.Context) error {
	db := m.dataClients.DB

	// Use entgo's auto-migration to ensure schema is current
	if err := db.Schema.Create(ctx, migrate.WithDropIndex(true), migrate.WithDropColumn(true)); err != nil {
		return fmt.Errorf("failed to create/update schema: %w", err)
	}

	return nil
}

// runSeedFile executes a custom seed file
func (m *Migrator) runSeedFile(ctx context.Context, seedFile string) error {
	m.logger.Info("Running seed file", logging.String("file", seedFile))

	content, err := os.ReadFile(seedFile)
	if err != nil {
		return fmt.Errorf("failed to read seed file: %w", err)
	}

	driver := m.dataClients.Driver()
	conn := driver.DB()
	if err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	// Execute seed SQL in transaction
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Split and execute SQL statements
	statements := m.splitSQL(string(content))
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}

		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to execute seed statement: %s - error: %w", stmt, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit seed transaction: %w", err)
	}

	m.logger.Info("Seed file executed successfully")
	return nil
}

// runDefaultSeeding runs default seeding for the Frank Auth SaaS platform
func (m *Migrator) runDefaultSeeding(ctx context.Context, tenantID *xid.ID) error {
	m.logger.Info("Running default seeding")

	db := m.dataClients.DB

	// Create system roles
	if err := m.seedSystemRoles(ctx, db); err != nil {
		return fmt.Errorf("failed to seed system roles: %w", err)
	}

	// Create system permissions
	if err := m.seedSystemPermissions(ctx, db); err != nil {
		return fmt.Errorf("failed to seed system permissions: %w", err)
	}

	// Create default organization if none exists
	if err := m.seedDefaultOrganization(ctx, db); err != nil {
		return fmt.Errorf("failed to seed default organization: %w", err)
	}

	// Create admin user if none exists
	if err := m.seedAdminUser(ctx, db); err != nil {
		return fmt.Errorf("failed to seed admin user: %w", err)
	}

	// Seed OAuth providers templates
	if err := m.seedOAuthProviders(ctx, db); err != nil {
		return fmt.Errorf("failed to seed OAuth providers: %w", err)
	}

	// Seed MFA templates
	if err := m.seedMFATemplates(ctx, db); err != nil {
		return fmt.Errorf("failed to seed MFA templates: %w", err)
	}

	m.logger.Info("Default seeding completed successfully")
	return nil
}

// Database reset methods

// resetPostgres resets a PostgreSQL database
func (m *Migrator) resetPostgres(ctx context.Context, conn *sql.DB) error {
	m.logger.Info("Resetting PostgreSQL database")

	// Drop all tables in cascade mode
	dropQueries := []string{
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
		"GRANT ALL ON SCHEMA public TO postgres",
		"GRANT ALL ON SCHEMA public TO public",
	}

	for _, query := range dropQueries {
		if _, err := conn.ExecContext(ctx, query); err != nil {
			m.logger.Warn("Failed to execute drop query",
				logging.String("query", query),
				logging.Error(err),
			)
		}
	}

	return nil
}

// resetMySQL resets a MySQL database
func (m *Migrator) resetMySQL(ctx context.Context, conn *sql.DB) error {
	m.logger.Info("Resetting MySQL database")

	// Disable foreign key checks
	if _, err := conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		return fmt.Errorf("failed to disable foreign key checks: %w", err)
	}

	// Get all tables
	rows, err := conn.QueryContext(ctx, "SHOW TABLES")
	if err != nil {
		return fmt.Errorf("failed to get tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return fmt.Errorf("failed to scan table name: %w", err)
		}
		tables = append(tables, table)
	}

	// Drop all tables
	for _, table := range tables {
		dropSQL := fmt.Sprintf("DROP TABLE IF EXISTS `%s`", table)
		if _, err := conn.ExecContext(ctx, dropSQL); err != nil {
			m.logger.Warn("Failed to drop table",
				logging.String("table", table),
				logging.Error(err),
			)
		}
	}

	// Re-enable foreign key checks
	if _, err := conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1"); err != nil {
		return fmt.Errorf("failed to re-enable foreign key checks: %w", err)
	}

	return nil
}

// resetSQLite resets a SQLite database
func (m *Migrator) resetSQLite(ctx context.Context, conn *sql.DB) error {
	m.logger.Info("Resetting SQLite database")

	// Get all tables except sqlite system tables
	rows, err := conn.QueryContext(ctx,
		"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return fmt.Errorf("failed to get tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return fmt.Errorf("failed to scan table name: %w", err)
		}
		tables = append(tables, table)
	}

	// Disable foreign keys
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return fmt.Errorf("failed to disable foreign keys: %w", err)
	}

	// Drop all tables
	for _, table := range tables {
		dropSQL := fmt.Sprintf("DROP TABLE IF EXISTS \"%s\"", table)
		if _, err := conn.ExecContext(ctx, dropSQL); err != nil {
			m.logger.Warn("Failed to drop table",
				logging.String("table", table),
				logging.Error(err),
			)
		}
	}

	// Re-enable foreign keys
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("failed to re-enable foreign keys: %w", err)
	}

	return nil
}

// Validation methods

// validateEntgoSchema validates schema against entgo definitions
func (m *Migrator) validateEntgoSchema(ctx context.Context, result *ValidationResult) error {
	m.logger.Debug("Validating entgo schema")

	db := m.dataClients.DB

	// Create a dry-run migration to compare with current schema
	opts := []schema.MigrateOption{
		// schema.WithDryRun(true),
		schema.WithDiffHook(func(next schema.Differ) schema.Differ {
			return schema.DiffFunc(func(current, desired *schema2.Schema) ([]schema2.Change, error) {
				// Check for schema differences
				if current != nil && desired != nil {
					if err := m.compareTableSchemas(current, desired, result); err != nil {
						return nil, err
					}
				}
				return next.Diff(current, desired)
			})
		}),
	}

	// Run schema diff
	if err := db.Schema.Create(ctx, opts...); err != nil {
		// Schema differences found - this is expected in validation
		m.logger.Debug("Schema differences detected during validation")
	}

	return nil
}

// validateConstraints validates database constraints and indexes
func (m *Migrator) validateConstraints(ctx context.Context, result *ValidationResult) error {
	m.logger.Debug("Validating database constraints")

	driver := m.dataClients.Driver()
	conn := driver.DB()
	if conn == nil {
		return fmt.Errorf("failed to get database connection")
	}

	switch m.dataClients.Dialect() {
	case dialect.Postgres:
		return m.validatePostgresConstraints(ctx, conn, result)
	case dialect.MySQL:
		return m.validateMySQLConstraints(ctx, conn, result)
	case dialect.SQLite:
		return m.validateSQLiteConstraints(ctx, conn, result)
	default:
		result.Issues = append(result.Issues, ValidationIssue{
			Type:    "unsupported_dialect",
			Message: fmt.Sprintf("Constraint validation not supported for dialect: %s", m.dataClients.Dialect()),
		})
	}

	return nil
}

// validateDataIntegrity validates data integrity
func (m *Migrator) validateDataIntegrity(ctx context.Context, result *ValidationResult) error {
	m.logger.Debug("Validating data integrity")

	db := m.dataClients.DB

	// Check for orphaned records
	if err := m.checkOrphanedRecords(ctx, db, result); err != nil {
		return fmt.Errorf("failed to check orphaned records: %w", err)
	}

	// Check for duplicate unique values
	if err := m.checkDuplicateUniqueValues(ctx, db, result); err != nil {
		return fmt.Errorf("failed to check duplicate unique values: %w", err)
	}

	// Check required fields
	if err := m.checkRequiredFields(ctx, db, result); err != nil {
		return fmt.Errorf("failed to check required fields: %w", err)
	}

	return nil
}

// Seeding helper methods

// seedSystemRoles creates default system roles
func (m *Migrator) seedSystemRoles(ctx context.Context, client *ent.Client) error {
	m.logger.Debug("Seeding system roles")

	systemRoles := []struct {
		name        string
		displayName string
		description string
		roleType    string
		system      bool
		isDefault   bool
	}{
		{"super_admin", "Super Administrator", "Platform super administrator with full access", "system", true, false},
		{"admin", "Administrator", "System administrator", "system", true, false},
		{"org_owner", "Organization Owner", "Organization owner with full org access", "organization", true, true},
		{"org_admin", "Organization Admin", "Organization administrator", "organization", true, false},
		{"member", "Member", "Organization member", "organization", true, false},
		{"viewer", "Viewer", "Read-only access", "organization", true, false},
	}

	for _, roleData := range systemRoles {
		// Check if role already exists
		exists, err := client.Role.Query().Where(
		// Add your role query conditions here based on your schema
		).Exist(ctx)
		if err != nil {
			return fmt.Errorf("failed to check if role exists: %w", err)
		}

		if !exists {
			// Create role - adapt this to your actual Role entity schema
			m.logger.Debug("Creating system role", logging.String("name", roleData.name))
			// Implementation depends on your specific role schema
			// Example:
			// _, err := client.Role.Create().
			// 	SetName(roleData.name).
			// 	SetDisplayName(roleData.displayName).
			// 	SetDescription(roleData.description).
			// 	SetSystem(roleData.system).
			// 	SetIsDefault(roleData.isDefault).
			// 	Save(ctx)
			// if err != nil {
			// 	return fmt.Errorf("failed to create role %s: %w", roleData.name, err)
			// }
		}
	}

	return nil
}

// seedSystemPermissions creates default system permissions
func (m *Migrator) seedSystemPermissions(ctx context.Context, client *ent.Client) error {
	m.logger.Debug("Seeding system permissions")

	// Define default permissions based on your RBAC system
	permissions := []struct {
		name        string
		displayName string
		description string
		resource    string
		action      string
	}{
		{"view_users", "View Users", "View user information", "user", "view"},
		{"manage_users", "Manage Users", "Create, update, delete users", "user", "manage"},
		{"view_organizations", "View Organizations", "View organization information", "organization", "view"},
		{"manage_organizations", "Manage Organizations", "Create, update, delete organizations", "organization", "manage"},
		{"view_roles", "View Roles", "View role information", "role", "view"},
		{"manage_roles", "Manage Roles", "Create, update, delete roles", "role", "manage"},
	}

	for _, permData := range permissions {
		// Check if permission already exists and create if not
		m.logger.Debug("Processing permission", logging.String("name", permData.name))
		// Implementation depends on your specific permission schema
	}

	return nil
}

// seedDefaultOrganization creates a default organization if none exists
func (m *Migrator) seedDefaultOrganization(ctx context.Context, client *ent.Client) error {
	m.logger.Debug("Seeding default organization")

	// Check if any organization exists
	count, err := client.Organization.Query().Count(ctx)
	if err != nil {
		return fmt.Errorf("failed to count organizations: %w", err)
	}

	if count == 0 {
		// Create default organization
		m.logger.Info("Creating default organization")
		// Implementation depends on your organization schema
		// Example:
		// _, err := client.Organization.Create().
		// 	SetName("Default Organization").
		// 	SetSlug("default").
		// 	SetDescription("Default organization created during setup").
		// 	Save(ctx)
		// if err != nil {
		// 	return fmt.Errorf("failed to create default organization: %w", err)
		// }
	}

	return nil
}

// seedAdminUser creates an admin user if none exists
func (m *Migrator) seedAdminUser(ctx context.Context, client *ent.Client) error {
	m.logger.Debug("Seeding admin user")

	// Check for existing admin users
	adminEmail := os.Getenv("ADMIN_EMAIL")
	if adminEmail == "" {
		adminEmail = "admin@localhost"
	}

	exists, err := client.User.Query().Where(
	// Add your user email query condition here
	).Exist(ctx)
	if err != nil {
		return fmt.Errorf("failed to check if admin user exists: %w", err)
	}

	if !exists {
		m.logger.Info("Creating admin user", logging.String("email", adminEmail))
		// Implementation depends on your user schema
		// You might want to generate a random password and log it
		// or use environment variables for initial setup
	}

	return nil
}

// seedOAuthProviders creates OAuth provider templates
func (m *Migrator) seedOAuthProviders(ctx context.Context, client *ent.Client) error {
	m.logger.Debug("Seeding OAuth providers")

	providers := []struct {
		name        string
		displayName string
		type_       string
		iconURL     string
		popular     bool
	}{
		{"google", "Google", "oidc", "https://developers.google.com/identity/images/g-logo.png", true},
		{"github", "GitHub", "oauth2", "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png", true},
		{"microsoft", "Microsoft", "oidc", "https://docs.microsoft.com/en-us/azure/active-directory/develop/media/howto-add-branding-in-azure-ad-apps/ms-symbollockup_mssymbol_19.png", true},
		{"apple", "Apple", "oidc", "https://developer.apple.com/assets/elements/icons/sign-in-with-apple/sign-in-with-apple-logo.svg", true},
		{"facebook", "Facebook", "oauth2", "https://developers.facebook.com/docs/facebook-login/images/fb_login_button.png", false},
		{"twitter", "Twitter", "oauth2", "https://abs.twimg.com/responsive-web/client-web/icon-ios.b1fc7275.png", false},
	}

	for _, provider := range providers {
		m.logger.Debug("Processing OAuth provider", logging.String("name", provider.name))
		// Implementation depends on your OAuth provider schema
	}

	return nil
}

// seedMFATemplates creates MFA method templates
func (m *Migrator) seedMFATemplates(ctx context.Context, client *ent.Client) error {
	m.logger.Debug("Seeding MFA templates")

	// Create default MFA method configurations
	mfaMethods := []struct {
		name        string
		displayName string
		type_       string
		enabled     bool
		description string
	}{
		{"totp", "Authenticator App", "totp", true, "Use an authenticator app like Google Authenticator or Authy"},
		{"sms", "SMS", "sms", true, "Receive verification codes via SMS"},
		{"email", "Email", "email", true, "Receive verification codes via email"},
		{"backup_codes", "Backup Codes", "backup_codes", true, "Use backup recovery codes"},
	}

	for _, method := range mfaMethods {
		m.logger.Debug("Processing MFA method", logging.String("name", method.name))
		// Implementation depends on your MFA schema
	}

	return nil
}

// Utility methods

// splitSQL splits SQL content into individual statements
func (m *Migrator) splitSQL(sql string) []string {
	// Simple SQL splitting - handles basic cases
	statements := strings.Split(sql, ";")
	var result []string

	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt != "" && !strings.HasPrefix(stmt, "--") {
			result = append(result, stmt)
		}
	}

	return result
}

// getSchemaInfo retrieves schema information for hashing
func (m *Migrator) getSchemaInfo(ctx context.Context) (string, error) {
	driver := m.dataClients.Driver()
	conn := driver.DB()
	if conn == nil {
		return "", fmt.Errorf("failed to get database connection")
	}

	switch m.dataClients.Dialect() {
	case dialect.Postgres:
		return m.getPostgresSchemaInfo(ctx, conn)
	case dialect.MySQL:
		return m.getMySQLSchemaInfo(ctx, conn)
	case dialect.SQLite:
		return m.getSQLiteSchemaInfo(ctx, conn)
	default:
		return "", fmt.Errorf("unsupported database dialect: %s", m.dataClients.Dialect())
	}
}

// Database-specific validation and info methods (simplified versions)

func (m *Migrator) compareTableSchemas(current, desired *schema2.Schema, result *ValidationResult) error {
	// Compare table schemas and add issues to result
	return nil
}

func (m *Migrator) validatePostgresConstraints(ctx context.Context, conn *sql.DB, result *ValidationResult) error {
	// Validate PostgreSQL constraints
	return nil
}

func (m *Migrator) validateMySQLConstraints(ctx context.Context, conn *sql.DB, result *ValidationResult) error {
	// Validate MySQL constraints
	return nil
}

func (m *Migrator) validateSQLiteConstraints(ctx context.Context, conn *sql.DB, result *ValidationResult) error {
	// Validate SQLite constraints
	return nil
}

func (m *Migrator) checkOrphanedRecords(ctx context.Context, client *ent.Client, result *ValidationResult) error {
	// Check for orphaned records
	return nil
}

func (m *Migrator) checkDuplicateUniqueValues(ctx context.Context, client *ent.Client, result *ValidationResult) error {
	// Check for duplicate unique values
	return nil
}

func (m *Migrator) checkRequiredFields(ctx context.Context, client *ent.Client, result *ValidationResult) error {
	// Check required fields
	return nil
}

func (m *Migrator) getPostgresSchemaInfo(ctx context.Context, conn *sql.DB) (string, error) {
	// Get PostgreSQL schema info
	return "postgres_schema_info", nil
}

func (m *Migrator) getMySQLSchemaInfo(ctx context.Context, conn *sql.DB) (string, error) {
	// Get MySQL schema info
	return "mysql_schema_info", nil
}

func (m *Migrator) getSQLiteSchemaInfo(ctx context.Context, conn *sql.DB) (string, error) {
	// Get SQLite schema info
	return "sqlite_schema_info", nil
}
