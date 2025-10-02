// Package migration provides enhanced database migration synchronization functionality
// for handling migration state mismatches and format changes in the Wakflo SaaS platform.
package migration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/xraph/frank/pkg/data"
	"github.com/xraph/frank/pkg/logging"
)

// SyncOptions represents options for migration synchronization
type SyncOptions struct {
	DryRun         bool  `json:"dryRun"`
	Force          bool  `json:"force"`
	TargetVersion  *uint `json:"targetVersion,omitempty"`
	SkipValidation bool  `json:"skipValidation"`
	CreateMissing  bool  `json:"createMissing"`
	UpdateExisting bool  `json:"updateExisting"`
}

// SyncResult represents the result of a migration synchronization
type SyncResult struct {
	Success           bool                `json:"success"`
	CurrentVersion    uint                `json:"currentVersion"`
	TargetVersion     uint                `json:"targetVersion"`
	SyncedMigrations  []MigrationSyncInfo `json:"syncedMigrations"`
	SkippedMigrations []MigrationSyncInfo `json:"skippedMigrations"`
	Errors            []string            `json:"errors"`
	DatabaseState     *DatabaseState      `json:"databaseState"`
	Duration          time.Duration       `json:"duration"`
}

// MigrationSyncInfo represents information about a migration sync operation
type MigrationSyncInfo struct {
	Version    uint                `json:"version"`
	Name       string              `json:"name"`
	Action     MigrationSyncAction `json:"action"`
	Status     MigrationSyncStatus `json:"status"`
	Error      string              `json:"error,omitempty"`
	ExecutedAt time.Time           `json:"executedAt"`
}

// MigrationSyncAction represents the action taken during sync
type MigrationSyncAction string

const (
	SyncActionApply    MigrationSyncAction = "apply"
	SyncActionSkip     MigrationSyncAction = "skip"
	SyncActionMark     MigrationSyncAction = "mark"
	SyncActionRollback MigrationSyncAction = "rollback"
	SyncActionForce    MigrationSyncAction = "force"
)

// MigrationSyncStatus represents the status of a sync action
type MigrationSyncStatus string

const (
	SyncStatusSuccess MigrationSyncStatus = "success"
	SyncStatusFailed  MigrationSyncStatus = "failed"
	SyncStatusSkipped MigrationSyncStatus = "skipped"
	SyncStatusPending MigrationSyncStatus = "pending"
)

// DatabaseState represents the current state of the database schema
type DatabaseState struct {
	Version     uint               `json:"version"`
	Dirty       bool               `json:"dirty"`
	Tables      []TableInfo        `json:"tables"`
	Indexes     []IndexInfo        `json:"indexes"`
	Constraints []ConstraintInfo   `json:"constraints"`
	Migrations  []AppliedMigration `json:"migrations"`
	LastUpdated time.Time          `json:"lastUpdated"`
}

// TableInfo represents information about a database table
type TableInfo struct {
	Name    string       `json:"name"`
	Columns []ColumnInfo `json:"columns"`
	Exists  bool         `json:"exists"`
}

// ColumnInfo represents information about a table column
type ColumnInfo struct {
	Name         string `json:"name"`
	DataType     string `json:"dataType"`
	IsNullable   bool   `json:"isNullable"`
	DefaultValue string `json:"defaultValue,omitempty"`
}

// IndexInfo represents information about a database index
type IndexInfo struct {
	Name      string   `json:"name"`
	TableName string   `json:"tableName"`
	Columns   []string `json:"columns"`
	IsUnique  bool     `json:"isUnique"`
	Exists    bool     `json:"exists"`
}

// ConstraintInfo represents information about a database constraint
type ConstraintInfo struct {
	Name       string `json:"name"`
	TableName  string `json:"tableName"`
	Type       string `json:"type"`
	Definition string `json:"definition"`
	Exists     bool   `json:"exists"`
}

// AppliedMigration represents a migration that has been applied
type AppliedMigration struct {
	Version   uint      `json:"version"`
	Dirty     bool      `json:"dirty"`
	AppliedAt time.Time `json:"appliedAt"`
}

// MigrationSyncer handles database migration synchronization
type MigrationSyncer struct {
	dataClients *data.Clients
	logger      logging.Logger
	migrate     *migrate.Migrate
}

// NewMigrationSyncer creates a new migration syncer
func NewMigrationSyncer(dataClients *data.Clients, logger logging.Logger, migrate *migrate.Migrate) *MigrationSyncer {
	return &MigrationSyncer{
		dataClients: dataClients,
		logger:      logger.Named("migration-syncer"),
		migrate:     migrate,
	}
}

// SyncMigrationState synchronizes the migration state with the actual database schema
func (ms *MigrationSyncer) SyncMigrationState(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	startTime := time.Now()

	ms.logger.Info("Starting migration state synchronization",
		logging.Bool("dryRun", opts.DryRun),
		logging.Bool("force", opts.Force))

	result := &SyncResult{
		SyncedMigrations:  make([]MigrationSyncInfo, 0),
		SkippedMigrations: make([]MigrationSyncInfo, 0),
		Errors:            make([]string, 0),
	}

	// Get current database state
	dbState, err := ms.analyzeDatabaseState(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze database state: %w", err)
	}
	result.DatabaseState = dbState
	result.CurrentVersion = dbState.Version

	// Get available migrations
	availableMigrations, err := ms.getAvailableMigrations()
	if err != nil {
		return nil, fmt.Errorf("failed to get available migrations: %w", err)
	}

	// Determine target version
	targetVersion := opts.TargetVersion
	if targetVersion == nil {
		if len(availableMigrations) > 0 {
			latest := availableMigrations[len(availableMigrations)-1]
			targetVersion = &latest
		} else {
			v := uint(0)
			targetVersion = &v
		}
	}
	result.TargetVersion = *targetVersion

	// Plan synchronization
	syncPlan, err := ms.createSyncPlan(ctx, dbState, availableMigrations, *targetVersion, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create sync plan: %w", err)
	}

	// Execute synchronization plan
	if !opts.DryRun {
		err = ms.executeSyncPlan(ctx, syncPlan, result)
		if err != nil {
			result.Success = false
			result.Errors = append(result.Errors, err.Error())
		} else {
			result.Success = true
		}
	} else {
		result.Success = true
		ms.logger.Info("Dry run completed - no changes applied")
	}

	result.Duration = time.Since(startTime)
	return result, nil
}

// analyzeDatabaseState analyzes the current state of the database
func (ms *MigrationSyncer) analyzeDatabaseState(ctx context.Context) (*DatabaseState, error) {
	driver := ms.dataClients.Driver()
	conn := driver.DB()
	if conn == nil {
		return nil, fmt.Errorf("failed to get database connection")
	}

	state := &DatabaseState{
		Tables:      make([]TableInfo, 0),
		Indexes:     make([]IndexInfo, 0),
		Constraints: make([]ConstraintInfo, 0),
		Migrations:  make([]AppliedMigration, 0),
		LastUpdated: time.Now(),
	}

	// Get current migration version
	if ms.migrate != nil {
		version, dirty, err := ms.migrate.Version()
		if err != nil && err != migrate.ErrNilVersion {
			ms.logger.Warn("Failed to get migration version", logging.Error(err))
		} else if err != migrate.ErrNilVersion {
			state.Version = version
			state.Dirty = dirty
		}
	}

	// Analyze tables
	tables, err := ms.analyzeTables(ctx, conn)
	if err != nil {
		ms.logger.Warn("Failed to analyze tables", logging.Error(err))
	} else {
		state.Tables = tables
	}

	// Analyze indexes
	indexes, err := ms.analyzeIndexes(ctx, conn)
	if err != nil {
		ms.logger.Warn("Failed to analyze indexes", logging.Error(err))
	} else {
		state.Indexes = indexes
	}

	// Analyze constraints
	constraints, err := ms.analyzeConstraints(ctx, conn)
	if err != nil {
		ms.logger.Warn("Failed to analyze constraints", logging.Error(err))
	} else {
		state.Constraints = constraints
	}

	// Get applied migrations
	migrations, err := ms.getAppliedMigrations(ctx, conn)
	if err != nil {
		ms.logger.Warn("Failed to get applied migrations", logging.Error(err))
	} else {
		state.Migrations = migrations
	}

	return state, nil
}

// getAvailableMigrations returns a list of available migration versions
func (ms *MigrationSyncer) getAvailableMigrations() ([]uint, error) {
	// Read migration files from the actual directory
	migrationsDir := "migrations" // or use the configured path

	files, err := os.ReadDir(migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read migration directory %s: %w", migrationsDir, err)
	}

	var versions []uint
	versionMap := make(map[uint]bool)

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filename := file.Name()

		// Skip non-SQL files
		if !strings.HasSuffix(filename, ".sql") {
			continue
		}

		// Extract version from filename
		// Expected format: {version}_{title}.up.sql or {version}_{title}.down.sql
		parts := strings.Split(filename, "_")
		if len(parts) < 2 {
			continue
		}

		versionStr := parts[0]
		version, err := strconv.ParseUint(versionStr, 10, 64)
		if err != nil {
			ms.logger.Warn("Invalid migration version in filename",
				logging.String("filename", filename),
				logging.String("version", versionStr),
				logging.Error(err))
			continue
		}

		// Add to map to avoid duplicates (up and down files have same version)
		versionMap[uint(version)] = true
	}

	// Convert map to sorted slice
	for version := range versionMap {
		versions = append(versions, version)
	}

	sort.Slice(versions, func(i, j int) bool {
		return versions[i] < versions[j]
	})

	ms.logger.Debug("Found migration versions", logging.Any("versions", versions))
	return versions, nil
}

// createSyncPlan creates a plan for synchronizing migrations
func (ms *MigrationSyncer) createSyncPlan(ctx context.Context, dbState *DatabaseState,
	availableMigrations []uint, targetVersion uint, opts SyncOptions) ([]MigrationSyncInfo, error) {

	var plan []MigrationSyncInfo
	appliedVersions := make(map[uint]bool)

	for _, migration := range dbState.Migrations {
		appliedVersions[migration.Version] = true
	}

	for _, version := range availableMigrations {
		if version > targetVersion {
			break
		}

		syncInfo := MigrationSyncInfo{
			Version:    version,
			Name:       fmt.Sprintf("migration_%05d", version),
			Status:     SyncStatusPending,
			ExecutedAt: time.Now(),
		}

		if appliedVersions[version] {
			if version <= dbState.Version {
				// Already applied and tracked
				syncInfo.Action = SyncActionSkip
				syncInfo.Status = SyncStatusSkipped
			} else {
				// Applied but not properly tracked
				if opts.UpdateExisting {
					syncInfo.Action = SyncActionMark
				} else {
					syncInfo.Action = SyncActionSkip
					syncInfo.Status = SyncStatusSkipped
				}
			}
		} else {
			// Need to apply
			if ms.migrationNeedsSchema(version) && ms.schemaAlreadyExists(ctx, version) {
				// Schema exists but migration not marked as applied
				if opts.Force {
					syncInfo.Action = SyncActionMark
				} else {
					syncInfo.Action = SyncActionSkip
					syncInfo.Status = SyncStatusSkipped
					syncInfo.Error = "schema exists but migration not applied - use force to mark as applied"
				}
			} else {
				syncInfo.Action = SyncActionApply
			}
		}

		plan = append(plan, syncInfo)
	}

	return plan, nil
}

// executeSyncPlan executes the synchronization plan
func (ms *MigrationSyncer) executeSyncPlan(ctx context.Context, plan []MigrationSyncInfo, result *SyncResult) error {
	for _, syncInfo := range plan {
		switch syncInfo.Action {
		case SyncActionApply:
			err := ms.applyMigration(ctx, syncInfo.Version)
			if err != nil {
				syncInfo.Status = SyncStatusFailed
				syncInfo.Error = err.Error()
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to apply migration %d: %v", syncInfo.Version, err))
			} else {
				syncInfo.Status = SyncStatusSuccess
			}

		case SyncActionMark:
			err := ms.markMigrationAsApplied(ctx, syncInfo.Version)
			if err != nil {
				syncInfo.Status = SyncStatusFailed
				syncInfo.Error = err.Error()
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to mark migration %d as applied: %v", syncInfo.Version, err))
			} else {
				syncInfo.Status = SyncStatusSuccess
			}

		case SyncActionSkip:
			syncInfo.Status = SyncStatusSkipped
			result.SkippedMigrations = append(result.SkippedMigrations, syncInfo)
			continue

		case SyncActionRollback:
			err := ms.rollbackMigration(ctx, syncInfo.Version)
			if err != nil {
				syncInfo.Status = SyncStatusFailed
				syncInfo.Error = err.Error()
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to rollback migration %d: %v", syncInfo.Version, err))
			} else {
				syncInfo.Status = SyncStatusSuccess
			}
		}

		if syncInfo.Status == SyncStatusSuccess || syncInfo.Status == SyncStatusSkipped {
			result.SyncedMigrations = append(result.SyncedMigrations, syncInfo)
		}

		ms.logger.Info("Migration sync step completed",
			logging.Uint64("version", uint64(syncInfo.Version)),
			logging.String("action", string(syncInfo.Action)),
			logging.String("status", string(syncInfo.Status)),
			logging.String("error", syncInfo.Error))
	}

	return nil
}

// applyMigration applies a specific migration
func (ms *MigrationSyncer) applyMigration(ctx context.Context, version uint) error {
	if ms.migrate == nil {
		return fmt.Errorf("migrate instance not available")
	}

	// Get current version
	currentVersion, _, err := ms.migrate.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if err == migrate.ErrNilVersion {
		currentVersion = 0
	}

	// Apply migration
	if version > currentVersion {
		err = ms.migrate.Migrate(version)
		if err != nil && err != migrate.ErrNoChange {
			return fmt.Errorf("failed to migrate to version %d: %w", version, err)
		}
	}

	return nil
}

// markMigrationAsApplied marks a migration as applied without running it
func (ms *MigrationSyncer) markMigrationAsApplied(ctx context.Context, version uint) error {
	driver := ms.dataClients.Driver()
	conn := driver.DB()
	if conn == nil {
		return fmt.Errorf("failed to get database connection")
	}

	// Insert into schema_migrations table (or equivalent)
	// This depends on your migration tracking table structure
	query := `INSERT INTO schema_migrations (version, dirty) VALUES ($1, false) 
			  ON CONFLICT (version) DO UPDATE SET dirty = false`

	_, err := conn.ExecContext(ctx, query, version)
	if err != nil {
		return fmt.Errorf("failed to mark migration %d as applied: %w", version, err)
	}

	ms.logger.Info("Marked migration as applied", logging.Uint64("version", uint64(version)))
	return nil
}

// rollbackMigration rolls back a specific migration
func (ms *MigrationSyncer) rollbackMigration(ctx context.Context, version uint) error {
	if ms.migrate == nil {
		return fmt.Errorf("migrate instance not available")
	}

	err := ms.migrate.Migrate(version - 1)
	if err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to rollback to version %d: %w", version-1, err)
	}

	return nil
}

// migrationNeedsSchema checks if a migration creates schema objects
func (ms *MigrationSyncer) migrationNeedsSchema(version uint) bool {
	// This would typically analyze the migration file content
	// For now, assume migrations 1 and 2 create schema
	return version <= 2
}

// schemaAlreadyExists checks if the schema for a migration already exists
func (ms *MigrationSyncer) schemaAlreadyExists(ctx context.Context, version uint) bool {
	driver := ms.dataClients.Driver()
	conn := driver.DB()
	if conn == nil {
		return false
	}

	// Check for key tables that would be created by the migration
	// This is specific to your migration content
	switch version {
	case 1:
		// Check if enum types exist (setup_enums migration)
		return ms.checkEnumTypesExist(ctx, conn)
	case 2:
		// Check if main tables exist (initial_schema migration)
		return ms.checkMainTablesExist(ctx, conn)
	default:
		return false
	}
}

// Database-specific analysis methods

func (ms *MigrationSyncer) analyzeTables(ctx context.Context, conn *sql.DB) ([]TableInfo, error) {
	var tables []TableInfo

	// This is PostgreSQL-specific - adjust for other databases
	query := `
		SELECT table_name, column_name, data_type, is_nullable, column_default
		FROM information_schema.columns 
		WHERE table_schema = 'public' 
		ORDER BY table_name, ordinal_position`

	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tableMap := make(map[string]*TableInfo)

	for rows.Next() {
		var tableName, columnName, dataType, isNullable string
		var columnDefault sql.NullString

		err := rows.Scan(&tableName, &columnName, &dataType, &isNullable, &columnDefault)
		if err != nil {
			return nil, err
		}

		if _, exists := tableMap[tableName]; !exists {
			tableMap[tableName] = &TableInfo{
				Name:    tableName,
				Columns: make([]ColumnInfo, 0),
				Exists:  true,
			}
		}

		column := ColumnInfo{
			Name:         columnName,
			DataType:     dataType,
			IsNullable:   isNullable == "YES",
			DefaultValue: columnDefault.String,
		}

		tableMap[tableName].Columns = append(tableMap[tableName].Columns, column)
	}

	for _, table := range tableMap {
		tables = append(tables, *table)
	}

	return tables, nil
}

func (ms *MigrationSyncer) analyzeIndexes(ctx context.Context, conn *sql.DB) ([]IndexInfo, error) {
	var indexes []IndexInfo

	// PostgreSQL-specific query
	query := `
		SELECT i.relname as index_name, t.relname as table_name, ix.indisunique,
			   array_agg(a.attname ORDER BY a.attnum) as columns
		FROM pg_class t, pg_class i, pg_index ix, pg_attribute a
		WHERE t.oid = ix.indrelid
		AND i.oid = ix.indexrelid
		AND a.attrelid = t.oid
		AND a.attnum = ANY(ix.indkey)
		AND t.relkind = 'r'
		AND t.relname NOT LIKE 'pg_%'
		GROUP BY i.relname, t.relname, ix.indisunique
		ORDER BY t.relname, i.relname`

	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var indexName, tableName string
		var isUnique bool
		var columnsArray string

		err := rows.Scan(&indexName, &tableName, &isUnique, &columnsArray)
		if err != nil {
			return nil, err
		}

		// Parse PostgreSQL array format
		columns := strings.Split(strings.Trim(columnsArray, "{}"), ",")

		indexes = append(indexes, IndexInfo{
			Name:      indexName,
			TableName: tableName,
			Columns:   columns,
			IsUnique:  isUnique,
			Exists:    true,
		})
	}

	return indexes, nil
}

func (ms *MigrationSyncer) analyzeConstraints(ctx context.Context, conn *sql.DB) ([]ConstraintInfo, error) {
	var constraints []ConstraintInfo

	// PostgreSQL-specific query
	query := `
		SELECT con.conname, cls.relname, con.contype,
			   pg_get_constraintdef(con.oid) as definition
		FROM pg_constraint con
		JOIN pg_class cls ON con.conrelid = cls.oid
		WHERE cls.relname NOT LIKE 'pg_%'
		ORDER BY cls.relname, con.conname`

	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var constraintName, tableName, constraintType, definition string

		err := rows.Scan(&constraintName, &tableName, &constraintType, &definition)
		if err != nil {
			return nil, err
		}

		constraints = append(constraints, ConstraintInfo{
			Name:       constraintName,
			TableName:  tableName,
			Type:       constraintType,
			Definition: definition,
			Exists:     true,
		})
	}

	return constraints, nil
}

func (ms *MigrationSyncer) getAppliedMigrations(ctx context.Context, conn *sql.DB) ([]AppliedMigration, error) {
	var migrations []AppliedMigration

	// Check if schema_migrations table exists
	existsQuery := `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = 'schema_migrations'
		)`

	var exists bool
	err := conn.QueryRowContext(ctx, existsQuery).Scan(&exists)
	if err != nil {
		return migrations, err
	}

	if !exists {
		return migrations, nil
	}

	// Get applied migrations
	query := `SELECT version, dirty FROM schema_migrations ORDER BY version`
	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var version uint64
		var dirty bool

		err := rows.Scan(&version, &dirty)
		if err != nil {
			return nil, err
		}

		migrations = append(migrations, AppliedMigration{
			Version:   uint(version),
			Dirty:     dirty,
			AppliedAt: time.Now(), // This would be actual timestamp if stored
		})
	}

	return migrations, nil
}

func (ms *MigrationSyncer) checkEnumTypesExist(ctx context.Context, conn *sql.DB) bool {
	query := `SELECT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'auth_handler_type')`
	var exists bool
	err := conn.QueryRowContext(ctx, query).Scan(&exists)
	return err == nil && exists
}

func (ms *MigrationSyncer) checkMainTablesExist(ctx context.Context, conn *sql.DB) bool {
	query := `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'api_keys')`
	var exists bool
	err := conn.QueryRowContext(ctx, query).Scan(&exists)
	return err == nil && exists
}

// RepairMigrationState attempts to repair a corrupted migration state
func (ms *MigrationSyncer) RepairMigrationState(ctx context.Context, force bool) error {
	ms.logger.Info("Starting migration state repair", logging.Bool("force", force))

	driver := ms.dataClients.Driver()
	conn := driver.DB()
	if conn == nil {
		return fmt.Errorf("failed to get database connection")
	}

	// Clear dirty state
	query := `UPDATE schema_migrations SET dirty = false WHERE dirty = true`
	_, err := conn.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to clear dirty state: %w", err)
	}

	// Force unlock migration if using golang-migrate
	if ms.migrate != nil {
		err = ms.migrate.Force(-1)
		if err != nil {
			ms.logger.Warn("Failed to force unlock migration", logging.Error(err))
		}
	}

	ms.logger.Info("Migration state repair completed")
	return nil
}
