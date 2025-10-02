package models

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/uptrace/bun"
)

// Hook types for lifecycle events

// SoftDeleteHook automatically filters soft-deleted records
type SoftDeleteHook struct{}

func (h *SoftDeleteHook) BeforeSelectQuery(ctx context.Context, query *bun.SelectQuery) error {
	// Skip soft delete filter if explicitly requested
	if ShouldSkipSoftDelete(ctx) {
		return nil
	}

	// Add deleted_at IS NULL condition
	query.Where("deleted_at IS NULL")
	return nil
}

// TimestampHook automatically manages timestamps
type TimestampHook struct{}

func (h *TimestampHook) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	now := time.Now()

	switch q := query.(type) {
	case *bun.InsertQuery:
		if tm, ok := q.GetModel().(interface{ SetCreatedAt(time.Time) }); ok {
			tm.SetCreatedAt(now)
		}
		if tm, ok := q.GetModel().(interface{ SetUpdatedAt(time.Time) }); ok {
			tm.SetUpdatedAt(now)
		}
	case *bun.UpdateQuery:
		if tm, ok := q.GetModel().(interface{ SetUpdatedAt(time.Time) }); ok {
			tm.SetUpdatedAt(now)
		}
	}

	return nil
}

// AuditLogHook logs changes to audit table
type AuditLogHook struct {
	db *bun.DB
}

func NewAuditLogHook(db *bun.DB) *AuditLogHook {
	return &AuditLogHook{db: db}
}

func (h *AuditLogHook) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	// Only audit CUD operations
	operation := event.Query

	switch operation {
	case "INSERT", "UPDATE", "DELETE":
		// Extract model information and log to audit table
		// This is a simplified version - you'd want to extract actual values
		go h.logAudit(ctx, operation, event)
	}
}

func (h *AuditLogHook) logAudit(ctx context.Context, operation string, event *bun.QueryEvent) {
	// Implement audit logging logic here
	// This would create an Audit record based on the operation
}

// Validation hooks

// ValidationHook validates models before insert/update
type ValidationHook struct{}

func (h *ValidationHook) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	model := query.GetModel()

	// Check if model implements Validator interface
	if validator, ok := model.(interface{ Validate() error }); ok {
		if err := validator.Validate(); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}

	return nil
}

// Migration helpers

// CreateIndexes creates indexes for a model
func CreateIndexes(ctx context.Context, db *bun.DB, model interface{}, indexes []Index) error {
	tableName := getTableName(model)

	for _, idx := range indexes {
		query := fmt.Sprintf("CREATE")

		if idx.Unique {
			query += " UNIQUE"
		}

		query += fmt.Sprintf(" INDEX IF NOT EXISTS %s ON %s (%s)",
			idx.Name,
			tableName,
			idx.Columns,
		)

		if _, err := db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("failed to create index %s: %w", idx.Name, err)
		}
	}

	return nil
}

// Index represents a database index
type Index struct {
	Name    string
	Columns string
	Unique  bool
}

// GetTableName extracts table name from model
func getTableName(model interface{}) string {
	t := reflect.TypeOf(model)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	// Check for bun.CommonModel and extract table name
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Type == reflect.TypeOf(bun.BaseModel{}) {
			tag := field.Tag.Get("bun")
			if tag != "" {
				// Parse table name from tag
				// Simplified - you'd want a more robust parser
				return tag
			}
		}
	}

	return ""
}

// Helper functions for common operations

// SoftDeleteRecord soft deletes a record
func SoftDeleteRecord(ctx context.Context, db *bun.DB, model interface{}) error {
	if sd, ok := model.(interface{ Delete() }); ok {
		sd.Delete()
		_, err := db.NewUpdate().
			Model(model).
			WherePK().
			Exec(ctx)
		return err
	}
	return fmt.Errorf("model does not support soft delete")
}

// RestoreRecord restores a soft-deleted record
func RestoreRecord(ctx context.Context, db *bun.DB, model interface{}) error {
	if sd, ok := model.(interface{ Restore() }); ok {
		sd.Restore()
		// Use SkipSoftDelete context to update deleted records
		ctx = SkipSoftDelete(ctx)
		_, err := db.NewUpdate().
			Model(model).
			WherePK().
			Exec(ctx)
		return err
	}
	return fmt.Errorf("model does not support soft delete restore")
}

// HardDeleteRecord permanently deletes a record
func HardDeleteRecord(ctx context.Context, db *bun.DB, model interface{}) error {
	ctx = SkipSoftDelete(ctx)
	_, err := db.NewDelete().
		Model(model).
		WherePK().
		Exec(ctx)
	return err
}

// Query builders with soft delete support

// NewSelectQuery creates a select query with soft delete filtering
func NewSelectQuery(db *bun.DB, model interface{}) *bun.SelectQuery {
	query := db.NewSelect().Model(model)

	// Check if model has soft delete
	if _, ok := model.(interface{ IsDeleted() bool }); ok {
		query.Where("deleted_at IS NULL")
	}

	return query
}

// Batch operations

// BulkInsert inserts multiple records efficiently
func BulkInsert(ctx context.Context, db *bun.DB, models interface{}) error {
	_, err := db.NewInsert().
		Model(models).
		Exec(ctx)
	return err
}

// BulkUpdate updates multiple records
func BulkUpdate(ctx context.Context, db *bun.DB, models interface{}) error {
	_, err := db.NewUpdate().
		Model(models).
		Bulk().
		Exec(ctx)
	return err
}

// Transaction helpers

// WithTransaction executes function within a transaction
func WithTransaction(ctx context.Context, db *bun.DB, fn func(tx bun.Tx) error) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		return fn(tx)
	})
}

// Repository pattern helper

// Repository provides common CRUD operations
type Repository[T any] struct {
	db *bun.DB
}

// NewRepository creates a new repository
func NewRepository[T any](db *bun.DB) *Repository[T] {
	return &Repository[T]{db: db}
}

// FindByID finds a record by ID
func (r *Repository[T]) FindByID(ctx context.Context, id string) (*T, error) {
	var model T
	err := r.db.NewSelect().
		Model(&model).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return &model, nil
}

// Create creates a new record
func (r *Repository[T]) Create(ctx context.Context, model *T) error {
	_, err := r.db.NewInsert().
		Model(model).
		Exec(ctx)
	return err
}

// Update updates a record
func (r *Repository[T]) Update(ctx context.Context, model *T) error {
	_, err := r.db.NewUpdate().
		Model(model).
		WherePK().
		Exec(ctx)
	return err
}

// Delete soft deletes a record
func (r *Repository[T]) Delete(ctx context.Context, id string) error {
	var model T
	_, err := r.db.NewUpdate().
		Model(&model).
		Set("deleted_at = ?", time.Now()).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// FindAll finds all records with pagination
func (r *Repository[T]) FindAll(ctx context.Context, limit, offset int) ([]T, error) {
	var models []T
	err := r.db.NewSelect().
		Model(&models).
		Where("deleted_at IS NULL").
		Limit(limit).
		Offset(offset).
		Scan(ctx)
	return models, err
}

// Count counts records
func (r *Repository[T]) Count(ctx context.Context) (int, error) {
	return r.db.NewSelect().
		Model((*T)(nil)).
		Where("deleted_at IS NULL").
		Count(ctx)
}

// Exists checks if a record exists
func (r *Repository[T]) Exists(ctx context.Context, id string) (bool, error) {
	count, err := r.db.NewSelect().
		Model((*T)(nil)).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Count(ctx)
	return count > 0, err
}
