package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"
	"github.com/xraph/frank/pkg/data"
)

// Error codes
const (
	CodeNotFound        = "NOT_FOUND"
	CodeConflict        = "CONFLICT"
	CodeDatabaseError   = "DATABASE_ERROR"
	CodeInternalServer  = "INTERNAL_SERVER"
	CodeValidationError = "VALIDATION_ERROR"
)

// Error types
type Error struct {
	Code    string
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	return e.Cause
}

// NewError creates a new error
func NewError(code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// WrapError wraps an error with additional context
func WrapError(err error, code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Cause:   err,
	}
}

// IsNotFoundError checks if error is a not found error
func IsNotFoundError(err error) bool {
	return err == sql.ErrNoRows
}

// IsDuplicateKeyError checks if error is a duplicate key error
func IsDuplicateKeyError(err error) bool {
	var pgErr *pgconn.PgError
	if err, ok := err.(*pgconn.PgError); ok {
		pgErr = err
	}
	if pgErr != nil {
		// PostgreSQL unique violation error code
		return pgErr.Code == "23505"
	}
	return strings.Contains(err.Error(), "duplicate key") ||
		strings.Contains(err.Error(), "UNIQUE constraint")
}

// Pagination types
type PaginationParams struct {
	Page     int
	PageSize int
	SortBy   string
	SortDir  string
}

type PaginatedOutput[T any] struct {
	Data       []T   `json:"data"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalPages int   `json:"total_pages"`
}

// DefaultPageSize is the default page size
const DefaultPageSize = 20

// MaxPageSize is the maximum page size
const MaxPageSize = 100

// Paginate applies pagination to a query
func Paginate[T any](ctx context.Context, query *bun.SelectQuery, params PaginationParams) (*PaginatedOutput[T], error) {
	// Set defaults
	if params.Page <= 0 {
		params.Page = 1
	}
	if params.PageSize <= 0 {
		params.PageSize = DefaultPageSize
	}
	if params.PageSize > MaxPageSize {
		params.PageSize = MaxPageSize
	}

	// Count total records
	total, err := query.Count(ctx)
	if err != nil {
		return nil, WrapError(err, CodeDatabaseError, "failed to count records")
	}

	// Calculate offset
	offset := (params.Page - 1) * params.PageSize

	// Apply sorting
	if params.SortBy != "" {
		sortDir := "ASC"
		if strings.ToUpper(params.SortDir) == "DESC" {
			sortDir = "DESC"
		}
		query = query.Order(fmt.Sprintf("%s %s", params.SortBy, sortDir))
	} else {
		// Default sort by created_at desc
		query = query.Order("created_at DESC")
	}

	// Apply pagination
	query = query.Limit(params.PageSize).Offset(offset)

	// Execute query
	var data []T
	err = query.Scan(ctx, &data)
	if err != nil {
		return nil, WrapError(err, CodeDatabaseError, "failed to fetch records")
	}

	// Calculate total pages
	totalPages := int(total) / params.PageSize
	if int(total)%params.PageSize != 0 {
		totalPages++
	}

	return &PaginatedOutput[T]{
		Data:       data,
		Total:      int64(total),
		Page:       params.Page,
		PageSize:   params.PageSize,
		TotalPages: totalPages,
	}, nil
}

// Transaction helper
func WithTransaction(ctx context.Context, db *data.DB, fn func(ctx context.Context, tx bun.Tx) error) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		return fn(ctx, tx)
	})
}

// Batch operations helper
type BatchOperation struct {
	tx bun.Tx
}

// NewBatchOperation creates a new batch operation
func NewBatchOperation(tx bun.Tx) *BatchOperation {
	return &BatchOperation{tx: tx}
}

// Insert adds an insert operation to the batch
func (b *BatchOperation) Insert(ctx context.Context, model interface{}) error {
	_, err := b.tx.NewInsert().Model(model).Exec(ctx)
	return err
}

// Update adds an update operation to the batch
func (b *BatchOperation) Update(ctx context.Context, model interface{}) error {
	_, err := b.tx.NewUpdate().Model(model).WherePK().Exec(ctx)
	return err
}

// Delete adds a delete operation to the batch
func (b *BatchOperation) Delete(ctx context.Context, model interface{}) error {
	_, err := b.tx.NewDelete().Model(model).WherePK().Exec(ctx)
	return err
}

// Query builder helpers

// BuildSearchQuery builds a search query with ILIKE
func BuildSearchQuery(query *bun.SelectQuery, searchTerm string, fields ...string) *bun.SelectQuery {
	if searchTerm == "" || len(fields) == 0 {
		return query
	}

	searchPattern := "%" + searchTerm + "%"
	conditions := make([]string, len(fields))
	args := make([]interface{}, len(fields))

	for i, field := range fields {
		conditions[i] = fmt.Sprintf("%s ILIKE ?", field)
		args[i] = searchPattern
	}

	whereClause := strings.Join(conditions, " OR ")
	return query.Where(whereClause, args...)
}

// BuildFilterQuery builds a filter query
func BuildFilterQuery(query *bun.SelectQuery, filters map[string]interface{}) *bun.SelectQuery {
	for field, value := range filters {
		if value != nil {
			query = query.Where(fmt.Sprintf("%s = ?", field), value)
		}
	}
	return query
}

// BuildDateRangeQuery builds a date range query
func BuildDateRangeQuery(query *bun.SelectQuery, field string, start, end interface{}) *bun.SelectQuery {
	if start != nil {
		query = query.Where(fmt.Sprintf("%s >= ?", field), start)
	}
	if end != nil {
		query = query.Where(fmt.Sprintf("%s <= ?", field), end)
	}
	return query
}

// Validation helpers

// ValidateID checks if an ID is valid
func ValidateID(id string) error {
	if id == "" {
		return NewError(CodeValidationError, "ID cannot be empty")
	}
	// Add more validation as needed (e.g., length, format)
	return nil
}

// ValidateEmail checks if an email is valid
func ValidateEmail(email string) error {
	if email == "" {
		return NewError(CodeValidationError, "Email cannot be empty")
	}
	// Add email format validation
	if !strings.Contains(email, "@") {
		return NewError(CodeValidationError, "Invalid email format")
	}
	return nil
}

// ValidateRequired checks if required fields are present
func ValidateRequired(fields map[string]interface{}) error {
	for name, value := range fields {
		if value == nil || value == "" {
			return NewError(CodeValidationError, fmt.Sprintf("%s is required", name))
		}
	}
	return nil
}

// Soft delete helpers

// SoftDeleteModel soft deletes a model
func SoftDeleteModel(ctx context.Context, db *data.DB, model interface{}, id string) error {
	_, err := db.NewUpdate().
		Model(model).
		Set("deleted_at = ?", bun.NullTime{Time: time.Now()}).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Exec(ctx)
	return err
}

// RestoreModel restores a soft-deleted model
func RestoreModel(ctx context.Context, db *data.DB, model interface{}, id string) error {
	_, err := db.NewUpdate().
		Model(model).
		Set("deleted_at = NULL").
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// ExcludeSoftDeleted adds soft delete filter to query
func ExcludeSoftDeleted(query *bun.SelectQuery) *bun.SelectQuery {
	return query.Where("deleted_at IS NULL")
}

// IncludeSoftDeleted removes soft delete filter (for admin queries)
func IncludeSoftDeleted(ctx context.Context) context.Context {
	return context.WithValue(ctx, "include_soft_deleted", true)
}

// ShouldIncludeSoftDeleted checks if soft deleted records should be included
func ShouldIncludeSoftDeleted(ctx context.Context) bool {
	val := ctx.Value("include_soft_deleted")
	if val == nil {
		return false
	}
	include, ok := val.(bool)
	return ok && include
}

// Repository base interface
type Repository interface {
	DB() *data.DB
}

// BaseRepository provides common repository functionality
type BaseRepository struct {
	db *data.DB
}

// NewBaseRepository creates a new base repository
func NewBaseRepository(db *data.DB) *BaseRepository {
	return &BaseRepository{db: db}
}

// DB returns the database instance
func (r *BaseRepository) DB() *data.DB {
	return r.db
}

// WithTx returns a new repository instance with a transaction
func (r *BaseRepository) WithTx(tx data.Tx) *BaseRepository {
	return &BaseRepository{db: tx}
}

// Exists checks if a record exists by ID
func Exists(ctx context.Context, db *data.DB, model interface{}, id string) (bool, error) {
	count, err := db.NewSelect().
		Model(model).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Count(ctx)
	return count > 0, err
}

// GetByID retrieves a record by ID
func GetByID[T any](ctx context.Context, db *data.DB, id string) (*T, error) {
	model := new(T)
	err := db.NewSelect().
		Model(model).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Record not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get record")
	}
	return model, nil
}

// Create creates a new record
func Create[T any](ctx context.Context, db *data.DB, model *T) error {
	_, err := db.NewInsert().Model(model).Exec(ctx)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return NewError(CodeConflict, "Record already exists")
		}
		return WrapError(err, CodeDatabaseError, "failed to create record")
	}
	return nil
}

// Update updates a record
func Update[T any](ctx context.Context, db *data.DB, model *T) error {
	_, err := db.NewUpdate().Model(model).WherePK().Exec(ctx)
	if err != nil {
		return WrapError(err, CodeDatabaseError, "failed to update record")
	}
	return nil
}

// Delete deletes a record
func Delete[T any](ctx context.Context, db *data.DB, id string) error {
	model := new(T)
	_, err := db.NewDelete().Model(model).Where("id = ?", id).Exec(ctx)
	if err != nil {
		return WrapError(err, CodeDatabaseError, "failed to delete record")
	}
	return nil
}

// BulkInsert inserts multiple records
func BulkInsert[T any](ctx context.Context, db *data.DB, models []T) error {
	if len(models) == 0 {
		return nil
	}
	_, err := db.NewInsert().Model(&models).Exec(ctx)
	if err != nil {
		return WrapError(err, CodeDatabaseError, "failed to bulk insert records")
	}
	return nil
}

// BulkUpdate updates multiple records
func BulkUpdate[T any](ctx context.Context, db *data.DB, models []T) error {
	if len(models) == 0 {
		return nil
	}

	return WithTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		for _, model := range models {
			if _, err := tx.NewUpdate().Model(&model).WherePK().Exec(ctx); err != nil {
				return err
			}
		}
		return nil
	})
}

// CountAll counts all records
func CountAll[T any](ctx context.Context, db *data.DB) (int, error) {
	model := new(T)
	count, err := db.NewSelect().
		Model(model).
		Where("deleted_at IS NULL").
		Count(ctx)
	return count, err
}

// ListAll retrieves all records
func ListAll[T any](ctx context.Context, db *data.DB) ([]T, error) {
	var models []T
	err := db.NewSelect().
		Model(&models).
		Where("deleted_at IS NULL").
		Scan(ctx)
	return models, err
}

// Cache helper types and functions
type CacheKey struct {
	Prefix string
	ID     string
}

func (k CacheKey) String() string {
	return fmt.Sprintf("%s:%s", k.Prefix, k.ID)
}

// BuildCacheKey builds a cache key
func BuildCacheKey(prefix, id string) string {
	return CacheKey{Prefix: prefix, ID: id}.String()
}
