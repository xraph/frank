package models

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/uptrace/bun"
	"github.com/xraph/frank/pkg/errors"
)

// BunQuery interface defines the methods needed for pagination with Bun
type BunQuery interface {
	Limit(int) *bun.SelectQuery
	Offset(int) *bun.SelectQuery
	Order(order string, orders ...string) *bun.SelectQuery
	Column(columns ...string) *bun.SelectQuery
	Count(ctx context.Context) (int, error)
	Scan(ctx context.Context, dest ...interface{}) error
}

// WithPagination is a generic function that adds pagination to a bun query.
// It accepts a query builder, pagination options, and returns a PaginatedOutput.
func WithPagination[T any](
	ctx context.Context,
	query *bun.SelectQuery,
	first *int,
	after *string,
	last *int,
	before *string,
) (*PaginatedOutput[T], error) {
	// Get total count for pagination info
	totalCount, err := query.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("counting total items: %w", err)
	}

	// Default limit if not provided
	limit := 10
	// Handle cursor-based pagination
	offset := 0

	// Forward pagination (first/after)
	if first != nil {
		limit = *first
		if after != nil {
			decodedCursor, err := decodeCursor(*after)
			if err != nil {
				return nil, fmt.Errorf("decoding cursor: %w", err)
			}
			offset = decodedCursor
		}
	}

	// Backward pagination (last/before)
	if last != nil {
		limit = *last
		if before != nil {
			decodedCursor, err := decodeCursor(*before)
			if err != nil {
				return nil, fmt.Errorf("decoding cursor: %w", err)
			}
			// For backward pagination, calculate the correct offset
			offset = decodedCursor - *last
			if offset < 0 {
				offset = 0
				limit = decodedCursor
			}
		} else {
			// If only "last" is provided without "before", get items from the end
			offset = totalCount - *last
			if offset < 0 {
				offset = 0
				limit = totalCount
			}
		}
	}

	// Apply pagination to query and get results
	var items []T
	err = query.Limit(limit).Offset(offset).Scan(ctx, &items)
	if err != nil {
		return nil, fmt.Errorf("querying items: %w", err)
	}

	// Build pagination info
	pagination := &Pagination{
		TotalCount:      totalCount,
		HasNextPage:     (offset + len(items)) < totalCount,
		HasPreviousPage: offset > 0,
	}

	// Set cursors if we have items
	if len(items) > 0 {
		startCursor := encodeCursor(offset)
		pagination.StartCursor = &startCursor

		endCursor := encodeCursor(offset + len(items) - 1)
		pagination.EndCursor = &endCursor
	}

	return &PaginatedOutput[T]{
		Data:       items,
		Pagination: pagination,
	}, nil
}

// WithPageNavigation adds page-based navigation functionality to the pagination system
func WithPageNavigation[T any](
	ctx context.Context,
	query *bun.SelectQuery,
	opts PaginationParams,
) (*PaginatedOutput[T], error) {
	// If page parameter is provided, convert it to offset/limit
	if opts.Page > 0 {
		// Default page size to limit if specified, otherwise use 20
		pageSize := opts.Limit
		if pageSize <= 0 {
			pageSize = 20
		}

		// Calculate offset based on page number (1-indexed)
		opts.Offset = (opts.Page - 1) * pageSize
		opts.Limit = pageSize

		// Clear cursor-based pagination params to avoid conflicts
		opts.After = ""
		opts.Before = ""
		opts.First = 0
		opts.Last = 0
	}

	// Use the existing pagination function with the updated parameters
	return WithPaginationAndOptions[T](ctx, query, opts)
}

// WithPaginationAndOptions is a comprehensive function that adds pagination to bun queries
// with support for field selection and ordering.
func WithPaginationAndOptions[T any](
	ctx context.Context,
	query *bun.SelectQuery,
	opts PaginationParams,
) (*PaginatedOutput[T], error) {
	// If page parameter is provided, convert it to offset/limit
	if opts.Page > 0 {
		// Default page size to limit if specified, otherwise use 20
		pageSize := opts.Limit
		if pageSize <= 0 {
			pageSize = 20
		}

		// Calculate offset based on page number (1-indexed)
		opts.Offset = (opts.Page - 1) * pageSize
		opts.Limit = pageSize

		// Clear cursor-based pagination params to avoid conflicts
		opts.After = ""
		opts.Before = ""
		opts.First = 0
		opts.Last = 0
	}

	// Clone the query for counting to avoid modifying the original
	countQuery := query.Clone()

	// Get total count for pagination info
	totalCount, err := countQuery.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("counting total items: %w", err)
	}

	// Default limit if not provided
	limit := 20
	if opts.Limit > 0 {
		limit = opts.Limit
	}

	// Handle cursor-based pagination
	offset := opts.Offset

	// Forward pagination (first/after)
	if opts.First != 0 {
		limit = opts.First
		if opts.After != "" && opts.After != "null" && opts.After != "undefined" {
			decodedCursor, err := decodeCursor(opts.After)
			if err != nil {
				return nil, fmt.Errorf("decoding cursor: %w", err)
			}
			offset = decodedCursor
		}
	}

	// Backward pagination (last/before)
	if opts.Last != 0 {
		limit = opts.Last
		if opts.Before != "" && opts.Before != "null" && opts.Before != "undefined" {
			decodedCursor, err := decodeCursor(opts.Before)
			if err != nil {
				return nil, fmt.Errorf("decoding cursor: %w", err)
			}
			// For backward pagination, calculate the correct offset
			offset = decodedCursor - opts.Last
			if offset < 0 {
				offset = 0
				limit = decodedCursor
			}
		} else {
			// If only "last" is provided without "before", get items from the end
			offset = totalCount - opts.Last
			if offset < 0 {
				offset = 0
				limit = totalCount
			}
		}
	}

	// Apply field selection if specified
	if len(opts.Fields) > 0 {
		query = query.Column(opts.Fields...)
	}

	// Apply ordering if specified
	if len(opts.OrderBy) > 0 {
		orders := parseOrderBy(opts.OrderBy)
		if len(orders) > 0 {
			query = query.Order(orders[0], orders[1])
		}
	}

	// Apply limit and offset for pagination
	query = query.Limit(limit).Offset(offset)

	// Execute query to get paginated results
	var items []T
	err = query.Scan(ctx, &items)
	if err != nil {
		return nil, fmt.Errorf("querying items: %w", err)
	}

	effectiveLimit := limit
	if opts.Limit > 0 {
		effectiveLimit = opts.Limit
	}

	// Build pagination info
	pagination := &Pagination{
		TotalCount:      totalCount,
		HasNextPage:     (offset + len(items)) < totalCount,
		HasPreviousPage: offset > 0,
		CurrentPage:     offset/effectiveLimit + 1,
		TotalPages:      (totalCount + effectiveLimit - 1) / effectiveLimit, // Ceiling division
		PageSize:        effectiveLimit,
		Limit:           effectiveLimit,
		Offset:          offset,
	}

	// Set cursors if we have items
	if len(items) > 0 {
		startCursor := encodeCursor(offset)
		pagination.StartCursor = &startCursor

		endCursor := encodeCursor(offset + len(items) - 1)
		pagination.EndCursor = &endCursor
	}

	return &PaginatedOutput[T]{
		Data:       items,
		Pagination: pagination,
	}, nil
}

// parseOrderBy converts OrderBy string array to Bun-compatible order strings
// Format: "field:asc" or "field:desc" -> "field ASC" or "field DESC"
func parseOrderBy(orderBy []string) []string {
	orders := make([]string, 0, len(orderBy))

	for _, order := range orderBy {
		parts := strings.Split(order, ":")
		if len(parts) != 2 {
			// If format is invalid, skip this ordering
			continue
		}

		field := strings.TrimSpace(parts[0])
		direction := strings.ToUpper(strings.TrimSpace(parts[1]))

		// Validate direction
		if direction != "ASC" && direction != "DESC" {
			// Default to ASC if invalid
			direction = "ASC"
		}

		orders = append(orders, fmt.Sprintf("%s %s", field, direction))
	}

	return orders
}

// GetOrdering extracts ordering options from pagination params
func GetOrdering(opts PaginationParams) []OrderOption {
	orderings := []OrderOption{}

	// Apply ordering if specified
	if len(opts.OrderBy) > 0 {
		for _, order := range opts.OrderBy {
			orders := strings.Split(order, ":")
			if len(orders) != 2 {
				continue
			}
			orderField := orders[0]
			orderDesc := strings.ToLower(orders[1]) == "desc"

			orderings = append(orderings, OrderOption{
				Field: orderField,
				Desc:  orderDesc,
			})
		}
	}

	return orderings
}

// ApplyOrderOptions applies ordering to a Bun query
func ApplyOrderOptions(query *bun.SelectQuery, options []OrderOption) *bun.SelectQuery {
	if len(options) == 0 {
		return query
	}

	orders := make([]string, len(options))
	for i, opt := range options {
		direction := "ASC"
		if opt.Desc {
			direction = "DESC"
		}
		orders[i] = fmt.Sprintf("%s %s", opt.Field, direction)
	}

	if len(orders) > 0 {
		query = query.Order(orders[0], orders[1])
	}

	return query
}

// OrderOption represents a field ordering option
type OrderOption struct {
	Field string // Field name to order by
	Desc  bool   // If true, order in descending order; otherwise ascending
}

// Helper functions for cursor encoding/decoding
func encodeCursor(offset int) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", offset)))
}

func decodeCursor(cursor string) (int, error) {
	decoded, err := base64.StdEncoding.DecodeString(cursor)
	if err != nil {
		return 0, err
	}

	offset, err := strconv.Atoi(string(decoded))
	if err != nil {
		return 0, err
	}

	return offset, nil
}

// Pagination represents the structure for handling paginated data.
// HasNextPage indicates if more items exist after the requested range.
// HasPreviousPage indicates if more items exist before the requested range.
// StartCursor is the cursor pointing to the first item in the current range.
// EndCursor is the cursor pointing to the last item in the current range.
// TotalCount provides the total number of items available across all pages.
type Pagination struct {
	// Indicates whether more items exist after the requested range
	HasNextPage bool `json:"hasNextPage" xml:"hasNextPage" example:"true" doc:"Whether there are more results"`
	// Indicates whether more items exist before the requested range
	HasPreviousPage bool `json:"hasPreviousPage" xml:"hasPreviousPage"`
	// Cursor for the first item
	StartCursor *string `json:"startCursor" xml:"startCursor"`
	// Cursor for the last item
	EndCursor *string `json:"endCursor" xml:"endCursor"`
	// Total number of items
	TotalCount int `json:"totalCount" xml:"totalCount" example:"100" doc:"Total number of documents"`
	Limit      int `json:"limit" xml:"limit"`
	Offset     int `json:"offset" xml:"offset"`

	CurrentPage int `json:"currentPage" xml:"currentPage"`
	TotalPages  int `json:"totalPages" xml:"totalPages"`
	PageSize    int `json:"pageSize" xml:"pageSize"`
}

// PaginationInfo is an alias for backward compatibility
type PaginationInfo = Pagination

// PaginatedOutput provides a generic structure for paginated responses, containing data and pagination metadata.
type PaginatedOutput[T any] struct {
	Data       []T         `json:"data" required:"true"`
	Pagination *Pagination `json:"pagination"`
}

type BasicParams struct {
	Fields []string `json:"fields" xml:"fields" query:"fields"`
}

type PaginationParams struct {
	After   string   `json:"after" xml:"after" query:"after"`
	Before  string   `json:"before" xml:"before" query:"before"`
	First   int      `json:"first" xml:"first" query:"first"`
	Last    int      `json:"last" xml:"last" query:"last"`
	Limit   int      `json:"limit" xml:"limit" query:"limit"`
	Offset  int      `json:"offset" xml:"offset" query:"offset"`
	Fields  []string `json:"fields" xml:"fields" query:"fields"`
	OrderBy []string `json:"orderBy" xml:"orderBy" query:"orderBy"`

	// Add page navigation support
	Page int `json:"page" xml:"page" query:"page"`
}

// SimplePaginationParams for cases where you only need limit/offset
type SimplePaginationParams struct {
	Limit  int `json:"limit" query:"limit"`
	Offset int `json:"offset" query:"offset"`
}

// ToPaginationParams converts SimplePaginationParams to full PaginationParams
func (s SimplePaginationParams) ToPaginationParams() PaginationParams {
	return PaginationParams{
		Limit:  s.Limit,
		Offset: s.Offset,
	}
}

// QuickPaginate is a convenience function for simple limit/offset pagination
func QuickPaginate[T any](
	ctx context.Context,
	query *bun.SelectQuery,
	limit, offset int,
) (*PaginatedOutput[T], error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	return WithPaginationAndOptions[T](ctx, query, PaginationParams{
		Limit:  limit,
		Offset: offset,
	})
}

// PaginateWithOrder is a convenience function for pagination with ordering
func PaginateWithOrder[T any](
	ctx context.Context,
	query *bun.SelectQuery,
	limit, offset int,
	orderBy ...string,
) (*PaginatedOutput[T], error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	return WithPaginationAndOptions[T](ctx, query, PaginationParams{
		Limit:   limit,
		Offset:  offset,
		OrderBy: orderBy,
	})
}

// CursorPaginate is a convenience function for cursor-based pagination
func CursorPaginate[T any](
	ctx context.Context,
	query *bun.SelectQuery,
	first int,
	after string,
) (*PaginatedOutput[T], error) {
	if first <= 0 {
		first = 20
	}
	if first > 100 {
		first = 100
	}

	return WithPaginationAndOptions[T](ctx, query, PaginationParams{
		First: first,
		After: after,
	})
}

// ValidatePaginationParams validates and normalizes pagination parameters
func ValidatePaginationParams(params *PaginationParams) error {
	// Validate limit
	if params.Limit < 0 {
		return errors.New(errors.CodeBadRequest, "limit must be non-negative")
	}
	if params.Limit > 1000 {
		return errors.New(errors.CodeBadRequest, "limit cannot exceed 1000")
	}

	// Validate offset
	if params.Offset < 0 {
		return errors.New(errors.CodeBadRequest, "offset must be non-negative")
	}

	// Validate page
	if params.Page < 0 {
		return errors.New(errors.CodeBadRequest, "page must be non-negative")
	}

	// Validate first/last
	if params.First < 0 {
		return errors.New(errors.CodeBadRequest, "first must be non-negative")
	}
	if params.Last < 0 {
		return errors.New(errors.CodeBadRequest, "last must be non-negative")
	}
	if params.First > 0 && params.Last > 0 {
		return errors.New(errors.CodeBadRequest, "cannot specify both first and last")
	}

	// Normalize empty cursor strings
	if params.After == "null" || params.After == "undefined" {
		params.After = ""
	}
	if params.Before == "null" || params.Before == "undefined" {
		params.Before = ""
	}

	return nil
}
