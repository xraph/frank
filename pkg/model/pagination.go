package model

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/juicycleff/frank/pkg/errors"
)

// WithPagination is a generic function that adds pagination to an ent query.
// It accepts a query builder, pagination options, and returns a PaginatedOutput.
func WithPagination[T any, Q interface {
	Limit(int) Q
	Offset(int) Q
	Count(context.Context) (int, error)
	All(context.Context) ([]T, error)
}](ctx context.Context, query Q, first *int, after *string, last *int, before *string) (*PaginatedOutput[T], error) {
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
	items, err := query.Limit(limit).Offset(offset).All(ctx)
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

type Entity[D any, Q any, O any, S any] interface {
	Limit(int) Q
	Offset(int) Q
	Order(o ...O) Q
	Select(o ...string) S
	Count(context.Context) (int, error)
	All(context.Context) ([]D, error)
}

// WithPageNavigation adds page-based navigation functionality to the pagination system
func WithPageNavigation[T any, Q Entity[T, Q, O, S], O any, S any](
	ctx context.Context,
	queryBuilder any,
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
	return WithPaginationAndOptions[T, Q, O, S](ctx, queryBuilder, opts)
}

// WithPaginationAndOptions is a comprehensive function that adds pagination to entgo queries
// with support for field selection and ordering, specifically handling entgo's query patterns.
func WithPaginationAndOptions[T any, Q Entity[T, Q, O, S], O any, S any](
	ctx context.Context,
	queryBuilder any,
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

	// Cast the query builder to the appropriate type based on its methods
	var totalCount int
	var err error
	var items []T

	entityQuery, ok := queryBuilder.(Entity[T, Q, O, S])
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "query builder does not support Limit/Offset/Order methods")
	}

	// // Apply ordering if specified
	// if len(opts.OrderBy) > 0 {
	// 	for _, order := range opts.OrderBy {
	// 		orders := strings.Split(order, ":")
	// 		if len(orders) != 2 {
	// 			continue
	// 		}
	// 		orderField := orders[0]
	// 		orderDesc := strings.ToLower(orders[1]) == "desc"
	//
	// 		var ord any
	// 		var d func(*sql.Selector)
	// 		if orderDesc {
	// 			d = ent.Desc(orderField)
	// 		} else {
	// 			d = ent.Asc(orderField)
	// 		}
	//
	// 		entityQuery.Order(ord.(O))
	//
	// 	}
	// }

	// Get total count for pagination info
	totalCount, err = entityQuery.Count(ctx)
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
		queryBuilder = entityQuery.Select(opts.Fields...)
	}

	// Apply limit and offset for pagination
	queryBuilder = entityQuery.Limit(limit)
	queryBuilder = entityQuery.Offset(offset)

	// Execute query to get paginated results
	items, err = entityQuery.All(ctx)
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

// // QueryOptions groups all query parameters for pagination, ordering, and field selection
// type QueryOptions struct {
// 	First   *int          // Number of items to return (forward pagination)
// 	After   *string       // Cursor after which to start (forward pagination)
// 	Last    *int          // Number of items to return (backward pagination)
// 	Before  *string       // Cursor before which to start (backward pagination)
// 	Fields  []string      // Fields to include in the response
// 	OrderBy []OrderOption // Ordering configuration
// }

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
	HasNextPage bool `json:"hasNextPage" xml:"hasNextPage"  example:"true" doc:"Whether there are more results"`
	// Indicates whether more items exist before the requested range
	HasPreviousPage bool `json:"hasPreviousPage" xml:"hasPreviousPage"`
	// Cursor for the first item
	StartCursor *string `json:"startCursor" xml:"startCursor"`
	// Cursor for the last item
	EndCursor *string `json:"endCursor" xml:"endCursor"`
	// Total number of items
	TotalCount int `json:"totalCount" xml:"totalCount" example:"100" doc:"Total number of documents"`

	CurrentPage int `json:"currentPage" xml:"currentPage"`
	TotalPages  int `json:"totalPages" xml:"totalPages"`
	PageSize    int `json:"pageSize" xml:"pageSize"`
}

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

func GetOrdering(
	opts PaginationParams,
) []OrderOption {
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

			// var ord any
			// var d func(*sql.Selector)
			// if orderDesc {
			// 	d = ent.Desc(orderField)
			// } else {
			// 	d = ent.Asc(orderField)
			// }
			//
			// entityQuery.Order(ord.(O))

			orderings = append(orderings, OrderOption{
				Field: orderField,
				Desc:  orderDesc,
			})

		}
	}

	return orderings
}
