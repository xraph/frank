package repository

import (
	"context"
	"database/sql"
	errors2 "errors"
	"fmt"
	"time"

	"github.com/rs/xid"
	"github.com/uptrace/bun"
	"github.com/xraph/frank/internal/models"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/model"
)

type AuditRepository interface {
	Create(ctx context.Context, input CreateAuditInput) (*models.Audit, error)
	GetByID(ctx context.Context, id xid.ID) (*models.Audit, error)
	Delete(ctx context.Context, id xid.ID) error

	ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error)
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error)
	ListByAction(ctx context.Context, action string, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error)
	ListByResourceType(ctx context.Context, resourceType string, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error)

	ListByTimeRange(ctx context.Context, from, to time.Time, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error)
	ListFailedActions(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error)

	CountByUserAndAction(ctx context.Context, userID xid.ID, action string, since time.Time) (int, error)
	GetActionStats(ctx context.Context, orgID xid.ID, since time.Time) (map[string]int, error)
	GetComplianceReport(ctx context.Context, orgID xid.ID, from, to time.Time) (*ComplianceReport, error)

	DeleteOldLogs(ctx context.Context, before time.Time) (int, error)
}

type auditRepository struct {
	db *bun.DB
}

func NewAuditRepository(db *bun.DB) AuditRepository {
	return &auditRepository{db: db}
}

type CreateAuditInput struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SessionID      *xid.ID
	Action         string
	ResourceType   string
	ResourceID     *xid.ID
	Status         string
	IPAddress      *string
	UserAgent      *string
	Location       *string
	DeviceID       *string
	RequestID      *string
	ErrorCode      *string
	ErrorMessage   *string
	Description    *string
	Metadata       map[string]any
	OldValues      map[string]any
	CurrentValues  map[string]any
	Timestamp      time.Time
}

type ComplianceReport struct {
	OrganizationID   xid.ID
	ReportPeriod     string
	From             time.Time
	To               time.Time
	TotalEvents      int
	SuccessfulEvents int
	FailedEvents     int
	UniqueUsers      int
	ActionBreakdown  map[string]int
}

func (r *auditRepository) Create(ctx context.Context, input CreateAuditInput) (*models.Audit, error) {
	audit := &models.Audit{
		CommonModel:  models.CommonModel{ID: xid.New().String()},
		Action:       input.Action,
		ResourceType: input.ResourceType,
		Status:       input.Status,
		Timestamp:    input.Timestamp,
	}

	if input.UserID != nil {
		userID := input.UserID.String()
		audit.UserID = &userID
	}
	if input.OrganizationID != nil {
		orgID := input.OrganizationID.String()
		audit.OrganizationID = &orgID
	}
	if input.SessionID != nil {
		sessID := input.SessionID.String()
		audit.SessionID = &sessID
	}
	if input.ResourceID != nil {
		resID := input.ResourceID.String()
		audit.ResourceID = &resID
	}

	audit.IPAddress = input.IPAddress
	audit.UserAgent = input.UserAgent
	audit.Location = input.Location
	audit.DeviceID = input.DeviceID
	audit.RequestID = input.RequestID
	audit.ErrorCode = input.ErrorCode
	audit.ErrorMessage = input.ErrorMessage
	audit.Description = input.Description
	audit.Metadata = input.Metadata
	audit.OldValues = input.OldValues
	audit.CurrentValues = input.CurrentValues

	_, err := r.db.NewInsert().
		Model(audit).
		Exec(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to create audit log")
	}

	return audit, nil
}

func (r *auditRepository) GetByID(ctx context.Context, id xid.ID) (*models.Audit, error) {
	var audit models.Audit

	err := r.db.NewSelect().
		Model(&audit).
		Where("id = ?", id.String()).
		Where("deleted_at IS NULL").
		Relation("User").
		Relation("Organization").
		Relation("Session").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "Audit log not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get audit log")
	}

	return &audit, nil
}

func (r *auditRepository) Delete(ctx context.Context, id xid.ID) error {
	result, err := r.db.NewDelete().
		Model((*models.Audit)(nil)).
		Where("id = ?", id.String()).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete audit log")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New(errors.CodeNotFound, "Audit log not found")
	}

	return nil
}

func (r *auditRepository) ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error) {
	return r.listWithPagination(ctx, opts, func(query *bun.SelectQuery) *bun.SelectQuery {
		return query.Where("user_id = ?", userID.String())
	})
}

func (r *auditRepository) ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error) {
	return r.listWithPagination(ctx, opts, func(query *bun.SelectQuery) *bun.SelectQuery {
		return query.Where("organization_id = ?", orgID.String())
	})
}

func (r *auditRepository) ListByAction(ctx context.Context, action string, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error) {
	return r.listWithPagination(ctx, opts, func(query *bun.SelectQuery) *bun.SelectQuery {
		return query.Where("action = ?", action)
	})
}

func (r *auditRepository) ListByResourceType(ctx context.Context, resourceType string, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error) {
	return r.listWithPagination(ctx, opts, func(query *bun.SelectQuery) *bun.SelectQuery {
		return query.Where("resource_type = ?", resourceType)
	})
}

func (r *auditRepository) ListByTimeRange(ctx context.Context, from, to time.Time, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error) {
	return r.listWithPagination(ctx, opts, func(query *bun.SelectQuery) *bun.SelectQuery {
		return query.
			Where("timestamp >= ?", from).
			Where("timestamp <= ?", to)
	})
}

func (r *auditRepository) ListFailedActions(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*models.Audit], error) {
	return r.listWithPagination(ctx, opts, func(query *bun.SelectQuery) *bun.SelectQuery {
		return query.Where("status = ?", "failure")
	})
}

func (r *auditRepository) CountByUserAndAction(ctx context.Context, userID xid.ID, action string, since time.Time) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.Audit)(nil)).
		Where("user_id = ?", userID.String()).
		Where("action = ?", action).
		Where("timestamp >= ?", since).
		Where("deleted_at IS NULL").
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count audit logs by user and action")
	}

	return count, nil
}

func (r *auditRepository) GetActionStats(ctx context.Context, orgID xid.ID, since time.Time) (map[string]int, error) {
	type ActionStat struct {
		Action string
		Count  int
	}

	var results []ActionStat
	err := r.db.NewSelect().
		Model((*models.Audit)(nil)).
		ColumnExpr("action, COUNT(*) as count").
		Where("organization_id = ?", orgID.String()).
		Where("timestamp >= ?", since).
		Where("deleted_at IS NULL").
		Group("action").
		Scan(ctx, &results)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get action statistics")
	}

	stats := make(map[string]int)
	for _, result := range results {
		stats[result.Action] = result.Count
	}

	return stats, nil
}

func (r *auditRepository) GetComplianceReport(ctx context.Context, orgID xid.ID, from, to time.Time) (*ComplianceReport, error) {
	report := &ComplianceReport{
		OrganizationID: orgID,
		From:           from,
		To:             to,
		ReportPeriod:   fmt.Sprintf("%s to %s", from.Format("2006-01-02"), to.Format("2006-01-02")),
	}

	baseQuery := r.db.NewSelect().
		Model((*models.Audit)(nil)).
		Where("organization_id = ?", orgID.String()).
		Where("timestamp >= ?", from).
		Where("timestamp <= ?", to).
		Where("deleted_at IS NULL")

	// Count total events
	totalEvents, err := baseQuery.Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count total events")
	}
	report.TotalEvents = totalEvents

	// Count successful events
	successfulEvents, err := baseQuery.Clone().
		Where("status = ?", "success").
		Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count successful events")
	}
	report.SuccessfulEvents = successfulEvents
	report.FailedEvents = totalEvents - successfulEvents

	var uniqueUsers int
	// Get unique users count
	err = baseQuery.Clone().
		Where("user_id IS NOT NULL").
		ColumnExpr("COUNT(DISTINCT user_id)").
		Scan(ctx, &uniqueUsers)
	if err == nil {
		report.UniqueUsers = uniqueUsers
	}

	// Get action breakdown
	type ActionStat struct {
		Action string
		Count  int
	}
	var actionStats []ActionStat
	err = baseQuery.Clone().
		ColumnExpr("action, COUNT(*) as count").
		Group("action").
		Scan(ctx, &actionStats)
	if err == nil {
		report.ActionBreakdown = make(map[string]int)
		for _, stat := range actionStats {
			report.ActionBreakdown[stat.Action] = stat.Count
		}
	}

	return report, nil
}

func (r *auditRepository) DeleteOldLogs(ctx context.Context, before time.Time) (int, error) {
	result, err := r.db.NewDelete().
		Model((*models.Audit)(nil)).
		Where("timestamp < ?", before).
		Exec(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete old audit logs")
	}

	deleted, _ := result.RowsAffected()
	return int(deleted), nil
}

// Helper method for common list pattern
func (r *auditRepository) listWithPagination(
	ctx context.Context,
	opts model.PaginationParams,
	filter func(*bun.SelectQuery) *bun.SelectQuery,
) (*model.PaginatedOutput[*models.Audit], error) {
	query := r.db.NewSelect().
		Model((*models.Audit)(nil)).
		Where("deleted_at IS NULL").
		Relation("User").
		Relation("Organization").
		Relation("Session")

	// Apply custom filter
	query = filter(query)

	// Count total
	total, err := query.Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count audit logs")
	}

	// Apply pagination and ordering
	limit := opts.Limit
	if limit == 0 {
		limit = 20
	}

	query = query.
		Order("timestamp DESC").
		Limit(limit).
		Offset(opts.Offset)

	var audits []*models.Audit
	err = query.Scan(ctx, &audits)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list audit logs")
	}

	return &model.PaginatedOutput[*models.Audit]{
		Data: audits,
		Pagination: &model.Pagination{
			TotalCount: total,
			Limit:      limit,
			Offset:     opts.Offset,
		},
	}, nil
}
