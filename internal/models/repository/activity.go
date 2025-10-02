package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/rs/xid"
	"github.com/uptrace/bun"
	"github.com/xraph/frank/internal/models"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"go.uber.org/zap"
)

// ActivityRepository defines the interface for generic activity operations
type ActivityRepository interface {
	Create(ctx context.Context, activity *model.ActivityRecord) error
	CreateBulk(ctx context.Context, activities []*model.ActivityRecord) error
	GetByID(ctx context.Context, id xid.ID) (*model.ActivityRecord, error)
	List(ctx context.Context, req *GetActivitiesRequest) (*models.PaginatedOutput[*model.ActivityRecord], error)

	ListByResource(ctx context.Context, resourceType model.ResourceType, resourceID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error)
	ListByUser(ctx context.Context, userID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error)
	ListByOrganization(ctx context.Context, orgID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error)

	GetStats(ctx context.Context, req *ActivityStatsRequest) (*ActivityStats, error)
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

type activityRepository struct {
	db     *bun.DB
	logger logging.Logger
}

func NewActivityRepository(db *bun.DB, logger logging.Logger) ActivityRepository {
	return &activityRepository{
		db:     db,
		logger: logger,
	}
}

// Create creates a new activity record
func (r *activityRepository) Create(ctx context.Context, activityRecord *model.ActivityRecord) error {
	activity := &models.Activity{
		CommonModel:  models.CommonModel{ID: activityRecord.ID.String()},
		ResourceType: activityRecord.ResourceType,
		ResourceID:   activityRecord.ResourceID.String(),
		Action:       activityRecord.Action,
		Category:     activityRecord.Category,
		Success:      activityRecord.Success,
		Timestamp:    activityRecord.Timestamp,
	}

	// Set optional fields
	if activityRecord.UserID != nil {
		userID := activityRecord.UserID.String()
		activity.UserID = &userID
	}
	if activityRecord.OrganizationID != nil {
		orgID := activityRecord.OrganizationID.String()
		activity.OrganizationID = &orgID
	}
	if activityRecord.SessionID != nil {
		sessID := activityRecord.SessionID.String()
		activity.SessionID = &sessID
	}

	activity.Source = &activityRecord.Source
	activity.Endpoint = &activityRecord.Endpoint
	activity.Method = &activityRecord.Method

	if activityRecord.StatusCode != 0 {
		activity.StatusCode = &activityRecord.StatusCode
	}
	if activityRecord.ResponseTime != 0 {
		activity.ResponseTime = &activityRecord.ResponseTime
	}

	activity.IPAddress = &activityRecord.IPAddress
	activity.UserAgent = &activityRecord.UserAgent
	activity.Location = &activityRecord.Location
	activity.Error = &activityRecord.Error
	activity.ErrorCode = &activityRecord.ErrorCode

	if activityRecord.Size != 0 {
		activity.Size = &activityRecord.Size
	}
	if activityRecord.Count != 0 {
		activity.Count = &activityRecord.Count
	}
	if activityRecord.Value != 0 {
		activity.Value = &activityRecord.Value
	}

	activity.ExpiresAt = activityRecord.ExpiresAt
	activity.Metadata = activityRecord.Metadata
	activity.Tags = activityRecord.Tags

	_, err := r.db.NewInsert().
		Model(activity).
		Exec(ctx)

	if err != nil {
		r.logger.Error("Failed to create activity record", zap.Error(err),
			zap.String("resource_type", string(activityRecord.ResourceType)),
			zap.String("resource_id", activityRecord.ResourceID.String()),
		)
		return fmt.Errorf("creating activity record: %w", err)
	}

	return nil
}

// CreateBulk creates multiple activity records
func (r *activityRepository) CreateBulk(ctx context.Context, activities []*model.ActivityRecord) error {
	if len(activities) == 0 {
		return nil
	}

	bunActivities := make([]*models.Activity, len(activities))
	for i, record := range activities {
		activity := &models.Activity{
			CommonModel:  models.CommonModel{ID: record.ID.String()},
			ResourceType: record.ResourceType,
			ResourceID:   record.ResourceID.String(),
			Action:       record.Action,
			Category:     record.Category,
			Success:      record.Success,
			Timestamp:    record.Timestamp,
		}

		if record.UserID != nil {
			userID := record.UserID.String()
			activity.UserID = &userID
		}
		if record.OrganizationID != nil {
			orgID := record.OrganizationID.String()
			activity.OrganizationID = &orgID
		}

		bunActivities[i] = activity
	}

	_, err := r.db.NewInsert().
		Model(&bunActivities).
		Exec(ctx)

	if err != nil {
		r.logger.Error("Failed to create bulk activity records", zap.Error(err), zap.Int("count", len(activities)))
		return fmt.Errorf("creating bulk activity records: %w", err)
	}

	return nil
}

// GetByID retrieves an activity record by ID
func (r *activityRepository) GetByID(ctx context.Context, id xid.ID) (*model.ActivityRecord, error) {
	var activity models.Activity

	err := r.db.NewSelect().
		Model(&activity).
		Where("id = ?", id.String()).
		Scan(ctx)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("activity not found")
		}
		r.logger.Error("Failed to get activity by ID", zap.Error(err), zap.String("id", id.String()))
		return nil, fmt.Errorf("getting activity by ID: %w", err)
	}

	return r.toActivityRecord(&activity), nil
}

// List retrieves a paginated list of activities with filtering
func (r *activityRepository) List(ctx context.Context, req *GetActivitiesRequest) (*models.PaginatedOutput[*model.ActivityRecord], error) {
	query := r.db.NewSelect().Model((*models.Activity)(nil))

	// Apply filters
	query = r.applyFilters(query, req)

	return models.WithPaginationAndOptions[*model.ActivityRecord](ctx, query, req.PaginationParams)
}

// ListByResource retrieves activities for a specific resource
func (r *activityRepository) ListByResource(ctx context.Context, resourceType model.ResourceType, resourceID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error) {
	query := r.db.NewSelect().
		Model((*models.Activity)(nil)).
		Where("resource_type = ?", resourceType).
		Where("resource_id = ?", resourceID.String())

	query = r.applyQueryOptions(query, opts)

	var activities []*models.Activity
	err := query.Scan(ctx, &activities)
	if err != nil {
		r.logger.Error("Failed to list activities by resource", zap.Error(err))
		return nil, fmt.Errorf("listing activities by resource: %w", err)
	}

	result := make([]*model.ActivityRecord, len(activities))
	for i, act := range activities {
		result[i] = r.toActivityRecord(act)
	}

	return result, nil
}

// ListByUser retrieves activities for a specific user
func (r *activityRepository) ListByUser(ctx context.Context, userID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error) {
	query := r.db.NewSelect().
		Model((*models.Activity)(nil)).
		Where("user_id = ?", userID.String())

	query = r.applyQueryOptions(query, opts)

	var activities []*models.Activity
	err := query.Scan(ctx, &activities)
	if err != nil {
		r.logger.Error("Failed to list activities by user", zap.Error(err))
		return nil, fmt.Errorf("listing activities by user: %w", err)
	}

	result := make([]*model.ActivityRecord, len(activities))
	for i, act := range activities {
		result[i] = r.toActivityRecord(act)
	}

	return result, nil
}

// ListByOrganization retrieves activities for a specific organization
func (r *activityRepository) ListByOrganization(ctx context.Context, orgID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error) {
	query := r.db.NewSelect().
		Model((*models.Activity)(nil)).
		Where("organization_id = ?", orgID.String())

	query = r.applyQueryOptions(query, opts)

	var activities []*models.Activity
	err := query.Scan(ctx, &activities)
	if err != nil {
		r.logger.Error("Failed to list activities by organization", zap.Error(err))
		return nil, fmt.Errorf("listing activities by organization: %w", err)
	}

	result := make([]*model.ActivityRecord, len(activities))
	for i, act := range activities {
		result[i] = r.toActivityRecord(act)
	}

	return result, nil
}

// GetStats retrieves activity statistics
func (r *activityRepository) GetStats(ctx context.Context, req *ActivityStatsRequest) (*ActivityStats, error) {
	query := r.db.NewSelect().Model((*models.Activity)(nil))

	// Apply filters
	if req.ResourceType != "" {
		query = query.Where("resource_type = ?", req.ResourceType)
	}
	if req.ResourceID != nil {
		query = query.Where("resource_id = ?", req.ResourceID.String())
	}
	if req.UserID != nil {
		query = query.Where("user_id = ?", req.UserID.String())
	}
	if req.OrganizationID != nil {
		query = query.Where("organization_id = ?", req.OrganizationID.String())
	}
	if req.StartDate != nil {
		query = query.Where("timestamp >= ?", *req.StartDate)
	}
	if req.EndDate != nil {
		query = query.Where("timestamp <= ?", *req.EndDate)
	}

	// Get total count
	totalCount, err := query.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting total activity count: %w", err)
	}

	// Get success count
	successCount, err := query.Clone().Where("success = ?", true).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting success count: %w", err)
	}

	failedCount := totalCount - successCount
	successRate := 0.0
	if totalCount > 0 {
		successRate = float64(successCount) / float64(totalCount) * 100
	}

	// Get activities by action using raw query
	type ActionStat struct {
		Action string
		Count  int
	}
	var actionStats []ActionStat
	err = query.Clone().
		ColumnExpr("action, COUNT(*) as count").
		Group("action").
		Scan(ctx, &actionStats)
	if err != nil {
		return nil, fmt.Errorf("getting activities by action: %w", err)
	}

	activitiesByAction := make(map[string]int)
	for _, stat := range actionStats {
		activitiesByAction[stat.Action] = stat.Count
	}

	return &ActivityStats{
		TotalActivities:    totalCount,
		SuccessfulCount:    successCount,
		FailedCount:        failedCount,
		SuccessRate:        successRate,
		ActivitiesByAction: activitiesByAction,
		GeneratedAt:        time.Now(),
	}, nil
}

// DeleteExpired deletes expired activity records
func (r *activityRepository) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	result, err := r.db.NewDelete().
		Model((*models.Activity)(nil)).
		Where("expires_at < ?", before).
		WhereOr("(expires_at IS NULL AND timestamp < ?)", before).
		Exec(ctx)

	if err != nil {
		r.logger.Error("Failed to delete expired activities", zap.Time("before", before), zap.Error(err))
		return 0, fmt.Errorf("deleting expired activities: %w", err)
	}

	deleted, _ := result.RowsAffected()
	r.logger.Info("Deleted expired activities", zap.Int64("count", deleted), zap.Time("before", before))
	return int(deleted), nil
}

// Helper methods

func (r *activityRepository) applyFilters(query *bun.SelectQuery, req *GetActivitiesRequest) *bun.SelectQuery {
	if req.ResourceType != "" {
		query = query.Where("resource_type = ?", req.ResourceType)
	}
	if req.ResourceID != nil {
		query = query.Where("resource_id = ?", req.ResourceID.String())
	}
	if req.UserID != nil {
		query = query.Where("user_id = ?", req.UserID.String())
	}
	if req.OrganizationID != nil {
		query = query.Where("organization_id = ?", req.OrganizationID.String())
	}
	if req.Action != "" {
		query = query.Where("action = ?", req.Action)
	}
	if req.Category != "" {
		query = query.Where("category = ?", req.Category)
	}
	if req.Success != nil {
		query = query.Where("success = ?", *req.Success)
	}
	if req.StartDate != nil {
		query = query.Where("timestamp >= ?", *req.StartDate)
	}
	if req.EndDate != nil {
		query = query.Where("timestamp <= ?", *req.EndDate)
	}

	return query
}

func (r *activityRepository) applyQueryOptions(query *bun.SelectQuery, opts *ActivityQueryOptions) *bun.SelectQuery {
	if opts == nil {
		return query.Order("timestamp DESC").Limit(100)
	}

	if opts.StartDate != nil {
		query = query.Where("timestamp >= ?", *opts.StartDate)
	}
	if opts.EndDate != nil {
		query = query.Where("timestamp <= ?", *opts.EndDate)
	}
	if len(opts.Actions) > 0 {
		query = query.Where("action IN (?)", bun.In(opts.Actions))
	}
	if opts.Success != nil {
		query = query.Where("success = ?", *opts.Success)
	}

	// Apply ordering
	orderField := "timestamp"
	if opts.OrderBy != "" {
		orderField = opts.OrderBy
	}
	if opts.OrderDir == "asc" {
		query = query.Order(orderField + " ASC")
	} else {
		query = query.Order(orderField + " DESC")
	}

	// Apply pagination
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	query = query.Limit(limit)

	if opts.Offset > 0 {
		query = query.Offset(opts.Offset)
	}

	return query
}

func (r *activityRepository) toActivityRecord(activity *models.Activity) *model.ActivityRecord {
	record := &model.ActivityRecord{
		ID:           xid.ID{}, // Parse from activity.ID
		ResourceType: activity.ResourceType,
		ResourceID:   xid.ID{}, // Parse from activity.ResourceID
		Action:       activity.Action,
		Category:     activity.Category,
		Success:      activity.Success,
		Timestamp:    activity.Timestamp,
	}

	// Parse IDs
	if id, err := xid.FromString(activity.ID); err == nil {
		record.ID = id
	}
	if rid, err := xid.FromString(activity.ResourceID); err == nil {
		record.ResourceID = rid
	}

	// Set optional fields
	if activity.UserID != nil {
		if uid, err := xid.FromString(*activity.UserID); err == nil {
			record.UserID = &uid
		}
	}
	if activity.OrganizationID != nil {
		if oid, err := xid.FromString(*activity.OrganizationID); err == nil {
			record.OrganizationID = &oid
		}
	}

	if activity.Source != nil {
		record.Source = *activity.Source
	}
	if activity.Endpoint != nil {
		record.Endpoint = *activity.Endpoint
	}
	if activity.Method != nil {
		record.Method = *activity.Method
	}
	if activity.StatusCode != nil {
		record.StatusCode = *activity.StatusCode
	}
	if activity.ResponseTime != nil {
		record.ResponseTime = *activity.ResponseTime
	}
	if activity.IPAddress != nil {
		record.IPAddress = *activity.IPAddress
	}
	if activity.UserAgent != nil {
		record.UserAgent = *activity.UserAgent
	}
	if activity.Error != nil {
		record.Error = *activity.Error
	}

	record.ExpiresAt = activity.ExpiresAt
	record.Metadata = activity.Metadata
	record.Tags = activity.Tags

	return record
}

// Type definitions from original
type GetActivitiesRequest struct {
	model.PaginationParams
	ResourceType   model.ResourceType
	ResourceID     *xid.ID
	UserID         *xid.ID
	OrganizationID *xid.ID
	Action         string
	Category       string
	Success        *bool
	StartDate      *time.Time
	EndDate        *time.Time
}

type ActivityQueryOptions struct {
	Limit     int
	Offset    int
	StartDate *time.Time
	EndDate   *time.Time
	Actions   []string
	Success   *bool
	OrderBy   string
	OrderDir  string
}

type ActivityStatsRequest struct {
	ResourceType   model.ResourceType
	ResourceID     *xid.ID
	UserID         *xid.ID
	OrganizationID *xid.ID
	StartDate      *time.Time
	EndDate        *time.Time
}

type ActivityStats struct {
	TotalActivities    int
	SuccessfulCount    int
	FailedCount        int
	SuccessRate        float64
	ActivitiesByAction map[string]int
	GeneratedAt        time.Time
}
