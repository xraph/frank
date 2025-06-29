package repository

import (
	"context"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/activity"
	"github.com/xraph/frank/pkg/data"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"go.uber.org/zap"
)

// ActivityRepository defines the interface for generic activity operations
type ActivityRepository interface {
	// Basic CRUD
	Create(ctx context.Context, activity *model.ActivityRecord) error
	CreateBulk(ctx context.Context, activities []*model.ActivityRecord) error
	GetByID(ctx context.Context, id xid.ID) (*model.ActivityRecord, error)
	List(ctx context.Context, req *GetActivitiesRequest) (*model.PaginatedOutput[*model.ActivityRecord], error)

	// Resource-specific queries
	ListByResource(ctx context.Context, resourceType model.ResourceType, resourceID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error)
	ListByUser(ctx context.Context, userID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error)
	ListByOrganization(ctx context.Context, orgID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error)

	// Analytics queries
	GetStats(ctx context.Context, req *ActivityStatsRequest) (*ActivityStats, error)
	GetUsageMetrics(ctx context.Context, req *UsageMetricsRequest) (*UsageMetrics, error)
	GetTrendAnalysis(ctx context.Context, req *TrendAnalysisRequest) (*TrendAnalysis, error)

	// Maintenance
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
	ArchiveOld(ctx context.Context, before time.Time) error

	// Performance queries
	GetHourlyStats(ctx context.Context, resourceType string, hours int) (map[string]int, error)
	GetPopularEndpoints(ctx context.Context, organizationID *xid.ID, limit int) ([]EndpointStats, error)
	GetErrorRates(ctx context.Context, resourceType string, organizationID *xid.ID) (*ErrorRateStats, error)
}

// Query types for the generic activity system

// GetActivitiesRequest for listing activities with filters
type GetActivitiesRequest struct {
	model.PaginationParams

	// Resource filters
	ResourceType  model.ResourceType   `json:"resourceType,omitempty"`
	ResourceID    *xid.ID              `json:"resourceId,omitempty"`
	ResourceTypes []model.ResourceType `json:"resourceTypes,omitempty"`

	// Context filters
	UserID         *xid.ID `json:"userId,omitempty"`
	OrganizationID *xid.ID `json:"organizationId,omitempty"`
	SessionID      *xid.ID `json:"sessionId,omitempty"`

	// Action filters
	Action     string   `json:"action,omitempty"`
	Actions    []string `json:"actions,omitempty"`
	Category   string   `json:"category,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Source     string   `json:"source,omitempty"`
	Sources    []string `json:"sources,omitempty"`

	// API-specific filters
	Endpoint    string `json:"endpoint,omitempty"`
	Method      string `json:"method,omitempty"`
	StatusCode  int    `json:"statusCode,omitempty"`
	StatusCodes []int  `json:"statusCodes,omitempty"`

	// Result filters
	Success   *bool  `json:"success,omitempty"`
	ErrorCode string `json:"errorCode,omitempty"`

	// Time filters
	StartDate *time.Time `json:"startDate,omitempty"`
	EndDate   *time.Time `json:"endDate,omitempty"`

	// Location filters
	IPAddress string `json:"ipAddress,omitempty"`
	Location  string `json:"location,omitempty"`

	// Performance filters
	MinResponseTime int `json:"minResponseTime,omitempty"`
	MaxResponseTime int `json:"maxResponseTime,omitempty"`
	MinSize         int `json:"minSize,omitempty"`
	MaxSize         int `json:"maxSize,omitempty"`

	// Tag filters
	Tags    []string `json:"tags,omitempty"`
	HasTags bool     `json:"hasTags,omitempty"`

	// Search
	Search string `json:"search,omitempty"`
}

// ActivityQueryOptions for simpler queries
type ActivityQueryOptions struct {
	Limit     int        `json:"limit"`
	Offset    int        `json:"offset"`
	StartDate *time.Time `json:"startDate,omitempty"`
	EndDate   *time.Time `json:"endDate,omitempty"`
	Actions   []string   `json:"actions,omitempty"`
	Success   *bool      `json:"success,omitempty"`
	OrderBy   string     `json:"orderBy,omitempty"`  // "timestamp", "response_time", etc.
	OrderDir  string     `json:"orderDir,omitempty"` // "asc", "desc"
}

// ActivityStatsRequest for getting activity statistics
type ActivityStatsRequest struct {
	ResourceType   model.ResourceType `json:"resourceType,omitempty"`
	ResourceID     *xid.ID            `json:"resourceId,omitempty"`
	UserID         *xid.ID            `json:"userId,omitempty"`
	OrganizationID *xid.ID            `json:"organizationId,omitempty"`
	StartDate      *time.Time         `json:"startDate,omitempty"`
	EndDate        *time.Time         `json:"endDate,omitempty"`
	Granularity    string             `json:"granularity,omitempty"` // "hour", "day", "week", "month"
}

// ActivityStats response
type ActivityStats struct {
	TotalActivities    int                `json:"totalActivities"`
	SuccessfulCount    int                `json:"successfulCount"`
	FailedCount        int                `json:"failedCount"`
	SuccessRate        float64            `json:"successRate"`
	ActivitiesByAction map[string]int     `json:"activitiesByAction"`
	ActivitiesBySource map[string]int     `json:"activitiesBySource"`
	ActivitiesByHour   map[string]int     `json:"activitiesByHour"`
	ActivitiesByDay    map[string]int     `json:"activitiesByDay"`
	TopEndpoints       []EndpointStats    `json:"topEndpoints"`
	ErrorRates         *ErrorRateStats    `json:"errorRates"`
	ResponseTimeStats  *ResponseTimeStats `json:"responseTimeStats"`
	UniqueUsers        int                `json:"uniqueUsers"`
	UniqueIPs          int                `json:"uniqueIps"`
	PeakHour           string             `json:"peakHour"`
	GeneratedAt        time.Time          `json:"generatedAt"`
}

// UsageMetricsRequest for usage analytics
type UsageMetricsRequest struct {
	ResourceType   model.ResourceType `json:"resourceType"`
	OrganizationID *xid.ID            `json:"organizationId,omitempty"`
	Period         string             `json:"period"`                // "day", "week", "month", "quarter", "year"
	MetricTypes    []string           `json:"metricTypes,omitempty"` // "requests", "users", "errors", "response_time"
	StartDate      *time.Time         `json:"startDate,omitempty"`
	EndDate        *time.Time         `json:"endDate,omitempty"`
}

// UsageMetrics response
type UsageMetrics struct {
	Period              string             `json:"period"`
	StartDate           time.Time          `json:"startDate"`
	EndDate             time.Time          `json:"endDate"`
	TotalRequests       int                `json:"totalRequests"`
	UniqueUsers         int                `json:"uniqueUsers"`
	AvgResponseTime     float64            `json:"avgResponseTime"`
	SuccessRate         float64            `json:"successRate"`
	ErrorRate           float64            `json:"errorRate"`
	RequestsByDay       map[string]int     `json:"requestsByDay"`
	UsersByDay          map[string]int     `json:"usersByDay"`
	ResponseTimeByDay   map[string]float64 `json:"responseTimeByDay"`
	PopularEndpoints    []EndpointStats    `json:"popularEndpoints"`
	PopularActions      map[string]int     `json:"popularActions"`
	GeographicBreakdown map[string]int     `json:"geographicBreakdown"`
	DeviceBreakdown     map[string]int     `json:"deviceBreakdown"`
	GeneratedAt         time.Time          `json:"generatedAt"`
}

// TrendAnalysisRequest for trend analysis
type TrendAnalysisRequest struct {
	ResourceType   model.ResourceType `json:"resourceType"`
	OrganizationID *xid.ID            `json:"organizationId,omitempty"`
	Days           int                `json:"days"`                  // Number of days to analyze
	CompareWith    *time.Time         `json:"compareWith,omitempty"` // Compare with this period
}

// TrendAnalysis response
type TrendAnalysis struct {
	Period            string             `json:"period"`
	RequestTrend      string             `json:"requestTrend"` // "increasing", "decreasing", "stable"
	UserTrend         string             `json:"userTrend"`
	ErrorTrend        string             `json:"errorTrend"`
	ResponseTimeTrend string             `json:"responseTimeTrend"`
	Growth            *GrowthMetrics     `json:"growth"`
	Seasonality       []SeasonalPattern  `json:"seasonality"`
	Anomalies         []Anomaly          `json:"anomalies"`
	Predictions       *PredictionMetrics `json:"predictions"`
	GeneratedAt       time.Time          `json:"generatedAt"`
}

// Supporting types
type EndpointStats struct {
	Endpoint        string  `json:"endpoint"`
	Method          string  `json:"method"`
	RequestCount    int     `json:"requestCount"`
	SuccessRate     float64 `json:"successRate"`
	AvgResponseTime float64 `json:"avgResponseTime"`
	ErrorCount      int     `json:"errorCount"`
}

type ErrorRateStats struct {
	OverallErrorRate float64            `json:"overallErrorRate"`
	ErrorsByCode     map[string]int     `json:"errorsByCode"`
	ErrorsByEndpoint map[string]float64 `json:"errorsByEndpoint"`
	TopErrors        []ErrorDetail      `json:"topErrors"`
	ErrorTrend       string             `json:"errorTrend"`
}

type ErrorDetail struct {
	ErrorCode  string    `json:"errorCode"`
	Count      int       `json:"count"`
	Percentage float64   `json:"percentage"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
}

type ResponseTimeStats struct {
	Average float64 `json:"average"`
	Median  float64 `json:"median"`
	P95     float64 `json:"p95"`
	P99     float64 `json:"p99"`
	Min     int     `json:"min"`
	Max     int     `json:"max"`
	Trend   string  `json:"trend"`
}

type GrowthMetrics struct {
	RequestGrowth  float64 `json:"requestGrowth"` // Percentage growth
	UserGrowth     float64 `json:"userGrowth"`
	WeekOverWeek   float64 `json:"weekOverWeek"`
	MonthOverMonth float64 `json:"monthOverMonth"`
	YearOverYear   float64 `json:"yearOverYear"`
}

type SeasonalPattern struct {
	Pattern     string  `json:"pattern"` // "daily_peak", "weekly_low", etc.
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"` // 0-1
}

type Anomaly struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`     // "spike", "drop", "unusual_pattern"
	Severity    string    `json:"severity"` // "low", "medium", "high", "critical"
	Description string    `json:"description"`
	Value       float64   `json:"value"`
	Expected    float64   `json:"expected"`
	Deviation   float64   `json:"deviation"`
}

type PredictionMetrics struct {
	NextWeekRequests  int      `json:"nextWeekRequests"`
	NextMonthRequests int      `json:"nextMonthRequests"`
	GrowthPrediction  float64  `json:"growthPrediction"`
	Confidence        float64  `json:"confidence"`
	Factors           []string `json:"factors"` // Factors influencing prediction
}

// activityRepository implements the ActivityRepository interface
type activityRepository struct {
	clients *data.Clients
	logger  logging.Logger
}

// NewActivityRepository creates a new activity repository instance
func NewActivityRepository(clients *data.Clients, logger logging.Logger) ActivityRepository {
	return &activityRepository{
		clients: clients,
		logger:  logger,
	}
}

// Create creates a new activity record
func (r *activityRepository) Create(ctx context.Context, activityRecord *model.ActivityRecord) error {
	client := r.clients.DB

	query := client.Activity.Create().
		SetID(activityRecord.ID).
		SetResourceType(activityRecord.ResourceType).
		SetResourceID(activityRecord.ResourceID).
		SetAction(activityRecord.Action).
		SetCategory(activityRecord.Category).
		SetSuccess(activityRecord.Success).
		SetTimestamp(activityRecord.Timestamp)

	// Set optional fields
	if activityRecord.UserID != nil {
		query = query.SetUserID(*activityRecord.UserID)
	}
	if activityRecord.OrganizationID != nil {
		query = query.SetOrganizationID(*activityRecord.OrganizationID)
	}
	if activityRecord.SessionID != nil {
		query = query.SetSessionID(*activityRecord.SessionID)
	}
	if activityRecord.Source != "" {
		query = query.SetSource(activityRecord.Source)
	}
	if activityRecord.Endpoint != "" {
		query = query.SetEndpoint(activityRecord.Endpoint)
	}
	if activityRecord.Method != "" {
		query = query.SetMethod(activityRecord.Method)
	}
	if activityRecord.StatusCode != 0 {
		query = query.SetStatusCode(activityRecord.StatusCode)
	}
	if activityRecord.ResponseTime != 0 {
		query = query.SetResponseTime(activityRecord.ResponseTime)
	}
	if activityRecord.IPAddress != "" {
		query = query.SetIPAddress(activityRecord.IPAddress)
	}
	if activityRecord.UserAgent != "" {
		query = query.SetUserAgent(activityRecord.UserAgent)
	}
	if activityRecord.Location != "" {
		query = query.SetLocation(activityRecord.Location)
	}
	if activityRecord.Error != "" {
		query = query.SetError(activityRecord.Error)
	}
	if activityRecord.ErrorCode != "" {
		query = query.SetErrorCode(activityRecord.ErrorCode)
	}
	if activityRecord.Size != 0 {
		query = query.SetSize(activityRecord.Size)
	}
	if activityRecord.Count != 0 {
		query = query.SetCount(activityRecord.Count)
	}
	if activityRecord.Value != 0 {
		query = query.SetValue(activityRecord.Value)
	}
	if activityRecord.ExpiresAt != nil {
		query = query.SetExpiresAt(*activityRecord.ExpiresAt)
	}
	if activityRecord.Metadata != nil {
		query = query.SetMetadata(activityRecord.Metadata)
	}
	if len(activityRecord.Tags) > 0 {
		query = query.SetTags(activityRecord.Tags)
	}

	_, err := query.Save(ctx)
	if err != nil {
		r.logger.Error("Failed to create activity record", zap.Error(err),
			zap.String("resource_type", string(activityRecord.ResourceType)),
			zap.String("resource_id", activityRecord.ResourceID.String()),
		)
		return fmt.Errorf("creating activity record: %w", err)
	}

	return nil
}

// CreateBulk creates multiple activity records in a single transaction
func (r *activityRepository) CreateBulk(ctx context.Context, activities []*model.ActivityRecord) error {
	if len(activities) == 0 {
		return nil
	}

	client := r.clients.DB
	bulk := make([]*ent.ActivityCreate, len(activities))

	for i, activityRecord := range activities {
		query := client.Activity.Create().
			SetID(activityRecord.ID).
			SetResourceType(activityRecord.ResourceType).
			SetResourceID(activityRecord.ResourceID).
			SetAction(activityRecord.Action).
			SetCategory(activityRecord.Category).
			SetSuccess(activityRecord.Success).
			SetTimestamp(activityRecord.Timestamp)

		// Set optional fields (same pattern as Create method)
		if activityRecord.UserID != nil {
			query = query.SetUserID(*activityRecord.UserID)
		}
		if activityRecord.OrganizationID != nil {
			query = query.SetOrganizationID(*activityRecord.OrganizationID)
		}
		if activityRecord.SessionID != nil {
			query = query.SetSessionID(*activityRecord.SessionID)
		}
		if activityRecord.Source != "" {
			query = query.SetSource(activityRecord.Source)
		}
		if activityRecord.Endpoint != "" {
			query = query.SetEndpoint(activityRecord.Endpoint)
		}
		if activityRecord.Method != "" {
			query = query.SetMethod(activityRecord.Method)
		}
		if activityRecord.StatusCode != 0 {
			query = query.SetStatusCode(activityRecord.StatusCode)
		}
		if activityRecord.ResponseTime != 0 {
			query = query.SetResponseTime(activityRecord.ResponseTime)
		}
		if activityRecord.IPAddress != "" {
			query = query.SetIPAddress(activityRecord.IPAddress)
		}
		if activityRecord.UserAgent != "" {
			query = query.SetUserAgent(activityRecord.UserAgent)
		}
		if activityRecord.Location != "" {
			query = query.SetLocation(activityRecord.Location)
		}
		if activityRecord.Error != "" {
			query = query.SetError(activityRecord.Error)
		}
		if activityRecord.ErrorCode != "" {
			query = query.SetErrorCode(activityRecord.ErrorCode)
		}
		if activityRecord.Size != 0 {
			query = query.SetSize(activityRecord.Size)
		}
		if activityRecord.Count != 0 {
			query = query.SetCount(activityRecord.Count)
		}
		if activityRecord.Value != 0 {
			query = query.SetValue(activityRecord.Value)
		}
		if activityRecord.ExpiresAt != nil {
			query = query.SetExpiresAt(*activityRecord.ExpiresAt)
		}
		if activityRecord.Metadata != nil {
			query = query.SetMetadata(activityRecord.Metadata)
		}
		if len(activityRecord.Tags) > 0 {
			query = query.SetTags(activityRecord.Tags)
		}

		bulk[i] = query
	}

	_, err := client.Activity.CreateBulk(bulk...).Save(ctx)
	if err != nil {
		r.logger.Error("Failed to create bulk activity records", zap.Error(err), zap.Int("count", len(activities)))
		return fmt.Errorf("creating bulk activity records: %w", err)
	}

	return nil
}

// GetByID retrieves an activity record by ID
func (r *activityRepository) GetByID(ctx context.Context, id xid.ID) (*model.ActivityRecord, error) {
	client := r.clients.DB

	act, err := client.Activity.Query().
		Where(activity.ID(id)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("activity not found")
		}
		r.logger.Error("Failed to get activity by ID", zap.Error(err), zap.String("id", id.String()))
		return nil, fmt.Errorf("getting activity by ID: %w", err)
	}

	return r.entToActivityRecord(act), nil
}

// List retrieves a paginated list of activities with filtering
func (r *activityRepository) List(ctx context.Context, req *GetActivitiesRequest) (*model.PaginatedOutput[*model.ActivityRecord], error) {
	client := r.clients.DB
	query := client.Activity.Query()

	// Apply filters
	query = r.applyFilters(query, req)

	// Apply pagination using the model's pagination helper
	result, err := model.WithPaginationAndOptions[*ent.Activity, *ent.ActivityQuery](ctx, query, req.PaginationParams)
	if err != nil {
		r.logger.Error("Failed to list activities", zap.Error(err))
		return nil, fmt.Errorf("listing activities: %w", err)
	}

	// Convert ent activities to ActivityRecord
	activities := make([]*model.ActivityRecord, len(result.Data))
	for i, act := range result.Data {
		activities[i] = r.entToActivityRecord(act)
	}

	return &model.PaginatedOutput[*model.ActivityRecord]{
		Data:       activities,
		Pagination: result.Pagination,
	}, nil
}

// ListByResource retrieves activities for a specific resource
func (r *activityRepository) ListByResource(ctx context.Context, resourceType model.ResourceType, resourceID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error) {
	client := r.clients.DB
	query := client.Activity.Query().
		Where(
			activity.ResourceTypeEQ(resourceType),
			activity.ResourceID(resourceID),
		)

	// Apply query options
	query = r.applyQueryOptions(query, opts)

	activities, err := query.All(ctx)
	if err != nil {
		r.logger.Error("Failed to list activities by resource", zap.Error(err), zap.String("resource_type", string(resourceType)), zap.String("resource_id", resourceID.String()))
		return nil, fmt.Errorf("listing activities by resource: %w", err)
	}

	result := make([]*model.ActivityRecord, len(activities))
	for i, act := range activities {
		result[i] = r.entToActivityRecord(act)
	}

	return result, nil
}

// ListByUser retrieves activities for a specific user
func (r *activityRepository) ListByUser(ctx context.Context, userID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error) {
	client := r.clients.DB
	query := client.Activity.Query().
		Where(activity.UserID(userID))

	// Apply query options
	query = r.applyQueryOptions(query, opts)

	activities, err := query.All(ctx)
	if err != nil {
		r.logger.Error("Failed to list activities by user", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, fmt.Errorf("listing activities by user: %w", err)
	}

	result := make([]*model.ActivityRecord, len(activities))
	for i, act := range activities {
		result[i] = r.entToActivityRecord(act)
	}

	return result, nil
}

// ListByOrganization retrieves activities for a specific organization
func (r *activityRepository) ListByOrganization(ctx context.Context, orgID xid.ID, opts *ActivityQueryOptions) ([]*model.ActivityRecord, error) {
	client := r.clients.DB
	query := client.Activity.Query().
		Where(activity.OrganizationID(orgID))

	// Apply query options
	query = r.applyQueryOptions(query, opts)

	activities, err := query.All(ctx)
	if err != nil {
		r.logger.Error("Failed to list activities by organization", zap.Error(err), zap.String("org_id", orgID.String()))
		return nil, fmt.Errorf("listing activities by organization: %w", err)
	}

	result := make([]*model.ActivityRecord, len(activities))
	for i, act := range activities {
		result[i] = r.entToActivityRecord(act)
	}

	return result, nil
}

// GetStats retrieves activity statistics
func (r *activityRepository) GetStats(ctx context.Context, req *ActivityStatsRequest) (*ActivityStats, error) {
	client := r.clients.DB
	query := client.Activity.Query()

	// Apply basic filters
	if req.ResourceType != "" {
		query = query.Where(activity.ResourceTypeEQ(req.ResourceType))
	}
	if req.ResourceID != nil {
		query = query.Where(activity.ResourceID(*req.ResourceID))
	}
	if req.UserID != nil {
		query = query.Where(activity.UserID(*req.UserID))
	}
	if req.OrganizationID != nil {
		query = query.Where(activity.OrganizationID(*req.OrganizationID))
	}
	if req.StartDate != nil {
		query = query.Where(activity.TimestampGTE(*req.StartDate))
	}
	if req.EndDate != nil {
		query = query.Where(activity.TimestampLTE(*req.EndDate))
	}

	// Get total count
	totalCount, err := query.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting total activity count: %w", err)
	}

	// Get success/failure counts
	successCount, err := query.Clone().Where(activity.Success(true)).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting success count: %w", err)
	}

	failedCount := totalCount - successCount
	successRate := 0.0
	if totalCount > 0 {
		successRate = float64(successCount) / float64(totalCount) * 100
	}

	// Get activities by action
	var actionStats []struct {
		Action string `json:"action"`
		Count  int    `json:"count"`
	}
	err = query.Clone().
		GroupBy(activity.FieldAction).
		Aggregate(ent.Count()).
		Scan(ctx, &actionStats)
	if err != nil {
		return nil, fmt.Errorf("getting activities by action: %w", err)
	}

	activitiesByAction := make(map[string]int)
	for _, stat := range actionStats {
		activitiesByAction[stat.Action] = stat.Count
	}

	// Get activities by source
	var sourceStats []struct {
		Source string `json:"source"`
		Count  int    `json:"count"`
	}
	err = query.Clone().
		GroupBy(activity.FieldSource).
		Aggregate(ent.Count()).
		Scan(ctx, &sourceStats)
	if err != nil {
		return nil, fmt.Errorf("getting activities by source: %w", err)
	}

	activitiesBySource := make(map[string]int)
	for _, stat := range sourceStats {
		activitiesBySource[stat.Source] = stat.Count
	}

	// Get unique users count
	uniqueUsers, err := query.Clone().
		Where(activity.UserIDNotNil()).
		GroupBy(activity.FieldUserID).
		Int(ctx)
	if err != nil {
		uniqueUsers = 0 // Don't fail the entire stats request
	}

	// Get unique IPs count
	uniqueIPs, err := query.Clone().
		Where(activity.IPAddressNotNil()).
		GroupBy(activity.FieldIPAddress).
		Int(ctx)
	if err != nil {
		uniqueIPs = 0 // Don't fail the entire stats request
	}

	return &ActivityStats{
		TotalActivities:    totalCount,
		SuccessfulCount:    successCount,
		FailedCount:        failedCount,
		SuccessRate:        successRate,
		ActivitiesByAction: activitiesByAction,
		ActivitiesBySource: activitiesBySource,
		UniqueUsers:        uniqueUsers,
		UniqueIPs:          uniqueIPs,
		GeneratedAt:        time.Now(),
	}, nil
}

// GetUsageMetrics retrieves usage metrics for billing and monitoring
func (r *activityRepository) GetUsageMetrics(ctx context.Context, req *UsageMetricsRequest) (*UsageMetrics, error) {
	client := r.clients.DB
	query := client.Activity.Query()

	// Apply filters
	if req.ResourceType != "" {
		query = query.Where(activity.ResourceTypeEQ(req.ResourceType))
	}
	if req.OrganizationID != nil {
		query = query.Where(activity.OrganizationID(*req.OrganizationID))
	}

	// Calculate date range based on period
	endDate := time.Now()
	if req.EndDate != nil {
		endDate = *req.EndDate
	}

	var startDate time.Time
	if req.StartDate != nil {
		startDate = *req.StartDate
	} else {
		switch req.Period {
		case "day":
			startDate = endDate.AddDate(0, 0, -1)
		case "week":
			startDate = endDate.AddDate(0, 0, -7)
		case "month":
			startDate = endDate.AddDate(0, -1, 0)
		case "quarter":
			startDate = endDate.AddDate(0, -3, 0)
		case "year":
			startDate = endDate.AddDate(-1, 0, 0)
		default:
			startDate = endDate.AddDate(0, -1, 0) // Default to month
		}
	}

	query = query.Where(
		activity.TimestampGTE(startDate),
		activity.TimestampLTE(endDate),
	)

	// Get total requests
	totalRequests, err := query.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting total requests: %w", err)
	}

	// Get unique users
	uniqueUsers, err := query.Clone().
		Where(activity.UserIDNotNil()).
		GroupBy(activity.FieldUserID).
		Int(ctx)
	if err != nil {
		uniqueUsers = 0
	}

	// Get average response time
	var avgResponseTime float64
	err = query.Clone().
		Where(activity.ResponseTimeGT(0)).
		Aggregate(ent.Mean(activity.FieldResponseTime)).
		Scan(ctx, &avgResponseTime)
	if err != nil {
		avgResponseTime = 0
	}

	// Get success rate
	successCount, err := query.Clone().Where(activity.Success(true)).Count(ctx)
	if err != nil {
		successCount = 0
	}

	successRate := 0.0
	errorRate := 0.0
	if totalRequests > 0 {
		successRate = float64(successCount) / float64(totalRequests) * 100
		errorRate = 100 - successRate
	}

	return &UsageMetrics{
		Period:          req.Period,
		StartDate:       startDate,
		EndDate:         endDate,
		TotalRequests:   totalRequests,
		UniqueUsers:     uniqueUsers,
		AvgResponseTime: avgResponseTime,
		SuccessRate:     successRate,
		ErrorRate:       errorRate,
		GeneratedAt:     time.Now(),
	}, nil
}

// GetTrendAnalysis retrieves trend analysis for activity patterns
func (r *activityRepository) GetTrendAnalysis(ctx context.Context, req *TrendAnalysisRequest) (*TrendAnalysis, error) {
	// This is a simplified implementation. In production, you might use more sophisticated
	// time series analysis libraries or external analytics services
	client := r.clients.DB
	query := client.Activity.Query()

	// Apply filters
	if req.ResourceType != "" {
		query = query.Where(activity.ResourceTypeEQ(req.ResourceType))
	}
	if req.OrganizationID != nil {
		query = query.Where(activity.OrganizationID(*req.OrganizationID))
	}

	// Calculate date ranges
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -req.Days)

	query = query.Where(
		activity.TimestampGTE(startDate),
		activity.TimestampLTE(endDate),
	)

	// Get current period count
	currentCount, err := query.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting current period count: %w", err)
	}

	// Get previous period count for comparison
	var previousCount int
	if req.CompareWith != nil {
		prevQuery := client.Activity.Query()
		if req.ResourceType != "" {
			prevQuery = prevQuery.Where(activity.ResourceTypeEQ(req.ResourceType))
		}
		if req.OrganizationID != nil {
			prevQuery = prevQuery.Where(activity.OrganizationID(*req.OrganizationID))
		}

		prevEnd := *req.CompareWith
		prevStart := prevEnd.AddDate(0, 0, -req.Days)
		prevQuery = prevQuery.Where(
			activity.TimestampGTE(prevStart),
			activity.TimestampLTE(prevEnd),
		)

		previousCount, err = prevQuery.Count(ctx)
		if err != nil {
			previousCount = 0 // Don't fail the entire analysis
		}
	}

	// Calculate growth metrics
	var growth *GrowthMetrics
	if previousCount > 0 {
		requestGrowth := float64(currentCount-previousCount) / float64(previousCount) * 100
		growth = &GrowthMetrics{
			RequestGrowth: requestGrowth,
		}
	}

	// Determine trends (simplified logic)
	requestTrend := "stable"
	if growth != nil {
		if growth.RequestGrowth > 10 {
			requestTrend = "increasing"
		} else if growth.RequestGrowth < -10 {
			requestTrend = "decreasing"
		}
	}

	return &TrendAnalysis{
		Period:       fmt.Sprintf("%d days", req.Days),
		RequestTrend: requestTrend,
		UserTrend:    "stable", // Simplified
		ErrorTrend:   "stable", // Simplified
		Growth:       growth,
		GeneratedAt:  time.Now(),
	}, nil
}

// DeleteExpired deletes expired activity records
func (r *activityRepository) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	client := r.clients.DB

	deleted, err := client.Activity.Delete().
		Where(
			activity.Or(
				activity.ExpiresAtLT(before),
				activity.And(
					activity.ExpiresAtIsNil(),
					activity.TimestampLT(before),
				),
			),
		).
		Exec(ctx)
	if err != nil {
		r.logger.Error("Failed to delete expired activities", zap.Time("before", before), zap.Error(err))
		return 0, fmt.Errorf("deleting expired activities: %w", err)
	}

	r.logger.Info("Deleted expired activities", zap.Int("count", deleted), zap.Time("before", before))
	return deleted, nil
}

// ArchiveOld archives old activity records (implementation depends on your archival strategy)
func (r *activityRepository) ArchiveOld(ctx context.Context, before time.Time) error {
	// This is a placeholder implementation. In production, you might:
	// 1. Move records to an archive table
	// 2. Export to cold storage (S3, etc.)
	// 3. Compress and store in a separate database
	r.logger.Info("Archive old activities called", zap.Time("before", before))
	return nil
}

// Performance query methods

// GetHourlyStats retrieves hourly statistics for a resource type
func (r *activityRepository) GetHourlyStats(ctx context.Context, resourceType string, hours int) (map[string]int, error) {
	client := r.clients.DB
	query := client.Activity.Query().
		Where(
			activity.ResourceTypeEQ(model.ResourceType(resourceType)),
			activity.TimestampGTE(time.Now().Add(-time.Duration(hours)*time.Hour)),
		)

	// This is a simplified implementation. In production, you might use database-specific
	// functions to group by hour
	activities, err := query.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting hourly stats: %w", err)
	}

	hourlyStats := make(map[string]int)
	for _, act := range activities {
		hour := act.Timestamp.Format("2006-01-02 15:00")
		hourlyStats[hour]++
	}

	return hourlyStats, nil
}

// GetPopularEndpoints retrieves popular endpoints statistics
func (r *activityRepository) GetPopularEndpoints(ctx context.Context, organizationID *xid.ID, limit int) ([]EndpointStats, error) {
	client := r.clients.DB
	query := client.Activity.Query().
		Where(activity.EndpointNotNil())

	if organizationID != nil {
		query = query.Where(activity.OrganizationID(*organizationID))
	}

	// This is a simplified implementation. In production, you would use more sophisticated
	// SQL queries with proper grouping and aggregation
	activities, err := query.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting popular endpoints: %w", err)
	}

	endpointMap := make(map[string]*EndpointStats)
	for _, act := range activities {
		key := fmt.Sprintf("%s %s", act.Method, act.Endpoint)
		if _, exists := endpointMap[key]; !exists {
			endpointMap[key] = &EndpointStats{
				Endpoint: act.Endpoint,
				Method:   act.Method,
			}
		}
		endpointMap[key].RequestCount++
		if act.Success {
			endpointMap[key].SuccessRate++
		}
		if act.ResponseTime > 0 {
			// Simple average calculation (in production, use proper aggregation)
			endpointMap[key].AvgResponseTime = (endpointMap[key].AvgResponseTime + float64(act.ResponseTime)) / 2
		}
	}

	// Convert to slice and sort by request count
	var result []EndpointStats
	for _, stats := range endpointMap {
		if stats.RequestCount > 0 {
			stats.SuccessRate = stats.SuccessRate / float64(stats.RequestCount) * 100
		}
		result = append(result, *stats)
		if len(result) >= limit {
			break
		}
	}

	return result, nil
}

// GetErrorRates retrieves error rate statistics
func (r *activityRepository) GetErrorRates(ctx context.Context, resourceType string, organizationID *xid.ID) (*ErrorRateStats, error) {
	client := r.clients.DB
	query := client.Activity.Query()

	if resourceType != "" {
		query = query.Where(activity.ResourceTypeEQ(model.ResourceType(resourceType)))
	}
	if organizationID != nil {
		query = query.Where(activity.OrganizationID(*organizationID))
	}

	// Get total count
	totalCount, err := query.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting total count for error rates: %w", err)
	}

	// Get error count
	errorCount, err := query.Clone().Where(activity.Success(false)).Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting error count: %w", err)
	}

	overallErrorRate := 0.0
	if totalCount > 0 {
		overallErrorRate = float64(errorCount) / float64(totalCount) * 100
	}

	// Get errors by code
	errorActivities, err := query.Clone().
		Where(
			activity.Success(false),
			activity.ErrorCodeNotNil(),
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting error activities: %w", err)
	}

	errorsByCode := make(map[string]int)
	for _, act := range errorActivities {
		errorsByCode[act.ErrorCode]++
	}

	return &ErrorRateStats{
		OverallErrorRate: overallErrorRate,
		ErrorsByCode:     errorsByCode,
		ErrorTrend:       "stable", // Simplified
	}, nil
}

// Helper methods

// applyFilters applies filters to an activity query based on GetActivitiesRequest
func (r *activityRepository) applyFilters(query *ent.ActivityQuery, req *GetActivitiesRequest) *ent.ActivityQuery {
	// Resource filters
	if req.ResourceType != "" {
		query = query.Where(activity.ResourceTypeEQ(req.ResourceType))
	}
	if req.ResourceID != nil {
		query = query.Where(activity.ResourceID(*req.ResourceID))
	}
	if len(req.ResourceTypes) > 0 {
		query = query.Where(activity.ResourceTypeIn(req.ResourceTypes...))
	}

	// Context filters
	if req.UserID != nil {
		query = query.Where(activity.UserID(*req.UserID))
	}
	if req.OrganizationID != nil {
		query = query.Where(activity.OrganizationID(*req.OrganizationID))
	}
	if req.SessionID != nil {
		query = query.Where(activity.SessionID(*req.SessionID))
	}

	// Action filters
	if req.Action != "" {
		query = query.Where(activity.Action(req.Action))
	}
	if len(req.Actions) > 0 {
		query = query.Where(activity.ActionIn(req.Actions...))
	}
	if req.Category != "" {
		query = query.Where(activity.Category(req.Category))
	}
	if len(req.Categories) > 0 {
		query = query.Where(activity.CategoryIn(req.Categories...))
	}
	if req.Source != "" {
		query = query.Where(activity.Source(req.Source))
	}
	if len(req.Sources) > 0 {
		query = query.Where(activity.SourceIn(req.Sources...))
	}

	// API-specific filters
	if req.Endpoint != "" {
		query = query.Where(activity.Endpoint(req.Endpoint))
	}
	if req.Method != "" {
		query = query.Where(activity.Method(req.Method))
	}
	if req.StatusCode != 0 {
		query = query.Where(activity.StatusCode(req.StatusCode))
	}
	if len(req.StatusCodes) > 0 {
		query = query.Where(activity.StatusCodeIn(req.StatusCodes...))
	}

	// Result filters
	if req.Success != nil {
		query = query.Where(activity.Success(*req.Success))
	}
	if req.ErrorCode != "" {
		query = query.Where(activity.ErrorCode(req.ErrorCode))
	}

	// Time filters
	if req.StartDate != nil {
		query = query.Where(activity.TimestampGTE(*req.StartDate))
	}
	if req.EndDate != nil {
		query = query.Where(activity.TimestampLTE(*req.EndDate))
	}

	// Location filters
	if req.IPAddress != "" {
		query = query.Where(activity.IPAddress(req.IPAddress))
	}
	if req.Location != "" {
		query = query.Where(activity.Location(req.Location))
	}

	// Performance filters
	if req.MinResponseTime > 0 {
		query = query.Where(activity.ResponseTimeGTE(req.MinResponseTime))
	}
	if req.MaxResponseTime > 0 {
		query = query.Where(activity.ResponseTimeLTE(req.MaxResponseTime))
	}
	if req.MinSize > 0 {
		query = query.Where(activity.SizeGTE(req.MinSize))
	}
	if req.MaxSize > 0 {
		query = query.Where(activity.SizeLTE(req.MaxSize))
	}

	// Tag filters
	if len(req.Tags) > 0 {
		// This would need to be implemented based on how tags are stored/queried in your schema
		// Assuming tags are stored as JSON array
		for _, tag := range req.Tags {
			query = query.Where(func(s *sql.Selector) {
				s.Where(sqljson.ValueContains(activity.FieldTags, tag))
			})
		}
	}

	// Search functionality (simplified)
	if req.Search != "" {
		query = query.Where(
			activity.Or(
				activity.ActionContains(req.Search),
				activity.EndpointContains(req.Search),
				activity.ErrorContains(req.Search),
			),
		)
	}

	return query
}

// applyQueryOptions applies query options to an activity query
func (r *activityRepository) applyQueryOptions(query *ent.ActivityQuery, opts *ActivityQueryOptions) *ent.ActivityQuery {
	if opts == nil {
		return query.Order(ent.Desc(activity.FieldTimestamp)).Limit(100)
	}

	// Apply filters
	if opts.StartDate != nil {
		query = query.Where(activity.TimestampGTE(*opts.StartDate))
	}
	if opts.EndDate != nil {
		query = query.Where(activity.TimestampLTE(*opts.EndDate))
	}
	if len(opts.Actions) > 0 {
		query = query.Where(activity.ActionIn(opts.Actions...))
	}
	if opts.Success != nil {
		query = query.Where(activity.Success(*opts.Success))
	}

	// Apply ordering
	if opts.OrderBy != "" && opts.OrderDir != "" {
		if opts.OrderDir == "desc" {
			switch opts.OrderBy {
			case "timestamp":
				query = query.Order(ent.Desc(activity.FieldTimestamp))
			case "response_time":
				query = query.Order(ent.Desc(activity.FieldResponseTime))
			default:
				query = query.Order(ent.Desc(activity.FieldTimestamp))
			}
		} else {
			switch opts.OrderBy {
			case "timestamp":
				query = query.Order(ent.Asc(activity.FieldTimestamp))
			case "response_time":
				query = query.Order(ent.Asc(activity.FieldResponseTime))
			default:
				query = query.Order(ent.Asc(activity.FieldTimestamp))
			}
		}
	} else {
		query = query.Order(ent.Desc(activity.FieldTimestamp))
	}

	// Apply pagination
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	query = query.Limit(opts.Limit)

	if opts.Offset > 0 {
		query = query.Offset(opts.Offset)
	}

	return query
}

// entToActivityRecord converts an ent.Activity to ActivityRecord
func (r *activityRepository) entToActivityRecord(entActivity *ent.Activity) *model.ActivityRecord {
	record := &model.ActivityRecord{
		ID:           entActivity.ID,
		ResourceType: entActivity.ResourceType,
		ResourceID:   entActivity.ResourceID,
		Action:       entActivity.Action,
		Category:     entActivity.Category,
		Success:      entActivity.Success,
		Timestamp:    entActivity.Timestamp,
	}

	// Set optional fields
	if entActivity.UserID != (xid.ID{}) {
		record.UserID = &entActivity.UserID
	}
	if entActivity.OrganizationID != (xid.ID{}) {
		record.OrganizationID = &entActivity.OrganizationID
	}
	if entActivity.SessionID != (xid.ID{}) {
		record.SessionID = &entActivity.SessionID
	}
	if entActivity.Source != "" {
		record.Source = entActivity.Source
	}
	if entActivity.Endpoint != "" {
		record.Endpoint = entActivity.Endpoint
	}
	if entActivity.Method != "" {
		record.Method = entActivity.Method
	}
	if entActivity.StatusCode != 0 {
		record.StatusCode = entActivity.StatusCode
	}
	if entActivity.ResponseTime != 0 {
		record.ResponseTime = entActivity.ResponseTime
	}
	if entActivity.IPAddress != "" {
		record.IPAddress = entActivity.IPAddress
	}
	if entActivity.UserAgent != "" {
		record.UserAgent = entActivity.UserAgent
	}
	if entActivity.Location != "" {
		record.Location = entActivity.Location
	}
	if entActivity.Error != "" {
		record.Error = entActivity.Error
	}
	if entActivity.ErrorCode != "" {
		record.ErrorCode = entActivity.ErrorCode
	}
	if entActivity.Size != 0 {
		record.Size = entActivity.Size
	}
	if entActivity.Count != 0 {
		record.Count = entActivity.Count
	}
	if entActivity.Value != 0 {
		record.Value = entActivity.Value
	}
	if !entActivity.ExpiresAt.IsZero() {
		record.ExpiresAt = &entActivity.ExpiresAt
	}
	if entActivity.Metadata != nil {
		record.Metadata = entActivity.Metadata
	}
	if len(entActivity.Tags) > 0 {
		record.Tags = entActivity.Tags
	}

	return record
}
