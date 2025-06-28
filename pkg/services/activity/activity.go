package activity

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/logging"
	"github.com/rs/xid"
	"go.uber.org/zap"
)

// Service provides generic activity tracking for all resources
type Service interface {
	// Record activities
	RecordActivity(ctx context.Context, activity *ActivityRecord) error
	RecordAPIActivity(ctx context.Context, apiActivity *APIActivityRecord) error
	RecordUserActivity(ctx context.Context, userActivity *UserActivityRecord) error
	RecordBulkActivities(ctx context.Context, activities []*ActivityRecord) error

	// Query activities
	GetActivities(ctx context.Context, req *GetActivitiesRequest) (*model.PaginatedOutput[*ActivityRecord], error)
	GetResourceActivities(ctx context.Context, resourceType string, resourceID xid.ID, opts *ActivityQueryOptions) ([]*ActivityRecord, error)
	GetUserActivities(ctx context.Context, userID xid.ID, opts *ActivityQueryOptions) ([]*ActivityRecord, error)
	GetOrganizationActivities(ctx context.Context, orgID xid.ID, opts *ActivityQueryOptions) ([]*ActivityRecord, error)

	// Analytics
	GetActivityStats(ctx context.Context, req *ActivityStatsRequest) (*ActivityStats, error)
	GetUsageMetrics(ctx context.Context, req *UsageMetricsRequest) (*UsageMetrics, error)
	GetTrendAnalysis(ctx context.Context, req *TrendAnalysisRequest) (*TrendAnalysis, error)

	// Maintenance
	CleanupExpiredActivities(ctx context.Context, before time.Time) (int, error)
	ArchiveOldActivities(ctx context.Context, before time.Time) error
}

// Specialized activity records for type safety
type APIActivityRecord struct {
	KeyID          xid.ID    `json:"keyId"`
	Endpoint       string    `json:"endpoint"`
	Method         string    `json:"method"`
	StatusCode     int       `json:"statusCode"`
	ResponseTime   int       `json:"responseTime"`
	IPAddress      string    `json:"ipAddress,omitempty"`
	UserAgent      string    `json:"userAgent,omitempty"`
	Success        bool      `json:"success"`
	Error          string    `json:"error,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
	UserID         *xid.ID   `json:"userId,omitempty"`
	OrganizationID *xid.ID   `json:"organizationId,omitempty"`
}

type UserActivityRecord struct {
	UserID         xid.ID    `json:"userId"`
	OrganizationID *xid.ID   `json:"organizationId,omitempty"`
	Action         string    `json:"action"` // "login", "logout", "profile_update"
	IPAddress      string    `json:"ipAddress,omitempty"`
	UserAgent      string    `json:"userAgent,omitempty"`
	Success        bool      `json:"success"`
	Error          string    `json:"error,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

// activityService implements the Service interface
type activityService struct {
	repo   repository.ActivityRepository
	logger logging.Logger
}

// NewService creates a new activity service instance
func NewService(repo repository.ActivityRepository, logger logging.Logger) Service {
	return &activityService{
		repo:   repo,
		logger: logger,
	}
}

// RecordActivity records a generic activity
func (s *activityService) RecordActivity(ctx context.Context, activity *ActivityRecord) error {
	// Validate required fields
	if err := s.validateActivityRecord(activity); err != nil {
		return fmt.Errorf("invalid activity record: %w", err)
	}

	// Set ID if not provided
	if activity.ID == (xid.ID{}) {
		activity.ID = xid.New()
	}

	// Set timestamp if not provided
	if activity.Timestamp.IsZero() {
		activity.Timestamp = time.Now()
	}

	// Convert to repository type and save
	repoActivity := s.activityRecordToRepo(activity)
	if err := s.repo.Create(ctx, repoActivity); err != nil {
		s.logger.Error("Failed to record activity",
			zap.Error(err),
			zap.String("resource_type", string(activity.ResourceType)),
			zap.String("resource_id", activity.ResourceID.String()),
			zap.String("action", activity.Action),
		)
		return fmt.Errorf("recording activity: %w", err)
	}

	s.logger.Debug("Activity recorded successfully",
		zap.String("activity_id", activity.ID.String()),
		zap.String("resource_type", string(activity.ResourceType)),
		zap.String("action", activity.Action),
	)

	return nil
}

// RecordAPIActivity records API-specific activity with type safety
func (s *activityService) RecordAPIActivity(ctx context.Context, apiActivity *APIActivityRecord) error {
	if apiActivity == nil {
		return fmt.Errorf("API activity record is required")
	}

	// Validate API activity specific fields
	if apiActivity.KeyID == (xid.ID{}) {
		return fmt.Errorf("API key ID is required")
	}
	if apiActivity.Endpoint == "" {
		return fmt.Errorf("endpoint is required for API activities")
	}
	if apiActivity.Method == "" {
		return fmt.Errorf("HTTP method is required for API activities")
	}

	// Convert to generic activity record
	activity := &ActivityRecord{
		ID:           xid.New(),
		ResourceType: "api_key",
		ResourceID:   apiActivity.KeyID,
		Action:       "api_request",
		Category:     "api",
		Source:       "api",
		Endpoint:     apiActivity.Endpoint,
		Method:       apiActivity.Method,
		StatusCode:   apiActivity.StatusCode,
		ResponseTime: apiActivity.ResponseTime,
		IPAddress:    apiActivity.IPAddress,
		UserAgent:    apiActivity.UserAgent,
		Success:      apiActivity.Success,
		Error:        apiActivity.Error,
		Timestamp:    apiActivity.Timestamp,
		// Auto-expire API activities after 90 days for storage optimization
		ExpiresAt: &[]time.Time{apiActivity.Timestamp.AddDate(0, 0, 90)}[0],
		Metadata: map[string]interface{}{
			"api_key_id":    apiActivity.KeyID.String(),
			"activity_type": "api_request",
		},
		Tags: []string{"api", "request"},
	}

	return s.RecordActivity(ctx, activity)
}

// RecordUserActivity records user-specific activity with type safety
func (s *activityService) RecordUserActivity(ctx context.Context, userActivity *UserActivityRecord) error {
	if userActivity == nil {
		return fmt.Errorf("user activity record is required")
	}

	// Validate user activity specific fields
	if userActivity.UserID == (xid.ID{}) {
		return fmt.Errorf("user ID is required")
	}
	if userActivity.Action == "" {
		return fmt.Errorf("action is required for user activities")
	}

	// Convert to generic activity record
	activity := &ActivityRecord{
		ID:             xid.New(),
		ResourceType:   "user",
		ResourceID:     userActivity.UserID,
		UserID:         &userActivity.UserID,
		OrganizationID: userActivity.OrganizationID,
		Action:         userActivity.Action,
		Category:       "auth",
		Source:         "web",
		IPAddress:      userActivity.IPAddress,
		UserAgent:      userActivity.UserAgent,
		Success:        userActivity.Success,
		Error:          userActivity.Error,
		Timestamp:      userActivity.Timestamp,
		// Auto-expire user activities after 2 years for compliance
		ExpiresAt: &[]time.Time{userActivity.Timestamp.AddDate(2, 0, 0)}[0],
		Metadata: map[string]interface{}{
			"user_id":       userActivity.UserID.String(),
			"activity_type": "user_action",
		},
		Tags: []string{"user", "auth", userActivity.Action},
	}

	return s.RecordActivity(ctx, activity)
}

// RecordBulkActivities records multiple activities in a single transaction
func (s *activityService) RecordBulkActivities(ctx context.Context, activities []*ActivityRecord) error {
	if len(activities) == 0 {
		return nil
	}

	// Validate all activities before bulk insert
	for i, activity := range activities {
		if err := s.validateActivityRecord(activity); err != nil {
			return fmt.Errorf("invalid activity record at index %d: %w", i, err)
		}

		// Set ID if not provided
		if activity.ID == (xid.ID{}) {
			activity.ID = xid.New()
		}

		// Set timestamp if not provided
		if activity.Timestamp.IsZero() {
			activity.Timestamp = time.Now()
		}
	}

	// Convert to repository types
	repoActivities := make([]*ActivityRecord, len(activities))
	for i, activity := range activities {
		repoActivities[i] = s.activityRecordToRepo(activity)
	}

	// Perform bulk insert
	if err := s.repo.CreateBulk(ctx, repoActivities); err != nil {
		s.logger.Error("Failed to record bulk activities", zap.Error(err), zap.Int("count", len(activities)))
		return fmt.Errorf("recording bulk activities: %w", err)
	}

	s.logger.Info("Bulk activities recorded successfully", zap.Int("count", len(activities)))
	return nil
}

// GetActivities retrieves activities with comprehensive filtering and pagination
func (s *activityService) GetActivities(ctx context.Context, req *GetActivitiesRequest) (*model.PaginatedOutput[*ActivityRecord], error) {
	if req == nil {
		req = &GetActivitiesRequest{
			PaginationParams: model.PaginationParams{
				Limit: 20,
			},
		}
	}

	// Set default pagination if not provided
	if req.Limit <= 0 {
		req.Limit = 20
	}
	if req.Limit > 1000 {
		req.Limit = 1000 // Prevent excessive queries
	}

	// Convert request to repository type
	repoReq := &repository.GetActivitiesRequest{
		PaginationParams: req.PaginationParams,
		ResourceType:     req.ResourceType,
		ResourceID:       req.ResourceID,
		ResourceTypes:    req.ResourceTypes,
		UserID:           req.UserID,
		OrganizationID:   req.OrganizationID,
		SessionID:        req.SessionID,
		Action:           req.Action,
		Actions:          req.Actions,
		Category:         req.Category,
		Categories:       req.Categories,
		Source:           req.Source,
		Sources:          req.Sources,
		Endpoint:         req.Endpoint,
		Method:           req.Method,
		StatusCode:       req.StatusCode,
		StatusCodes:      req.StatusCodes,
		Success:          req.Success,
		ErrorCode:        req.ErrorCode,
		StartDate:        req.StartDate,
		EndDate:          req.EndDate,
		IPAddress:        req.IPAddress,
		Location:         req.Location,
		MinResponseTime:  req.MinResponseTime,
		MaxResponseTime:  req.MaxResponseTime,
		MinSize:          req.MinSize,
		MaxSize:          req.MaxSize,
		Tags:             req.Tags,
		HasTags:          req.HasTags,
		Search:           req.Search,
	}

	result, err := s.repo.List(ctx, repoReq)
	if err != nil {
		s.logger.Error("Failed to get activities", zap.Error(err))
		return nil, fmt.Errorf("getting activities: %w", err)
	}

	// Convert repository results to service types
	activities := make([]*ActivityRecord, len(result.Data))
	for i, repoActivity := range result.Data {
		activities[i] = s.repoToActivityRecord(repoActivity)
	}

	return &model.PaginatedOutput[*ActivityRecord]{
		Data:       activities,
		Pagination: result.Pagination,
	}, nil
}

// GetResourceActivities gets all activities for a specific resource
func (s *activityService) GetResourceActivities(ctx context.Context, resourceType string, resourceID xid.ID, opts *ActivityQueryOptions) ([]*ActivityRecord, error) {
	if resourceType == "" {
		return nil, fmt.Errorf("resource type is required")
	}
	if resourceID == (xid.ID{}) {
		return nil, fmt.Errorf("resource ID is required")
	}

	// Set default options if not provided
	if opts == nil {
		opts = &ActivityQueryOptions{
			Limit:    100,
			OrderBy:  "timestamp",
			OrderDir: "desc",
		}
	}

	// Convert to repository options
	repoOpts := &repository.ActivityQueryOptions{
		Limit:     opts.Limit,
		Offset:    opts.Offset,
		StartDate: opts.StartDate,
		EndDate:   opts.EndDate,
		Actions:   opts.Actions,
		Success:   opts.Success,
		OrderBy:   opts.OrderBy,
		OrderDir:  opts.OrderDir,
	}

	repoActivities, err := s.repo.ListByResource(ctx, model.ResourceType(resourceType), resourceID, repoOpts)
	if err != nil {
		s.logger.Error("Failed to get resource activities",
			zap.Error(err),
			zap.String("resource_type", resourceType),
			zap.String("resource_id", resourceID.String()),
		)
		return nil, fmt.Errorf("getting resource activities: %w", err)
	}

	// Convert to service types
	activities := make([]*ActivityRecord, len(repoActivities))
	for i, repoActivity := range repoActivities {
		activities[i] = s.repoToActivityRecord(repoActivity)
	}

	return activities, nil
}

// GetUserActivities gets all activities for a specific user
func (s *activityService) GetUserActivities(ctx context.Context, userID xid.ID, opts *ActivityQueryOptions) ([]*ActivityRecord, error) {
	if userID == (xid.ID{}) {
		return nil, fmt.Errorf("user ID is required")
	}

	// Set default options if not provided
	if opts == nil {
		opts = &ActivityQueryOptions{
			Limit:    100,
			OrderBy:  "timestamp",
			OrderDir: "desc",
		}
	}

	// Convert to repository options
	repoOpts := &repository.ActivityQueryOptions{
		Limit:     opts.Limit,
		Offset:    opts.Offset,
		StartDate: opts.StartDate,
		EndDate:   opts.EndDate,
		Actions:   opts.Actions,
		Success:   opts.Success,
		OrderBy:   opts.OrderBy,
		OrderDir:  opts.OrderDir,
	}

	repoActivities, err := s.repo.ListByUser(ctx, userID, repoOpts)
	if err != nil {
		s.logger.Error("Failed to get user activities", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, fmt.Errorf("getting user activities: %w", err)
	}

	// Convert to service types
	activities := make([]*ActivityRecord, len(repoActivities))
	for i, repoActivity := range repoActivities {
		activities[i] = s.repoToActivityRecord(repoActivity)
	}

	return activities, nil
}

// GetOrganizationActivities gets all activities for a specific organization
func (s *activityService) GetOrganizationActivities(ctx context.Context, orgID xid.ID, opts *ActivityQueryOptions) ([]*ActivityRecord, error) {
	if orgID == (xid.ID{}) {
		return nil, fmt.Errorf("organization ID is required")
	}

	// Set default options if not provided
	if opts == nil {
		opts = &ActivityQueryOptions{
			Limit:    100,
			OrderBy:  "timestamp",
			OrderDir: "desc",
		}
	}

	// Convert to repository options
	repoOpts := &repository.ActivityQueryOptions{
		Limit:     opts.Limit,
		Offset:    opts.Offset,
		StartDate: opts.StartDate,
		EndDate:   opts.EndDate,
		Actions:   opts.Actions,
		Success:   opts.Success,
		OrderBy:   opts.OrderBy,
		OrderDir:  opts.OrderDir,
	}

	repoActivities, err := s.repo.ListByOrganization(ctx, orgID, repoOpts)
	if err != nil {
		s.logger.Error("Failed to get organization activities", zap.Error(err), zap.String("organization_id", orgID.String()))
		return nil, fmt.Errorf("getting organization activities: %w", err)
	}

	// Convert to service types
	activities := make([]*ActivityRecord, len(repoActivities))
	for i, repoActivity := range repoActivities {
		activities[i] = s.repoToActivityRecord(repoActivity)
	}

	return activities, nil
}

// GetActivityStats gets comprehensive activity statistics
func (s *activityService) GetActivityStats(ctx context.Context, req *ActivityStatsRequest) (*ActivityStats, error) {
	if req == nil {
		req = &ActivityStatsRequest{}
	}

	// Set default time range if not provided
	if req.StartDate == nil && req.EndDate == nil {
		now := time.Now()
		startDate := now.AddDate(0, 0, -30) // Default to last 30 days
		req.StartDate = &startDate
		req.EndDate = &now
	}

	// Convert to repository request
	repoReq := &repository.ActivityStatsRequest{
		ResourceType:   req.ResourceType,
		ResourceID:     req.ResourceID,
		UserID:         req.UserID,
		OrganizationID: req.OrganizationID,
		StartDate:      req.StartDate,
		EndDate:        req.EndDate,
		Granularity:    req.Granularity,
	}

	stats, err := s.repo.GetStats(ctx, repoReq)
	if err != nil {
		s.logger.Error("Failed to get activity stats", zap.Error(err))
		return nil, fmt.Errorf("getting activity stats: %w", err)
	}

	// Convert to service type (repository and service types are the same for stats)
	return (*ActivityStats)(stats), nil
}

// GetUsageMetrics gets usage metrics for billing and monitoring
func (s *activityService) GetUsageMetrics(ctx context.Context, req *UsageMetricsRequest) (*UsageMetrics, error) {
	if req == nil {
		return nil, fmt.Errorf("usage metrics request is required")
	}

	// Validate required fields
	if req.ResourceType == "" {
		return nil, fmt.Errorf("resource type is required")
	}
	if req.Period == "" {
		req.Period = "month" // Default to monthly metrics
	}

	// Convert to repository request
	repoReq := &repository.UsageMetricsRequest{
		ResourceType:   req.ResourceType,
		OrganizationID: req.OrganizationID,
		Period:         req.Period,
		MetricTypes:    req.MetricTypes,
		StartDate:      req.StartDate,
		EndDate:        req.EndDate,
	}

	metrics, err := s.repo.GetUsageMetrics(ctx, repoReq)
	if err != nil {
		s.logger.Error("Failed to get usage metrics", zap.Error(err))
		return nil, fmt.Errorf("getting usage metrics: %w", err)
	}

	// Convert to service type (repository and service types are the same for metrics)
	return (*UsageMetrics)(metrics), nil
}

// GetTrendAnalysis gets trend analysis and predictions
func (s *activityService) GetTrendAnalysis(ctx context.Context, req *TrendAnalysisRequest) (*TrendAnalysis, error) {
	if req == nil {
		return nil, fmt.Errorf("trend analysis request is required")
	}

	// Validate and set defaults
	if req.ResourceType == "" {
		return nil, fmt.Errorf("resource type is required")
	}
	if req.Days <= 0 {
		req.Days = 30 // Default to 30 days
	}
	if req.Days > 365 {
		req.Days = 365 // Maximum 1 year
	}

	// Convert to repository request
	repoReq := &repository.TrendAnalysisRequest{
		ResourceType:   req.ResourceType,
		OrganizationID: req.OrganizationID,
		Days:           req.Days,
		CompareWith:    req.CompareWith,
	}

	trends, err := s.repo.GetTrendAnalysis(ctx, repoReq)
	if err != nil {
		s.logger.Error("Failed to get trend analysis", zap.Error(err))
		return nil, fmt.Errorf("getting trend analysis: %w", err)
	}

	// Convert to service type (repository and service types are the same for trends)
	return trends, nil
}

// CleanupExpiredActivities deletes expired activity records
func (s *activityService) CleanupExpiredActivities(ctx context.Context, before time.Time) (int, error) {
	if before.IsZero() {
		return 0, fmt.Errorf("before time is required")
	}

	// Don't allow cleanup of recent data (safety check)
	if before.After(time.Now().AddDate(0, 0, -7)) {
		return 0, fmt.Errorf("cannot cleanup activities newer than 7 days")
	}

	deleted, err := s.repo.DeleteExpired(ctx, before)
	if err != nil {
		s.logger.Error("Failed to cleanup expired activities", zap.Error(err), zap.Time("before", before))
		return 0, fmt.Errorf("cleaning up expired activities: %w", err)
	}

	s.logger.Info("Cleaned up expired activities", zap.Int("deleted", deleted), zap.Time("before", before))
	return deleted, nil
}

// ArchiveOldActivities archives old activity records
func (s *activityService) ArchiveOldActivities(ctx context.Context, before time.Time) error {
	if before.IsZero() {
		return fmt.Errorf("before time is required")
	}

	// Don't allow archiving of recent data (safety check)
	if before.After(time.Now().AddDate(0, -3, 0)) {
		return fmt.Errorf("cannot archive activities newer than 3 months")
	}

	if err := s.repo.ArchiveOld(ctx, before); err != nil {
		s.logger.Error("Failed to archive old activities", zap.Error(err), zap.Time("before", before))
		return fmt.Errorf("archiving old activities: %w", err)
	}

	s.logger.Info("Archived old activities", zap.Time("before", before))
	return nil
}

// Helper and validation methods

// validateActivityRecord validates an activity record
func (s *activityService) validateActivityRecord(activity *ActivityRecord) error {
	if activity == nil {
		return fmt.Errorf("activity record is required")
	}

	// Required fields
	if activity.ResourceType == "" {
		return fmt.Errorf("resource type is required")
	}
	if activity.ResourceID == (xid.ID{}) {
		return fmt.Errorf("resource ID is required")
	}
	if activity.Action == "" {
		return fmt.Errorf("action is required")
	}

	// Validate resource type
	validResourceTypes := map[string]bool{
		"api_key":      true,
		"user":         true,
		"organization": true,
		"session":      true,
		"webhook":      true,
		"oauth_client": true,
		"passkey":      true,
		"mfa_device":   true,
		"role":         true,
		"permission":   true,
		"invitation":   true,
		"membership":   true,
	}
	if !validResourceTypes[string(activity.ResourceType)] {
		return fmt.Errorf("invalid resource type: %s", activity.ResourceType)
	}

	// Validate category
	if activity.Category == "" {
		activity.Category = "general" // Set default
	}

	validCategories := map[string]bool{
		"general":    true,
		"api":        true,
		"auth":       true,
		"admin":      true,
		"compliance": true,
		"security":   true,
		"billing":    true,
		"webhook":    true,
	}
	if !validCategories[activity.Category] {
		return fmt.Errorf("invalid category: %s", activity.Category)
	}

	// Validate source
	if activity.Source != "" {
		validSources := map[string]bool{
			"web":    true,
			"api":    true,
			"mobile": true,
			"system": true,
			"cli":    true,
		}
		if !validSources[activity.Source] {
			return fmt.Errorf("invalid source: %s", activity.Source)
		}
	}

	// Validate HTTP method if provided
	if activity.Method != "" {
		validMethods := map[string]bool{
			"GET":     true,
			"POST":    true,
			"PUT":     true,
			"PATCH":   true,
			"DELETE":  true,
			"HEAD":    true,
			"OPTIONS": true,
		}
		if !validMethods[activity.Method] {
			return fmt.Errorf("invalid HTTP method: %s", activity.Method)
		}
	}

	// Validate status code if provided
	if activity.StatusCode != 0 {
		if activity.StatusCode < 100 || activity.StatusCode > 599 {
			return fmt.Errorf("invalid HTTP status code: %d", activity.StatusCode)
		}
	}

	// Validate response time if provided
	if activity.ResponseTime < 0 {
		return fmt.Errorf("response time cannot be negative")
	}

	// Validate size if provided
	if activity.Size < 0 {
		return fmt.Errorf("size cannot be negative")
	}

	// Validate count if provided
	if activity.Count < 0 {
		return fmt.Errorf("count cannot be negative")
	}

	return nil
}

// activityRecordToRepo converts a service ActivityRecord to repository ActivityRecord
func (s *activityService) activityRecordToRepo(activity *ActivityRecord) *ActivityRecord {
	return &ActivityRecord{
		ID:             activity.ID,
		ResourceType:   activity.ResourceType,
		ResourceID:     activity.ResourceID,
		UserID:         activity.UserID,
		OrganizationID: activity.OrganizationID,
		SessionID:      activity.SessionID,
		Action:         activity.Action,
		Category:       activity.Category,
		Source:         activity.Source,
		Endpoint:       activity.Endpoint,
		Method:         activity.Method,
		StatusCode:     activity.StatusCode,
		ResponseTime:   activity.ResponseTime,
		IPAddress:      activity.IPAddress,
		UserAgent:      activity.UserAgent,
		Location:       activity.Location,
		Success:        activity.Success,
		Error:          activity.Error,
		ErrorCode:      activity.ErrorCode,
		Size:           activity.Size,
		Count:          activity.Count,
		Value:          activity.Value,
		Timestamp:      activity.Timestamp,
		ExpiresAt:      activity.ExpiresAt,
		Metadata:       activity.Metadata,
		Tags:           activity.Tags,
	}
}

// repoToActivityRecord converts a repository ActivityRecord to service ActivityRecord
func (s *activityService) repoToActivityRecord(repoActivity *model.ActivityRecord) *ActivityRecord {
	return &ActivityRecord{
		ID:             repoActivity.ID,
		ResourceType:   repoActivity.ResourceType,
		ResourceID:     repoActivity.ResourceID,
		UserID:         repoActivity.UserID,
		OrganizationID: repoActivity.OrganizationID,
		SessionID:      repoActivity.SessionID,
		Action:         repoActivity.Action,
		Category:       repoActivity.Category,
		Source:         repoActivity.Source,
		Endpoint:       repoActivity.Endpoint,
		Method:         repoActivity.Method,
		StatusCode:     repoActivity.StatusCode,
		ResponseTime:   repoActivity.ResponseTime,
		IPAddress:      repoActivity.IPAddress,
		UserAgent:      repoActivity.UserAgent,
		Location:       repoActivity.Location,
		Success:        repoActivity.Success,
		Error:          repoActivity.Error,
		ErrorCode:      repoActivity.ErrorCode,
		Size:           repoActivity.Size,
		Count:          repoActivity.Count,
		Value:          repoActivity.Value,
		Timestamp:      repoActivity.Timestamp,
		ExpiresAt:      repoActivity.ExpiresAt,
		Metadata:       repoActivity.Metadata,
		Tags:           repoActivity.Tags,
	}
}

// Type aliases for better readability and consistency with repository types
type (
	GetActivitiesRequest = repository.GetActivitiesRequest
	ActivityQueryOptions = repository.ActivityQueryOptions
	ActivityStatsRequest = repository.ActivityStatsRequest
	ActivityStats        = repository.ActivityStats
	UsageMetricsRequest  = repository.UsageMetricsRequest
	UsageMetrics         = repository.UsageMetrics
	TrendAnalysisRequest = repository.TrendAnalysisRequest
	TrendAnalysis        = repository.TrendAnalysis
	EndpointStats        = repository.EndpointStats
	ErrorRateStats       = repository.ErrorRateStats
	ErrorDetail          = repository.ErrorDetail
	ResponseTimeStats    = repository.ResponseTimeStats
	GrowthMetrics        = repository.GrowthMetrics
	SeasonalPattern      = repository.SeasonalPattern
	Anomaly              = repository.Anomaly
	PredictionMetrics    = repository.PredictionMetrics
	ActivityRecord       = model.ActivityRecord
)

// // RecordAPIActivity records API-specific activity
// func (s *activityService) RecordAPIActivity(ctx context.Context, apiActivity *APIActivityRecord) error {
// 	activity := &ActivityRecord{
// 		ID:           xid.New(),
// 		ResourceType: "api_key",
// 		ResourceID:   apiActivity.KeyID,
// 		Action:       "api_request",
// 		Category:     "api",
// 		Source:       "api",
// 		Endpoint:     apiActivity.Endpoint,
// 		Method:       apiActivity.Method,
// 		StatusCode:   apiActivity.StatusCode,
// 		ResponseTime: apiActivity.ResponseTime,
// 		IPAddress:    apiActivity.IPAddress,
// 		UserAgent:    apiActivity.UserAgent,
// 		Success:      apiActivity.Success,
// 		Error:        apiActivity.Error,
// 		Timestamp:    apiActivity.Timestamp,
// 		// Auto-expire API activities after 90 days
// 		ExpiresAt: &[]time.Time{apiActivity.Timestamp.AddDate(0, 0, 90)}[0],
// 	}
//
// 	return s.RecordActivity(ctx, activity)
// }
//
// // RecordUserActivity records user-specific activity
// func (s *activityService) RecordUserActivity(ctx context.Context, userActivity *UserActivityRecord) error {
// 	activity := &ActivityRecord{
// 		ID:             xid.New(),
// 		ResourceType:   "user",
// 		ResourceID:     userActivity.UserID,
// 		UserID:         &userActivity.UserID,
// 		OrganizationID: userActivity.OrganizationID,
// 		Action:         userActivity.Action,
// 		Category:       "auth",
// 		Source:         "web",
// 		IPAddress:      userActivity.IPAddress,
// 		UserAgent:      userActivity.UserAgent,
// 		Success:        userActivity.Success,
// 		Error:          userActivity.Error,
// 		Timestamp:      userActivity.Timestamp,
// 		// Auto-expire user activities after 2 years for compliance
// 		ExpiresAt: &[]time.Time{userActivity.Timestamp.AddDate(2, 0, 0)}[0],
// 	}
//
// 	return s.RecordActivity(ctx, activity)
// }
//
// // GetResourceActivities gets all activities for a specific resource
// func (s *activityService) GetResourceActivities(ctx context.Context, resourceType string, resourceID xid.ID, opts *ActivityQueryOptions) ([]*ActivityRecord, error) {
// 	if opts == nil {
// 		opts = &ActivityQueryOptions{
// 			Limit: 100,
// 		}
// 	}
//
// 	req := &GetActivitiesRequest{
// 		ResourceType: resourceType,
// 		ResourceID:   &resourceID,
// 		Limit:        opts.Limit,
// 		Offset:       opts.Offset,
// 		StartDate:    opts.StartDate,
// 		EndDate:      opts.EndDate,
// 		Actions:      opts.Actions,
// 		Success:      opts.Success,
// 	}
//
// 	result, err := s.GetActivities(ctx, req)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return result.Data, nil
// }
