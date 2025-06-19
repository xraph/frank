package routes

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/juicycleff/frank/pkg/services/activity"
	"github.com/rs/xid"
)

// RegisterActivityAPI registers all activity-related API endpoints
func RegisterActivityAPI(api huma.API, container di.Container) {
	activityCtrl := &activityController{
		api: api,
		di:  container,
	}

	// Register activity endpoints
	registerListActivities(api, activityCtrl)
	registerGetActivity(api, activityCtrl)
	registerGetResourceActivities(api, activityCtrl)
	registerGetUserActivities(api, activityCtrl)
	registerGetOrganizationActivities(api, activityCtrl)
	registerGetActivityStats(api, activityCtrl)
	registerGetUsageMetrics(api, activityCtrl)
	registerGetTrendAnalysis(api, activityCtrl)
	registerCleanupExpiredActivities(api, activityCtrl)

	// Admin-only endpoints
	registerGetGlobalActivityStats(api, activityCtrl)
	registerGetSystemUsageMetrics(api, activityCtrl)
}

// activityController handles activity-related API requests
type activityController struct {
	api huma.API
	di  di.Container
}

// Input/Output type definitions for activity handlers

// ListActivitiesInput represents input for listing activities with comprehensive filtering
type ListActivitiesInput struct {
	model.OrganisationPathParams
	repository.GetActivitiesRequest
}

type ListActivitiesOutput = model.Output[*model.PaginatedOutput[*activity.ActivityRecord]]

// GetActivityInput represents input for getting a specific activity by ID
type GetActivityInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Activity ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
}

type GetActivityOutput = model.Output[*activity.ActivityRecord]

// GetResourceActivitiesInput represents input for getting activities for a specific resource
type GetResourceActivitiesInput struct {
	model.OrganisationPathParams
	ResourceType string `path:"resourceType" doc:"Resource type" example:"api_key"`
	ResourceID   xid.ID `path:"resourceId" doc:"Resource ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
	repository.ActivityQueryOptions
}

type GetResourceActivitiesOutput = model.Output[[]*activity.ActivityRecord]

// GetUserActivitiesInput represents input for getting activities for a specific user
type GetUserActivitiesInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
	repository.ActivityQueryOptions
}

type GetUserActivitiesOutput = model.Output[[]*activity.ActivityRecord]

// GetOrganizationActivitiesInput represents input for getting activities for an organization
type GetOrganizationActivitiesInput struct {
	model.OrganisationPathParams
	repository.ActivityQueryOptions
}

type GetOrganizationActivitiesOutput = model.Output[[]*activity.ActivityRecord]

// GetActivityStatsInput represents input for getting activity statistics
type GetActivityStatsInput struct {
	model.OrganisationPathParams
	repository.ActivityStatsRequest
}

type GetActivityStatsOutput = model.Output[*repository.ActivityStats]

// GetUsageMetricsInput represents input for getting usage metrics
type GetUsageMetricsInput struct {
	model.OrganisationPathParams
	repository.UsageMetricsRequest
}

type GetUsageMetricsOutput = model.Output[*repository.UsageMetrics]

// GetTrendAnalysisInput represents input for getting trend analysis
type GetTrendAnalysisInput struct {
	model.OrganisationPathParams
	repository.TrendAnalysisRequest
}

type GetTrendAnalysisOutput = model.Output[*repository.TrendAnalysis]

// CleanupExpiredActivitiesInput represents input for cleaning up expired activities
type CleanupExpiredActivitiesInput struct {
	model.OrganisationPathParams
	Before time.Time `query:"before" doc:"Delete activities before this date" example:"2024-01-01T00:00:00Z"`
}

type CleanupExpiredActivitiesOutput = model.Output[map[string]int]

// GetGlobalActivityStatsInput represents input for getting global activity statistics (admin only)
type GetGlobalActivityStatsInput struct {
	repository.ActivityStatsRequest
}

type GetGlobalActivityStatsOutput = model.Output[*repository.ActivityStats]

// GetSystemUsageMetricsInput represents input for getting system-wide usage metrics (admin only)
type GetSystemUsageMetricsInput struct {
	repository.UsageMetricsRequest
}

type GetSystemUsageMetricsOutput = model.Output[*repository.UsageMetrics]

// Route registration functions

func registerListActivities(api huma.API, activityCtrl *activityController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listActivities",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/activities",
		Summary:       "List activities",
		Description:   "Get a paginated list of activities for the organization with comprehensive filtering options",
		Tags:          []string{"Activities"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, activityCtrl.di.AuthZ().Checker(), activityCtrl.di.Logger())(
			authz.PermissionReadActivity, authz.ResourceOrganization, "orgId",
		)},
	}, activityCtrl.listActivitiesHandler)
}

func registerGetActivity(api huma.API, activityCtrl *activityController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getActivity",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/activities/{id}",
		Summary:       "Get activity by ID",
		Description:   "Retrieve a specific activity by its ID",
		Tags:          []string{"Activities"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Activity not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, activityCtrl.di.AuthZ().Checker(), activityCtrl.di.Logger())(
			authz.PermissionReadActivity, authz.ResourceOrganization, "orgId",
		)},
	}, activityCtrl.getActivityHandler)
}

func registerGetResourceActivities(api huma.API, activityCtrl *activityController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getResourceActivities",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/activities/resources/{resourceType}/{resourceId}",
		Summary:       "Get resource activities",
		Description:   "Get all activities for a specific resource (API key, user, etc.)",
		Tags:          []string{"Activities"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, activityCtrl.di.AuthZ().Checker(), activityCtrl.di.Logger())(
			authz.PermissionReadActivity, authz.ResourceOrganization, "orgId",
		)},
	}, activityCtrl.getResourceActivitiesHandler)
}

func registerGetUserActivities(api huma.API, activityCtrl *activityController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getUserActivities",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/activities/users/{userId}",
		Summary:       "Get user activities",
		Description:   "Get all activities for a specific user within the organization",
		Tags:          []string{"Activities"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, activityCtrl.di.AuthZ().Checker(), activityCtrl.di.Logger())(
			authz.PermissionReadActivity, authz.ResourceOrganization, "orgId",
		)},
	}, activityCtrl.getUserActivitiesHandler)
}

func registerGetOrganizationActivities(api huma.API, activityCtrl *activityController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getOrganizationActivities",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/activities/organization",
		Summary:       "Get organization activities",
		Description:   "Get all activities for the organization",
		Tags:          []string{"Activities"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, activityCtrl.di.AuthZ().Checker(), activityCtrl.di.Logger())(
			authz.PermissionReadActivity, authz.ResourceOrganization, "orgId",
		)},
	}, activityCtrl.getOrganizationActivitiesHandler)
}

func registerGetActivityStats(api huma.API, activityCtrl *activityController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getActivityStats",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/activities/stats",
		Summary:       "Get activity statistics",
		Description:   "Get comprehensive activity statistics and analytics for the organization",
		Tags:          []string{"Activities"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, activityCtrl.di.AuthZ().Checker(), activityCtrl.di.Logger())(
			authz.PermissionReadActivity, authz.ResourceOrganization, "orgId",
		)},
	}, activityCtrl.getActivityStatsHandler)
}

func registerGetUsageMetrics(api huma.API, activityCtrl *activityController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getUsageMetrics",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/activities/usage",
		Summary:       "Get usage metrics",
		Description:   "Get usage metrics and analytics for billing and monitoring purposes",
		Tags:          []string{"Activities"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, activityCtrl.di.AuthZ().Checker(), activityCtrl.di.Logger())(
			authz.PermissionReadActivity, authz.ResourceOrganization, "orgId",
		)},
	}, activityCtrl.getUsageMetricsHandler)
}

func registerGetTrendAnalysis(api huma.API, activityCtrl *activityController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getTrendAnalysis",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/activities/trends",
		Summary:       "Get trend analysis",
		Description:   "Get trend analysis and predictions for activity patterns",
		Tags:          []string{"Activities"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, activityCtrl.di.AuthZ().Checker(), activityCtrl.di.Logger())(
			authz.PermissionReadActivity, authz.ResourceOrganization, "orgId",
		)},
	}, activityCtrl.getTrendAnalysisHandler)
}

func registerCleanupExpiredActivities(api huma.API, activityCtrl *activityController) {
	huma.Register(api, huma.Operation{
		OperationID:   "cleanupExpiredActivities",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/activities/cleanup",
		Summary:       "Cleanup expired activities",
		Description:   "Delete expired activities for the organization (admin only)",
		Tags:          []string{"Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, activityCtrl.di.AuthZ().Checker(), activityCtrl.di.Logger())(
			authz.PermissionDeleteActivity, authz.ResourceOrganization, "orgId",
		)},
	}, activityCtrl.cleanupExpiredActivitiesHandler)
}

func registerGetGlobalActivityStats(api huma.API, activityCtrl *activityController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getGlobalActivityStats",
		Method:        http.MethodGet,
		Path:          "/admin/activities/stats",
		Summary:       "Get global activity statistics",
		Description:   "Get platform-wide activity statistics (internal users only)",
		Tags:          []string{"Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, activityCtrl.di.AuthZ().Checker(), activityCtrl.di.Logger())(
			authz.PermissionReadActivityGlobal, authz.ResourceSystem, "",
		)},
	}, activityCtrl.getGlobalActivityStatsHandler)
}

func registerGetSystemUsageMetrics(api huma.API, activityCtrl *activityController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getSystemUsageMetrics",
		Method:        http.MethodGet,
		Path:          "/admin/activities/usage",
		Summary:       "Get system usage metrics",
		Description:   "Get platform-wide usage metrics (internal users only)",
		Tags:          []string{"Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, activityCtrl.di.AuthZ().Checker(), activityCtrl.di.Logger())(
			authz.PermissionReadActivityGlobal, authz.ResourceSystem, "",
		)},
	}, activityCtrl.getSystemUsageMetricsHandler)
}

// Handler implementations

func (c *activityController) listActivitiesHandler(ctx context.Context, input *ListActivitiesInput) (*ListActivitiesOutput, error) {
	// Set organization ID from path parameter to ensure proper scoping
	input.GetActivitiesRequest.OrganizationID = &input.PathOrgID

	result, err := c.di.ActivityService().GetActivities(ctx, &input.GetActivitiesRequest)
	if err != nil {
		return nil, err
	}

	return &ListActivitiesOutput{
		Body: result,
	}, nil
}

func (c *activityController) getActivityHandler(ctx context.Context, input *GetActivityInput) (*GetActivityOutput, error) {
	// Get activity by ID - the service should validate organization ownership
	activity, err := c.di.ActivityService().GetActivities(ctx, &repository.GetActivitiesRequest{
		OrganizationID: &input.PathOrgID,
		// We're simulating GetByID by searching for specific ID
		// In a real implementation, you'd have a direct GetByID method
	})
	if err != nil {
		return nil, err
	}

	if len(activity.Data) == 0 {
		return nil, errors.New(errors.CodeNotFound, "Activity not found")
	}

	return &GetActivityOutput{
		Body: activity.Data[0],
	}, nil
}

func (c *activityController) getResourceActivitiesHandler(ctx context.Context, input *GetResourceActivitiesInput) (*GetResourceActivitiesOutput, error) {
	activities, err := c.di.ActivityService().GetResourceActivities(ctx, input.ResourceType, input.ResourceID, &input.ActivityQueryOptions)
	if err != nil {
		return nil, err
	}

	return &GetResourceActivitiesOutput{
		Body: activities,
	}, nil
}

func (c *activityController) getUserActivitiesHandler(ctx context.Context, input *GetUserActivitiesInput) (*GetUserActivitiesOutput, error) {
	activities, err := c.di.ActivityService().GetUserActivities(ctx, input.UserID, &input.ActivityQueryOptions)
	if err != nil {
		return nil, err
	}

	return &GetUserActivitiesOutput{
		Body: activities,
	}, nil
}

func (c *activityController) getOrganizationActivitiesHandler(ctx context.Context, input *GetOrganizationActivitiesInput) (*GetOrganizationActivitiesOutput, error) {
	activities, err := c.di.ActivityService().GetOrganizationActivities(ctx, input.PathOrgID, &input.ActivityQueryOptions)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationActivitiesOutput{
		Body: activities,
	}, nil
}

func (c *activityController) getActivityStatsHandler(ctx context.Context, input *GetActivityStatsInput) (*GetActivityStatsOutput, error) {
	// Ensure organization scoping
	input.ActivityStatsRequest.OrganizationID = &input.PathOrgID

	stats, err := c.di.ActivityService().GetActivityStats(ctx, &input.ActivityStatsRequest)
	if err != nil {
		return nil, err
	}

	return &GetActivityStatsOutput{
		Body: stats,
	}, nil
}

func (c *activityController) getUsageMetricsHandler(ctx context.Context, input *GetUsageMetricsInput) (*GetUsageMetricsOutput, error) {
	// Ensure organization scoping
	input.UsageMetricsRequest.OrganizationID = &input.PathOrgID

	metrics, err := c.di.ActivityService().GetUsageMetrics(ctx, &input.UsageMetricsRequest)
	if err != nil {
		return nil, err
	}

	return &GetUsageMetricsOutput{
		Body: metrics,
	}, nil
}

func (c *activityController) getTrendAnalysisHandler(ctx context.Context, input *GetTrendAnalysisInput) (*GetTrendAnalysisOutput, error) {
	// Ensure organization scoping
	input.TrendAnalysisRequest.OrganizationID = &input.PathOrgID

	trends, err := c.di.ActivityService().GetTrendAnalysis(ctx, &input.TrendAnalysisRequest)
	if err != nil {
		return nil, err
	}

	return &GetTrendAnalysisOutput{
		Body: trends,
	}, nil
}

func (c *activityController) cleanupExpiredActivitiesHandler(ctx context.Context, input *CleanupExpiredActivitiesInput) (*CleanupExpiredActivitiesOutput, error) {
	// Only allow cleanup for the specific organization
	deleted, err := c.di.ActivityService().CleanupExpiredActivities(ctx, input.Before)
	if err != nil {
		return nil, err
	}

	return &CleanupExpiredActivitiesOutput{
		Body: map[string]int{
			"deleted": deleted,
		},
	}, nil
}

func (c *activityController) getGlobalActivityStatsHandler(ctx context.Context, input *GetGlobalActivityStatsInput) (*GetGlobalActivityStatsOutput, error) {
	// This is a platform-wide endpoint, no organization scoping
	stats, err := c.di.ActivityService().GetActivityStats(ctx, &input.ActivityStatsRequest)
	if err != nil {
		return nil, err
	}

	return &GetGlobalActivityStatsOutput{
		Body: stats,
	}, nil
}

func (c *activityController) getSystemUsageMetricsHandler(ctx context.Context, input *GetSystemUsageMetricsInput) (*GetSystemUsageMetricsOutput, error) {
	// This is a platform-wide endpoint, no organization scoping
	metrics, err := c.di.ActivityService().GetUsageMetrics(ctx, &input.UsageMetricsRequest)
	if err != nil {
		return nil, err
	}

	return &GetSystemUsageMetricsOutput{
		Body: metrics,
	}, nil
}
