package routes

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/xid"
	"github.com/xraph/frank/internal/authz"
	"github.com/xraph/frank/internal/di"
	"github.com/xraph/frank/pkg/model"
)

// RegisterPlatformAdminAPI registers internal platform administration endpoints
func RegisterPlatformAdminAPI(group huma.API, di di.Container) {
	di.Logger().Info("Registering platform admin API routes")

	platformCtrl := &platformAdminController{
		api: group,
		di:  di,
	}

	// Organization Management
	registerListAllOrganizations(group, platformCtrl)
	registerGetOrganizationDetails(group, platformCtrl)
	registerSuspendOrganization(group, platformCtrl)
	registerCreatePlatformUserHandler(group, platformCtrl)
	registerCreateOrganizationHandlerPlatform(group, platformCtrl)
	registerActivateOrganization(group, platformCtrl)
	registerDeleteOrganizationPlatform(group, platformCtrl)
	registerGetOrganizationStatsPlatform(group, platformCtrl)
	registerGetOrganizationUsagePlatform(group, platformCtrl)

	// User Management
	registerListAllUsers(group, platformCtrl)
	registerGetUserDetails(group, platformCtrl)
	registerImpersonateUser(group, platformCtrl)
	registerBlockUser(group, platformCtrl)
	registerUnblockUser(group, platformCtrl)
	registerResetUserPassword(group, platformCtrl)
	registerGetUserSessionsPlatform(group, platformCtrl)
	registerRevokeUserSessions(group, platformCtrl)

	// Platform Analytics
	registerGetPlatformStats(group, platformCtrl)
	registerGetPlatformMetrics(group, platformCtrl)
	registerGetGrowthMetrics(group, platformCtrl)
	registerGetRevenueMetrics(group, platformCtrl)
	registerGetUsageAnalytics(group, platformCtrl)

	// System Monitoring
	registerGetSystemHealth(group, platformCtrl)
	registerGetSystemMetrics(group, platformCtrl)
	registerGetPerformanceMetrics(group, platformCtrl)
	registerGetErrorRates(group, platformCtrl)
	registerGetAuditSummary(group, platformCtrl)

	// Feature Management
	registerListFeatureFlags(group, platformCtrl)
	registerCreateFeatureFlag(group, platformCtrl)
	registerUpdateFeatureFlag(group, platformCtrl)
	registerDeleteFeatureFlag(group, platformCtrl)
	registerGetFeatureUsage(group, platformCtrl)

	// Billing & Subscriptions
	registerGetBillingOverview(group, platformCtrl)
	registerListSubscriptions(group, platformCtrl)
	registerGetSubscriptionDetails(group, platformCtrl)
	registerUpdateSubscription(group, platformCtrl)
	registerCancelSubscription(group, platformCtrl)
	registerGetRevenueReport(group, platformCtrl)

	// Security & Compliance
	registerGetSecurityDashboard(group, platformCtrl)
	registerListSecurityIncidents(group, platformCtrl)
	registerGetComplianceReport(group, platformCtrl)
	registerRunSecurityScan(group, platformCtrl)
	registerGetAuditTrail(group, platformCtrl)

	// API Management
	registerGetAPIUsage(group, platformCtrl)
	registerListAPIKeysPlatform(group, platformCtrl)
	registerRevokeAPIKey(group, platformCtrl)
	registerGetRateLimitStats(group, platformCtrl)

	// Support & Operations
	registerListSupportTickets(group, platformCtrl)
	registerGetMaintenanceWindows(group, platformCtrl)
	registerScheduleMaintenance(group, platformCtrl)
	registerSendPlatformNotification(group, platformCtrl)
}

// platformAdminController handles platform administration requests
type platformAdminController struct {
	api huma.API
	di  di.Container
}

// Organization Management Routes

func registerListAllOrganizations(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listAllOrganizationsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/organizations",
		Summary:       "List all organizations",
		Description:   "Get a paginated list of all organizations on the platform",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.listAllOrganizationsHandler)
}

func registerGetOrganizationDetails(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getOrganizationDetailsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/organizations/{id}",
		Summary:       "Get organization details",
		Description:   "Get detailed information about a specific organization",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getOrganizationDetailsHandler)
}

func registerSuspendOrganization(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "suspendOrganizationPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/organizations/{id}/suspend",
		Summary:       "Suspend organization",
		Description:   "Suspend an organization and disable all access",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.suspendOrganizationHandler)
}

func registerActivateOrganization(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "activateOrganizationPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/organizations/{id}/activate",
		Summary:       "Activate organization",
		Description:   "Activate a suspended organization",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.activateOrganizationHandler)
}

func registerDeleteOrganizationPlatform(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteOrganizationPlatform",
		Method:        http.MethodDelete,
		Path:          "/platform/organizations/{id}",
		Summary:       "Delete organization",
		Description:   "Permanently delete an organization and all associated data",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.deleteOrganizationHandler)
}

func registerCreateOrganizationHandlerPlatform(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "createPlatformOrganization",
		Method:        http.MethodPost,
		Path:          "/platform/organizations",
		Summary:       "Create organization",
		Description:   "Create an organization",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.createOrganizationHandler)
}

func registerGetOrganizationStatsPlatform(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getOrganizationStatsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/organizations/{id}/stats",
		Summary:       "Get organization statistics",
		Description:   "Get usage and performance statistics for an organization",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getOrganizationStatsHandler)
}

func registerGetOrganizationUsagePlatform(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganizationUsagePlatform",
		Method:      http.MethodGet,
		Path:        "/platform/organizations/{id}/usage",
		Summary:     "Get organization usage",
		Description: "Get detailed usage metrics for billing and monitoring",
		// Tags:          []string{"Platform Admin"},
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getOrganizationUsageHandler)
}

// User Management Routes

func registerListAllUsers(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listAllUsersPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/users",
		Summary:       "List all users",
		Description:   "Get a paginated list of all users across all organizations",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.listAllUsersHandler)
}

func registerGetUserDetails(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getUserDetailsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/users/{id}",
		Summary:       "Get user details",
		Description:   "Get detailed information about a specific user",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getUserDetailsHandler)
}

func registerCreatePlatformUserHandler(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "createUserPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/users",
		Summary:       "Create user",
		Description:   "Create user information about a specific user",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.createPlatformUserHandler)
}

func registerImpersonateUser(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "impersonateUserPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/users/{id}/impersonate",
		Summary:       "Impersonate user",
		Description:   "Create an impersonation session for troubleshooting",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.impersonateUserHandler)
}

func registerBlockUser(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "blockUserPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/users/{id}/block",
		Summary:       "Block user",
		Description:   "Block a user account for security or compliance reasons",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.blockUserHandler)
}

func registerUnblockUser(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "unblockUserPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/users/{id}/unblock",
		Summary:       "Unblock user",
		Description:   "Unblock a previously blocked user account",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.unblockUserHandler)
}

func registerResetUserPassword(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "resetUserPasswordPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/users/{id}/reset-password",
		Summary:       "Reset user password",
		Description:   "Force a password reset for a user account",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.resetUserPasswordHandler)
}

func registerGetUserSessionsPlatform(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getUserSessionsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/users/{id}/sessions",
		Summary:       "Get user sessions",
		Description:   "Get all active sessions for a user",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getUserSessionsHandler)
}

func registerRevokeUserSessions(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "revokeUserSessionsPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/users/{id}/revoke-sessions",
		Summary:       "Revoke user sessions",
		Description:   "Revoke all active sessions for a user",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.revokeUserSessionsHandler)
}

// Platform Analytics Routes

func registerGetPlatformStats(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getPlatformStatsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/stats",
		Summary:       "Get platform statistics",
		Description:   "Get overall platform statistics and KPIs",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getPlatformStatsHandler)
}

func registerGetPlatformMetrics(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getPlatformMetricsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/metrics",
		Summary:       "Get platform metrics",
		Description:   "Get detailed platform performance and usage metrics",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getPlatformMetricsHandler)
}

func registerGetGrowthMetrics(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getGrowthMetricsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/metrics/growth",
		Summary:       "Get growth metrics",
		Description:   "Get platform growth and adoption metrics",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getGrowthMetricsHandler)
}

func registerGetRevenueMetrics(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getRevenueMetricsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/metrics/revenue",
		Summary:       "Get revenue metrics",
		Description:   "Get platform revenue and financial metrics",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getRevenueMetricsHandler)
}

func registerGetUsageAnalytics(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getUsageAnalyticsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/analytics/usage",
		Summary:       "Get usage analytics",
		Description:   "Get detailed usage analytics across all features",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getUsageAnalyticsHandler)
}

// System Monitoring Routes

func registerGetSystemHealth(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getSystemHealthPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/system/health",
		Summary:       "Get system health",
		Description:   "Get overall system health status and checks",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getSystemHealthHandler)
}

func registerGetSystemMetrics(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getSystemMetricsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/system/metrics",
		Summary:       "Get system metrics",
		Description:   "Get system performance metrics and resource usage",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getSystemMetricsHandler)
}

func registerGetPerformanceMetrics(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getPerformanceMetricsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/system/performance",
		Summary:       "Get performance metrics",
		Description:   "Get detailed system performance metrics",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getPerformanceMetricsHandler)
}

func registerGetErrorRates(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getErrorRatesPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/system/errors",
		Summary:       "Get error rates",
		Description:   "Get system error rates and error analysis",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getErrorRatesHandler)
}

func registerGetAuditSummary(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getAuditSummaryPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/audit/summary",
		Summary:       "Get audit summary",
		Description:   "Get high-level audit activity summary",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getAuditSummaryHandler)
}

// Feature Management Routes

func registerListFeatureFlags(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listFeatureFlagsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/features",
		Summary:       "List feature flags",
		Description:   "Get all platform feature flags and their status",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.listFeatureFlagsHandler)
}

func registerCreateFeatureFlag(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "createFeatureFlagPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/features",
		Summary:       "Create feature flag",
		Description:   "Create a new platform feature flag",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 201,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid feature flag configuration")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.createFeatureFlagHandler)
}

func registerUpdateFeatureFlag(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "updateFeatureFlagPlatform",
		Method:        http.MethodPut,
		Path:          "/platform/features/{id}",
		Summary:       "Update feature flag",
		Description:   "Update an existing feature flag",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Feature flag not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.updateFeatureFlagHandler)
}

func registerDeleteFeatureFlag(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteFeatureFlagPlatform",
		Method:        http.MethodDelete,
		Path:          "/platform/features/{id}",
		Summary:       "Delete feature flag",
		Description:   "Delete a feature flag",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Feature flag not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.deleteFeatureFlagHandler)
}

func registerGetFeatureUsage(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getFeatureUsagePlatform",
		Method:        http.MethodGet,
		Path:          "/platform/features/usage",
		Summary:       "Get feature usage",
		Description:   "Get usage statistics for all platform features",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getFeatureUsageHandler)
}

// Billing & Subscriptions Routes

func registerGetBillingOverview(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getBillingOverviewPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/billing/overview",
		Summary:       "Get billing overview",
		Description:   "Get platform-wide billing overview and metrics",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getBillingOverviewHandler)
}

func registerListSubscriptions(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listSubscriptionsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/subscriptions",
		Summary:       "List subscriptions",
		Description:   "Get all active subscriptions across the platform",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.listSubscriptionsHandler)
}

func registerGetSubscriptionDetails(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getSubscriptionDetailsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/subscriptions/{id}",
		Summary:       "Get subscription details",
		Description:   "Get detailed information about a specific subscription",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Subscription not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getSubscriptionDetailsHandler)
}

func registerUpdateSubscription(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "updateSubscriptionPlatform",
		Method:        http.MethodPut,
		Path:          "/platform/subscriptions/{id}",
		Summary:       "Update subscription",
		Description:   "Update subscription details or status",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Subscription not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.updateSubscriptionHandler)
}

func registerCancelSubscription(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "cancelSubscriptionPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/subscriptions/{id}/cancel",
		Summary:       "Cancel subscription",
		Description:   "Cancel a subscription",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Subscription not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.cancelSubscriptionHandler)
}

func registerGetRevenueReport(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getRevenueReportPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/billing/revenue",
		Summary:       "Get revenue report",
		Description:   "Get detailed revenue report and projections",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getRevenueReportHandler)
}

// Security & Compliance Routes

func registerGetSecurityDashboard(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getSecurityDashboardPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/security/dashboard",
		Summary:       "Get security dashboard",
		Description:   "Get security overview and threat analysis",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getSecurityDashboardHandler)
}

func registerListSecurityIncidents(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listSecurityIncidentsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/security/incidents",
		Summary:       "List security incidents",
		Description:   "Get all security incidents and alerts",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.listSecurityIncidentsHandler)
}

func registerGetComplianceReport(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getComplianceReportPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/compliance/report",
		Summary:       "Get compliance report",
		Description:   "Get comprehensive compliance status report",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getComplianceReportHandler)
}

func registerRunSecurityScan(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "runSecurityScanPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/security/scan",
		Summary:       "Run security scan",
		Description:   "Initiate a comprehensive security scan",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 202,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.runSecurityScanHandler)
}

func registerGetAuditTrail(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getAuditTrailPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/audit/trail",
		Summary:       "Get audit trail",
		Description:   "Get comprehensive audit trail with advanced filtering",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getAuditTrailHandler)
}

// API Management Routes

func registerGetAPIUsage(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getAPIUsagePlatform",
		Method:        http.MethodGet,
		Path:          "/platform/api/usage",
		Summary:       "Get API usage",
		Description:   "Get platform-wide API usage statistics",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getAPIUsageHandler)
}

func registerListAPIKeysPlatform(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listAPIKeysPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/api/keys",
		Summary:       "List API keys",
		Description:   "Get all API keys across all organizations",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.listAPIKeysHandler)
}

func registerRevokeAPIKey(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "revokeAPIKeyPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/api/keys/{id}/revoke",
		Summary:       "Revoke API key",
		Description:   "Revoke an API key for security reasons",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("API key not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.revokeAPIKeyHandler)
}

func registerGetRateLimitStats(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getRateLimitStatsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/api/rate-limits",
		Summary:       "Get rate limit statistics",
		Description:   "Get API rate limiting statistics and violations",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getRateLimitStatsHandler)
}

// Support & Operations Routes

func registerListSupportTickets(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listSupportTicketsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/support/tickets",
		Summary:       "List support tickets",
		Description:   "Get all support tickets across the platform",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.listSupportTicketsHandler)
}

func registerGetMaintenanceWindows(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getMaintenanceWindowsPlatform",
		Method:        http.MethodGet,
		Path:          "/platform/maintenance",
		Summary:       "Get maintenance windows",
		Description:   "Get scheduled and completed maintenance windows",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.getMaintenanceWindowsHandler)
}

func registerScheduleMaintenance(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "scheduleMaintenancePlatform",
		Method:        http.MethodPost,
		Path:          "/platform/maintenance",
		Summary:       "Schedule maintenance",
		Description:   "Schedule a maintenance window",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 201,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid maintenance schedule")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.scheduleMaintenanceHandler)
}

func registerSendPlatformNotification(api huma.API, ctrl *platformAdminController) {
	huma.Register(api, huma.Operation{
		OperationID:   "sendPlatformNotificationPlatform",
		Method:        http.MethodPost,
		Path:          "/platform/notifications",
		Summary:       "Send platform notification",
		Description:   "Send a notification to all or specific organizations",
		Tags:          []string{"Platform Admin"},
		DefaultStatus: 202,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid notification")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManagePlatform, model.ResourceSystem, "",
		)},
	}, ctrl.sendPlatformNotificationHandler)
}

// Handler Input/Output Types

// ListAllOrganizationsInput Organization Management
type ListAllOrganizationsInput struct {
	model.PaginationParams
	Status model.OptionalParam[string] `query:"status" doc:"Filter by organization status"`
	Plan   model.OptionalParam[string] `query:"plan" doc:"Filter by subscription plan"`
	Search model.OptionalParam[string] `query:"search" doc:"Search organizations by name or domain"`
}

type ListAllOrganizationsOutput = model.Output[*model.PlatformOrganizationListResponse]

type GetOrganizationDetailsInput struct {
	ID xid.ID `path:"id" doc:"Organization ID"`
}

type GetOrganizationDetailsOutput = model.Output[*model.PlatformOrganizationDetails]

type SuspendOrganizationInput struct {
	ID   xid.ID                           `path:"id" doc:"Organization ID"`
	Body model.SuspendOrganizationRequest `json:"body"`
}

type SuspendOrganizationOutput = model.Output[map[string]interface{}]

type ActivateOrganizationInput struct {
	ID   xid.ID                            `path:"id" doc:"Organization ID"`
	Body model.ActivateOrganizationRequest `json:"body"`
}

type ActivateOrganizationOutput = model.Output[map[string]interface{}]

type DeleteOrganizationPlatformInput struct {
	ID   xid.ID                          `path:"id" doc:"Organization ID"`
	Body model.DeleteOrganizationRequest `json:"body"`
}

type DeleteOrganizationOutput = model.Output[map[string]interface{}]

type GetOrganizationStatsInput struct {
	ID     xid.ID                      `path:"id" doc:"Organization ID"`
	Period model.OptionalParam[string] `query:"period" doc:"Stats period (7d, 30d, 90d)"`
}

type GetOrganizationStatsPlatformOutput = model.Output[*model.PlatformOrganizationStats]

type GetOrganizationUsagePlatformInput struct {
	ID     xid.ID                      `path:"id" doc:"Organization ID"`
	Period model.OptionalParam[string] `query:"period" doc:"Usage period (month, quarter, year)"`
}

type GetOrganizationUsagePlatformOutput = model.Output[*model.OrganizationUsage]

// User Management
type ListAllUsersInput struct {
	model.PaginationParams
	OrganizationID model.OptionalParam[xid.ID]         `query:"organizationId" doc:"Filter by organization"`
	UserType       model.OptionalParam[model.UserType] `query:"user_type" doc:"Filter by user type"`
	Status         model.OptionalParam[string]         `query:"status" doc:"Filter by user status"`
	Search         model.OptionalParam[string]         `query:"search" doc:"Search users by email or name"`
}

type ListAllUsersOutput = model.Output[*model.PlatformUserListResponse]

type GetUserDetailsInput struct {
	ID xid.ID `path:"id" doc:"User ID"`
}

type GetUserDetailsOutput = model.Output[*model.PlatformUserDetails]

type ImpersonateUserInput struct {
	ID   xid.ID                       `path:"id" doc:"User ID"`
	Body model.ImpersonateUserRequest `json:"body"`
}

type ImpersonateUserOutput = model.Output[*model.ImpersonationResponse]

type BlockUserInput struct {
	ID   xid.ID                 `path:"id" doc:"User ID"`
	Body model.BlockUserRequest `json:"body"`
}

type BlockUserOutput = model.Output[map[string]interface{}]

type UnblockUserInput struct {
	ID   xid.ID                   `path:"id" doc:"User ID"`
	Body model.UnblockUserRequest `json:"body"`
}

type UnblockUserOutput = model.Output[map[string]interface{}]

type ResetUserPasswordInput struct {
	ID   xid.ID                         `path:"id" doc:"User ID"`
	Body model.ResetUserPasswordRequest `json:"body"`
}

type ResetUserPasswordOutput = model.Output[*model.ResetUserPasswordResponse]

type GetUserSessionsInput struct {
	ID xid.ID `path:"id" doc:"User ID"`
}

type GetUserSessionsPlatformOutput = model.Output[*model.UserSessionListResponse]

type RevokeUserSessionsInput struct {
	ID   xid.ID                          `path:"id" doc:"User ID"`
	Body model.RevokeUserSessionsRequest `json:"body"`
}

type RevokeUserSessionsOutput = model.Output[*model.RevokeUserSessionsResponse]

// Platform Analytics
type GetPlatformStatsInput struct {
	Period model.OptionalParam[string] `query:"period" doc:"Stats period (24h, 7d, 30d, 90d)"`
}

type GetPlatformStatsOutput = model.Output[*model.PlatformStats]

type GetPlatformMetricsInput struct {
	Period   model.OptionalParam[string] `query:"period" doc:"Metrics period"`
	Metrics  model.OptionalParam[string] `query:"metrics" doc:"Comma-separated list of metrics"`
	Detailed model.OptionalParam[bool]   `query:"detailed" doc:"Include detailed breakdowns"`
}

type GetPlatformMetricsOutput = model.Output[*model.PlatformMetrics]

type GetGrowthMetricsInput struct {
	Period    model.OptionalParam[string] `query:"period" doc:"Growth analysis period"`
	Compare   model.OptionalParam[string] `query:"compare" doc:"Comparison period"`
	Breakdown model.OptionalParam[string] `query:"breakdown" doc:"Breakdown by (plan, region, source)"`
}

type GetGrowthMetricsOutput = model.Output[*model.PlatformGrowthMetrics]

type GetRevenueMetricsInput struct {
	Period    model.OptionalParam[string] `query:"period" doc:"Revenue analysis period"`
	Currency  model.OptionalParam[string] `query:"currency" doc:"Currency for reporting"`
	Breakdown model.OptionalParam[string] `query:"breakdown" doc:"Revenue breakdown"`
}

type GetRevenueMetricsOutput = model.Output[*model.RevenueMetrics]

type GetUsageAnalyticsInput struct {
	Period   model.OptionalParam[string] `query:"period" doc:"Analysis period"`
	Features model.OptionalParam[string] `query:"features" doc:"Specific features to analyze"`
	Compare  model.OptionalParam[bool]   `query:"compare" doc:"Include period comparison"`
}

type GetUsageAnalyticsOutput = model.Output[*model.UsageAnalytics]

// System Monitoring
type GetSystemHealthInput struct{}

type GetSystemHealthOutput = model.Output[*model.SystemHealth]

type GetSystemMetricsInput struct {
	Period model.OptionalParam[string] `query:"period" doc:"Metrics period"`
}

type GetSystemMetricsOutput = model.Output[*model.SystemMetrics]

type GetPerformanceMetricsInput struct {
	Period    model.OptionalParam[string] `query:"period" doc:"Performance analysis period"`
	Component model.OptionalParam[string] `query:"component" doc:"Specific component to analyze"`
}

type GetPerformanceMetricsOutput = model.Output[*model.PerformanceMetrics]

type GetErrorRatesInput struct {
	Period model.OptionalParam[string] `query:"period" doc:"Error analysis period"`
	Level  model.OptionalParam[string] `query:"level" doc:"Error level filter"`
}

type GetErrorRatesOutput = model.Output[*model.ErrorRateMetrics]

type GetAuditSummaryInput struct {
	Period model.OptionalParam[string] `query:"period" doc:"Audit summary period"`
}

type GetAuditSummaryOutput = model.Output[*model.AuditSummary]

// Feature Management
type ListFeatureFlagsInput struct {
	model.PaginationParams
	Status model.OptionalParam[string] `query:"status" doc:"Filter by feature status"`
	Search model.OptionalParam[string] `query:"search" doc:"Search features by name"`
}

type ListFeatureFlagsOutput = model.Output[*model.FeatureFlagListResponse]

type CreateFeatureFlagInput struct {
	Body model.CreateFeatureFlagRequest `json:"body"`
}

type CreateFeatureFlagOutput = model.Output[*model.FeatureFlag]

type UpdateFeatureFlagInput struct {
	ID   xid.ID                         `path:"id" doc:"Feature flag ID"`
	Body model.UpdateFeatureFlagRequest `json:"body"`
}

type UpdateFeatureFlagOutput = model.Output[*model.FeatureFlag]

type DeleteFeatureFlagInput struct {
	ID xid.ID `path:"id" doc:"Feature flag ID"`
}

type DeleteFeatureFlagOutput = model.Output[map[string]interface{}]

type GetFeatureUsageInput struct {
	Period model.OptionalParam[string] `query:"period" doc:"Usage analysis period"`
}

type GetFeatureUsageOutput = model.Output[*model.FeatureUsageReport]

// Billing & Subscriptions
type GetBillingOverviewInput struct {
	Period model.OptionalParam[string] `query:"period" doc:"Billing overview period"`
}

type GetBillingOverviewOutput = model.Output[*model.BillingOverview]

type ListSubscriptionsInput struct {
	model.PaginationParams
	Status model.OptionalParam[string] `query:"status" doc:"Filter by subscription status"`
	Plan   model.OptionalParam[string] `query:"plan" doc:"Filter by plan"`
	Search model.OptionalParam[string] `query:"search" doc:"Search subscriptions"`
}

type ListSubscriptionsOutput = model.Output[*model.SubscriptionListResponse]

type GetSubscriptionDetailsInput struct {
	ID xid.ID `path:"id" doc:"Subscription ID"`
}

type GetSubscriptionDetailsOutput = model.Output[*model.SubscriptionDetails]

type UpdateSubscriptionInput struct {
	ID   xid.ID                          `path:"id" doc:"Subscription ID"`
	Body model.UpdateSubscriptionRequest `json:"body"`
}

type UpdateSubscriptionOutput = model.Output[*model.SubscriptionDetails]

type CancelSubscriptionInput struct {
	ID   xid.ID                          `path:"id" doc:"Subscription ID"`
	Body model.CancelSubscriptionRequest `json:"body"`
}

type CancelSubscriptionOutput = model.Output[map[string]interface{}]

type GetRevenueReportInput struct {
	Period    model.OptionalParam[string] `query:"period" doc:"Report period"`
	Format    model.OptionalParam[string] `query:"format" doc:"Report format (json, csv, pdf)"`
	Breakdown model.OptionalParam[string] `query:"breakdown" doc:"Revenue breakdown"`
}

type GetRevenueReportOutput = model.Output[*model.RevenueReport]

// Security & Compliance
type GetSecurityDashboardInput struct{}

type GetSecurityDashboardOutput = model.Output[*model.SecurityDashboard]

type ListSecurityIncidentsInput struct {
	model.PaginationParams
	Severity model.OptionalParam[string] `query:"severity" doc:"Filter by incident severity"`
	Status   model.OptionalParam[string] `query:"status" doc:"Filter by incident status"`
	Period   model.OptionalParam[string] `query:"period" doc:"Time period filter"`
}

type ListSecurityIncidentsOutput = model.Output[*model.SecurityIncidentListResponse]

type GetComplianceReportInput struct {
	Type   model.OptionalParam[string] `query:"type" doc:"Compliance framework (soc2, hipaa, gdpr)"`
	Period model.OptionalParam[string] `query:"period" doc:"Report period"`
}

type GetComplianceReportOutput = model.Output[*model.ComplianceReport]

type RunSecurityScanInput struct {
	Body model.SecurityScanRequest `json:"body"`
}

type RunSecurityScanOutput = model.Output[*model.SecurityScanResponse]

type GetAuditTrailInput struct {
	model.PaginationParams
	OrganizationID model.OptionalParam[xid.ID]    `query:"organizationId" doc:"Filter by organization"`
	UserID         model.OptionalParam[xid.ID]    `query:"userId" doc:"Filter by user"`
	Action         model.OptionalParam[string]    `query:"action" doc:"Filter by action"`
	Resource       model.OptionalParam[string]    `query:"resource" doc:"Filter by resource type"`
	Status         model.OptionalParam[string]    `query:"status" doc:"Filter by status"`
	RiskLevel      model.OptionalParam[string]    `query:"riskLevel" doc:"Filter by risk level"`
	StartDate      model.OptionalParam[time.Time] `query:"startDate" doc:"OnStart date (ISO 8601)"`
	EndDate        model.OptionalParam[time.Time] `query:"endDate" doc:"End date (ISO 8601)"`
	Search         model.OptionalParam[string]    `query:"search" doc:"Search audit logs"`
}

type GetAuditTrailOutput = model.Output[*model.AuditTrailResponse]

// API Management
type GetAPIUsageInput struct {
	Period       model.OptionalParam[string] `query:"period" doc:"Usage analysis period"`
	Organization model.OptionalParam[xid.ID] `query:"organization_id" doc:"Filter by organization"`
	Breakdown    model.OptionalParam[string] `query:"breakdown" doc:"Usage breakdown"`
}

type GetAPIUsageOutput = model.Output[*model.APIUsageReport]

type ListAPIKeysPlatformInput struct {
	model.PaginationParams
	OrganizationID model.OptionalParam[xid.ID] `query:"organization_id" doc:"Filter by organization"`
	Status         model.OptionalParam[string] `query:"status" doc:"Filter by key status"`
	Search         model.OptionalParam[string] `query:"search" doc:"Search API keys"`
}

type ListAPIKeysPlatformOutput = model.Output[*model.APIKeyListResponse]

type RevokeAPIKeyInput struct {
	ID   xid.ID                    `path:"id" doc:"API key ID"`
	Body model.RevokeAPIKeyRequest `json:"body"`
}

type RevokeAPIKeyOutput = model.Output[map[string]interface{}]

type GetRateLimitStatsInput struct {
	Period       model.OptionalParam[string] `query:"period" doc:"Analysis period"`
	Organization model.OptionalParam[xid.ID] `query:"organization_id" doc:"Filter by organization"`
}

type GetRateLimitStatsOutput = model.Output[*model.RateLimitStats]

// Support & Operations
type ListSupportTicketsInput struct {
	model.PaginationParams
	Status   model.OptionalParam[string] `query:"status" doc:"Filter by ticket status"`
	Priority model.OptionalParam[string] `query:"priority" doc:"Filter by priority"`
	Assignee model.OptionalParam[xid.ID] `query:"assignee" doc:"Filter by assignee"`
	Search   model.OptionalParam[string] `query:"search" doc:"Search tickets"`
}

type ListSupportTicketsOutput = model.Output[*model.SupportTicketListResponse]

type GetMaintenanceWindowsInput struct {
	Status model.OptionalParam[string] `query:"status" doc:"Filter by maintenance status"`
	Period model.OptionalParam[string] `query:"period" doc:"Time period filter"`
}

type GetMaintenanceWindowsOutput = model.Output[*model.MaintenanceWindowListResponse]

type ScheduleMaintenanceInput struct {
	Body model.ScheduleMaintenanceRequest `json:"body"`
}

type ScheduleMaintenanceOutput = model.Output[*model.MaintenanceWindow]

type SendPlatformNotificationInput struct {
	Body model.PlatformNotificationRequest `json:"body"`
}

type SendPlatformNotificationOutput = model.Output[*model.PlatformNotificationResponse]

// Handler Implementations

func (c *platformAdminController) listAllOrganizationsHandler(ctx context.Context, input *ListAllOrganizationsInput) (*ListAllOrganizationsOutput, error) {
	// Build organization list request
	req := model.OrganizationListRequest{
		PaginationParams: input.PaginationParams,
	}

	if input.Status.IsSet {
		// req.Status = &input.Status.Value
	}
	if input.Plan.IsSet {
		req.Plan = input.Plan.Value
	}
	if input.Search.IsSet {
		req.Search = input.Search.Value
	}

	organizations, err := c.di.OrganizationService().ListAllOrganizations(ctx, req)
	if err != nil {
		return nil, err
	}

	return &ListAllOrganizationsOutput{
		Body: organizations,
	}, nil
}

func (c *platformAdminController) getOrganizationDetailsHandler(ctx context.Context, input *GetOrganizationDetailsInput) (*GetOrganizationDetailsOutput, error) {
	org, err := c.di.OrganizationService().GetOrganization(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	// Get additional details for platform view
	stats, _ := c.di.OrganizationService().GetOrganizationStats(ctx, input.ID)
	usage, _ := c.di.OrganizationService().GetOrganizationUsage(ctx, input.ID)

	platformDetails := &model.PlatformOrganizationDetails{
		Organization: *org,
		Stats:        stats,
		Usage:        usage,
		// Additional platform-specific fields would be populated here
	}

	return &GetOrganizationDetailsOutput{
		Body: platformDetails,
	}, nil
}

func (c *platformAdminController) suspendOrganizationHandler(ctx context.Context, input *SuspendOrganizationInput) (*SuspendOrganizationOutput, error) {
	// Update organization to suspended status
	updateReq := model.UpdateOrganizationRequest{
		Active: &[]bool{false}[0],
	}

	_, err := c.di.OrganizationService().UpdateOrganization(ctx, input.ID, updateReq)
	if err != nil {
		return nil, err
	}

	// TODO: Implement suspension logic (disable access, notify users, etc.)

	return &SuspendOrganizationOutput{
		Body: map[string]interface{}{
			"success":    true,
			"message":    "Organization suspended successfully",
			"reason":     input.Body.Reason,
			"notified":   input.Body.NotifyUsers,
			"expires_at": input.Body.ExpiresAt,
		},
	}, nil
}

func (c *platformAdminController) activateOrganizationHandler(ctx context.Context, input *ActivateOrganizationInput) (*ActivateOrganizationOutput, error) {
	// Update organization to active status
	updateReq := model.UpdateOrganizationRequest{
		Active: &[]bool{true}[0],
	}

	_, err := c.di.OrganizationService().UpdateOrganization(ctx, input.ID, updateReq)
	if err != nil {
		return nil, err
	}

	return &ActivateOrganizationOutput{
		Body: map[string]interface{}{
			"success": true,
			"message": "Organization activated successfully",
			"reason":  input.Body.Reason,
		},
	}, nil
}

func (c *platformAdminController) deleteOrganizationHandler(ctx context.Context, input *DeleteOrganizationPlatformInput) (*DeleteOrganizationOutput, error) {
	err := c.di.OrganizationService().DeleteOrganization(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &DeleteOrganizationOutput{
		Body: map[string]interface{}{
			"success": true,
			"message": "Organization deleted successfully",
		},
	}, nil
}

type CreateOrganizationPlatformInput struct {
	Body model.CreateOrganizationPlatformRequest
}

func (c *platformAdminController) createOrganizationHandler(ctx context.Context, input *CreateOrganizationPlatformInput) (*CreateOrganizationOutput, error) {
	orgService := c.di.OrganizationService()

	org, err := orgService.CreatePlatformOrganization(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreateOrganizationOutput{
		Body: org,
	}, nil
}

func (c *platformAdminController) getOrganizationStatsHandler(ctx context.Context, input *GetOrganizationStatsInput) (*GetOrganizationStatsPlatformOutput, error) {
	stats, err := c.di.OrganizationService().GetOrganizationStats(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	// Convert to platform stats format
	platformStats := &model.PlatformOrganizationStats{
		OrganizationID: input.ID,
		Period:         input.Period.Value,
		Stats:          stats,
		// Additional platform-specific metrics would be added here
	}

	return &GetOrganizationStatsPlatformOutput{
		Body: platformStats,
	}, nil
}

func (c *platformAdminController) getOrganizationUsageHandler(ctx context.Context, input *GetOrganizationUsagePlatformInput) (*GetOrganizationUsagePlatformOutput, error) {
	usage, err := c.di.OrganizationService().GetOrganizationUsage(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationUsagePlatformOutput{
		Body: usage,
	}, nil
}

// User Management Handlers

func (c *platformAdminController) listAllUsersHandler(ctx context.Context, input *ListAllUsersInput) (*ListAllUsersOutput, error) {
	req := model.UserListRequest{
		PaginationParams: input.PaginationParams,
	}

	if input.Status.IsSet {
		// req.Stats = &input.Status.Value
	}

	if input.Search.IsSet {
		req.Search = input.Search.Value
	}

	if input.OrganizationID.IsSet {
		req.OrganizationID = &input.OrganizationID.Value
	}

	if input.UserType.IsSet {
		req.UserType = input.UserType.Value
	}

	platformResponse, err := c.di.UserService().ListPlatformUsers(ctx, req)
	if err != nil {
		return nil, err
	}

	return &ListAllUsersOutput{
		Body: platformResponse,
	}, nil
}

func (c *platformAdminController) getUserDetailsHandler(ctx context.Context, input *GetUserDetailsInput) (*GetUserDetailsOutput, error) {
	user, err := c.di.UserService().GetUser(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	// Get additional details for platform view
	sessions, _ := c.di.SessionService().ListUserSessions(ctx, input.ID, model.ListSessionsParams{})
	activity, _ := c.di.ActivityService().GetUserActivities(ctx, input.ID, nil)

	platformDetails := &model.PlatformUserDetails{
		User:     *user,
		Sessions: sessions.Data,
		Activity: activity,
		// Additional platform-specific fields would be populated here
	}

	return &GetUserDetailsOutput{
		Body: platformDetails,
	}, nil
}

func (c *platformAdminController) impersonateUserHandler(ctx context.Context, input *ImpersonateUserInput) (*ImpersonateUserOutput, error) {
	// TODO: Implement user impersonation logic
	// This would create a special impersonation session for troubleshooting

	response := &model.ImpersonationResponse{
		Success:          true,
		ImpersonationID:  xid.New(),
		ExpiresAt:        nil, // Set expiration time
		OriginalUserID:   input.Body.AdminUserID,
		ImpersonatedUser: input.ID,
		ImpersonationURL: "", // Generate impersonation URL
	}

	return &ImpersonateUserOutput{
		Body: response,
	}, nil
}

func (c *platformAdminController) blockUserHandler(ctx context.Context, input *BlockUserInput) (*BlockUserOutput, error) {
	err := c.di.UserService().BlockUser(ctx, input.ID, input.Body.Reason)
	if err != nil {
		return nil, err
	}

	return &BlockUserOutput{
		Body: map[string]interface{}{
			"success": true,
			"message": "User blocked successfully",
			"reason":  input.Body.Reason,
		},
	}, nil
}

func (c *platformAdminController) unblockUserHandler(ctx context.Context, input *UnblockUserInput) (*UnblockUserOutput, error) {
	err := c.di.UserService().UnblockUser(ctx, input.ID, input.Body.Reason)
	if err != nil {
		return nil, err
	}

	return &UnblockUserOutput{
		Body: map[string]interface{}{
			"success": true,
			"message": "User unblocked successfully",
			"reason":  input.Body.Reason,
		},
	}, nil
}

func (c *platformAdminController) resetUserPasswordHandler(ctx context.Context, input *ResetUserPasswordInput) (*ResetUserPasswordOutput, error) {
	// TODO: Implement admin password reset
	response := &model.ResetUserPasswordResponse{
		Success:      true,
		ResetToken:   xid.New().String(),
		ExpiresAt:    nil, // Set expiration
		NotifyUser:   input.Body.NotifyUser,
		TemporaryPwd: input.Body.GenerateTemporary,
	}

	return &ResetUserPasswordOutput{
		Body: response,
	}, nil
}

type CreatePlatformUserInput struct {
	Body model.CreateUserRequest
}

func (c *platformAdminController) createPlatformUserHandler(ctx context.Context, input *CreatePlatformUserInput) (*CreateUserOutput, error) {
	userService := c.di.UserService()

	// Create user
	user, err := userService.CreateUser(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreateUserOutput{
		Body: user,
	}, nil
}

func (c *platformAdminController) getUserSessionsHandler(ctx context.Context, input *GetUserSessionsInput) (*GetUserSessionsPlatformOutput, error) {
	sessions, err := c.di.SessionService().ListUserSessions(ctx, input.ID, model.ListSessionsParams{})
	if err != nil {
		return nil, err
	}

	response := &model.UserSessionListResponse{
		Sessions: sessions.Data,
		Total:    sessions.Pagination.TotalCount,
		Active:   0, // Count active sessions
	}

	return &GetUserSessionsPlatformOutput{
		Body: response,
	}, nil
}

func (c *platformAdminController) revokeUserSessionsHandler(ctx context.Context, input *RevokeUserSessionsInput) (*RevokeUserSessionsOutput, error) {
	count, err := c.di.SessionService().InvalidateAllUserSessions(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	response := &model.RevokeUserSessionsResponse{
		Success:         true,
		SessionsRevoked: count,
		Reason:          input.Body.Reason,
		NotifyUser:      input.Body.NotifyUser,
	}

	return &RevokeUserSessionsOutput{
		Body: response,
	}, nil
}

// Placeholder handlers for remaining endpoints
// These would be implemented with actual business logic

func (c *platformAdminController) getPlatformStatsHandler(ctx context.Context, input *GetPlatformStatsInput) (*GetPlatformStatsOutput, error) {
	// TODO: Implement platform statistics aggregation
	return &GetPlatformStatsOutput{
		Body: &model.PlatformStats{},
	}, nil
}

func (c *platformAdminController) getPlatformMetricsHandler(ctx context.Context, input *GetPlatformMetricsInput) (*GetPlatformMetricsOutput, error) {
	return &GetPlatformMetricsOutput{Body: &model.PlatformMetrics{}}, nil
}

func (c *platformAdminController) getGrowthMetricsHandler(ctx context.Context, input *GetGrowthMetricsInput) (*GetGrowthMetricsOutput, error) {
	return &GetGrowthMetricsOutput{Body: &model.PlatformGrowthMetrics{}}, nil
}

func (c *platformAdminController) getRevenueMetricsHandler(ctx context.Context, input *GetRevenueMetricsInput) (*GetRevenueMetricsOutput, error) {
	return &GetRevenueMetricsOutput{Body: &model.RevenueMetrics{}}, nil
}

func (c *platformAdminController) getUsageAnalyticsHandler(ctx context.Context, input *GetUsageAnalyticsInput) (*GetUsageAnalyticsOutput, error) {
	return &GetUsageAnalyticsOutput{Body: &model.UsageAnalytics{}}, nil
}

func (c *platformAdminController) getSystemHealthHandler(ctx context.Context, input *GetSystemHealthInput) (*GetSystemHealthOutput, error) {
	return &GetSystemHealthOutput{Body: &model.SystemHealth{}}, nil
}

func (c *platformAdminController) getSystemMetricsHandler(ctx context.Context, input *GetSystemMetricsInput) (*GetSystemMetricsOutput, error) {
	return &GetSystemMetricsOutput{Body: &model.SystemMetrics{}}, nil
}

func (c *platformAdminController) getPerformanceMetricsHandler(ctx context.Context, input *GetPerformanceMetricsInput) (*GetPerformanceMetricsOutput, error) {
	return &GetPerformanceMetricsOutput{Body: &model.PerformanceMetrics{}}, nil
}

func (c *platformAdminController) getErrorRatesHandler(ctx context.Context, input *GetErrorRatesInput) (*GetErrorRatesOutput, error) {
	return &GetErrorRatesOutput{Body: &model.ErrorRateMetrics{}}, nil
}

func (c *platformAdminController) getAuditSummaryHandler(ctx context.Context, input *GetAuditSummaryInput) (*GetAuditSummaryOutput, error) {
	return &GetAuditSummaryOutput{Body: &model.AuditSummary{}}, nil
}

func (c *platformAdminController) listFeatureFlagsHandler(ctx context.Context, input *ListFeatureFlagsInput) (*ListFeatureFlagsOutput, error) {
	return &ListFeatureFlagsOutput{Body: &model.FeatureFlagListResponse{}}, nil
}

func (c *platformAdminController) createFeatureFlagHandler(ctx context.Context, input *CreateFeatureFlagInput) (*CreateFeatureFlagOutput, error) {
	return &CreateFeatureFlagOutput{Body: &model.FeatureFlag{}}, nil
}

func (c *platformAdminController) updateFeatureFlagHandler(ctx context.Context, input *UpdateFeatureFlagInput) (*UpdateFeatureFlagOutput, error) {
	return &UpdateFeatureFlagOutput{Body: &model.FeatureFlag{}}, nil
}

func (c *platformAdminController) deleteFeatureFlagHandler(ctx context.Context, input *DeleteFeatureFlagInput) (*DeleteFeatureFlagOutput, error) {
	return &DeleteFeatureFlagOutput{Body: map[string]interface{}{"success": true}}, nil
}

func (c *platformAdminController) getFeatureUsageHandler(ctx context.Context, input *GetFeatureUsageInput) (*GetFeatureUsageOutput, error) {
	return &GetFeatureUsageOutput{Body: &model.FeatureUsageReport{}}, nil
}

func (c *platformAdminController) getBillingOverviewHandler(ctx context.Context, input *GetBillingOverviewInput) (*GetBillingOverviewOutput, error) {
	return &GetBillingOverviewOutput{Body: &model.BillingOverview{}}, nil
}

func (c *platformAdminController) listSubscriptionsHandler(ctx context.Context, input *ListSubscriptionsInput) (*ListSubscriptionsOutput, error) {
	return &ListSubscriptionsOutput{Body: &model.SubscriptionListResponse{}}, nil
}

func (c *platformAdminController) getSubscriptionDetailsHandler(ctx context.Context, input *GetSubscriptionDetailsInput) (*GetSubscriptionDetailsOutput, error) {
	return &GetSubscriptionDetailsOutput{Body: &model.SubscriptionDetails{}}, nil
}

func (c *platformAdminController) updateSubscriptionHandler(ctx context.Context, input *UpdateSubscriptionInput) (*UpdateSubscriptionOutput, error) {
	return &UpdateSubscriptionOutput{Body: &model.SubscriptionDetails{}}, nil
}

func (c *platformAdminController) cancelSubscriptionHandler(ctx context.Context, input *CancelSubscriptionInput) (*CancelSubscriptionOutput, error) {
	return &CancelSubscriptionOutput{Body: map[string]interface{}{"success": true}}, nil
}

func (c *platformAdminController) getRevenueReportHandler(ctx context.Context, input *GetRevenueReportInput) (*GetRevenueReportOutput, error) {
	return &GetRevenueReportOutput{Body: &model.RevenueReport{}}, nil
}

func (c *platformAdminController) getSecurityDashboardHandler(ctx context.Context, input *GetSecurityDashboardInput) (*GetSecurityDashboardOutput, error) {
	return &GetSecurityDashboardOutput{Body: &model.SecurityDashboard{}}, nil
}

func (c *platformAdminController) listSecurityIncidentsHandler(ctx context.Context, input *ListSecurityIncidentsInput) (*ListSecurityIncidentsOutput, error) {
	return &ListSecurityIncidentsOutput{Body: &model.SecurityIncidentListResponse{}}, nil
}

func (c *platformAdminController) getComplianceReportHandler(ctx context.Context, input *GetComplianceReportInput) (*GetComplianceReportOutput, error) {
	return &GetComplianceReportOutput{Body: &model.ComplianceReport{}}, nil
}

func (c *platformAdminController) runSecurityScanHandler(ctx context.Context, input *RunSecurityScanInput) (*RunSecurityScanOutput, error) {
	return &RunSecurityScanOutput{Body: &model.SecurityScanResponse{}}, nil
}

func (c *platformAdminController) getAuditTrailHandler(ctx context.Context, input *GetAuditTrailInput) (*GetAuditTrailOutput, error) {
	// Build audit search request
	auditReq := model.AuditLogListRequest{
		PaginationParams: input.PaginationParams,
		OrganizationID:   input.OrganizationID,
		UserID:           input.UserID,
		Action:           input.Action.Value,
		Status:           input.Status.Value,
		StartDate:        input.StartDate,
		EndDate:          input.EndDate,
		Search:           input.Search.Value,
	}

	auditLogs, err := c.di.AuditService().GetAuditLogs(ctx, auditReq)
	if err != nil {
		return nil, err
	}

	response := &model.AuditTrailResponse{
		AuditLogs:  auditLogs.Data,
		Pagination: auditLogs.Pagination,
		Filters: map[string]interface{}{
			"organization_id": input.OrganizationID.Value,
			"user_id":         input.UserID.Value,
			"action":          input.Action.Value,
			"resource":        input.Resource.Value,
			"status":          input.Status.Value,
			"risk_level":      input.RiskLevel.Value,
		},
	}

	return &GetAuditTrailOutput{Body: response}, nil
}

func (c *platformAdminController) getAPIUsageHandler(ctx context.Context, input *GetAPIUsageInput) (*GetAPIUsageOutput, error) {
	return &GetAPIUsageOutput{Body: &model.APIUsageReport{}}, nil
}

func (c *platformAdminController) listAPIKeysHandler(ctx context.Context, input *ListAPIKeysPlatformInput) (*ListAPIKeysPlatformOutput, error) {
	return &ListAPIKeysPlatformOutput{Body: &model.APIKeyListResponse{}}, nil
}

func (c *platformAdminController) revokeAPIKeyHandler(ctx context.Context, input *RevokeAPIKeyInput) (*RevokeAPIKeyOutput, error) {
	return &RevokeAPIKeyOutput{Body: map[string]interface{}{"success": true}}, nil
}

func (c *platformAdminController) getRateLimitStatsHandler(ctx context.Context, input *GetRateLimitStatsInput) (*GetRateLimitStatsOutput, error) {
	return &GetRateLimitStatsOutput{Body: &model.RateLimitStats{}}, nil
}

func (c *platformAdminController) listSupportTicketsHandler(ctx context.Context, input *ListSupportTicketsInput) (*ListSupportTicketsOutput, error) {
	return &ListSupportTicketsOutput{Body: &model.SupportTicketListResponse{}}, nil
}

func (c *platformAdminController) getMaintenanceWindowsHandler(ctx context.Context, input *GetMaintenanceWindowsInput) (*GetMaintenanceWindowsOutput, error) {
	return &GetMaintenanceWindowsOutput{Body: &model.MaintenanceWindowListResponse{}}, nil
}

func (c *platformAdminController) scheduleMaintenanceHandler(ctx context.Context, input *ScheduleMaintenanceInput) (*ScheduleMaintenanceOutput, error) {
	return &ScheduleMaintenanceOutput{Body: &model.MaintenanceWindow{}}, nil
}

func (c *platformAdminController) sendPlatformNotificationHandler(ctx context.Context, input *SendPlatformNotificationInput) (*SendPlatformNotificationOutput, error) {
	return &SendPlatformNotificationOutput{Body: &model.PlatformNotificationResponse{}}, nil
}
