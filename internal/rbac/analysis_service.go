package rbac

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// AnalyticsService provides comprehensive analytics and reporting for RBAC
type AnalyticsService struct {
	logger       logging.Logger
	repo         Repository
	auditService *AuditTrailService
}

// PermissionAnalytics provides insights into permission usage patterns
type PermissionAnalytics struct {
	OrganizationID    *xid.ID                   `json:"organization_id,omitempty"`
	GeneratedAt       time.Time                 `json:"generated_at"`
	Period            AnalyticsPeriod           `json:"period"`
	Summary           *PermissionSummary        `json:"summary"`
	UsagePatterns     *UsagePatterns            `json:"usage_patterns"`
	RiskAnalysis      *RiskAnalysis             `json:"risk_analysis"`
	UserSegmentation  *UserSegmentation         `json:"user_segmentation"`
	RoleEffectiveness *RoleEffectiveness        `json:"role_effectiveness"`
	ComplianceMetrics *ComplianceMetrics        `json:"compliance_metrics"`
	Recommendations   []*SecurityRecommendation `json:"recommendations"`
	TrendAnalysis     *TrendAnalysis            `json:"trend_analysis"`
}

type AnalyticsPeriod struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Duration  string    `json:"duration"` // "24h", "7d", "30d", "90d"
}

type PermissionSummary struct {
	TotalUsers            int            `json:"total_users"`
	TotalRoles            int            `json:"total_roles"`
	TotalPermissions      int            `json:"total_permissions"`
	ActiveUsers           int            `json:"active_users"`
	InactiveUsers         int            `json:"inactive_users"`
	OverprivilegedUsers   int            `json:"overprivileged_users"`
	UnderprivilegedUsers  int            `json:"underprivileged_users"`
	OrphanedPermissions   int            `json:"orphaned_permissions"`
	UnusedRoles           int            `json:"unused_roles"`
	PermissionsByResource map[string]int `json:"permissions_by_resource"`
	PermissionsByAction   map[string]int `json:"permissions_by_action"`
	UsersByRole           map[string]int `json:"users_by_role"`
}

type UsagePatterns struct {
	MostAccessedResources    []*ResourceUsage          `json:"most_accessed_resources"`
	MostUsedPermissions      []*PermissionUsage        `json:"most_used_permissions"`
	LeastUsedPermissions     []*PermissionUsage        `json:"least_used_permissions"`
	PeakUsageHours           []int                     `json:"peak_usage_hours"`
	UserActivityDistribution *ActivityDistribution     `json:"user_activity_distribution"`
	PermissionCooccurrence   []*PermissionPair         `json:"permission_cooccurrence"`
	AccessPatternsByUserType map[string]*AccessPattern `json:"access_patterns_by_user_type"`
}

type ResourceUsage struct {
	Resource        string        `json:"resource"`
	AccessCount     int64         `json:"access_count"`
	UniqueUsers     int           `json:"unique_users"`
	SuccessRate     float64       `json:"success_rate"`
	AvgResponseTime time.Duration `json:"avg_response_time"`
}

type PermissionUsage struct {
	Permission  string    `json:"permission"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	UsageCount  int64     `json:"usage_count"`
	UniqueUsers int       `json:"unique_users"`
	LastUsed    time.Time `json:"last_used"`
	SuccessRate float64   `json:"success_rate"`
	RiskScore   float64   `json:"risk_score"`
}

type ActivityDistribution struct {
	VeryActive  int `json:"very_active"`  // >100 actions/day
	Active      int `json:"active"`       // 10-100 actions/day
	Moderate    int `json:"moderate"`     // 1-10 actions/day
	LowActivity int `json:"low_activity"` // <1 action/day
	Inactive    int `json:"inactive"`     // No activity
}

type PermissionPair struct {
	Permission1      string  `json:"permission1"`
	Permission2      string  `json:"permission2"`
	CooccurrenceRate float64 `json:"cooccurrence_rate"`
	Confidence       float64 `json:"confidence"`
}

type AccessPattern struct {
	UserType           string        `json:"user_type"`
	MostCommonActions  []string      `json:"most_common_actions"`
	AverageSessionTime time.Duration `json:"average_session_time"`
	PeakHours          []int         `json:"peak_hours"`
	PreferredResources []string      `json:"preferred_resources"`
	ErrorRate          float64       `json:"error_rate"`
}

type RiskAnalysis struct {
	OverallRiskScore        float64            `json:"overall_risk_score"`
	HighRiskUsers           []*UserRiskProfile `json:"high_risk_users"`
	HighRiskPermissions     []*PermissionRisk  `json:"high_risk_permissions"`
	VulnerableRoles         []*RoleRisk        `json:"vulnerable_roles"`
	PrivilegeEscalationRisk float64            `json:"privilege_escalation_risk"`
	DataExposureRisk        float64            `json:"data_exposure_risk"`
	ComplianceRisk          float64            `json:"compliance_risk"`
	TrendRisk               string             `json:"trend_risk"` // "increasing", "stable", "decreasing"
}

type UserRiskProfile struct {
	UserID             xid.ID                `json:"user_id"`
	RiskScore          float64               `json:"risk_score"`
	RiskFactors        []string              `json:"risk_factors"`
	SuspiciousActivity []*SuspiciousActivity `json:"suspicious_activity"`
	PermissionCount    int                   `json:"permission_count"`
	LastActivity       time.Time             `json:"last_activity"`
	AccountAge         time.Duration         `json:"account_age"`
}

type PermissionRisk struct {
	Permission      string    `json:"permission"`
	RiskScore       float64   `json:"risk_score"`
	RiskFactors     []string  `json:"risk_factors"`
	UsersWithAccess int       `json:"users_with_access"`
	LastUsed        time.Time `json:"last_used"`
	BusinessImpact  string    `json:"business_impact"` // "high", "medium", "low"
}

type RoleRisk struct {
	RoleID          xid.ID    `json:"role_id"`
	RoleName        string    `json:"role_name"`
	RiskScore       float64   `json:"risk_score"`
	RiskFactors     []string  `json:"risk_factors"`
	UserCount       int       `json:"user_count"`
	PermissionCount int       `json:"permission_count"`
	LastModified    time.Time `json:"last_modified"`
}

type SuspiciousActivity struct {
	ActivityType string                 `json:"activity_type"`
	Description  string                 `json:"description"`
	Timestamp    time.Time              `json:"timestamp"`
	Severity     string                 `json:"severity"`
	Context      map[string]interface{} `json:"context"`
}

type UserSegmentation struct {
	Segments       []*UserSegment             `json:"segments"`
	PowerUsers     []*PowerUser               `json:"power_users"`
	InactiveUsers  []*InactiveUser            `json:"inactive_users"`
	NewUsers       []*NewUser                 `json:"new_users"`
	SegmentMetrics map[string]*SegmentMetrics `json:"segment_metrics"`
}

type UserSegment struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	UserCount      int      `json:"user_count"`
	Criteria       []string `json:"criteria"`
	AvgPermissions float64  `json:"avg_permissions"`
	AvgActivity    float64  `json:"avg_activity"`
	RiskScore      float64  `json:"risk_score"`
}

type PowerUser struct {
	UserID          xid.ID    `json:"user_id"`
	PermissionCount int       `json:"permission_count"`
	ActivityScore   float64   `json:"activity_score"`
	LastActivity    time.Time `json:"last_activity"`
	Departments     []string  `json:"departments"`
}

type InactiveUser struct {
	UserID          xid.ID    `json:"user_id"`
	LastActivity    time.Time `json:"last_activity"`
	InactiveDays    int       `json:"inactive_days"`
	PermissionCount int       `json:"permission_count"`
	RiskIfActive    float64   `json:"risk_if_active"`
}

type NewUser struct {
	UserID          xid.ID    `json:"user_id"`
	CreatedAt       time.Time `json:"created_at"`
	DaysSinceJoined int       `json:"days_since_joined"`
	InitialRoles    []string  `json:"initial_roles"`
	ActivityLevel   string    `json:"activity_level"`
}

type SegmentMetrics struct {
	AverageSessionTime  time.Duration `json:"average_session_time"`
	MostCommonResources []string      `json:"most_common_resources"`
	ErrorRate           float64       `json:"error_rate"`
	ComplianceScore     float64       `json:"compliance_score"`
}

type RoleEffectiveness struct {
	RoleUtilization         []*RoleUtilization  `json:"role_utilization"`
	RoleOverlap             []*RoleOverlap      `json:"role_overlap"`
	OptimizationSuggestions []*RoleOptimization `json:"optimization_suggestions"`
	RoleComplexity          map[string]float64  `json:"role_complexity"`
}

type RoleUtilization struct {
	RoleID          xid.ID    `json:"role_id"`
	RoleName        string    `json:"role_name"`
	AssignedUsers   int       `json:"assigned_users"`
	ActiveUsers     int       `json:"active_users"`
	UtilizationRate float64   `json:"utilization_rate"`
	PermissionUsage float64   `json:"permission_usage"`
	LastUsed        time.Time `json:"last_used"`
	CreatedAt       time.Time `json:"created_at"`
}

type RoleOverlap struct {
	Role1                  string   `json:"role1"`
	Role2                  string   `json:"role2"`
	OverlapPercent         float64  `json:"overlap_percent"`
	SharedPermissions      []string `json:"shared_permissions"`
	ConsolidationPotential float64  `json:"consolidation_potential"`
}

type RoleOptimization struct {
	Type            string   `json:"type"` // "merge", "split", "remove", "modify"
	Description     string   `json:"description"`
	AffectedRoles   []string `json:"affected_roles"`
	EstimatedImpact string   `json:"estimated_impact"`
	Priority        string   `json:"priority"`
	SafetyScore     float64  `json:"safety_score"`
}

type ComplianceMetrics struct {
	SODViolations        []*SODViolation         `json:"sod_violations"`
	OverprivilegedAccess []*OverprivilegedAccess `json:"overprivileged_access"`
	AccessCertification  *CertificationStatus    `json:"access_certification"`
	PolicyCompliance     *PolicyCompliance       `json:"policy_compliance"`
	AuditReadiness       *AuditReadiness         `json:"audit_readiness"`
}

type SODViolation struct {
	UserID                 xid.ID   `json:"user_id"`
	ConflictingRoles       []string `json:"conflicting_roles"`
	ConflictingPermissions []string `json:"conflicting_permissions"`
	ViolationType          string   `json:"violation_type"`
	Severity               string   `json:"severity"`
	BusinessRisk           string   `json:"business_risk"`
}

type OverprivilegedAccess struct {
	UserID            xid.ID    `json:"user_id"`
	UnusedPermissions []string  `json:"unused_permissions"`
	ExcessiveRoles    []string  `json:"excessive_roles"`
	LastUsed          time.Time `json:"last_used"`
	RiskScore         float64   `json:"risk_score"`
}

type CertificationStatus struct {
	TotalUsers            int       `json:"total_users"`
	CertifiedUsers        int       `json:"certified_users"`
	PendingCertification  int       `json:"pending_certification"`
	LastCertificationDate time.Time `json:"last_certification_date"`
	NextCertificationDue  time.Time `json:"next_certification_due"`
	ComplianceRate        float64   `json:"compliance_rate"`
}

type PolicyCompliance struct {
	TotalPolicies      int     `json:"total_policies"`
	CompliantPolicies  int     `json:"compliant_policies"`
	ViolatedPolicies   int     `json:"violated_policies"`
	ComplianceScore    float64 `json:"compliance_score"`
	CriticalViolations int     `json:"critical_violations"`
}

type AuditReadiness struct {
	ReadinessScore         float64   `json:"readiness_score"`
	MissingDocumentation   []string  `json:"missing_documentation"`
	AuditTrailCompleteness float64   `json:"audit_trail_completeness"`
	LastAuditDate          time.Time `json:"last_audit_date"`
	NextAuditDue           time.Time `json:"next_audit_due"`
}

type TrendAnalysis struct {
	UserGrowthTrend      *Trend               `json:"user_growth_trend"`
	PermissionUsageTrend *Trend               `json:"permission_usage_trend"`
	RiskTrend            *Trend               `json:"risk_trend"`
	ComplianceTrend      *Trend               `json:"compliance_trend"`
	SeasonalPatterns     map[string]*Pattern  `json:"seasonal_patterns"`
	Forecasts            map[string]*Forecast `json:"forecasts"`
}

type Trend struct {
	Direction  string      `json:"direction"` // "increasing", "decreasing", "stable"
	Rate       float64     `json:"rate"`      // Rate of change
	Confidence float64     `json:"confidence"`
	StartValue float64     `json:"start_value"`
	EndValue   float64     `json:"end_value"`
	DataPoints []DataPoint `json:"data_points"`
}

type Pattern struct {
	PatternType  string  `json:"pattern_type"`
	Description  string  `json:"description"`
	Frequency    string  `json:"frequency"`
	Amplitude    float64 `json:"amplitude"`
	Significance float64 `json:"significance"`
}

type Forecast struct {
	Metric             string        `json:"metric"`
	ForecastPeriod     time.Duration `json:"forecast_period"`
	PredictedValue     float64       `json:"predicted_value"`
	ConfidenceInterval [2]float64    `json:"confidence_interval"`
	Method             string        `json:"method"`
}

type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Label     string    `json:"label,omitempty"`
}

type SecurityRecommendation struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`     // "security", "compliance", "optimization", "risk"
	Priority      string    `json:"priority"` // "critical", "high", "medium", "low"
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	Impact        string    `json:"impact"`
	Effort        string    `json:"effort"`
	Category      string    `json:"category"`
	AffectedItems []string  `json:"affected_items"`
	Actions       []string  `json:"actions"`
	CreatedAt     time.Time `json:"created_at"`
}

// NewAnalyticsService creates a new analytics service
func NewAnalyticsService(repo Repository, auditService *AuditTrailService, logger logging.Logger) *AnalyticsService {
	return &AnalyticsService{
		logger:       logger,
		repo:         repo,
		auditService: auditService,
	}
}

// GeneratePermissionAnalytics generates comprehensive permission analytics
func (as *AnalyticsService) GeneratePermissionAnalytics(ctx context.Context, orgID *xid.ID, period AnalyticsPeriod) (*PermissionAnalytics, error) {
	analytics := &PermissionAnalytics{
		OrganizationID: orgID,
		GeneratedAt:    time.Now(),
		Period:         period,
	}

	// Generate each section
	var err error

	analytics.Summary, err = as.generatePermissionSummary(ctx, orgID, period)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to generate permission summary")
	}

	analytics.UsagePatterns, err = as.generateUsagePatterns(ctx, orgID, period)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to generate usage patterns")
	}

	analytics.RiskAnalysis, err = as.generateRiskAnalysis(ctx, orgID, period)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to generate risk analysis")
	}

	analytics.UserSegmentation, err = as.generateUserSegmentation(ctx, orgID, period)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to generate user segmentation")
	}

	analytics.RoleEffectiveness, err = as.generateRoleEffectiveness(ctx, orgID, period)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to generate role effectiveness")
	}

	analytics.ComplianceMetrics, err = as.generateComplianceMetrics(ctx, orgID, period)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to generate compliance metrics")
	}

	analytics.TrendAnalysis, err = as.generateTrendAnalysis(ctx, orgID, period)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to generate trend analysis")
	}

	analytics.Recommendations = as.generateRecommendations(analytics)

	as.logger.Info("Permission analytics generated",
		logging.String("org_id", func() string {
			if orgID != nil {
				return orgID.String()
			}
			return "system"
		}()),
		logging.String("period", period.Duration))

	return analytics, nil
}

// generatePermissionSummary creates a high-level summary of permissions
func (as *AnalyticsService) generatePermissionSummary(ctx context.Context, orgID *xid.ID, period AnalyticsPeriod) (*PermissionSummary, error) {
	summary := &PermissionSummary{
		PermissionsByResource: make(map[string]int),
		PermissionsByAction:   make(map[string]int),
		UsersByRole:           make(map[string]int),
	}

	// Get all roles for the organization
	roles, err := as.getRolesForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	summary.TotalRoles = len(roles)

	// Get all permissions
	permissions, err := as.getPermissionsForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	summary.TotalPermissions = len(permissions)

	// Analyze permissions by resource and action
	for _, perm := range permissions {
		summary.PermissionsByResource[perm.Resource]++
		summary.PermissionsByAction[perm.Action]++
	}

	// Get user statistics
	users, err := as.getUsersForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	summary.TotalUsers = len(users)

	// Analyze user activity and role assignments
	activeUsers := 0
	for _, user := range users {
		// Check if user was active during the period
		if as.isUserActive(ctx, user.ID, period) {
			activeUsers++
		}

		// Get user roles and count them
		userRoles, _ := as.getUserRoles(ctx, user.ID, orgID)
		for _, role := range userRoles {
			summary.UsersByRole[role.Name]++
		}
	}

	summary.ActiveUsers = activeUsers
	summary.InactiveUsers = summary.TotalUsers - activeUsers

	// Calculate overprivileged and underprivileged users
	summary.OverprivilegedUsers = as.countOverprivilegedUsers(ctx, users, orgID, period)
	summary.UnderprivilegedUsers = as.countUnderprivilegedUsers(ctx, users, orgID, period)

	// Find orphaned permissions and unused roles
	summary.OrphanedPermissions = as.countOrphanedPermissions(ctx, permissions, roles)
	summary.UnusedRoles = as.countUnusedRoles(ctx, roles, period)

	return summary, nil
}

// generateUsagePatterns analyzes permission usage patterns
func (as *AnalyticsService) generateUsagePatterns(ctx context.Context, orgID *xid.ID, period AnalyticsPeriod) (*UsagePatterns, error) {
	patterns := &UsagePatterns{
		AccessPatternsByUserType: make(map[string]*AccessPattern),
	}

	// Get audit events for the period
	auditQuery := &AuditQuery{
		StartTime:      &period.StartTime,
		EndTime:        &period.EndTime,
		OrganizationID: orgID,
		EventTypes:     []AuditEventType{EventTypeAccessAttempt},
		Limit:          10000,
	}

	events, err := as.auditService.QueryEvents(ctx, auditQuery)
	if err != nil {
		return nil, err
	}

	// Analyze resource usage
	resourceUsage := make(map[string]*ResourceUsage)
	permissionUsage := make(map[string]*PermissionUsage)
	hourlyUsage := make(map[int]int64)

	for _, event := range events {
		hour := event.Timestamp.Hour()
		hourlyUsage[hour]++

		// Track resource usage
		if usage, exists := resourceUsage[event.Resource]; exists {
			usage.AccessCount++
			if event.Success {
				usage.SuccessRate = (usage.SuccessRate + 1) / 2 // Simple moving average
			}
		} else {
			successRate := 0.0
			if event.Success {
				successRate = 1.0
			}
			resourceUsage[event.Resource] = &ResourceUsage{
				Resource:    event.Resource,
				AccessCount: 1,
				UniqueUsers: 1,
				SuccessRate: successRate,
			}
		}

		// Track permission usage
		permKey := fmt.Sprintf("%s:%s", event.Resource, event.Action)
		if usage, exists := permissionUsage[permKey]; exists {
			usage.UsageCount++
			usage.LastUsed = event.Timestamp
		} else {
			permissionUsage[permKey] = &PermissionUsage{
				Permission:  permKey,
				Resource:    event.Resource,
				Action:      string(event.Action),
				UsageCount:  1,
				UniqueUsers: 1,
				LastUsed:    event.Timestamp,
				SuccessRate: 1.0,
				RiskScore:   as.calculatePermissionRiskScore(event.Resource, string(event.Action)),
			}
		}
	}

	// Convert maps to sorted slices
	patterns.MostAccessedResources = as.sortResourceUsage(resourceUsage, 10, true)
	patterns.MostUsedPermissions = as.sortPermissionUsage(permissionUsage, 10, true)
	patterns.LeastUsedPermissions = as.sortPermissionUsage(permissionUsage, 10, false)

	// Find peak usage hours
	patterns.PeakUsageHours = as.findPeakHours(hourlyUsage, 3)

	// // Generate user activity distribution
	// patterns.UserActivityDistribution = as.generateActivityDistribution(ctx, orgID, period)
	//
	// // Find permission co-occurrence patterns
	// patterns.PermissionCooccurrence = as.findPermissionCooccurrence(ctx, orgID, period)

	return patterns, nil
}

// generateRiskAnalysis performs security risk analysis
func (as *AnalyticsService) generateRiskAnalysis(ctx context.Context, orgID *xid.ID, period AnalyticsPeriod) (*RiskAnalysis, error) {
	risk := &RiskAnalysis{}

	// // Get all users for risk analysis
	// users, err := as.getUsersForOrg(ctx, orgID)
	// if err != nil {
	// 	return nil, err
	// }

	// // Analyze user risk profiles
	// var totalRisk float64
	// for _, user := range users {
	// 	profile, err := as.generateUserRiskProfile(ctx, user.ID, orgID, period)
	// 	if err != nil {
	// 		continue
	// 	}
	//
	// 	totalRisk += profile.RiskScore
	//
	// 	// Collect high-risk users
	// 	if profile.RiskScore > 0.7 { // Threshold for high risk
	// 		risk.HighRiskUsers = append(risk.HighRiskUsers, profile)
	// 	}
	// }
	//
	// // Calculate overall risk score
	// if len(users) > 0 {
	// 	risk.OverallRiskScore = totalRisk / float64(len(users))
	// }
	//
	// // Analyze permission risks
	// permissions, err := as.getPermissionsForOrg(ctx, orgID)
	// if err != nil {
	// 	return nil, err
	// }
	//
	// for _, perm := range permissions {
	// 	permRisk := as.calculatePermissionRisk(ctx, perm, orgID, period)
	// 	if permRisk.RiskScore > 0.6 { // Threshold for high risk
	// 		risk.HighRiskPermissions = append(risk.HighRiskPermissions, permRisk)
	// 	}
	// }
	//
	// // Analyze role risks
	// roles, err := as.getRolesForOrg(ctx, orgID)
	// if err != nil {
	// 	return nil, err
	// }
	//
	// for _, role := range roles {
	// 	roleRisk := as.calculateRoleRisk(ctx, role, orgID, period)
	// 	if roleRisk.RiskScore > 0.6 { // Threshold for vulnerable roles
	// 		risk.VulnerableRoles = append(risk.VulnerableRoles, roleRisk)
	// 	}
	// }
	//
	// // Calculate specific risk metrics
	// risk.PrivilegeEscalationRisk = as.calculatePrivilegeEscalationRisk(ctx, orgID)
	// risk.DataExposureRisk = as.calculateDataExposureRisk(ctx, orgID)
	// risk.ComplianceRisk = as.calculateComplianceRisk(ctx, orgID)
	// risk.TrendRisk = as.calculateTrendRisk(ctx, orgID, period)

	// Sort high-risk items by risk score
	sort.Slice(risk.HighRiskUsers, func(i, j int) bool {
		return risk.HighRiskUsers[i].RiskScore > risk.HighRiskUsers[j].RiskScore
	})

	sort.Slice(risk.HighRiskPermissions, func(i, j int) bool {
		return risk.HighRiskPermissions[i].RiskScore > risk.HighRiskPermissions[j].RiskScore
	})

	sort.Slice(risk.VulnerableRoles, func(i, j int) bool {
		return risk.VulnerableRoles[i].RiskScore > risk.VulnerableRoles[j].RiskScore
	})

	return risk, nil
}

// generateUserSegmentation creates user segments based on behavior and permissions
func (as *AnalyticsService) generateUserSegmentation(ctx context.Context, orgID *xid.ID, period AnalyticsPeriod) (*UserSegmentation, error) {
	segmentation := &UserSegmentation{
		SegmentMetrics: make(map[string]*SegmentMetrics),
	}

	// users, err := as.getUsersForOrg(ctx, orgID)
	// if err != nil {
	// 	return nil, err
	// }

	// Create user segments based on activity and permissions
	segments := map[string]*UserSegment{
		"power_users": {
			Name:        "Power Users",
			Description: "Users with high permission count and activity",
			Criteria:    []string{"permission_count > 50", "activity_score > 0.8"},
		},
		"regular_users": {
			Name:        "Regular Users",
			Description: "Standard users with moderate permissions",
			Criteria:    []string{"permission_count 10-50", "activity_score 0.3-0.8"},
		},
		"limited_users": {
			Name:        "Limited Users",
			Description: "Users with minimal permissions",
			Criteria:    []string{"permission_count < 10", "activity_score < 0.3"},
		},
		"inactive_users": {
			Name:        "Inactive Users",
			Description: "Users with no recent activity",
			Criteria:    []string{"last_activity > 30 days"},
		},
	}

	// // Classify users into segments
	// for _, user := range users {
	// 	permissionCount := as.getUserPermissionCount(ctx, user.ID, orgID)
	// 	activityScore := as.getUserActivityScore(ctx, user.ID, period)
	// 	lastActivity := as.getUserLastActivity(ctx, user.ID)
	//
	// 	// Determine segment
	// 	segmentName := as.classifyUserSegment(permissionCount, activityScore, lastActivity)
	// 	if segment, exists := segments[segmentName]; exists {
	// 		segment.UserCount++
	// 		segment.AvgPermissions = (segment.AvgPermissions + float64(permissionCount)) / 2
	// 		segment.AvgActivity = (segment.AvgActivity + activityScore) / 2
	// 	}
	//
	// 	// Track special user types
	// 	if permissionCount > 100 && activityScore > 0.9 {
	// 		segmentation.PowerUsers = append(segmentation.PowerUsers, &PowerUser{
	// 			UserID:          user.ID,
	// 			PermissionCount: permissionCount,
	// 			ActivityScore:   activityScore,
	// 			LastActivity:    lastActivity,
	// 		})
	// 	}
	//
	// 	if time.Since(lastActivity) > 30*24*time.Hour {
	// 		segmentation.InactiveUsers = append(segmentation.InactiveUsers, &InactiveUser{
	// 			UserID:          user.ID,
	// 			LastActivity:    lastActivity,
	// 			InactiveDays:    int(time.Since(lastActivity).Hours() / 24),
	// 			PermissionCount: permissionCount,
	// 			RiskIfActive:    as.calculateInactiveUserRisk(user, permissionCount),
	// 		})
	// 	}
	//
	// 	if time.Since(user.CreatedAt) < 30*24*time.Hour {
	// 		segmentation.NewUsers = append(segmentation.NewUsers, &NewUser{
	// 			UserID:          user.ID,
	// 			CreatedAt:       user.CreatedAt,
	// 			DaysSinceJoined: int(time.Since(user.CreatedAt).Hours() / 24),
	// 			ActivityLevel:   as.classifyActivityLevel(activityScore),
	// 		})
	// 	}
	// }

	// Convert segments map to slice
	for _, segment := range segments {
		if segment.UserCount > 0 {
			segmentation.Segments = append(segmentation.Segments, segment)
		}
	}

	return segmentation, nil
}

// generateRoleEffectiveness analyzes role usage and effectiveness
func (as *AnalyticsService) generateRoleEffectiveness(ctx context.Context, orgID *xid.ID, period AnalyticsPeriod) (*RoleEffectiveness, error) {
	effectiveness := &RoleEffectiveness{
		RoleComplexity: make(map[string]float64),
	}

	// roles, err := as.getRolesForOrg(ctx, orgID)
	// if err != nil {
	// 	return nil, err
	// }

	// // Analyze each role
	// for _, role := range roles {
	// 	// Calculate utilization
	// 	utilization := as.calculateRoleUtilization(ctx, role, period)
	// 	effectiveness.RoleUtilization = append(effectiveness.RoleUtilization, utilization)
	//
	// 	// Calculate complexity
	// 	complexity := as.calculateRoleComplexity(ctx, role)
	// 	effectiveness.RoleComplexity[role.Name] = complexity
	// }
	//
	// // Find role overlaps
	// effectiveness.RoleOverlap = as.findRoleOverlaps(ctx, roles)
	//
	// // Generate optimization suggestions
	// effectiveness.OptimizationSuggestions = as.generateRoleOptimizationSuggestions(effectiveness)

	return effectiveness, nil
}

// generateComplianceMetrics creates compliance-related metrics
func (as *AnalyticsService) generateComplianceMetrics(ctx context.Context, orgID *xid.ID, period AnalyticsPeriod) (*ComplianceMetrics, error) {
	metrics := &ComplianceMetrics{}

	// // Find SOD violations
	// metrics.SODViolations = as.findSODViolations(ctx, orgID)
	//
	// // Find overprivileged access
	// metrics.OverprivilegedAccess = as.findOverprivilegedAccess(ctx, orgID, period)
	//
	// // Access certification status
	// metrics.AccessCertification = as.getAccessCertificationStatus(ctx, orgID)
	//
	// // Policy compliance
	// metrics.PolicyCompliance = as.getPolicyCompliance(ctx, orgID)
	//
	// // Audit readiness
	// metrics.AuditReadiness = as.getAuditReadiness(ctx, orgID)

	return metrics, nil
}

// generateTrendAnalysis creates trend analysis over time
func (as *AnalyticsService) generateTrendAnalysis(ctx context.Context, orgID *xid.ID, period AnalyticsPeriod) (*TrendAnalysis, error) {
	trends := &TrendAnalysis{
		SeasonalPatterns: make(map[string]*Pattern),
		Forecasts:        make(map[string]*Forecast),
	}

	// // Analyze user growth trend
	// trends.UserGrowthTrend = as.analyzeUserGrowthTrend(ctx, orgID, period)
	//
	// // Analyze permission usage trend
	// trends.PermissionUsageTrend = as.analyzePermissionUsageTrend(ctx, orgID, period)
	//
	// // Analyze risk trend
	// trends.RiskTrend = as.analyzeRiskTrend(ctx, orgID, period)
	//
	// // Analyze compliance trend
	// trends.ComplianceTrend = as.analyzeComplianceTrend(ctx, orgID, period)
	//
	// // Detect seasonal patterns
	// trends.SeasonalPatterns["usage"] = as.detectUsageSeasonalPattern(ctx, orgID, period)
	// trends.SeasonalPatterns["access"] = as.detectAccessSeasonalPattern(ctx, orgID, period)
	//
	// // Generate forecasts
	// trends.Forecasts["user_growth"] = as.forecastUserGrowth(trends.UserGrowthTrend)
	// trends.Forecasts["risk_level"] = as.forecastRiskLevel(trends.RiskTrend)

	return trends, nil
}

// generateRecommendations creates actionable security recommendations
func (as *AnalyticsService) generateRecommendations(analytics *PermissionAnalytics) []*SecurityRecommendation {
	var recommendations []*SecurityRecommendation

	// High-risk user recommendations
	if len(analytics.RiskAnalysis.HighRiskUsers) > 0 {
		recommendations = append(recommendations, &SecurityRecommendation{
			ID:          "high-risk-users",
			Type:        "security",
			Priority:    "high",
			Title:       "Review High-Risk Users",
			Description: fmt.Sprintf("%d users have elevated risk scores", len(analytics.RiskAnalysis.HighRiskUsers)),
			Impact:      "Reduce security exposure and potential data breaches",
			Effort:      "medium",
			Category:    "user_management",
			Actions:     []string{"Review user permissions", "Implement additional monitoring", "Consider MFA requirements"},
			CreatedAt:   time.Now(),
		})
	}

	// Overprivileged users recommendations
	if analytics.Summary.OverprivilegedUsers > 0 {
		recommendations = append(recommendations, &SecurityRecommendation{
			ID:          "overprivileged-users",
			Type:        "compliance",
			Priority:    "medium",
			Title:       "Address Overprivileged Users",
			Description: fmt.Sprintf("%d users have excessive permissions", analytics.Summary.OverprivilegedUsers),
			Impact:      "Improve least privilege compliance",
			Effort:      "high",
			Category:    "access_management",
			Actions:     []string{"Conduct access review", "Remove unused permissions", "Implement role-based access"},
			CreatedAt:   time.Now(),
		})
	}

	// Unused roles recommendations
	if analytics.Summary.UnusedRoles > 0 {
		recommendations = append(recommendations, &SecurityRecommendation{
			ID:          "unused-roles",
			Type:        "optimization",
			Priority:    "low",
			Title:       "Clean Up Unused Roles",
			Description: fmt.Sprintf("%d roles are not assigned to any users", analytics.Summary.UnusedRoles),
			Impact:      "Reduce complexity and maintenance overhead",
			Effort:      "low",
			Category:    "role_management",
			Actions:     []string{"Review role necessity", "Archive or delete unused roles", "Document role purposes"},
			CreatedAt:   time.Now(),
		})
	}

	// Risk trend recommendations
	if analytics.RiskAnalysis.TrendRisk == "increasing" {
		recommendations = append(recommendations, &SecurityRecommendation{
			ID:          "increasing-risk",
			Type:        "risk",
			Priority:    "critical",
			Title:       "Address Increasing Risk Trend",
			Description: "Overall security risk is trending upward",
			Impact:      "Prevent potential security incidents",
			Effort:      "high",
			Category:    "risk_management",
			Actions:     []string{"Conduct security assessment", "Review recent changes", "Implement additional controls"},
			CreatedAt:   time.Now(),
		})
	}

	// Sort recommendations by priority
	priorityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.Slice(recommendations, func(i, j int) bool {
		return priorityOrder[recommendations[i].Priority] < priorityOrder[recommendations[j].Priority]
	})

	return recommendations
}

// Helper methods (simplified implementations for brevity)

func (as *AnalyticsService) getRolesForOrg(ctx context.Context, orgID *xid.ID) ([]*ent.Role, error) {
	// Implementation would query roles for the organization
	return []*ent.Role{}, nil
}

func (as *AnalyticsService) getPermissionsForOrg(ctx context.Context, orgID *xid.ID) ([]*ent.Permission, error) {
	// Implementation would query permissions for the organization
	return []*ent.Permission{}, nil
}

func (as *AnalyticsService) getUsersForOrg(ctx context.Context, orgID *xid.ID) ([]*ent.User, error) {
	// Implementation would query users for the organization
	return []*ent.User{}, nil
}

func (as *AnalyticsService) isUserActive(ctx context.Context, userID xid.ID, period AnalyticsPeriod) bool {
	// Implementation would check if user had any activity during the period
	return true
}

func (as *AnalyticsService) getUserRoles(ctx context.Context, userID xid.ID, orgID *xid.ID) ([]*ent.Role, error) {
	// Implementation would get user roles
	return []*ent.Role{}, nil
}

func (as *AnalyticsService) countOverprivilegedUsers(ctx context.Context, users []*ent.User, orgID *xid.ID, period AnalyticsPeriod) int {
	// Implementation would count users with excessive permissions
	return 0
}

func (as *AnalyticsService) countUnderprivilegedUsers(ctx context.Context, users []*ent.User, orgID *xid.ID, period AnalyticsPeriod) int {
	// Implementation would count users with insufficient permissions
	return 0
}

func (as *AnalyticsService) countOrphanedPermissions(ctx context.Context, permissions []*ent.Permission, roles []*ent.Role) int {
	// Implementation would count permissions not assigned to any role
	return 0
}

func (as *AnalyticsService) countUnusedRoles(ctx context.Context, roles []*ent.Role, period AnalyticsPeriod) int {
	// Implementation would count roles not assigned to any user
	return 0
}

func (as *AnalyticsService) calculatePermissionRiskScore(resource, action string) float64 {
	// Implementation would calculate risk score based on resource and action
	riskMap := map[string]float64{
		"delete": 0.8,
		"create": 0.6,
		"update": 0.4,
		"read":   0.2,
	}

	if score, exists := riskMap[action]; exists {
		return score
	}
	return 0.3 // Default risk score
}

func (as *AnalyticsService) sortResourceUsage(usage map[string]*ResourceUsage, limit int, descending bool) []*ResourceUsage {
	var sorted []*ResourceUsage
	for _, ru := range usage {
		sorted = append(sorted, ru)
	}

	sort.Slice(sorted, func(i, j int) bool {
		if descending {
			return sorted[i].AccessCount > sorted[j].AccessCount
		}
		return sorted[i].AccessCount < sorted[j].AccessCount
	})

	if len(sorted) > limit {
		sorted = sorted[:limit]
	}

	return sorted
}

func (as *AnalyticsService) sortPermissionUsage(usage map[string]*PermissionUsage, limit int, descending bool) []*PermissionUsage {
	var sorted []*PermissionUsage
	for _, pu := range usage {
		sorted = append(sorted, pu)
	}

	sort.Slice(sorted, func(i, j int) bool {
		if descending {
			return sorted[i].UsageCount > sorted[j].UsageCount
		}
		return sorted[i].UsageCount < sorted[j].UsageCount
	})

	if len(sorted) > limit {
		sorted = sorted[:limit]
	}

	return sorted
}

func (as *AnalyticsService) findPeakHours(hourlyUsage map[int]int64, topN int) []int {
	type hourUsage struct {
		hour  int
		usage int64
	}

	var hours []hourUsage
	for hour, usage := range hourlyUsage {
		hours = append(hours, hourUsage{hour, usage})
	}

	sort.Slice(hours, func(i, j int) bool {
		return hours[i].usage > hours[j].usage
	})

	var peakHours []int
	for i := 0; i < topN && i < len(hours); i++ {
		peakHours = append(peakHours, hours[i].hour)
	}

	return peakHours
}

// Additional helper methods would be implemented here...
// For brevity, I'm including just the key structure and a few representative implementations
