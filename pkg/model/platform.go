package model

import (
	"time"

	"github.com/rs/xid"
)

// Platform Organization Models

type PlatformOrganizationListResponse struct {
	Organizations []OrganizationSummary    `json:"organizations"`
	Pagination    *Pagination              `json:"pagination"`
	Summary       OrganizationSummaryStats `json:"summary"`
}

type OrganizationSummaryStats struct {
	Total     int `json:"total"`
	Active    int `json:"active"`
	Suspended int `json:"suspended"`
	Trial     int `json:"trial"`
	Paid      int `json:"paid"`
	Canceled  int `json:"canceled"`
}

type PlatformOrganizationDetails struct {
	Organization Organization         `json:"organization"`
	Stats        *OrgStats            `json:"stats,omitempty"`
	Usage        *OrganizationUsage   `json:"usage,omitempty"`
	Members      []UserSummary        `json:"members,omitempty"`
	Billing      *OrganizationBilling `json:"billing,omitempty"`
	Activity     []ActivityRecord     `json:"recentActivity,omitempty"`
	Security     *SecuritySummary     `json:"security,omitempty"`
	Features     []FeatureSummary     `json:"enabledFeatures,omitempty"`
}

type PlatformOrganizationStats struct {
	OrganizationID xid.ID          `json:"organizationId"`
	Period         string          `json:"period"`
	Stats          *OrgStats       `json:"stats"`
	Trends         *OrgTrends      `json:"trends,omitempty"`
	Comparisons    *OrgComparisons `json:"comparisons,omitempty"`
}

type OrgTrends struct {
	UserGrowth      float64 `json:"userGrowthPercent"`
	APIUsageGrowth  float64 `json:"apiUsageGrowthPercent"`
	RevenueGrowth   float64 `json:"revenueGrowthPercent"`
	ActivityGrowth  float64 `json:"activityGrowthPercent"`
	ErrorRateChange float64 `json:"errorRateChangePercent"`
}

type OrgComparisons struct {
	PreviousPeriod    *OrgStats `json:"previousPeriod,omitempty"`
	PlatformAverage   *OrgStats `json:"platformAverage,omitempty"`
	PeerOrganizations *OrgStats `json:"peerOrganizations,omitempty"`
}

// Platform User Models

type PlatformUserListResponse struct {
	Users      []UserSummary    `json:"users"`
	Pagination *Pagination      `json:"pagination"`
	Summary    UserSummaryStats `json:"summary"`
}

type UserSummaryStats struct {
	Total    int `json:"total"`
	Active   int `json:"active"`
	Blocked  int `json:"blocked"`
	Verified int `json:"verified"`
	Internal int `json:"internal"`
	External int `json:"external"`
	EndUsers int `json:"endUsers"`
}

type PlatformUserDetails struct {
	User          User                       `json:"user"`
	Sessions      []Session                  `json:"sessions,omitempty"`
	Activity      []*ActivityRecord          `json:"recent_activity,omitempty"`
	Organizations []OrganizationSummary      `json:"organizations,omitempty"`
	Permissions   []UserPermissionAssignment `json:"permissions,omitempty"`
	Roles         []UserRoleAssignment       `json:"roles,omitempty"`
	MFA           []MFA                      `json:"mfa_methods,omitempty"`
	APIKeys       []APIKey                   `json:"api_keys,omitempty"`
	Security      *UserSecuritySummary       `json:"security,omitempty"`
	Billing       *UserBillingSummary        `json:"billing,omitempty"`
}

type UserSecuritySummary struct {
	LastLogin        *time.Time `json:"last_login,omitempty"`
	LoginCount       int        `json:"login_count"`
	FailedAttempts   int        `json:"failed_attempts"`
	MFAEnabled       bool       `json:"mfa_enabled"`
	PasskeysEnabled  bool       `json:"passkeys_enabled"`
	RiskScore        int        `json:"risk_score"`
	SecurityAlerts   int        `json:"security_alerts"`
	CompromisedCheck *time.Time `json:"last_compromised_check,omitempty"`
}

type UserBillingSummary struct {
	IsBillableUser  bool    `json:"is_billable_user"`
	MonthlyAPIUsage int     `json:"monthly_api_usage"`
	StorageUsage    int64   `json:"storage_usage_bytes"`
	BandwidthUsage  int64   `json:"bandwidth_usage_bytes"`
	EstimatedCost   float64 `json:"estimated_monthly_cost"`
}

// Platform Statistics Models

type PlatformStats struct {
	Period        string                   `json:"period"`
	GeneratedAt   time.Time                `json:"generated_at"`
	Organizations PlatformOrgStats         `json:"organizations"`
	Users         PlatformUserStats        `json:"users"`
	API           PlatformAPIStats         `json:"api"`
	Security      PlatformSecurityStats    `json:"security"`
	Performance   PlatformPerformanceStats `json:"performance"`
	Revenue       PlatformRevenueStats     `json:"revenue"`
	Growth        PlatformGrowthStats      `json:"growth"`
}

type PlatformOrgStats struct {
	Total       int     `json:"total"`
	Active      int     `json:"active"`
	Suspended   int     `json:"suspended"`
	Trial       int     `json:"trial"`
	Paid        int     `json:"paid"`
	ChurnRate   float64 `json:"churn_rate_percent"`
	GrowthRate  float64 `json:"growth_rate_percent"`
	AvgLifetime int     `json:"avg_lifetime_days"`
}

type PlatformUserStats struct {
	Total        int     `json:"total"`
	Active       int     `json:"active"`
	Internal     int     `json:"internal"`
	External     int     `json:"external"`
	EndUsers     int     `json:"end_users"`
	Verified     int     `json:"verified"`
	WithMFA      int     `json:"with_mfa"`
	WithPasskeys int     `json:"with_passkeys"`
	GrowthRate   float64 `json:"growth_rate_percent"`
}

type PlatformAPIStats struct {
	TotalRequests   int64                  `json:"total_requests"`
	RequestsToday   int64                  `json:"requests_today"`
	AvgResponseTime float64                `json:"avg_response_time_ms"`
	ErrorRate       float64                `json:"error_rate_percent"`
	RateLimit       PlatformRateLimitStats `json:"rate_limiting"`
	TopEndpoints    []EndpointUsage        `json:"top_endpoints"`
}

type PlatformRateLimitStats struct {
	TotalLimited   int64   `json:"total_limited"`
	LimitedToday   int64   `json:"limited_today"`
	LimitedPercent float64 `json:"limited_percent"`
}

type PlatformSecurityStats struct {
	SecurityEvents      int     `json:"security_events"`
	HighRiskEvents      int     `json:"high_risk_events"`
	BlockedAttempts     int     `json:"blocked_attempts"`
	CompromisedAccounts int     `json:"compromised_accounts"`
	MFAAdoptionRate     float64 `json:"mfa_adoption_rate_percent"`
	PasskeyAdoptionRate float64 `json:"passkey_adoption_rate_percent"`
}

type PlatformPerformanceStats struct {
	Uptime          float64 `json:"uptime_percent"`
	AvgResponseTime float64 `json:"avg_response_time_ms"`
	P95ResponseTime float64 `json:"p95_response_time_ms"`
	P99ResponseTime float64 `json:"p99_response_time_ms"`
	DatabaseLatency float64 `json:"database_latency_ms"`
	CacheHitRate    float64 `json:"cache_hit_rate_percent"`
}

type PlatformRevenueStats struct {
	TotalRevenue   float64 `json:"total_revenue"`
	MonthlyRevenue float64 `json:"monthly_revenue"`
	AnnualRevenue  float64 `json:"annual_revenue"`
	ARPU           float64 `json:"arpu"` // Average Revenue Per User
	LTV            float64 `json:"ltv"`  // Lifetime Value
	GrowthRate     float64 `json:"growth_rate_percent"`
	ChurnRate      float64 `json:"churn_rate_percent"`
}

type PlatformGrowthStats struct {
	NewOrganizations       int     `json:"new_organizations"`
	NewUsers               int     `json:"new_users"`
	OrganizationGrowthRate float64 `json:"org_growth_rate_percent"`
	UserGrowthRate         float64 `json:"user_growth_rate_percent"`
	RevenueGrowthRate      float64 `json:"revenue_growth_rate_percent"`
	APIUsageGrowthRate     float64 `json:"api_usage_growth_rate_percent"`
}

// Platform Metrics Models

type PlatformMetrics struct {
	Period      string                `json:"period"`
	GeneratedAt time.Time             `json:"generated_at"`
	System      SystemResourceMetrics `json:"system"`
	Database    DatabaseMetrics       `json:"database"`
	Cache       CacheMetrics          `json:"cache"`
	Queue       QueueMetrics          `json:"queue"`
	Storage     StorageMetrics        `json:"storage"`
	Network     NetworkMetrics        `json:"network"`
	Application ApplicationMetrics    `json:"application"`
}

type SystemResourceMetrics struct {
	CPUUsage    float64 `json:"cpu_usage_percent"`
	MemoryUsage float64 `json:"memory_usage_percent"`
	DiskUsage   float64 `json:"disk_usage_percent"`
	LoadAverage float64 `json:"load_average"`
}

type DatabaseMetrics struct {
	ConnectionCount int     `json:"connection_count"`
	ActiveQueries   int     `json:"active_queries"`
	SlowQueries     int     `json:"slow_queries"`
	QueryTime       float64 `json:"avg_query_time_ms"`
	ReplicationLag  float64 `json:"replication_lag_ms"`
	DeadlockCount   int     `json:"deadlock_count"`
}

type CacheMetrics struct {
	HitRate      float64 `json:"hit_rate_percent"`
	MissRate     float64 `json:"miss_rate_percent"`
	EvictionRate float64 `json:"eviction_rate"`
	MemoryUsage  float64 `json:"memory_usage_percent"`
	KeyCount     int64   `json:"key_count"`
	ExpiredKeys  int64   `json:"expired_keys"`
}

type QueueMetrics struct {
	PendingJobs    int     `json:"pending_jobs"`
	ProcessedJobs  int     `json:"processed_jobs"`
	FailedJobs     int     `json:"failed_jobs"`
	AvgWaitTime    float64 `json:"avg_wait_time_ms"`
	AvgProcessTime float64 `json:"avg_process_time_ms"`
}

type StorageMetrics struct {
	TotalStorage int64   `json:"total_storage_bytes"`
	UsedStorage  int64   `json:"used_storage_bytes"`
	UsagePercent float64 `json:"usage_percent"`
	FilesCount   int64   `json:"files_count"`
	AvgFileSize  int64   `json:"avg_file_size_bytes"`
}

type NetworkMetrics struct {
	InboundTraffic  int64   `json:"inbound_traffic_bytes"`
	OutboundTraffic int64   `json:"outbound_traffic_bytes"`
	RequestRate     float64 `json:"request_rate_per_second"`
	ConnectionCount int     `json:"connection_count"`
	BandwidthUsage  float64 `json:"bandwidth_usage_percent"`
}

type ApplicationMetrics struct {
	ActiveSessions  int     `json:"active_sessions"`
	RequestCount    int64   `json:"request_count"`
	ErrorCount      int64   `json:"error_count"`
	AvgResponseTime float64 `json:"avg_response_time_ms"`
	GoroutineCount  int     `json:"goroutine_count"`
	MemoryAllocated int64   `json:"memory_allocated_bytes"`
}

// Growth and Revenue Models

type PlatformGrowthMetrics struct {
	Period        string               `json:"period"`
	GeneratedAt   time.Time            `json:"generated_at"`
	Organizations GrowthOrgMetrics     `json:"organizations"`
	Users         GrowthUserMetrics    `json:"users"`
	Revenue       GrowthRevenueMetrics `json:"revenue"`
	API           GrowthAPIMetrics     `json:"api"`
	Retention     RetentionMetrics     `json:"retention"`
	Acquisition   AcquisitionMetrics   `json:"acquisition"`
}

type GrowthOrgMetrics struct {
	NewOrganizations     int     `json:"new_organizations"`
	ChurnedOrganizations int     `json:"churned_organizations"`
	NetGrowth            int     `json:"net_growth"`
	GrowthRate           float64 `json:"growth_rate_percent"`
	ConversionRate       float64 `json:"conversion_rate_percent"`
}

type GrowthUserMetrics struct {
	NewUsers       int     `json:"new_users"`
	ActiveUsers    int     `json:"active_users"`
	ChurnedUsers   int     `json:"churned_users"`
	GrowthRate     float64 `json:"growth_rate_percent"`
	ActivationRate float64 `json:"activation_rate_percent"`
}

type GrowthRevenueMetrics struct {
	NewRevenue     float64 `json:"new_revenue"`
	ChurnedRevenue float64 `json:"churned_revenue"`
	NetRevenue     float64 `json:"net_revenue"`
	GrowthRate     float64 `json:"growth_rate_percent"`
	ARPU           float64 `json:"arpu"`
}

type GrowthAPIMetrics struct {
	NewAPIUsers     int     `json:"new_api_users"`
	APIUsageGrowth  float64 `json:"api_usage_growth_percent"`
	IntegrationRate float64 `json:"integration_rate_percent"`
}

type RetentionMetrics struct {
	Day1Retention  float64      `json:"day1_retention_percent"`
	Day7Retention  float64      `json:"day7_retention_percent"`
	Day30Retention float64      `json:"day30_retention_percent"`
	Day90Retention float64      `json:"day90_retention_percent"`
	CohortAnalysis []CohortData `json:"cohort_analysis"`
}

type CohortData struct {
	CohortMonth string    `json:"cohort_month"`
	UserCount   int       `json:"user_count"`
	Retention   []float64 `json:"retention_by_month"`
}

type AcquisitionMetrics struct {
	Channels       []AcquisitionChannel `json:"channels"`
	ConversionRate float64              `json:"conversion_rate_percent"`
	CostPerUser    float64              `json:"cost_per_user"`
	LTV            float64              `json:"lifetime_value"`
	PaybackPeriod  int                  `json:"payback_period_days"`
}

type AcquisitionChannel struct {
	Channel        string  `json:"channel"`
	NewUsers       int     `json:"new_users"`
	ConversionRate float64 `json:"conversion_rate_percent"`
	Cost           float64 `json:"cost"`
	CostPerUser    float64 `json:"cost_per_user"`
}

type RevenueMetricsPlatform struct {
	Period      string            `json:"period"`
	GeneratedAt time.Time         `json:"generated_at"`
	Overview    RevenueOverview   `json:"overview"`
	Breakdown   RevenueBreakdown  `json:"breakdown"`
	Forecasting RevenueForecast   `json:"forecasting"`
	Comparison  RevenueComparison `json:"comparison"`
}

type RevenueOverview struct {
	TotalRevenue     float64 `json:"total_revenue"`
	RecurringRevenue float64 `json:"recurring_revenue"`
	OneTimeRevenue   float64 `json:"one_time_revenue"`
	ARPU             float64 `json:"arpu"`
	ARPPU            float64 `json:"arppu"` // Average Revenue Per Paying User
	LTV              float64 `json:"ltv"`
	ChurnRate        float64 `json:"churn_rate_percent"`
}

type RevenueBreakdown struct {
	ByPlan    []PlanRevenue    `json:"by_plan"`
	ByRegion  []RegionRevenue  `json:"by_region"`
	ByChannel []ChannelRevenue `json:"by_channel"`
	ByFeature []FeatureRevenue `json:"by_feature"`
}

type RegionRevenue struct {
	Region  string  `json:"region"`
	Revenue float64 `json:"revenue"`
	Users   int     `json:"users"`
	Growth  float64 `json:"growth_percent"`
}

type ChannelRevenue struct {
	Channel string  `json:"channel"`
	Revenue float64 `json:"revenue"`
	Users   int     `json:"users"`
	Growth  float64 `json:"growth_percent"`
}

type FeatureRevenue struct {
	Feature string  `json:"feature"`
	Revenue float64 `json:"revenue"`
	Users   int     `json:"users"`
	Growth  float64 `json:"growth_percent"`
}

type RevenueComparison struct {
	PreviousPeriod     RevenueOverview   `json:"previous_period"`
	SamePeriodLastYear RevenueOverview   `json:"same_period_last_year"`
	Industry           IndustryBenchmark `json:"industry_benchmark"`
}

type IndustryBenchmark struct {
	ARPU       float64 `json:"arpu"`
	ChurnRate  float64 `json:"churn_rate_percent"`
	GrowthRate float64 `json:"growth_rate_percent"`
	Source     string  `json:"source"`
}

type UsageAnalytics struct {
	Period      string             `json:"period"`
	GeneratedAt time.Time          `json:"generated_at"`
	Features    []FeatureUsage     `json:"features"`
	API         APIUsageAnalytics  `json:"api"`
	Auth        AuthUsageAnalytics `json:"auth"`
	Trends      UsageTrends        `json:"trends"`
}

type FeatureUsage struct {
	Feature       string  `json:"feature"`
	ActiveUsers   int     `json:"active_users"`
	TotalUsage    int64   `json:"total_usage"`
	AdoptionRate  float64 `json:"adoption_rate_percent"`
	GrowthRate    float64 `json:"growth_rate_percent"`
	Revenue       float64 `json:"revenue"`
	Organizations int     `json:"organizations"`
}

type APIUsageAnalytics struct {
	TotalRequests      int64            `json:"total_requests"`
	UniqueConsumers    int              `json:"unique_consumers"`
	AvgRequestsPerUser float64          `json:"avg_requests_per_user"`
	TopEndpoints       []EndpointUsage  `json:"top_endpoints"`
	ErrorAnalysis      APIErrorAnalysis `json:"error_analysis"`
}

type APIErrorAnalysis struct {
	TotalErrors int64            `json:"total_errors"`
	ErrorRate   float64          `json:"error_rate_percent"`
	TopErrors   []ErrorBreakdown `json:"top_errors"`
	ErrorTrends []ErrorTrend     `json:"error_trends"`
}

type ErrorBreakdown struct {
	StatusCode int     `json:"status_code"`
	Count      int64   `json:"count"`
	Percentage float64 `json:"percentage"`
	Message    string  `json:"message"`
}

type ErrorTrend struct {
	Date       time.Time `json:"date"`
	ErrorCount int64     `json:"error_count"`
	ErrorRate  float64   `json:"error_rate_percent"`
}

type AuthUsageAnalytics struct {
	LoginMethods     []AuthMethodUsage `json:"login_methods"`
	MFAUsage         MFAUsageStats     `json:"mfa_usage"`
	PasskeyUsage     PasskeyUsageStats `json:"passkey_usage"`
	SSOUsage         SSOUsageStats     `json:"sso_usage"`
	SessionAnalytics SessionAnalytics  `json:"session_analytics"`
}

type AuthMethodUsage struct {
	Method      string  `json:"method"`
	Usage       int64   `json:"usage"`
	Percentage  float64 `json:"percentage"`
	SuccessRate float64 `json:"success_rate_percent"`
}

type MFAUsageStats struct {
	AdoptionRate float64           `json:"adoption_rate_percent"`
	Methods      []AuthMethodUsage `json:"methods"`
	BypassRate   float64           `json:"bypass_rate_percent"`
}

type PasskeyUsageStats struct {
	AdoptionRate float64           `json:"adoption_rate_percent"`
	Usage        int64             `json:"usage"`
	SuccessRate  float64           `json:"success_rate_percent"`
	DeviceTypes  []DeviceTypeUsage `json:"device_types"`
}

type DeviceTypeUsage struct {
	DeviceType string  `json:"device_type"`
	Usage      int64   `json:"usage"`
	Percentage float64 `json:"percentage"`
}

type SSOUsageStats struct {
	AdoptionRate float64            `json:"adoption_rate_percent"`
	Providers    []SSOProviderUsage `json:"providers"`
	Usage        int64              `json:"usage"`
	SuccessRate  float64            `json:"success_rate_percent"`
}

type SSOProviderUsage struct {
	Provider   string  `json:"provider"`
	Usage      int64   `json:"usage"`
	Percentage float64 `json:"percentage"`
}

type SessionAnalytics struct {
	AvgSessionDuration float64           `json:"avg_session_duration_minutes"`
	ActiveSessions     int               `json:"active_sessions"`
	SessionsByDevice   []DeviceTypeUsage `json:"sessions_by_device"`
	SessionsByLocation []LocationUsage   `json:"sessions_by_location"`
}

type LocationUsage struct {
	Location   string  `json:"location"`
	Sessions   int     `json:"sessions"`
	Percentage float64 `json:"percentage"`
}

type UsageTrends struct {
	Daily   []DailyUsage   `json:"daily"`
	Weekly  []WeeklyUsage  `json:"weekly"`
	Monthly []MonthlyUsage `json:"monthly"`
}

type DailyUsage struct {
	Date    time.Time `json:"date"`
	Usage   int64     `json:"usage"`
	Users   int       `json:"users"`
	Revenue float64   `json:"revenue"`
}

type WeeklyUsage struct {
	Week    string  `json:"week"`
	Usage   int64   `json:"usage"`
	Users   int     `json:"users"`
	Revenue float64 `json:"revenue"`
}

type MonthlyUsage struct {
	Month   string  `json:"month"`
	Usage   int64   `json:"usage"`
	Users   int     `json:"users"`
	Revenue float64 `json:"revenue"`
}

// System Health and Monitoring Models

type SystemHealth struct {
	Status       string             `json:"status"` // healthy, degraded, unhealthy
	LastChecked  time.Time          `json:"last_checked"`
	Services     []ServiceHealth    `json:"services"`
	Dependencies []DependencyHealth `json:"dependencies"`
	Metrics      HealthMetrics      `json:"metrics"`
	Alerts       []HealthAlert      `json:"alerts"`
}

type ServiceHealth struct {
	Name         string    `json:"name"`
	Status       string    `json:"status"`
	ResponseTime float64   `json:"response_time_ms"`
	LastChecked  time.Time `json:"last_checked"`
	Message      string    `json:"message,omitempty"`
}

type DependencyHealth struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"` // database, cache, queue, external_api
	Status      string    `json:"status"`
	Latency     float64   `json:"latency_ms"`
	LastChecked time.Time `json:"last_checked"`
	Message     string    `json:"message,omitempty"`
}

type HealthMetrics struct {
	Uptime       float64 `json:"uptime_percent"`
	Availability float64 `json:"availability_percent"`
	ResponseTime float64 `json:"avg_response_time_ms"`
	ErrorRate    float64 `json:"error_rate_percent"`
	Throughput   float64 `json:"throughput_rps"`
}

type HealthAlert struct {
	ID           xid.ID     `json:"id"`
	Severity     string     `json:"severity"`
	Service      string     `json:"service"`
	Message      string     `json:"message"`
	CreatedAt    time.Time  `json:"created_at"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
	Acknowledged bool       `json:"acknowledged"`
}

type SystemMetrics struct {
	Timestamp   time.Time             `json:"timestamp"`
	System      SystemResourceMetrics `json:"system"`
	Application ApplicationMetrics    `json:"application"`
	Database    DatabaseMetrics       `json:"database"`
	Cache       CacheMetrics          `json:"cache"`
	Queue       QueueMetrics          `json:"queue"`
	Network     NetworkMetrics        `json:"network"`
}

type PerformanceMetrics struct {
	Period      string                     `json:"period"`
	GeneratedAt time.Time                  `json:"generated_at"`
	Response    ResponseTimeMetrics        `json:"response_time"`
	Throughput  ThroughputMetrics          `json:"throughput"`
	Resources   ResourceUtilizationMetrics `json:"resources"`
	Bottlenecks []PerformanceBottleneck    `json:"bottlenecks"`
}

type ResponseTimeMetrics struct {
	Average    float64               `json:"average_ms"`
	Median     float64               `json:"median_ms"`
	P95        float64               `json:"p95_ms"`
	P99        float64               `json:"p99_ms"`
	ByEndpoint []EndpointPerformance `json:"by_endpoint"`
}

type EndpointPerformance struct {
	Endpoint     string  `json:"endpoint"`
	Method       string  `json:"method"`
	Average      float64 `json:"average_ms"`
	P95          float64 `json:"p95_ms"`
	P99          float64 `json:"p99_ms"`
	RequestCount int64   `json:"request_count"`
}

type ThroughputMetrics struct {
	RequestsPerSecond float64            `json:"requests_per_second"`
	Peak              float64            `json:"peak_rps"`
	Average           float64            `json:"average_rps"`
	ByHour            []HourlyThroughput `json:"by_hour"`
}

type HourlyThroughput struct {
	Hour         int     `json:"hour"`
	RPS          float64 `json:"rps"`
	RequestCount int64   `json:"request_count"`
}

type ResourceUtilizationMetrics struct {
	CPU     ResourceMetric `json:"cpu"`
	Memory  ResourceMetric `json:"memory"`
	Disk    ResourceMetric `json:"disk"`
	Network ResourceMetric `json:"network"`
}

type ResourceMetric struct {
	Current float64 `json:"current_percent"`
	Average float64 `json:"average_percent"`
	Peak    float64 `json:"peak_percent"`
	Trend   string  `json:"trend"` // increasing, decreasing, stable
}

type PerformanceBottleneck struct {
	Component   string `json:"component"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Suggestion  string `json:"suggestion"`
}

type ErrorRateMetrics struct {
	Period      string             `json:"period"`
	GeneratedAt time.Time          `json:"generated_at"`
	Overall     ErrorRateOverview  `json:"overall"`
	ByStatus    []StatusCodeErrors `json:"by_status_code"`
	ByEndpoint  []EndpointErrors   `json:"by_endpoint"`
	Trends      []ErrorRateTrend   `json:"trends"`
	// TopErrors   []ErrorDetail      `json:"top_errors"`
}

type ErrorRateOverview struct {
	TotalRequests int64   `json:"total_requests"`
	TotalErrors   int64   `json:"total_errors"`
	ErrorRate     float64 `json:"error_rate_percent"`
	Change        float64 `json:"change_percent"`
}

type StatusCodeErrors struct {
	StatusCode int     `json:"status_code"`
	Count      int64   `json:"count"`
	Percentage float64 `json:"percentage"`
	Change     float64 `json:"change_percent"`
}

type EndpointErrors struct {
	Endpoint  string  `json:"endpoint"`
	Method    string  `json:"method"`
	Errors    int64   `json:"errors"`
	Total     int64   `json:"total"`
	ErrorRate float64 `json:"error_rate_percent"`
}

type ErrorRateTrend struct {
	Timestamp time.Time `json:"timestamp"`
	ErrorRate float64   `json:"error_rate_percent"`
	Errors    int64     `json:"errors"`
	Requests  int64     `json:"requests"`
}

type AuditSummary struct {
	Period         string                 `json:"period"`
	GeneratedAt    time.Time              `json:"generated_at"`
	Overview       AuditOverview          `json:"overview"`
	ByAction       []AuditActionSummary   `json:"by_action"`
	ByResource     []AuditResourceSummary `json:"by_resource"`
	ByRiskLevel    []AuditRiskSummary     `json:"by_risk_level"`
	TopUsers       []AuditUserActivity    `json:"top_users"`
	SecurityEvents AuditSecuritySummary   `json:"security_events"`
	Trends         []AuditTrend           `json:"trends"`
}

type AuditOverview struct {
	TotalEvents    int64   `json:"total_events"`
	UniqueUsers    int     `json:"unique_users"`
	FailureRate    float64 `json:"failure_rate_percent"`
	HighRiskEvents int64   `json:"high_risk_events"`
	Change         float64 `json:"change_percent"`
}

type AuditActionSummary struct {
	Action  string  `json:"action"`
	Count   int64   `json:"count"`
	Success int64   `json:"success"`
	Failure int64   `json:"failure"`
	Rate    float64 `json:"success_rate_percent"`
}

type AuditResourceSummary struct {
	Resource string  `json:"resource"`
	Count    int64   `json:"count"`
	Success  int64   `json:"success"`
	Failure  int64   `json:"failure"`
	Rate     float64 `json:"success_rate_percent"`
}

type AuditRiskSummary struct {
	RiskLevel  string  `json:"risk_level"`
	Count      int64   `json:"count"`
	Percentage float64 `json:"percentage"`
}

type AuditUserActivity struct {
	UserID      xid.ID  `json:"userId"`
	Email       string  `json:"email"`
	EventCount  int64   `json:"event_count"`
	FailureRate float64 `json:"failure_rate_percent"`
	RiskScore   int     `json:"risk_score"`
}

type AuditSecuritySummary struct {
	SecurityEvents      int64 `json:"security_events"`
	FailedLogins        int64 `json:"failed_logins"`
	BlockedAttempts     int64 `json:"blocked_attempts"`
	SuspiciousActivity  int64 `json:"suspicious_activity"`
	CompromisedAccounts int64 `json:"compromised_accounts"`
	MFABypass           int64 `json:"mfa_bypass_attempts"`
}

type AuditTrend struct {
	Date           time.Time `json:"date"`
	Events         int64     `json:"events"`
	Failures       int64     `json:"failures"`
	HighRisk       int64     `json:"high_risk"`
	SecurityEvents int64     `json:"security_events"`
}

// Feature Management Models

type FeatureFlagListResponse struct {
	Features   []FeatureFlag  `json:"features"`
	Pagination *Pagination    `json:"pagination"`
	Summary    FeatureSummary `json:"summary"`
}

type FeatureFlag struct {
	Base
	Name         string             `json:"name"`
	Key          string             `json:"key"`
	Description  string             `json:"description"`
	Enabled      bool               `json:"enabled"`
	Type         string             `json:"type"` // boolean, string, number, json
	DefaultValue interface{}        `json:"default_value"`
	Variations   []FeatureVariation `json:"variations,omitempty"`
	Rules        []FeatureRule      `json:"rules,omitempty"`
	Tags         []string           `json:"tags,omitempty"`
	Environment  string             `json:"environment"`
	Rollout      *FeatureRollout    `json:"rollout,omitempty"`
	Targeting    *FeatureTargeting  `json:"targeting,omitempty"`
	Analytics    *FeatureAnalytics  `json:"analytics,omitempty"`
	LastModified time.Time          `json:"last_modified"`
	ModifiedBy   xid.ID             `json:"modified_by"`
}

type FeatureVariation struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Value       interface{} `json:"value"`
	Description string      `json:"description,omitempty"`
	Weight      float64     `json:"weight,omitempty"`
}

type FeatureRule struct {
	ID          string             `json:"id"`
	Description string             `json:"description,omitempty"`
	Conditions  []FeatureCondition `json:"conditions"`
	Variation   string             `json:"variation"`
	Enabled     bool               `json:"enabled"`
}

type FeatureCondition struct {
	Attribute string      `json:"attribute"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
}

type FeatureRollout struct {
	Type       string   `json:"type"` // percentage, user_list, organization_list
	Percentage float64  `json:"percentage,omitempty"`
	UserIDs    []xid.ID `json:"userIds,omitempty"`
	OrgIDs     []xid.ID `json:"org_ids,omitempty"`
}

type FeatureTargeting struct {
	Enabled     bool                   `json:"enabled"`
	Rules       []FeatureTargetingRule `json:"rules"`
	Fallthrough *FeatureVariation      `json:"fallthrough"`
}

type FeatureTargetingRule struct {
	ID        string          `json:"id"`
	Clauses   []FeatureClause `json:"clauses"`
	Variation string          `json:"variation"`
	Rollout   *FeatureRollout `json:"rollout,omitempty"`
}

type FeatureClause struct {
	Attribute string        `json:"attribute"`
	Op        string        `json:"op"`
	Values    []interface{} `json:"values"`
	Negate    bool          `json:"negate,omitempty"`
}

type FeatureAnalytics struct {
	Usage          int64                   `json:"usage"`
	LastEvaluated  *time.Time              `json:"last_evaluated,omitempty"`
	Evaluations    int64                   `json:"evaluations"`
	VariationStats []FeatureVariationStats `json:"variation_stats"`
}

type FeatureVariationStats struct {
	VariationID string  `json:"variation_id"`
	Count       int64   `json:"count"`
	Percentage  float64 `json:"percentage"`
}

type FeatureUsageReport struct {
	Period      string                `json:"period"`
	GeneratedAt time.Time             `json:"generated_at"`
	Summary     FeatureUsageSummary   `json:"summary"`
	Features    []FeatureUsageDetail  `json:"features"`
	Trends      []FeatureUsageTrend   `json:"trends"`
	TopFeatures []FeatureUsageRanking `json:"top_features"`
}

type FeatureUsageSummary struct {
	TotalFeatures    int   `json:"total_features"`
	ActiveFeatures   int   `json:"active_features"`
	TotalEvaluations int64 `json:"total_evaluations"`
	Organizations    int   `json:"organizations"`
	Users            int   `json:"users"`
}

type FeatureUsageDetail struct {
	FeatureKey     string     `json:"feature_key"`
	Name           string     `json:"name"`
	Evaluations    int64      `json:"evaluations"`
	Organizations  int        `json:"organizations"`
	Users          int        `json:"users"`
	AdoptionRate   float64    `json:"adoption_rate_percent"`
	EnabledPercent float64    `json:"enabled_percent"`
	LastEvaluated  *time.Time `json:"last_evaluated,omitempty"`
}

type FeatureUsageTrend struct {
	Date        time.Time `json:"date"`
	Evaluations int64     `json:"evaluations"`
	Features    int       `json:"active_features"`
	Users       int       `json:"users"`
}

type FeatureUsageRanking struct {
	Rank        int     `json:"rank"`
	FeatureKey  string  `json:"feature_key"`
	Name        string  `json:"name"`
	Evaluations int64   `json:"evaluations"`
	Growth      float64 `json:"growth_percent"`
}

// Billing and Subscription Models

type BillingOverview struct {
	Period        string               `json:"period"`
	GeneratedAt   time.Time            `json:"generated_at"`
	Revenue       BillingRevenue       `json:"revenue"`
	Subscriptions BillingSubscriptions `json:"subscriptions"`
	Usage         BillingUsage         `json:"usage"`
	Forecasting   BillingForecast      `json:"forecasting"`
	PaymentHealth BillingPaymentHealth `json:"payment_health"`
}

type BillingRevenue struct {
	Total      float64 `json:"total"`
	Recurring  float64 `json:"recurring"`
	OneTime    float64 `json:"one_time"`
	Pending    float64 `json:"pending"`
	Refunded   float64 `json:"refunded"`
	GrowthRate float64 `json:"growth_rate_percent"`
	ARPU       float64 `json:"arpu"`
	ARPPU      float64 `json:"arppu"`
}

type BillingSubscriptions struct {
	Active         int     `json:"active"`
	Trial          int     `json:"trial"`
	Canceled       int     `json:"canceled"`
	PastDue        int     `json:"past_due"`
	ChurnRate      float64 `json:"churn_rate_percent"`
	GrowthRate     float64 `json:"growth_rate_percent"`
	ConversionRate float64 `json:"conversion_rate_percent"`
}

type BillingUsage struct {
	APIRequests    int64   `json:"api_requests"`
	StorageUsed    int64   `json:"storage_used_bytes"`
	BandwidthUsed  int64   `json:"bandwidth_used_bytes"`
	UsersProcessed int     `json:"users_processed"`
	OverageCharges float64 `json:"overage_charges"`
}

type BillingForecast struct {
	NextMonth   ForecastPeriod `json:"next_month"`
	NextQuarter ForecastPeriod `json:"next_quarter"`
	NextYear    ForecastPeriod `json:"next_year"`
	Confidence  float64        `json:"confidence_percent"`
	Assumptions []string       `json:"assumptions"`
}

type ForecastPeriod struct {
	Revenue       float64 `json:"revenue"`
	Subscriptions int     `json:"subscriptions"`
	Churn         float64 `json:"churn_rate_percent"`
	Growth        float64 `json:"growth_rate_percent"`
}

type BillingPaymentHealth struct {
	SuccessRate      float64              `json:"success_rate_percent"`
	FailedPayments   int                  `json:"failed_payments"`
	DunningProcess   int                  `json:"in_dunning_process"`
	RecoveredRevenue float64              `json:"recovered_revenue"`
	AvgRecoveryTime  int                  `json:"avg_recovery_time_days"`
	PaymentMethods   []PaymentMethodStats `json:"payment_methods"`
}

type PaymentMethodStats struct {
	Method      string  `json:"method"`
	Usage       int     `json:"usage"`
	SuccessRate float64 `json:"success_rate_percent"`
	Revenue     float64 `json:"revenue"`
}

type SubscriptionListResponse struct {
	Subscriptions []SubscriptionSummary `json:"subscriptions"`
	Pagination    *Pagination           `json:"pagination"`
	Summary       SubscriptionStats     `json:"summary"`
}

type SubscriptionSummary struct {
	ID                 xid.ID     `json:"id"`
	OrganizationID     xid.ID     `json:"organization_id"`
	OrganizationName   string     `json:"organization_name"`
	Plan               string     `json:"plan"`
	Status             string     `json:"status"`
	Amount             float64    `json:"amount"`
	Currency           string     `json:"currency"`
	BillingCycle       string     `json:"billing_cycle"`
	CurrentPeriodStart time.Time  `json:"current_period_start"`
	CurrentPeriodEnd   time.Time  `json:"current_period_end"`
	CreatedAt          time.Time  `json:"created_at"`
	TrialEnd           *time.Time `json:"trial_end,omitempty"`
	CancelAt           *time.Time `json:"cancel_at,omitempty"`
}

type SubscriptionStats struct {
	Total        int     `json:"total"`
	Active       int     `json:"active"`
	Trial        int     `json:"trial"`
	Canceled     int     `json:"canceled"`
	PastDue      int     `json:"past_due"`
	TotalRevenue float64 `json:"total_revenue"`
}

type SubscriptionDetails struct {
	Subscription   SubscriptionSummary `json:"subscription"`
	Organization   OrganizationSummary `json:"organization"`
	Usage          SubscriptionUsage   `json:"usage"`
	Billing        SubscriptionBilling `json:"billing"`
	PaymentHistory []PaymentRecord     `json:"payment_history"`
	Invoices       []InvoiceSummary    `json:"invoices"`
	Events         []SubscriptionEvent `json:"events"`
}

type SubscriptionUsage struct {
	CurrentPeriod  UsagePeriod    `json:"current_period"`
	PreviousPeriod UsagePeriod    `json:"previous_period"`
	Limits         UsageLimits    `json:"limits"`
	Overages       []UsageOverage `json:"overages"`
}

type UsagePeriod struct {
	APIRequests   int64 `json:"api_requests"`
	StorageUsed   int64 `json:"storage_used_bytes"`
	BandwidthUsed int64 `json:"bandwidth_used_bytes"`
	ActiveUsers   int   `json:"active_users"`
	ExternalUsers int   `json:"external_users"`
	EndUsers      int   `json:"end_users"`
}

type UsageLimits struct {
	APIRequests   int64 `json:"api_requests"`
	Storage       int64 `json:"storage_bytes"`
	Bandwidth     int64 `json:"bandwidth_bytes"`
	ExternalUsers int   `json:"external_users"`
	EndUsers      int   `json:"end_users"`
}

type UsageOverage struct {
	Resource string  `json:"resource"`
	Used     int64   `json:"used"`
	Limit    int64   `json:"limit"`
	Overage  int64   `json:"overage"`
	Charge   float64 `json:"charge"`
}

type SubscriptionBilling struct {
	Amount        float64       `json:"amount"`
	Currency      string        `json:"currency"`
	BillingCycle  string        `json:"billing_cycle"`
	NextBilling   time.Time     `json:"next_billing"`
	PaymentMethod PaymentMethod `json:"payment_method"`
	Tax           TaxInfo       `json:"tax"`
	Discounts     []Discount    `json:"discounts"`
}

type TaxInfo struct {
	Rate    float64 `json:"rate"`
	Amount  float64 `json:"amount"`
	Country string  `json:"country"`
	Region  string  `json:"region,omitempty"`
}

type Discount struct {
	Code       string     `json:"code"`
	Type       string     `json:"type"` // percentage, fixed
	Value      float64    `json:"value"`
	Amount     float64    `json:"amount"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`
}

type PaymentRecord struct {
	ID            xid.ID     `json:"id"`
	Amount        float64    `json:"amount"`
	Currency      string     `json:"currency"`
	Status        string     `json:"status"`
	Method        string     `json:"method"`
	ProcessedAt   time.Time  `json:"processed_at"`
	FailureReason string     `json:"failure_reason,omitempty"`
	RefundedAt    *time.Time `json:"refunded_at,omitempty"`
	RefundAmount  float64    `json:"refund_amount,omitempty"`
}

type InvoiceSummary struct {
	ID          xid.ID     `json:"id"`
	Number      string     `json:"number"`
	Amount      float64    `json:"amount"`
	Currency    string     `json:"currency"`
	Status      string     `json:"status"`
	IssuedAt    time.Time  `json:"issued_at"`
	DueAt       time.Time  `json:"due_at"`
	PaidAt      *time.Time `json:"paid_at,omitempty"`
	DownloadURL string     `json:"download_url"`
}

type SubscriptionEvent struct {
	ID          xid.ID                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	CreatedBy   *xid.ID                `json:"created_by,omitempty"`
}

type RevenueReport struct {
	Period      string           `json:"period"`
	GeneratedAt time.Time        `json:"generated_at"`
	Format      string           `json:"format"`
	Overview    RevenueOverview  `json:"overview"`
	Breakdown   RevenueBreakdown `json:"breakdown"`
	Trends      []RevenueTrend   `json:"trends"`
	Forecasting RevenueForecast  `json:"forecasting"`
	Export      *RevenueExport   `json:"export,omitempty"`
}

type RevenueTrend struct {
	Date       time.Time `json:"date"`
	Revenue    float64   `json:"revenue"`
	Recurring  float64   `json:"recurring"`
	OneTime    float64   `json:"one_time"`
	Refunds    float64   `json:"refunds"`
	NetRevenue float64   `json:"net_revenue"`
}

type RevenueExport struct {
	Format    string    `json:"format"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
	FileSize  int64     `json:"file_size_bytes"`
}

// Security Models

type SecurityDashboard struct {
	GeneratedAt     time.Time                 `json:"generated_at"`
	ThreatLevel     string                    `json:"threat_level"` // low, medium, high, critical
	Overview        SecurityOverview          `json:"overview"`
	Threats         []ThreatSummary           `json:"threats"`
	Vulnerabilities []VulnerabilitySummary    `json:"vulnerabilities"`
	Incidents       []SecurityIncidentSummary `json:"recent_incidents"`
	Compliance      SecurityCompliance        `json:"compliance"`
	Recommendations []SecurityRecommendation  `json:"recommendations"`
}

type SecurityOverview struct {
	SecurityScore       int   `json:"security_score"` // 0-100
	ActiveThreats       int   `json:"active_threats"`
	ResolvedThreats     int   `json:"resolved_threats"`
	Vulnerabilities     int   `json:"vulnerabilities"`
	FailedLogins        int64 `json:"failed_logins"`
	SuspiciousActivity  int64 `json:"suspicious_activity"`
	CompromisedAccounts int   `json:"compromised_accounts"`
}

type ThreatSummary struct {
	ID          xid.ID    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Occurrences int       `json:"occurrences"`
}

type VulnerabilitySummary struct {
	ID           xid.ID     `json:"id"`
	CVE          string     `json:"cve,omitempty"`
	Title        string     `json:"title"`
	Severity     string     `json:"severity"`
	CVSS         float64    `json:"cvss_score,omitempty"`
	Component    string     `json:"component"`
	Status       string     `json:"status"`
	DiscoveredAt time.Time  `json:"discovered_at"`
	FixedAt      *time.Time `json:"fixed_at,omitempty"`
}

type SecurityIncidentSummary struct {
	ID         xid.ID     `json:"id"`
	Title      string     `json:"title"`
	Severity   string     `json:"severity"`
	Status     string     `json:"status"`
	Type       string     `json:"type"`
	Assignee   *xid.ID    `json:"assignee,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	Duration   *int       `json:"duration_minutes,omitempty"`
}

type SecurityCompliance struct {
	SOC2     PlatformComplianceStatus `json:"soc2"`
	HIPAA    PlatformComplianceStatus `json:"hipaa"`
	GDPR     PlatformComplianceStatus `json:"gdpr"`
	ISO27001 PlatformComplianceStatus `json:"iso27001"`
	PCI      PlatformComplianceStatus `json:"pci"`
	Overall  PlatformComplianceStatus `json:"overall"`
}

type PlatformComplianceStatus struct {
	Status     string     `json:"status"` // compliant, non_compliant, partial
	Score      float64    `json:"score"`
	LastAudit  *time.Time `json:"last_audit,omitempty"`
	NextAudit  *time.Time `json:"next_audit,omitempty"`
	Issues     int        `json:"issues"`
	Remediated int        `json:"remediated"`
}

type SecurityRecommendation struct {
	ID          xid.ID     `json:"id"`
	Priority    string     `json:"priority"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Impact      string     `json:"impact"`
	Effort      string     `json:"effort"`
	Category    string     `json:"category"`
	DueDate     *time.Time `json:"due_date,omitempty"`
	Status      string     `json:"status"`
}

type SecurityIncidentListResponse struct {
	Incidents  []SecurityIncident    `json:"incidents"`
	Pagination *Pagination           `json:"pagination"`
	Summary    SecurityIncidentStats `json:"summary"`
}

type SecurityIncident struct {
	Base
	Title         string                  `json:"title"`
	Description   string                  `json:"description"`
	Severity      string                  `json:"severity"`
	Status        string                  `json:"status"`
	Type          string                  `json:"type"`
	Source        string                  `json:"source"`
	Assignee      *xid.ID                 `json:"assignee,omitempty"`
	Reporter      xid.ID                  `json:"reporter"`
	AffectedUsers []xid.ID                `json:"affected_users,omitempty"`
	AffectedOrgs  []xid.ID                `json:"affected_orgs,omitempty"`
	Timeline      []SecurityIncidentEvent `json:"timeline"`
	Evidence      []SecurityEvidence      `json:"evidence,omitempty"`
	Remediation   *SecurityRemediation    `json:"remediation,omitempty"`
	ResolvedAt    *time.Time              `json:"resolved_at,omitempty"`
	Duration      *int                    `json:"duration_minutes,omitempty"`
	Tags          []string                `json:"tags,omitempty"`
}

type SecurityIncidentEvent struct {
	ID          xid.ID                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	UserID      *xid.ID                `json:"userId,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type SecurityEvidence struct {
	ID          xid.ID    `json:"id"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	URL         string    `json:"url,omitempty"`
	Hash        string    `json:"hash,omitempty"`
	CollectedAt time.Time `json:"collected_at"`
	CollectedBy xid.ID    `json:"collected_by"`
}

type SecurityRemediation struct {
	Steps       []RemediationStep `json:"steps"`
	Status      string            `json:"status"`
	StartedAt   *time.Time        `json:"started_at,omitempty"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	Notes       string            `json:"notes,omitempty"`
}

type RemediationStep struct {
	ID          xid.ID     `json:"id"`
	Description string     `json:"description"`
	Status      string     `json:"status"`
	AssignedTo  *xid.ID    `json:"assigned_to,omitempty"`
	DueDate     *time.Time `json:"due_date,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Notes       string     `json:"notes,omitempty"`
}

type SecurityIncidentStats struct {
	Total      int `json:"total"`
	Open       int `json:"open"`
	InProgress int `json:"in_progress"`
	Resolved   int `json:"resolved"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
}

type ComplianceReport struct {
	GeneratedAt     time.Time                  `json:"generated_at"`
	ReportType      string                     `json:"report_type"`
	Period          string                     `json:"period"`
	Framework       string                     `json:"framework"`
	Status          string                     `json:"status"`
	Score           float64                    `json:"score"`
	Overview        PlatformComplianceOverview `json:"overview"`
	Controls        []ComplianceControl        `json:"controls"`
	Findings        []ComplianceFinding        `json:"findings"`
	Recommendations []ComplianceRecommendation `json:"recommendations"`
	Evidence        []ComplianceEvidence       `json:"evidence"`
	Attestation     *ComplianceAttestation     `json:"attestation,omitempty"`
}

type PlatformComplianceOverview struct {
	TotalControls        int       `json:"total_controls"`
	CompliantControls    int       `json:"compliant_controls"`
	NonCompliantControls int       `json:"non_compliant_controls"`
	PartialControls      int       `json:"partial_controls"`
	ComplianceScore      float64   `json:"compliance_score"`
	LastAssessment       time.Time `json:"last_assessment"`
	NextAssessment       time.Time `json:"next_assessment"`
}

type ComplianceControl struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Status      string                 `json:"status"`
	Evidence    []string               `json:"evidence"`
	LastTested  time.Time              `json:"last_tested"`
	NextTest    time.Time              `json:"next_test"`
	Owner       string                 `json:"owner"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type ComplianceFinding struct {
	ID          xid.ID     `json:"id"`
	ControlID   string     `json:"control_id"`
	Severity    string     `json:"severity"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Impact      string     `json:"impact"`
	Status      string     `json:"status"`
	FoundAt     time.Time  `json:"found_at"`
	DueDate     time.Time  `json:"due_date"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
	Assignee    *xid.ID    `json:"assignee,omitempty"`
}

type ComplianceRecommendation struct {
	ID          xid.ID    `json:"id"`
	Priority    string    `json:"priority"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	ControlID   string    `json:"control_id"`
	Impact      string    `json:"impact"`
	Effort      string    `json:"effort"`
	DueDate     time.Time `json:"due_date"`
	Status      string    `json:"status"`
}

type ComplianceEvidence struct {
	ID          xid.ID    `json:"id"`
	ControlID   string    `json:"control_id"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	URL         string    `json:"url,omitempty"`
	CollectedAt time.Time `json:"collected_at"`
	ValidUntil  time.Time `json:"valid_until"`
}

type ComplianceAttestation struct {
	AttestedBy xid.ID    `json:"attested_by"`
	AttestedAt time.Time `json:"attested_at"`
	ValidUntil time.Time `json:"valid_until"`
	Signature  string    `json:"signature"`
	Comments   string    `json:"comments,omitempty"`
}

type SecurityScanRequest struct {
	Type        string                 `json:"type"` // vulnerability, compliance, penetration
	Scope       []string               `json:"scope,omitempty"`
	Depth       string                 `json:"depth"` // basic, standard, comprehensive
	Schedule    *time.Time             `json:"schedule,omitempty"`
	NotifyUsers []xid.ID               `json:"notify_users,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
}

type SecurityScanResponse struct {
	ScanID            xid.ID    `json:"scan_id"`
	Type              string    `json:"type"`
	Status            string    `json:"status"`
	StartedAt         time.Time `json:"started_at"`
	EstimatedDuration int       `json:"estimated_duration_minutes"`
	Progress          int       `json:"progress_percent"`
	Message           string    `json:"message"`
	ResultsURL        string    `json:"results_url,omitempty"`
}

// Request/Response Models for Operations

type SuspendOrganizationRequest struct {
	Reason      string     `json:"reason"`
	NotifyUsers bool       `json:"notify_users"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type ActivateOrganizationRequest struct {
	Reason string `json:"reason,omitempty"`
}

type ImpersonateUserRequest struct {
	AdminUserID xid.ID `json:"adminUserId"`
	Reason      string `json:"reason"`
	Duration    int    `json:"duration_minutes,omitempty"`
}

type ImpersonationResponse struct {
	Success          bool       `json:"success"`
	ImpersonationID  xid.ID     `json:"impersonationId"`
	ExpiresAt        *time.Time `json:"expiresAt,omitempty"`
	OriginalUserID   xid.ID     `json:"originalUserId"`
	ImpersonatedUser xid.ID     `json:"impersonatedUserId"`
	ImpersonationURL string     `json:"impersonationUrl"`
}

type BlockUserRequest struct {
	Reason string `json:"reason"`
}

type UnblockUserRequest struct {
	Reason string `json:"reason"`
}

type ResetUserPasswordRequest struct {
	NotifyUser        bool `json:"notify_user"`
	GenerateTemporary bool `json:"generate_temporary"`
	RequireChange     bool `json:"require_change"`
}

type ResetUserPasswordResponse struct {
	Success      bool       `json:"success"`
	ResetToken   string     `json:"reset_token,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	NotifyUser   bool       `json:"notify_user"`
	TemporaryPwd bool       `json:"temporary_password_generated"`
}

type UserSessionListResponse struct {
	Sessions []Session `json:"sessions"`
	Total    int       `json:"total"`
	Active   int       `json:"active"`
}

type RevokeUserSessionsRequest struct {
	Reason     string `json:"reason"`
	NotifyUser bool   `json:"notify_user"`
}

type RevokeUserSessionsResponse struct {
	Success         bool   `json:"success"`
	SessionsRevoked int    `json:"sessions_revoked"`
	Reason          string `json:"reason"`
	NotifyUser      bool   `json:"notify_user"`
}

type CreateFeatureFlagRequest struct {
	Name         string             `json:"name"`
	Key          string             `json:"key"`
	Description  string             `json:"description,omitempty"`
	Type         string             `json:"type"`
	DefaultValue interface{}        `json:"default_value"`
	Variations   []FeatureVariation `json:"variations,omitempty"`
	Environment  string             `json:"environment"`
	Tags         []string           `json:"tags,omitempty"`
}

type UpdateFeatureFlagRequest struct {
	Name         *string            `json:"name,omitempty"`
	Description  *string            `json:"description,omitempty"`
	Enabled      *bool              `json:"enabled,omitempty"`
	DefaultValue interface{}        `json:"default_value,omitempty"`
	Variations   []FeatureVariation `json:"variations,omitempty"`
	Rules        []FeatureRule      `json:"rules,omitempty"`
	Rollout      *FeatureRollout    `json:"rollout,omitempty"`
	Tags         []string           `json:"tags,omitempty"`
}

type UpdateSubscriptionRequest struct {
	Plan       *string                `json:"plan,omitempty"`
	Status     *string                `json:"status,omitempty"`
	PauseUntil *time.Time             `json:"pause_until,omitempty"`
	CancelAt   *time.Time             `json:"cancel_at,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type CancelSubscriptionRequest struct {
	Reason     string     `json:"reason"`
	CancelAt   *time.Time `json:"cancel_at,omitempty"` // immediate if nil
	Prorate    bool       `json:"prorate"`
	NotifyUser bool       `json:"notify_user"`
}

type RevokeAPIKeyRequest struct {
	Reason string `json:"reason"`
}

type ScheduleMaintenanceRequest struct {
	Title            string    `json:"title"`
	Description      string    `json:"description"`
	StartTime        time.Time `json:"start_time"`
	EndTime          time.Time `json:"end_time"`
	AffectedServices []string  `json:"affected_services"`
	NotifyUsers      bool      `json:"notify_users"`
	NotifyOrgs       []xid.ID  `json:"notify_orgs,omitempty"`
}

type PlatformNotificationRequest struct {
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Type        string                 `json:"type"` // info, warning, critical, maintenance
	Recipients  NotificationRecipients `json:"recipients"`
	Channels    []string               `json:"channels"` // email, in_app, sms
	ScheduleFor *time.Time             `json:"schedule_for,omitempty"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
}

type NotificationRecipients struct {
	All           bool     `json:"all,omitempty"`
	Organizations []xid.ID `json:"organizations,omitempty"`
	Users         []xid.ID `json:"users,omitempty"`
	UserTypes     []string `json:"user_types,omitempty"`
	Plans         []string `json:"plans,omitempty"`
}

type PlatformNotificationResponse struct {
	NotificationID xid.ID     `json:"notification_id"`
	Status         string     `json:"status"`
	Recipients     int        `json:"recipients"`
	ScheduledFor   *time.Time `json:"scheduled_for,omitempty"`
	SentAt         *time.Time `json:"sent_at,omitempty"`
}

// Additional Response Models

type AuditTrailResponse struct {
	AuditLogs  []AuditLogSummary      `json:"audit_logs"`
	Pagination *Pagination            `json:"pagination"`
	Filters    map[string]interface{} `json:"applied_filters"`
}

type APIUsageReport struct {
	Period      string           `json:"period"`
	GeneratedAt time.Time        `json:"generated_at"`
	Overview    APIUsageOverview `json:"overview"`
	ByOrg       []OrgAPIUsage    `json:"by_organization"`
	ByEndpoint  []EndpointUsage  `json:"by_endpoint"`
	Trends      []APIUsageTrend  `json:"trends"`
	Errors      APIErrorAnalysis `json:"errors"`
}

type APIUsageOverview struct {
	TotalRequests      int64   `json:"total_requests"`
	TotalOrganizations int     `json:"total_organizations"`
	TotalAPIKeys       int     `json:"total_api_keys"`
	AvgResponseTime    float64 `json:"avg_response_time_ms"`
	ErrorRate          float64 `json:"error_rate_percent"`
	Growth             float64 `json:"growth_percent"`
}

type OrgAPIUsage struct {
	OrganizationID   xid.ID  `json:"organization_id"`
	OrganizationName string  `json:"organization_name"`
	Requests         int64   `json:"requests"`
	ErrorRate        float64 `json:"error_rate_percent"`
	AvgResponseTime  float64 `json:"avg_response_time_ms"`
	Plan             string  `json:"plan"`
	UsagePercent     float64 `json:"usage_percent_of_limit"`
}

type APIUsageTrend struct {
	Date     time.Time `json:"date"`
	Requests int64     `json:"requests"`
	Errors   int64     `json:"errors"`
	Latency  float64   `json:"avg_latency_ms"`
}

type APIKeyListPlatformResponse struct {
	APIKeys    []APIKeySummary `json:"api_keys"`
	Pagination *Pagination     `json:"pagination"`
	Summary    APIKeyStats     `json:"summary"`
}

type APIKeySummaryPlatform struct {
	ID               xid.ID     `json:"id"`
	Name             string     `json:"name"`
	OrganizationID   xid.ID     `json:"organization_id"`
	OrganizationName string     `json:"organization_name"`
	Status           string     `json:"status"`
	LastUsed         *time.Time `json:"last_used,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RequestCount     int64      `json:"request_count"`
	ErrorCount       int64      `json:"error_count"`
}

type APIKeyStatsPlatform struct {
	Total   int `json:"total"`
	Active  int `json:"active"`
	Expired int `json:"expired"`
	Revoked int `json:"revoked"`
}

type RateLimitStats struct {
	Period      string               `json:"period"`
	GeneratedAt time.Time            `json:"generated_at"`
	Overview    RateLimitOverview    `json:"overview"`
	ByOrg       []OrgRateLimitStats  `json:"by_organization"`
	ByEndpoint  []EndpointRateLimits `json:"by_endpoint"`
	Violations  []RateLimitViolation `json:"recent_violations"`
}

type RateLimitOverview struct {
	TotalRequests   int64   `json:"total_requests"`
	LimitedRequests int64   `json:"limited_requests"`
	LimitedPercent  float64 `json:"limited_percent"`
	TopViolators    int     `json:"top_violators"`
}

type OrgRateLimitStats struct {
	OrganizationID   xid.ID  `json:"organization_id"`
	OrganizationName string  `json:"organization_name"`
	Requests         int64   `json:"requests"`
	Limited          int64   `json:"limited"`
	LimitedPercent   float64 `json:"limited_percent"`
	Plan             string  `json:"plan"`
	Limit            int     `json:"rate_limit"`
}

type EndpointRateLimits struct {
	Endpoint       string  `json:"endpoint"`
	Method         string  `json:"method"`
	Requests       int64   `json:"requests"`
	Limited        int64   `json:"limited"`
	LimitedPercent float64 `json:"limited_percent"`
	Limit          int     `json:"rate_limit"`
}

type RateLimitViolation struct {
	ID             xid.ID    `json:"id"`
	OrganizationID xid.ID    `json:"organization_id"`
	APIKeyID       xid.ID    `json:"api_key_id"`
	Endpoint       string    `json:"endpoint"`
	Method         string    `json:"method"`
	IPAddress      string    `json:"ip_address"`
	Timestamp      time.Time `json:"timestamp"`
	RequestCount   int       `json:"request_count"`
	Limit          int       `json:"limit"`
	Window         string    `json:"window"`
}

type SupportTicketListResponse struct {
	Tickets    []SupportTicketSummary `json:"tickets"`
	Pagination *Pagination            `json:"pagination"`
	Summary    SupportTicketStats     `json:"summary"`
}

type SupportTicketSummary struct {
	ID             xid.ID     `json:"id"`
	Subject        string     `json:"subject"`
	Status         string     `json:"status"`
	Priority       string     `json:"priority"`
	OrganizationID *xid.ID    `json:"organizationId,omitempty"`
	UserID         xid.ID     `json:"userId"`
	UserEmail      string     `json:"user_email"`
	AssigneeID     *xid.ID    `json:"assigneeId,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
	ResolvedAt     *time.Time `json:"resolvedAt,omitempty"`
	ResponseTime   *int       `json:"responseTimeHours,omitempty"`
	ResolutionTime *int       `json:"resolutionTimeHours,omitempty"`
}

type SupportTicketStats struct {
	Total             int     `json:"total"`
	Open              int     `json:"open"`
	InProgress        int     `json:"in_progress"`
	Resolved          int     `json:"resolved"`
	AvgResponseTime   int     `json:"avgResponseTimeHours"`
	AvgResolutionTime int     `json:"avgResolutionTimeHours"`
	SatisfactionScore float64 `json:"satisfactionScore"`
}

type MaintenanceWindowListResponse struct {
	MaintenanceWindows []MaintenanceWindow `json:"maintenanceWindows"`
	Pagination         *Pagination         `json:"pagination"`
	Summary            MaintenanceStats    `json:"summary"`
}

type MaintenanceWindow struct {
	Base
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	Status           string     `json:"status"` // scheduled, in_progress, completed, canceled
	StartTime        time.Time  `json:"start_time"`
	EndTime          time.Time  `json:"end_time"`
	ActualStartTime  *time.Time `json:"actual_start_time,omitempty"`
	ActualEndTime    *time.Time `json:"actual_end_time,omitempty"`
	AffectedServices []string   `json:"affected_services"`
	Impact           string     `json:"impact"` // low, medium, high
	NotificationSent bool       `json:"notification_sent"`
	NotifiedUsers    int        `json:"notified_users"`
	CreatedBy        xid.ID     `json:"created_by"`
	UpdatedBy        *xid.ID    `json:"updated_by,omitempty"`
}

type MaintenanceStats struct {
	Total           int        `json:"total"`
	Scheduled       int        `json:"scheduled"`
	InProgress      int        `json:"in_progress"`
	Completed       int        `json:"completed"`
	Canceled        int        `json:"canceled"`
	AvgDuration     int        `json:"avg_duration_minutes"`
	NextMaintenance *time.Time `json:"next_maintenance,omitempty"`
}

// Security Summary Models for User/Organization Details

type SecuritySummary struct {
	SecurityScore    int                     `json:"security_score"`
	LastSecurityScan *time.Time              `json:"last_security_scan,omitempty"`
	Vulnerabilities  VulnerabilityCount      `json:"vulnerabilities"`
	Incidents        SecurityIncidentCount   `json:"incidents"`
	Compliance       SecurityComplianceScore `json:"compliance"`
	Recommendations  int                     `json:"open_recommendations"`
}

type VulnerabilityCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

type SecurityIncidentCount struct {
	Open     int `json:"open"`
	Resolved int `json:"resolved"`
	Total    int `json:"total"`
}

type SecurityComplianceScore struct {
	SOC2    float64 `json:"soc2"`
	HIPAA   float64 `json:"hipaa"`
	GDPR    float64 `json:"gdpr"`
	Overall float64 `json:"overall"`
}
