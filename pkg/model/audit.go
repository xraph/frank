package model

import (
	"time"

	"github.com/rs/xid"
)

// AuditLog represents an audit log entry
type AuditLog struct {
	Base
	OrganizationID *xid.ID                `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	UserID         *xid.ID                `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID who performed the action"`
	SessionID      *xid.ID                `json:"sessionId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Session ID"`
	Action         string                 `json:"action" example:"user.login" doc:"Action performed"`
	Resource       string                 `json:"resource,omitempty" example:"user" doc:"Resource affected"`
	ResourceID     *xid.ID                `json:"resourceId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"ID of affected resource"`
	Status         string                 `json:"status" example:"success" doc:"Action status (success, failure, error)"`
	IPAddress      string                 `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address"`
	UserAgent      string                 `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent"`
	Location       string                 `json:"location,omitempty" example:"New York, NY" doc:"Geographic location"`
	Details        map[string]interface{} `json:"details,omitempty" doc:"Additional action details"`
	Changes        map[string]interface{} `json:"changes,omitempty" doc:"Changed fields (before/after)"`
	Error          string                 `json:"error,omitempty" example:"Invalid credentials" doc:"Error message if failed"`
	Duration       int                    `json:"duration,omitempty" example:"250" doc:"Action duration in milliseconds"`
	RiskLevel      string                 `json:"riskLevel" example:"low" doc:"Risk level (low, medium, high, critical)"`
	Tags           []string               `json:"tags,omitempty" example:"[\"auth\", \"security\"]" doc:"Audit tags for categorization"`
	Source         string                 `json:"source,omitempty" example:"web" doc:"Source of the action (web, api, mobile, system)"`
	Timestamp      time.Time              `json:"timestamp" example:"2023-01-01T12:00:00Z" doc:"Action timestamp"`

	// Relationships
	User         *UserSummary         `json:"user,omitempty" doc:"User information"`
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
}

// AuditLogSummary represents a simplified audit log for listings
type AuditLogSummary struct {
	ID        xid.ID    `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Audit log ID"`
	Action    string    `json:"action" example:"user.login" doc:"Action performed"`
	Resource  string    `json:"resource,omitempty" example:"user" doc:"Resource affected"`
	Status    string    `json:"status" example:"success" doc:"Action status"`
	UserEmail string    `json:"userEmail,omitempty" example:"user@example.com" doc:"User email"`
	IPAddress string    `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address"`
	RiskLevel string    `json:"riskLevel" example:"low" doc:"Risk level"`
	Timestamp time.Time `json:"timestamp" example:"2023-01-01T12:00:00Z" doc:"Action timestamp"`
	Duration  int       `json:"duration,omitempty" example:"250" doc:"Duration in milliseconds"`
}

// CreateAuditLogRequest represents a request to create an audit log entry
type CreateAuditLogRequest struct {
	OrganizationID *xid.ID                `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	UserID         *xid.ID                `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	SessionID      *xid.ID                `json:"sessionId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Session ID"`
	Action         string                 `json:"action" example:"user.login" doc:"Action performed"`
	Resource       string                 `json:"resource,omitempty" example:"user" doc:"Resource affected"`
	ResourceID     *xid.ID                `json:"resourceId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Resource ID"`
	Status         string                 `json:"status" example:"success" doc:"Action status"`
	IPAddress      *string                `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address"`
	UserAgent      *string                `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent"`
	Location       *string                `json:"location,omitempty" example:"New York, NY" doc:"Location"`
	Details        map[string]interface{} `json:"details,omitempty" doc:"Action details"`
	Changes        map[string]interface{} `json:"changes,omitempty" doc:"Changed fields"`
	Error          string                 `json:"error,omitempty" example:"Invalid credentials" doc:"Error message"`
	Duration       int                    `json:"duration,omitempty" example:"250" doc:"Duration in milliseconds"`
	RiskLevel      string                 `json:"riskLevel,omitempty" example:"low" doc:"Risk level"`
	Tags           []string               `json:"tags,omitempty" example:"[\"auth\"]" doc:"Audit tags"`
	Source         string                 `json:"source,omitempty" example:"web" doc:"Action source"`
}

// AuditLogListRequest represents a request to list audit logs
type AuditLogListRequest struct {
	PaginationParams
	OrganizationID OptionalParam[xid.ID]    `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization" query:"organizationId"`
	UserID         OptionalParam[xid.ID]    `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user" query:"userId"`
	Action         string                   `json:"action,omitempty" example:"user.login" doc:"Filter by action" query:"action"`
	Resource       string                   `json:"resource,omitempty" example:"user" doc:"Filter by resource" query:"resource"`
	ResourceID     OptionalParam[xid.ID]    `json:"resourceId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by resource ID" query:"resourceId"`
	Status         string                   `json:"status,omitempty" example:"success" doc:"Filter by status" query:"status"`
	RiskLevel      string                   `json:"riskLevel,omitempty" example:"high" doc:"Filter by risk level" query:"riskLevel"`
	Source         string                   `json:"source,omitempty" example:"web" doc:"Filter by source" query:"source"`
	StartDate      OptionalParam[time.Time] `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"OnStart date" query:"startDate"`
	EndDate        OptionalParam[time.Time] `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date" query:"endDate"`
	IPAddress      string                   `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"Filter by IP address" query:"ipAddress"`
	Search         string                   `json:"search,omitempty" example:"login" doc:"Search in action/details" query:"search"`
	Tags           []string                 `json:"tags,omitempty" example:"[\"auth\", \"security\"]" doc:"Filter by tags" query:"tags"`
	UserEmail      string                   `json:"userEmail,omitempty" example:"user@example.com" doc:"Filter by user email" query:"userEmail"`
}

// AuditLogListResponse represents a list of audit logs
type AuditLogListResponse = PaginatedOutput[AuditLogSummary]

// AuditStats represents audit statistics
type AuditStats struct {
	TotalEvents         int            `json:"totalEvents" example:"50000" doc:"Total audit events"`
	EventsToday         int            `json:"eventsToday" example:"1500" doc:"Events today"`
	EventsWeek          int            `json:"eventsWeek" example:"10500" doc:"Events this week"`
	EventsMonth         int            `json:"eventsMonth" example:"45000" doc:"Events this month"`
	EventsByStatus      map[string]int `json:"eventsByStatus" example:"{\"success\": 45000, \"failure\": 5000}" doc:"Events by status"`
	EventsByAction      map[string]int `json:"eventsByAction" example:"{\"user.login\": 15000, \"user.logout\": 14500}" doc:"Events by action"`
	EventsByResource    map[string]int `json:"eventsByResource" example:"{\"user\": 25000, \"organization\": 5000}" doc:"Events by resource"`
	EventsByRiskLevel   map[string]int `json:"eventsByRiskLevel" example:"{\"low\": 40000, \"medium\": 8000, \"high\": 2000}" doc:"Events by risk level"`
	EventsBySource      map[string]int `json:"eventsBySource" example:"{\"web\": 30000, \"api\": 15000, \"mobile\": 5000}" doc:"Events by source"`
	UniqueUsers         int            `json:"uniqueUsers" example:"2500" doc:"Unique users in audit logs"`
	UniqueIPs           int            `json:"uniqueIps" example:"1200" doc:"Unique IP addresses"`
	FailureRate         float64        `json:"failureRate" example:"10.0" doc:"Failure rate percentage"`
	AverageResponseTime float64        `json:"averageResponseTime" example:"250.5" doc:"Average response time in milliseconds"`
	HighRiskEventsToday int            `json:"highRiskEventsToday" example:"15" doc:"High risk events today"`
	CriticalEventsToday int            `json:"criticalEventsToday" example:"2" doc:"Critical events today"`
}

// AuditAlert represents an audit alert configuration
type AuditAlert struct {
	Base
	AuditBase
	Name           string                 `json:"name" example:"Failed Login Alert" doc:"Alert name"`
	Description    string                 `json:"description,omitempty" example:"Alert for multiple failed logins" doc:"Alert description"`
	OrganizationID *xid.ID                `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Conditions     map[string]interface{} `json:"conditions" doc:"Alert conditions (JSON rules)"`
	Actions        []AlertAction          `json:"actions" doc:"Actions to take when alert triggers"`
	Enabled        bool                   `json:"enabled" example:"true" doc:"Whether alert is enabled"`
	Severity       string                 `json:"severity" example:"high" doc:"Alert severity (low, medium, high, critical)"`
	Cooldown       int                    `json:"cooldown" example:"300" doc:"Cooldown period in seconds"`
	TriggerCount   int                    `json:"triggerCount" example:"5" doc:"Number of events to trigger alert"`
	TimeWindow     int                    `json:"timeWindow" example:"600" doc:"Time window in seconds"`
	LastTriggered  *time.Time             `json:"lastTriggered,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last trigger timestamp"`
	TriggerHistory []AlertTrigger         `json:"triggerHistory,omitempty" doc:"Recent trigger history"`

	// Relationships
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
}

// AlertAction represents an action to take when an alert triggers
type AlertAction struct {
	Type   string                 `json:"type" example:"email" doc:"Action type (email, webhook, slack, sms)"`
	Config map[string]interface{} `json:"config" doc:"Action configuration"`
}

// AlertTrigger represents an alert trigger event
type AlertTrigger struct {
	Timestamp  time.Time              `json:"timestamp" example:"2023-01-01T12:00:00Z" doc:"Trigger timestamp"`
	EventCount int                    `json:"eventCount" example:"7" doc:"Number of events that triggered alert"`
	Details    map[string]interface{} `json:"details,omitempty" doc:"Trigger details"`
	Resolved   bool                   `json:"resolved" example:"false" doc:"Whether alert was resolved"`
	ResolvedAt *time.Time             `json:"resolvedAt,omitempty" example:"2023-01-01T12:30:00Z" doc:"Resolution timestamp"`
}

// CreateAuditAlertRequest represents a request to create an audit alert
type CreateAuditAlertRequest struct {
	Name         string                 `json:"name" example:"Suspicious Activity Alert" doc:"Alert name"`
	Description  string                 `json:"description,omitempty" example:"Alert for suspicious user activity" doc:"Alert description"`
	Conditions   map[string]interface{} `json:"conditions" doc:"Alert conditions"`
	Actions      []AlertAction          `json:"actions" doc:"Alert actions"`
	Severity     string                 `json:"severity" example:"medium" doc:"Alert severity"`
	Cooldown     int                    `json:"cooldown,omitempty" example:"300" doc:"Cooldown period in seconds"`
	TriggerCount int                    `json:"triggerCount" example:"3" doc:"Trigger threshold"`
	TimeWindow   int                    `json:"timeWindow" example:"300" doc:"Time window in seconds"`
}

// UpdateAuditAlertRequest represents a request to update an audit alert
type UpdateAuditAlertRequest struct {
	Name         string                 `json:"name,omitempty" example:"Updated Alert" doc:"Updated name"`
	Description  string                 `json:"description,omitempty" example:"Updated description" doc:"Updated description"`
	Conditions   map[string]interface{} `json:"conditions,omitempty" doc:"Updated conditions"`
	Actions      []AlertAction          `json:"actions,omitempty" doc:"Updated actions"`
	Enabled      bool                   `json:"enabled,omitempty" example:"true" doc:"Updated enabled status"`
	Severity     string                 `json:"severity,omitempty" example:"high" doc:"Updated severity"`
	Cooldown     int                    `json:"cooldown,omitempty" example:"600" doc:"Updated cooldown"`
	TriggerCount int                    `json:"triggerCount,omitempty" example:"5" doc:"Updated trigger count"`
	TimeWindow   int                    `json:"timeWindow,omitempty" example:"900" doc:"Updated time window"`
}

// AuditAlertListRequest represents a request to list audit alerts
type AuditAlertListRequest struct {
	PaginationParams
	OrganizationID OptionalParam[xid.ID] `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization" query:"organizationId"`
	Enabled        OptionalParam[bool]   `json:"enabled,omitempty" example:"true" doc:"Filter by enabled status" query:"enabled"`
	Severity       string                `json:"severity,omitempty" example:"high" doc:"Filter by severity" query:"severity"`
	Search         string                `json:"search,omitempty" example:"login" doc:"Search in name/description" query:"search"`
}

// AuditAlertListResponse represents a list of audit alerts
type AuditAlertListResponse = PaginatedOutput[AuditAlert]

// AuditExportRequest represents a request to export audit logs
type AuditExportRequest struct {
	OrganizationID *xid.ID   `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization"`
	UserID         *xid.ID   `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user"`
	StartDate      time.Time `json:"startDate" example:"2023-01-01T00:00:00Z" doc:"OnStart date"`
	EndDate        time.Time `json:"endDate" example:"2023-01-31T23:59:59Z" doc:"End date"`
	Actions        []string  `json:"actions,omitempty" example:"[\"user.login\", \"user.logout\"]" doc:"Filter by actions"`
	Resources      []string  `json:"resources,omitempty" example:"[\"user\", \"organization\"]" doc:"Filter by resources"`
	Status         string    `json:"status,omitempty" example:"success" doc:"Filter by status"`
	RiskLevel      string    `json:"riskLevel,omitempty" example:"high" doc:"Filter by risk level"`
	Format         string    `json:"format" example:"json" doc:"Export format (json, csv, xlsx)"`
	Compression    string    `json:"compression,omitempty" example:"gzip" doc:"Compression format"`
	IncludeDetails bool      `json:"includeDetails" example:"true" doc:"Include detailed event data"`
}

// AuditExportResponse represents audit export response
type AuditExportResponse struct {
	ExportID    xid.ID     `json:"exportId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Export job ID"`
	Status      string     `json:"status" example:"processing" doc:"Export status"`
	DownloadURL string     `json:"downloadUrl,omitempty" example:"https://api.example.com/downloads/audit-export-123.json" doc:"Download URL when ready"`
	ExpiresAt   time.Time  `json:"expiresAt" example:"2023-01-02T12:00:00Z" doc:"Download URL expiration"`
	RecordCount int        `json:"recordCount,omitempty" example:"5000" doc:"Number of records exported"`
	FileSize    int        `json:"fileSize,omitempty" example:"1048576" doc:"File size in bytes"`
	Format      string     `json:"format" example:"json" doc:"Export format"`
	StartedAt   time.Time  `json:"startedAt" example:"2023-01-01T12:00:00Z" doc:"Export start time"`
	CompletedAt *time.Time `json:"completedAt,omitempty" example:"2023-01-01T12:05:00Z" doc:"Export completion time"`
}

// AuditRetentionSettings represents audit log retention settings
type AuditRetentionSettings struct {
	OrganizationID     xid.ID `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	RetentionDays      int    `json:"retentionDays" example:"365" doc:"Retention period in days"`
	ArchiveEnabled     bool   `json:"archiveEnabled" example:"true" doc:"Whether to archive old logs"`
	ArchiveLocation    string `json:"archiveLocation,omitempty" example:"s3://bucket/audit-archive/" doc:"Archive storage location"`
	CompressionEnabled bool   `json:"compressionEnabled" example:"true" doc:"Whether to compress archived logs"`
	AutoDelete         bool   `json:"autoDelete" example:"false" doc:"Whether to auto-delete after retention period"`
	ComplianceLevel    string `json:"complianceLevel" example:"soc2" doc:"Compliance level (basic, hipaa, soc2, pci)"`
}

// UpdateAuditRetentionRequest represents a request to update retention settings
type UpdateAuditRetentionRequest struct {
	RetentionDays      int    `json:"retentionDays,omitempty" example:"730" doc:"Updated retention days"`
	ArchiveEnabled     bool   `json:"archiveEnabled,omitempty" example:"true" doc:"Updated archive setting"`
	ArchiveLocation    string `json:"archiveLocation,omitempty" example:"s3://new-bucket/" doc:"Updated archive location"`
	CompressionEnabled bool   `json:"compressionEnabled,omitempty" example:"false" doc:"Updated compression setting"`
	AutoDelete         bool   `json:"autoDelete,omitempty" example:"true" doc:"Updated auto-delete setting"`
	ComplianceLevel    string `json:"complianceLevel,omitempty" example:"hipaa" doc:"Updated compliance level"`
}

// AuditComplianceReport represents a compliance report
type AuditComplianceReport struct {
	OrganizationID      xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	ReportType          string                 `json:"reportType" example:"soc2" doc:"Report type"`
	Period              string                 `json:"period" example:"2023-Q1" doc:"Reporting period"`
	GeneratedAt         time.Time              `json:"generatedAt" example:"2023-04-01T09:00:00Z" doc:"Report generation time"`
	TotalEvents         int                    `json:"totalEvents" example:"50000" doc:"Total events in period"`
	ComplianceScore     float64                `json:"complianceScore" example:"98.5" doc:"Compliance score percentage"`
	Violations          []ComplianceViolation  `json:"violations" doc:"Compliance violations found"`
	Recommendations     []string               `json:"recommendations" doc:"Compliance recommendations"`
	CoverageMetrics     map[string]interface{} `json:"coverageMetrics" doc:"Coverage metrics by requirement"`
	AttestationRequired bool                   `json:"attestationRequired" example:"true" doc:"Whether attestation is required"`
	Status              string                 `json:"status" example:"passed" doc:"Overall compliance status"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	Rule        string    `json:"rule" example:"access_logging" doc:"Compliance rule violated"`
	Severity    string    `json:"severity" example:"medium" doc:"Violation severity"`
	Description string    `json:"description" example:"Missing access logs for privileged operations" doc:"Violation description"`
	Count       int       `json:"count" example:"3" doc:"Number of violations"`
	FirstSeen   time.Time `json:"firstSeen" example:"2023-01-01T12:00:00Z" doc:"First occurrence"`
	LastSeen    time.Time `json:"lastSeen" example:"2023-01-31T15:30:00Z" doc:"Last occurrence"`
	Remediation string    `json:"remediation" example:"Enable detailed logging for all admin actions" doc:"Remediation steps"`
}

// AuditMetrics represents detailed audit metrics
type AuditMetrics struct {
	OrganizationID         xid.ID             `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Period                 string             `json:"period" example:"24h" doc:"Metrics period"`
	EventsByHour           map[string]int     `json:"eventsByHour" example:"{\"00\": 500, \"01\": 300}" doc:"Events by hour"`
	EventsByDay            map[string]int     `json:"eventsByDay" example:"{\"monday\": 5000, \"tuesday\": 5200}" doc:"Events by day"`
	TopUsers               []UserActivity     `json:"topUsers" doc:"Most active users"`
	TopActions             map[string]int     `json:"topActions" example:"{\"user.login\": 2000, \"user.logout\": 1900}" doc:"Most common actions"`
	ErrorRateByAction      map[string]float64 `json:"errorRateByAction" example:"{\"user.login\": 5.2, \"api.call\": 2.1}" doc:"Error rates by action"`
	GeographicDistribution map[string]int     `json:"geographicDistribution" example:"{\"US\": 8000, \"CA\": 1500}" doc:"Events by location"`
	DeviceTypes            map[string]int     `json:"deviceTypes" example:"{\"desktop\": 7000, \"mobile\": 2500}" doc:"Events by device type"`
	RiskDistribution       map[string]int     `json:"riskDistribution" example:"{\"low\": 8500, \"medium\": 1000, \"high\": 500}" doc:"Events by risk level"`
	ComplianceMetrics      map[string]float64 `json:"complianceMetrics" example:"{\"data_retention\": 100.0, \"access_logging\": 98.5}" doc:"Compliance metrics"`
	TrendAnalysis          TrendAnalysis      `json:"trendAnalysis" doc:"Trend analysis data"`
	GeneratedAt            time.Time          `json:"generatedAt" example:"2023-01-01T12:00:00Z" doc:"Metrics generation time"`
}

// TrendAnalysis represents trend analysis data
type TrendAnalysis struct {
	EventCountTrend      string   `json:"eventCountTrend" example:"increasing" doc:"Event count trend (increasing, decreasing, stable)"`
	FailureRateTrend     string   `json:"failureRateTrend" example:"decreasing" doc:"Failure rate trend"`
	RiskLevelTrend       string   `json:"riskLevelTrend" example:"stable" doc:"Risk level trend"`
	UserActivityTrend    string   `json:"userActivityTrend" example:"increasing" doc:"User activity trend"`
	WeekOverWeekChange   float64  `json:"weekOverWeekChange" example:"12.5" doc:"Week over week change percentage"`
	MonthOverMonthChange float64  `json:"monthOverMonthChange" example:"8.3" doc:"Month over month change percentage"`
	SeasonalPatterns     []string `json:"seasonalPatterns" example:"[\"higher_weekday_activity\", \"lunch_hour_peak\"]" doc:"Detected seasonal patterns"`
}

// AuditSearchRequest represents an advanced audit search request
type AuditSearchRequest struct {
	PaginationParams
	Query          string                   `json:"query,omitempty" example:"action:login AND status:failure" doc:"Advanced search query" query:"q"`
	OrganizationID OptionalParam[xid.ID]    `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization" query:"organizationId"`
	UserID         OptionalParam[xid.ID]    `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user" query:"userId"`
	Actions        []string                 `json:"actions,omitempty" example:"[\"user.login\", \"user.logout\"]" doc:"Filter by actions" query:"actions"`
	Resources      []string                 `json:"resources,omitempty" example:"[\"user\", \"organization\"]" doc:"Filter by resources" query:"resources"`
	Status         []string                 `json:"status,omitempty" example:"[\"success\", \"failure\"]" doc:"Filter by status" query:"status"`
	RiskLevels     []string                 `json:"riskLevels,omitempty" example:"[\"high\", \"critical\"]" doc:"Filter by risk levels" query:"riskLevels"`
	IPAddresses    []string                 `json:"ipAddresses,omitempty" example:"[\"192.168.1.1\"]" doc:"Filter by IP addresses" query:"ipAddresses"`
	UserAgents     []string                 `json:"userAgents,omitempty" example:"[\"Mozilla/5.0\"]" doc:"Filter by user agents" query:"userAgents"`
	StartDate      OptionalParam[time.Time] `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"OnStart date" query:"startDate"`
	EndDate        OptionalParam[time.Time] `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date" query:"endDate"`
	HasChanges     *bool                    `json:"hasChanges,omitempty" example:"true" doc:"Filter events with field changes" query:"hasChanges"`
	HasErrors      *bool                    `json:"hasErrors,omitempty" example:"true" doc:"Filter events with errors" query:"hasErrors"`
	Aggregations   []string                 `json:"aggregations,omitempty" example:"[\"by_action\", \"by_user\"]" doc:"Requested aggregations" query:"aggregations"`
}

// AuditSearchResponse represents advanced audit search response
type AuditSearchResponse struct {
	Results      []AuditLogSummary      `json:"results" doc:"Search results"`
	Total        int                    `json:"total" example:"1500" doc:"Total matching results"`
	Limit        int                    `json:"limit" example:"50" doc:"Results limit"`
	Offset       int                    `json:"offset" example:"0" doc:"Results offset"`
	HasMore      bool                   `json:"hasMore" example:"true" doc:"Whether there are more results"`
	Query        string                 `json:"query" example:"action:login AND status:failure" doc:"Search query used"`
	Took         int                    `json:"took" example:"45" doc:"Search time in milliseconds"`
	Aggregations map[string]interface{} `json:"aggregations,omitempty" doc:"Aggregation results"`
	Suggestions  []string               `json:"suggestions,omitempty" example:"[\"Did you mean: user.login?\"]" doc:"Search suggestions"`
}
