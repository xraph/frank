package organization

import (
	"time"

	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/internal/model"
	"github.com/rs/xid"
)

// Payment provider types and inputs
type CreateCustomerInput struct {
	OrganizationID xid.ID
	Name           string
	Email          string
	Address        *model.Address
	TaxID          string
}

type CustomerResult struct {
	CustomerID string
}

type CreateSubscriptionProviderInput struct {
	CustomerID      string
	PlanID          string
	PaymentMethodID string
	TrialDays       int
	CouponCode      string
}

type UpdateSubscriptionProviderInput struct {
	PlanID          string
	PaymentMethodID string
	Proration       bool
	EffectiveDate   time.Time
}

type SubscriptionResult struct {
	SubscriptionID     string
	Status             organization.SubscriptionStatus
	CurrentPeriodStart time.Time
	CurrentPeriodEnd   time.Time
}

type AddPaymentMethodProviderInput struct {
	Type           string
	Token          string
	BillingAddress *model.Address
}

type PaymentMethodResult struct {
	PaymentMethodID string
	Type            string
	Last4           string
}

type InvoiceResult struct {
	InvoiceID string
	Amount    int
	Status    string
	DueDate   time.Time
}

type RefundResult struct {
	RefundID string
	Amount   int
	Status   string
}

type TrialStatus struct {
	IsActive      bool       `json:"isActive" example:"true" doc:"Whether trial is active"`
	StartedAt     time.Time  `json:"startedAt" example:"2023-01-01T00:00:00Z" doc:"Trial start date"`
	EndsAt        *time.Time `json:"endsAt,omitempty" example:"2023-01-15T23:59:59Z" doc:"Trial end date"`
	DaysRemaining int        `json:"daysRemaining" example:"7" doc:"Days remaining in trial"`
	IsExpired     bool       `json:"isExpired" example:"false" doc:"Whether trial has expired"`
	CanExtend     bool       `json:"canExtend" example:"true" doc:"Whether trial can be extended"`
	UsageStats    UsageStats `json:"usageStats" doc:"Usage during trial period"`
	TrialUsed     bool       `json:"trialUsed" example:"false" doc:"Whether trial has been used"`
	DaysTotal     int        `json:"daysTotal" example:"14" doc:"Total trial days"`
	Features      []string   `json:"features" example:"[\"advanced_analytics\", \"priority_support\"]" doc:"Trial features"`
	Converted     bool       `json:"converted" example:"false" doc:"Whether trial converted to paid"`
}

type UsageStats struct {
	ExternalUsers int `json:"externalUsers" example:"5" doc:"External users created"`
	EndUsers      int `json:"endUsers" example:"50" doc:"End users created"`
	APIRequests   int `json:"apiRequests" example:"1000" doc:"API requests made"`
	LoginEvents   int `json:"loginEvents" example:"200" doc:"Login events"`
	EmailsSent    int `json:"emailsSent" example:"25" doc:"Emails sent"`
	SMSSent       int `json:"smsSent" example:"10" doc:"SMS messages sent"`
}

type UserLimits struct {
	ExternalUserLimit        int  `json:"externalUserLimit" example:"100" doc:"Maximum external users"`
	EndUserLimit             int  `json:"endUserLimit" example:"1000" doc:"Maximum end users"`
	APIRequestLimit          int  `json:"apiRequestLimit" example:"100000" doc:"Monthly API request limit"`
	StorageLimit             int  `json:"storageLimit" example:"10737418240" doc:"Storage limit in bytes"`
	EmailLimit               int  `json:"emailLimit" example:"5000" doc:"Monthly email limit"`
	SMSLimit                 int  `json:"smsLimit" example:"1000" doc:"Monthly SMS limit"`
	EnforceExternalUserLimit bool `json:"enforceExternalUserLimit" example:"true" doc:"Whether to enforce external user limit"`
	EnforceEndUserLimit      bool `json:"enforceEndUserLimit" example:"true" doc:"Whether to enforce end user limit"`
	EnforceAPIRequestLimit   bool `json:"enforceApiRequestLimit" example:"true" doc:"Whether to enforce API request limit"`
}

type UserCounts struct {
	ExternalUsers int       `json:"externalUsers" example:"25" doc:"Current external user count"`
	EndUsers      int       `json:"endUsers" example:"500" doc:"Current end user count"`
	TotalUsers    int       `json:"totalUsers" example:"525" doc:"Total user count"`
	ActiveUsers   int       `json:"activeUsers" example:"450" doc:"Active user count"`
	InactiveUsers int       `json:"inactiveUsers" example:"75" doc:"Inactive user count"`
	LastUpdated   time.Time `json:"lastUpdated" example:"2023-01-01T12:00:00Z" doc:"Last update timestamp"`
}

type OrganizationActivity struct {
	Period       string                `json:"period" example:"30d" doc:"Activity period"`
	TotalEvents  int                   `json:"totalEvents" example:"5000" doc:"Total events in period"`
	EventsByType map[string]int        `json:"eventsByType" doc:"Events grouped by type"`
	EventsByDay  map[string]int        `json:"eventsByDay" doc:"Daily event counts"`
	TopUsers     []UserActivitySummary `json:"topUsers" doc:"Most active users"`
	TopActions   []ActionSummary       `json:"topActions" doc:"Most common actions"`
	GrowthTrend  string                `json:"growthTrend" example:"increasing" doc:"Growth trend (increasing, decreasing, stable)"`
	GeneratedAt  time.Time             `json:"generatedAt" example:"2023-01-01T12:00:00Z" doc:"Report generation time"`
}

type UserActivitySummary struct {
	UserID       xid.ID    `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Email        string    `json:"email" example:"user@example.com" doc:"User email"`
	Name         string    `json:"name" example:"John Doe" doc:"User name"`
	EventCount   int       `json:"eventCount" example:"150" doc:"Number of events"`
	LastActivity time.Time `json:"lastActivity" example:"2023-01-01T12:00:00Z" doc:"Last activity time"`
}

type ActionSummary struct {
	Action     string  `json:"action" example:"user.login" doc:"Action name"`
	Count      int     `json:"count" example:"500" doc:"Action count"`
	Percentage float64 `json:"percentage" example:"25.5" doc:"Percentage of total actions"`
	Trend      string  `json:"trend" example:"increasing" doc:"Action trend"`
}

type GrowthMetrics struct {
	Period               string    `json:"period" example:"monthly" doc:"Metrics period"`
	UserGrowth           int       `json:"userGrowth" example:"50" doc:"User growth in period"`
	UserGrowthRate       float64   `json:"userGrowthRate" example:"12.5" doc:"User growth rate percentage"`
	ActivityGrowth       int       `json:"activityGrowth" example:"200" doc:"Activity growth in period"`
	ActivityGrowthRate   float64   `json:"activityGrowthRate" example:"8.7" doc:"Activity growth rate percentage"`
	RevenueGrowth        float64   `json:"revenueGrowth" example:"500.00" doc:"Revenue growth in period"`
	RevenueGrowthRate    float64   `json:"revenueGrowthRate" example:"15.2" doc:"Revenue growth rate percentage"`
	ChurnRate            float64   `json:"churnRate" example:"2.1" doc:"User churn rate percentage"`
	RetentionRate        float64   `json:"retentionRate" example:"95.5" doc:"User retention rate percentage"`
	AverageSessionLength int       `json:"averageSessionLength" example:"1800" doc:"Average session length in seconds"`
	DailyActiveUsers     int       `json:"dailyActiveUsers" example:"450" doc:"Daily active users"`
	MonthlyActiveUsers   int       `json:"monthlyActiveUsers" example:"800" doc:"Monthly active users"`
	GeneratedAt          time.Time `json:"generatedAt" example:"2023-01-01T12:00:00Z" doc:"Metrics generation time"`
	NewUsers             int       `json:"newUsers" example:"25" doc:"New user count"`
	ActiveUsers          int       `json:"activeUsers" example:"85" doc:"Active user count"`
	ReturnUsers          int       `json:"returnUsers" example:"60" doc:"Returning user count"`
	UserRetentionRate    float64   `json:"userRetentionRate" example:"75.5" doc:"User retention rate"`
	GrowthRate           float64   `json:"growthRate" example:"12.5" doc:"Growth rate percentage"`
	ComparedToPrevious   float64   `json:"comparedToPrevious" example:"8.3" doc:"Compared to previous period"`
}

// PlanLimits represents organization plan limits
type PlanLimits struct {
	Plan              string   `json:"plan" example:"pro" doc:"Plan name"`
	ExternalUserLimit int      `json:"externalUserLimit" example:"100" doc:"Maximum external users"`
	EndUserLimit      int      `json:"endUserLimit" example:"1000" doc:"Maximum end users"`
	APIRequestLimit   int      `json:"apiRequestLimit" example:"100000" doc:"Monthly API request limit"`
	StorageLimit      int      `json:"storageLimit" example:"10485760" doc:"Storage limit in bytes"`
	BandwidthLimit    int      `json:"bandwidthLimit" example:"52428800" doc:"Bandwidth limit in bytes"`
	WebhookLimit      int      `json:"webhookLimit" example:"10" doc:"Maximum webhooks"`
	SSLCertificates   int      `json:"sslCertificates" example:"5" doc:"SSL certificate limit"`
	CustomDomains     int      `json:"customDomains" example:"3" doc:"Custom domain limit"`
	AuditLogRetention int      `json:"auditLogRetention" example:"365" doc:"Audit log retention in days"`
	BackupRetention   int      `json:"backupRetention" example:"30" doc:"Backup retention in days"`
	SupportLevel      string   `json:"supportLevel" example:"priority" doc:"Support level"`
	Features          []string `json:"features" example:"[\"sso\", \"advanced_security\"]" doc:"Included features"`
}

// PlanLimitCheck represents the result of a plan limit check
type PlanLimitCheck struct {
	Allowed         bool       `json:"allowed" example:"true" doc:"Whether the operation is allowed"`
	CurrentUsage    int        `json:"currentUsage" example:"50" doc:"Current usage count"`
	Limit           int        `json:"limit" example:"100" doc:"Plan limit"`
	Remaining       int        `json:"remaining" example:"50" doc:"Remaining quota"`
	PercentUsed     float64    `json:"percentUsed" example:"50.0" doc:"Percentage of limit used"`
	ResetDate       *time.Time `json:"resetDate,omitempty" example:"2023-02-01T00:00:00Z" doc:"When usage resets"`
	UpgradeRequired bool       `json:"upgradeRequired" example:"false" doc:"Whether upgrade is required"`
	RecommendedPlan string     `json:"recommendedPlan,omitempty" example:"enterprise" doc:"Recommended plan for upgrade"`
}

// QuotaCheck represents quota check result
type QuotaCheck struct {
	Resource         string    `json:"resource" example:"api_requests" doc:"Resource type"`
	Allowed          bool      `json:"allowed" example:"true" doc:"Whether operation is allowed"`
	CurrentUsage     int       `json:"currentUsage" example:"5000" doc:"Current usage"`
	Limit            int       `json:"limit" example:"10000" doc:"Usage limit"`
	Remaining        int       `json:"remaining" example:"5000" doc:"Remaining quota"`
	ResetDate        time.Time `json:"resetDate" example:"2023-02-01T00:00:00Z" doc:"When quota resets"`
	WarningThreshold float64   `json:"warningThreshold" example:"80.0" doc:"Warning threshold percentage"`
	WarningTriggered bool      `json:"warningTriggered" example:"false" doc:"Whether warning threshold reached"`
}

// UsageSnapshot represents usage at a point in time
type UsageSnapshot struct {
	Date        time.Time      `json:"date" example:"2023-01-01T00:00:00Z" doc:"Snapshot date"`
	Resources   map[string]int `json:"resources" doc:"Resource usage counts"`
	TotalUsers  int            `json:"totalUsers" example:"25" doc:"Total user count"`
	ActiveUsers int            `json:"activeUsers" example:"20" doc:"Active user count"`
	APIRequests int            `json:"apiRequests" example:"1500" doc:"API request count"`
	Storage     int            `json:"storage" example:"1048576" doc:"Storage used in bytes"`
	Bandwidth   int            `json:"bandwidth" example:"2097152" doc:"Bandwidth used in bytes"`
	Events      int            `json:"events" example:"500" doc:"Event count"`
}

// OwnershipTransfer represents an ownership transfer record
type OwnershipTransfer struct {
	ID            xid.ID    `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Transfer ID"`
	FromUserID    xid.ID    `json:"fromUserId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Previous owner user ID"`
	ToUserID      xid.ID    `json:"toUserId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"New owner user ID"`
	TransferredAt time.Time `json:"transferredAt" example:"2023-01-01T12:00:00Z" doc:"Transfer timestamp"`
	Reason        string    `json:"reason,omitempty" example:"User requested transfer" doc:"Transfer reason"`
	TransferredBy *xid.ID   `json:"transferredBy,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Who initiated the transfer"`
	Status        string    `json:"status" example:"completed" doc:"Transfer status"`
}

// OrganizationAnalytics represents analytics data
type OrganizationAnalytics struct {
	Period             string             `json:"period" example:"30d" doc:"Analytics period"`
	UserGrowth         GrowthMetrics      `json:"userGrowth" doc:"User growth metrics"`
	ActivityMetrics    ActivityMetrics    `json:"activityMetrics" doc:"Activity metrics"`
	FeatureUsage       map[string]int     `json:"featureUsage" doc:"Feature usage statistics"`
	GeographicData     map[string]int     `json:"geographicData" doc:"Geographic distribution"`
	DeviceData         map[string]int     `json:"deviceData" doc:"Device type distribution"`
	PerformanceMetrics PerformanceMetrics `json:"performanceMetrics" doc:"Performance metrics"`
	ConversionMetrics  ConversionMetrics  `json:"conversionMetrics" doc:"Conversion metrics"`
	RevenueMetrics     RevenueMetrics     `json:"revenueMetrics" doc:"Revenue metrics"`
	GeneratedAt        time.Time          `json:"generatedAt" example:"2023-01-01T12:00:00Z" doc:"Report generation time"`
}

// ActivityMetrics represents user activity analytics
type ActivityMetrics struct {
	TotalSessions      int     `json:"totalSessions" example:"1250" doc:"Total sessions"`
	AverageSessionTime float64 `json:"averageSessionTime" example:"1800.5" doc:"Average session duration in seconds"`
	PageViews          int     `json:"pageViews" example:"5000" doc:"Total page views"`
	UniquePageViews    int     `json:"uniquePageViews" example:"3500" doc:"Unique page views"`
	BounceRate         float64 `json:"bounceRate" example:"25.3" doc:"Bounce rate percentage"`
	APICallsTotal      int     `json:"apiCallsTotal" example:"15000" doc:"Total API calls"`
	APICallsUnique     int     `json:"apiCallsUnique" example:"12000" doc:"Unique API calls"`
	ErrorRate          float64 `json:"errorRate" example:"2.1" doc:"Error rate percentage"`
}

// PerformanceMetrics represents performance analytics
type PerformanceMetrics struct {
	AverageResponseTime float64 `json:"averageResponseTime" example:"125.5" doc:"Average response time in ms"`
	P95ResponseTime     float64 `json:"p95ResponseTime" example:"250.0" doc:"95th percentile response time"`
	P99ResponseTime     float64 `json:"p99ResponseTime" example:"500.0" doc:"99th percentile response time"`
	Uptime              float64 `json:"uptime" example:"99.95" doc:"Uptime percentage"`
	ErrorCount          int     `json:"errorCount" example:"50" doc:"Total error count"`
	SuccessRate         float64 `json:"successRate" example:"98.5" doc:"Success rate percentage"`
}

// ConversionMetrics represents conversion analytics
type ConversionMetrics struct {
	TrialToConversion    float64            `json:"trialToConversion" example:"25.5" doc:"Trial to paid conversion rate"`
	SignupToActivation   float64            `json:"signupToActivation" example:"85.2" doc:"Signup to activation rate"`
	FeatureAdoption      map[string]float64 `json:"featureAdoption" doc:"Feature adoption rates"`
	OnboardingCompletion float64            `json:"onboardingCompletion" example:"78.5" doc:"Onboarding completion rate"`
	TimeToValue          float64            `json:"timeToValue" example:"3.5" doc:"Average time to value in days"`
}

// RevenueMetrics represents revenue analytics
type RevenueMetrics struct {
	MonthlyRecurringRevenue float64 `json:"monthlyRecurringRevenue" example:"2500.00" doc:"MRR"`
	AnnualRecurringRevenue  float64 `json:"annualRecurringRevenue" example:"30000.00" doc:"ARR"`
	AverageRevenuePerUser   float64 `json:"averageRevenuePerUser" example:"25.00" doc:"ARPU"`
	CustomerLifetimeValue   float64 `json:"customerLifetimeValue" example:"750.00" doc:"CLV"`
	RevenueGrowthRate       float64 `json:"revenueGrowthRate" example:"15.5" doc:"Revenue growth rate"`
	ChurnRate               float64 `json:"churnRate" example:"5.0" doc:"Revenue churn rate"`
}

// ComplianceReport represents compliance status
type ComplianceReport struct {
	OrganizationID      xid.ID                  `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	GeneratedAt         time.Time               `json:"generatedAt" example:"2023-01-01T12:00:00Z" doc:"Report generation time"`
	ComplianceLevel     string                  `json:"complianceLevel" example:"soc2" doc:"Compliance level"`
	OverallScore        float64                 `json:"overallScore" example:"95.5" doc:"Overall compliance score"`
	Requirements        []ComplianceRequirement `json:"requirements" doc:"Compliance requirements"`
	Violations          []ComplianceViolation   `json:"violations" doc:"Compliance violations"`
	Recommendations     []string                `json:"recommendations" doc:"Compliance recommendations"`
	NextReviewDate      time.Time               `json:"nextReviewDate" example:"2023-04-01T00:00:00Z" doc:"Next review date"`
	CertificationStatus string                  `json:"certificationStatus" example:"certified" doc:"Certification status"`
}

// ComplianceRequirement represents a compliance requirement
type ComplianceRequirement struct {
	ID          string    `json:"id" example:"access_control" doc:"Requirement ID"`
	Name        string    `json:"name" example:"Access Control" doc:"Requirement name"`
	Description string    `json:"description" doc:"Requirement description"`
	Status      string    `json:"status" example:"compliant" doc:"Compliance status"`
	Score       float64   `json:"score" example:"100.0" doc:"Compliance score"`
	Evidence    []string  `json:"evidence,omitempty" doc:"Supporting evidence"`
	LastChecked time.Time `json:"lastChecked" example:"2023-01-01T12:00:00Z" doc:"Last check timestamp"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ID          string     `json:"id" example:"password_policy" doc:"Violation ID"`
	Severity    string     `json:"severity" example:"medium" doc:"Violation severity"`
	Description string     `json:"description" doc:"Violation description"`
	Requirement string     `json:"requirement" example:"Password Policy" doc:"Related requirement"`
	DetectedAt  time.Time  `json:"detectedAt" example:"2023-01-01T10:00:00Z" doc:"Detection timestamp"`
	Status      string     `json:"status" example:"open" doc:"Violation status"`
	Remediation string     `json:"remediation" doc:"Remediation steps"`
	DueDate     *time.Time `json:"dueDate,omitempty" example:"2023-01-15T00:00:00Z" doc:"Remediation due date"`
}

// AddMemberInput represents input for adding a member
type AddMemberInput struct {
	OrganizationID xid.ID                 `json:"organizationId"`
	UserID         xid.ID                 `json:"userId"`
	RoleID         xid.ID                 `json:"roleId"`
	InvitedBy      *xid.ID                `json:"invitedBy,omitempty"`
	IsBilling      bool                   `json:"isBilling"`
	IsPrimary      bool                   `json:"isPrimary"`
	CustomFields   map[string]interface{} `json:"customFields,omitempty"`
}
