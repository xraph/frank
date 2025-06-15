package model

import (
	"time"

	"github.com/rs/xid"
)

// BillingPlan represents a billing plan
type BillingPlan struct {
	ID                string                 `json:"id" example:"pro" doc:"Plan ID"`
	Name              string                 `json:"name" example:"Pro Plan" doc:"Plan name"`
	DisplayName       string                 `json:"displayName" example:"Professional" doc:"Display name"`
	Description       string                 `json:"description" example:"Perfect for growing businesses" doc:"Plan description"`
	Price             int                    `json:"price" example:"9900" doc:"Price in cents"`
	Currency          string                 `json:"currency" example:"usd" doc:"Currency code"`
	BillingInterval   string                 `json:"billingInterval" example:"month" doc:"Billing interval" enum:"month,year"`
	TrialDays         int                    `json:"trialDays" example:"14" doc:"Trial period in days"`
	ExternalUserLimit int                    `json:"externalUserLimit" example:"100" doc:"External user limit"`
	EndUserLimit      int                    `json:"endUserLimit" example:"10000" doc:"End user limit"`
	APIRequestLimit   int                    `json:"apiRequestLimit" example:"100000" doc:"Monthly API request limit"`
	StorageLimit      int                    `json:"storageLimit" example:"10737418240" doc:"Storage limit in bytes"`
	Features          []string               `json:"features" example:"[\"SSO\", \"Advanced MFA\", \"Audit Logs\"]" doc:"Included features"`
	Popular           bool                   `json:"popular" example:"true" doc:"Whether this is a popular plan"`
	Enterprise        bool                   `json:"enterprise" example:"false" doc:"Whether this is an enterprise plan"`
	CustomPricing     bool                   `json:"customPricing" example:"false" doc:"Whether plan has custom pricing"`
	ContactSales      bool                   `json:"contactSales" example:"false" doc:"Whether to contact sales for this plan"`
	Available         bool                   `json:"available" example:"true" doc:"Whether plan is available for signup"`
	Metadata          map[string]interface{} `json:"metadata,omitempty" doc:"Additional plan metadata"`
	CreatedAt         time.Time              `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Plan creation timestamp"`
	UpdatedAt         time.Time              `json:"updatedAt" example:"2023-01-01T12:00:00Z" doc:"Plan update timestamp"`
}

// UsageData represents usage tracking data
type UsageData struct {
	Type      string                 `json:"type" example:"api_requests" doc:"Usage type" enum:"api_requests,external_users,end_users,storage,bandwidth"`
	Count     int                    `json:"count" example:"5000" doc:"Usage count"`
	Delta     int                    `json:"delta" example:"100" doc:"Change in usage"`
	Timestamp time.Time              `json:"timestamp" example:"2023-01-01T12:00:00Z" doc:"Usage timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty" doc:"Additional usage metadata"`
}

// UsageAlert represents a usage alert
type UsageAlert struct {
	ID             xid.ID                 `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Alert ID"`
	OrganizationID xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	ResourceType   string                 `json:"resourceType" example:"api_requests" doc:"Resource type" enum:"api_requests,external_users,end_users,storage,bandwidth"`
	Threshold      int                    `json:"threshold" example:"80" doc:"Alert threshold percentage"`
	CurrentUsage   int                    `json:"currentUsage" example:"8500" doc:"Current usage count"`
	Limit          int                    `json:"limit" example:"10000" doc:"Usage limit"`
	AlertType      string                 `json:"alertType" example:"warning" doc:"Alert type" enum:"warning,critical,limit_exceeded"`
	Status         string                 `json:"status" example:"active" doc:"Alert status" enum:"active,resolved,dismissed"`
	CreatedAt      time.Time              `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Alert creation time"`
	ResolvedAt     *time.Time             `json:"resolvedAt,omitempty" example:"2023-01-01T13:00:00Z" doc:"Alert resolution time"`
	Message        string                 `json:"message" example:"API usage is at 85% of monthly limit" doc:"Alert message"`
	ActionRequired bool                   `json:"actionRequired" example:"false" doc:"Whether action is required"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional alert metadata"`
}

// UsageLimitCheck represents the result of a usage limit check
type UsageLimitCheck struct {
	ResourceType     string     `json:"resourceType" example:"external_users" doc:"Resource type checked"`
	CurrentUsage     int        `json:"currentUsage" example:"75" doc:"Current usage count"`
	Limit            int        `json:"limit" example:"100" doc:"Usage limit"`
	PercentageUsed   float64    `json:"percentageUsed" example:"75.0" doc:"Percentage of limit used"`
	WithinLimit      bool       `json:"withinLimit" example:"true" doc:"Whether usage is within limit"`
	Warning          bool       `json:"warning" example:"false" doc:"Whether usage is approaching limit"`
	WarningThreshold int        `json:"warningThreshold" example:"80" doc:"Warning threshold percentage"`
	Remaining        int        `json:"remaining" example:"25" doc:"Remaining usage before limit"`
	ResetDate        *time.Time `json:"resetDate,omitempty" example:"2023-02-01T00:00:00Z" doc:"When usage resets"`
	UpgradeRequired  bool       `json:"upgradeRequired" example:"false" doc:"Whether plan upgrade is required"`
	RecommendedPlan  string     `json:"recommendedPlan,omitempty" example:"pro" doc:"Recommended plan if upgrade needed"`
}

// PaymentMethod represents a payment method
type PaymentMethod struct {
	ID             string                 `json:"id" example:"pm_123456" doc:"Payment method ID"`
	OrganizationID xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Type           string                 `json:"type" example:"card" doc:"Payment method type" enum:"card,bank_account,paypal"`
	Brand          string                 `json:"brand,omitempty" example:"visa" doc:"Card brand"`
	Last4          string                 `json:"last4,omitempty" example:"4242" doc:"Last 4 digits"`
	ExpMonth       int                    `json:"expMonth,omitempty" example:"12" doc:"Expiration month"`
	ExpYear        int                    `json:"expYear,omitempty" example:"2025" doc:"Expiration year"`
	Country        string                 `json:"country,omitempty" example:"US" doc:"Country code"`
	IsDefault      bool                   `json:"isDefault" example:"true" doc:"Whether this is the default payment method"`
	Status         string                 `json:"status" example:"active" doc:"Payment method status" enum:"active,inactive,expired,failed"`
	BillingAddress *Address               `json:"billingAddress,omitempty" doc:"Billing address"`
	CreatedAt      time.Time              `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Creation timestamp"`
	UpdatedAt      time.Time              `json:"updatedAt" example:"2023-01-01T12:00:00Z" doc:"Update timestamp"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
}

// BillingContact represents a billing contact
type BillingContact struct {
	UserID         xid.ID    `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	OrganizationID xid.ID    `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Name           string    `json:"name" example:"John Doe" doc:"Contact name"`
	Email          string    `json:"email" example:"billing@example.com" doc:"Contact email"`
	Phone          string    `json:"phone,omitempty" example:"+1234567890" doc:"Contact phone"`
	IsPrimary      bool      `json:"isPrimary" example:"true" doc:"Whether this is the primary billing contact"`
	Role           string    `json:"role,omitempty" example:"CFO" doc:"Contact role/title"`
	Department     string    `json:"department,omitempty" example:"Finance" doc:"Department"`
	NotifyInvoices bool      `json:"notifyInvoices" example:"true" doc:"Notify for invoice events"`
	NotifyUsage    bool      `json:"notifyUsage" example:"false" doc:"Notify for usage alerts"`
	NotifyBilling  bool      `json:"notifyBilling" example:"true" doc:"Notify for billing changes"`
	CreatedAt      time.Time `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Creation timestamp"`
	UpdatedAt      time.Time `json:"updatedAt" example:"2023-01-01T12:00:00Z" doc:"Update timestamp"`
}

// Invoice represents a billing invoice
type Invoice struct {
	ID              string                 `json:"id" example:"inv_123456" doc:"Invoice ID"`
	OrganizationID  xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Number          string                 `json:"number" example:"INV-2023-001" doc:"Invoice number"`
	Status          InvoiceStatus          `json:"status" example:"paid" doc:"Invoice status" enum:"draft,open,paid,void,uncollectible"`
	Amount          int                    `json:"amount" example:"9900" doc:"Invoice amount in cents"`
	AmountPaid      int                    `json:"amountPaid" example:"9900" doc:"Amount paid in cents"`
	AmountRemaining int                    `json:"amountRemaining" example:"0" doc:"Amount remaining in cents"`
	Currency        string                 `json:"currency" example:"usd" doc:"Currency code"`
	Description     string                 `json:"description,omitempty" example:"Pro Plan - January 2023" doc:"Invoice description"`
	PeriodStart     time.Time              `json:"periodStart" example:"2023-01-01T00:00:00Z" doc:"Billing period start"`
	PeriodEnd       time.Time              `json:"periodEnd" example:"2023-01-31T23:59:59Z" doc:"Billing period end"`
	CreatedAt       time.Time              `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Invoice creation time"`
	DueDate         time.Time              `json:"dueDate" example:"2023-01-15T23:59:59Z" doc:"Invoice due date"`
	PaidAt          *time.Time             `json:"paidAt,omitempty" example:"2023-01-02T10:30:00Z" doc:"Payment timestamp"`
	LineItems       []LineItem             `json:"lineItems" doc:"Invoice line items"`
	TaxAmount       int                    `json:"taxAmount" example:"990" doc:"Tax amount in cents"`
	TaxRate         float64                `json:"taxRate" example:"10.0" doc:"Tax rate percentage"`
	DiscountAmount  int                    `json:"discountAmount" example:"0" doc:"Discount amount in cents"`
	Subtotal        int                    `json:"subtotal" example:"8910" doc:"Subtotal before tax in cents"`
	PaymentMethodID string                 `json:"paymentMethodId,omitempty" example:"pm_123456" doc:"Payment method used"`
	DownloadURL     string                 `json:"downloadUrl,omitempty" example:"https://api.example.com/invoices/123/download" doc:"Invoice download URL"`
	Metadata        map[string]interface{} `json:"metadata,omitempty" doc:"Additional invoice metadata"`
}

// LineItem represents an invoice line item
type LineItem struct {
	ID          string                 `json:"id" example:"li_123456" doc:"Line item ID"`
	Type        string                 `json:"type" example:"subscription" doc:"Line item type" enum:"subscription,usage,tax,discount"`
	Description string                 `json:"description" example:"Pro Plan (Jan 1 - Jan 31)" doc:"Line item description"`
	Quantity    int                    `json:"quantity" example:"1" doc:"Quantity"`
	UnitAmount  int                    `json:"unitAmount" example:"9900" doc:"Unit amount in cents"`
	Amount      int                    `json:"amount" example:"9900" doc:"Total amount in cents"`
	Currency    string                 `json:"currency" example:"usd" doc:"Currency code"`
	PeriodStart *time.Time             `json:"periodStart,omitempty" example:"2023-01-01T00:00:00Z" doc:"Service period start"`
	PeriodEnd   *time.Time             `json:"periodEnd,omitempty" example:"2023-01-31T23:59:59Z" doc:"Service period end"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" doc:"Additional line item metadata"`
}

// ListInvoicesParams represents parameters for listing invoices
type ListInvoicesParams struct {
	PaginationParams
	Status    InvoiceStatus            `json:"status,omitempty" query:"status" example:"paid" doc:"Filter by status" enum:"draft,open,paid,void,uncollectible"`
	StartDate OptionalParam[time.Time] `json:"startDate,omitempty" query:"startDate" example:"2023-01-01T00:00:00Z" doc:"Filter by creation date after"`
	EndDate   OptionalParam[time.Time] `json:"endDate,omitempty" query:"endDate" example:"2023-12-31T23:59:59Z" doc:"Filter by creation date before"`
	DueBefore OptionalParam[time.Time] `json:"dueBefore,omitempty" query:"dueBefore" example:"2023-01-31T23:59:59Z" doc:"Filter by due date before"`
	MinAmount OptionalParam[int]       `json:"minAmount,omitempty" query:"minAmount" example:"1000" doc:"Filter by minimum amount in cents"`
	MaxAmount OptionalParam[int]       `json:"maxAmount,omitempty" query:"maxAmount" example:"100000" doc:"Filter by maximum amount in cents"`
}

// InvoiceListResponse represents a list of invoices
type InvoiceListResponse = PaginatedOutput[Invoice]

// BillingStats represents billing statistics
type BillingStats struct {
	MonthlyRevenue     int        `json:"monthlyRevenue" example:"9900" doc:"Monthly recurring revenue in cents"`
	AnnualRevenue      int        `json:"annualRevenue" example:"118800" doc:"Annual recurring revenue in cents"`
	TotalRevenue       int        `json:"totalRevenue" example:"500000" doc:"Total revenue to date in cents"`
	ActiveSubscription bool       `json:"activeSubscription" example:"true" doc:"Whether subscription is active"`
	CurrentPlan        string     `json:"currentPlan" example:"pro" doc:"Current plan ID"`
	NextBillingDate    time.Time  `json:"nextBillingDate" example:"2023-02-01T00:00:00Z" doc:"Next billing date"`
	DaysUntilRenewal   int        `json:"daysUntilRenewal" example:"15" doc:"Days until next renewal"`
	UsagePercentage    float64    `json:"usagePercentage" example:"75.5" doc:"Overall usage percentage"`
	PaymentStatus      string     `json:"paymentStatus" example:"current" doc:"Payment status" enum:"current,past_due,cancelled"`
	TrialActive        bool       `json:"trialActive" example:"false" doc:"Whether trial is active"`
	TrialEndsAt        *time.Time `json:"trialEndsAt,omitempty" example:"2023-01-15T23:59:59Z" doc:"Trial end date"`
	LastPaymentDate    *time.Time `json:"lastPaymentDate,omitempty" example:"2023-01-01T10:00:00Z" doc:"Last successful payment"`
	LastPaymentAmount  int        `json:"lastPaymentAmount" example:"9900" doc:"Last payment amount in cents"`
	OutstandingBalance int        `json:"outstandingBalance" example:"0" doc:"Outstanding balance in cents"`
	Currency           string     `json:"currency" example:"usd" doc:"Currency code"`
	TaxRate            float64    `json:"taxRate" example:"10.0" doc:"Applied tax rate percentage"`
	DiscountPercentage float64    `json:"discountPercentage" example:"0.0" doc:"Applied discount percentage"`
	LifetimeValue      int        `json:"lifetimeValue" example:"250000" doc:"Customer lifetime value in cents"`
	PaymentMethodLast4 string     `json:"paymentMethodLast4,omitempty" example:"4242" doc:"Payment method last 4 digits"`
	PaymentMethodBrand string     `json:"paymentMethodBrand,omitempty" example:"visa" doc:"Payment method brand"`
	BillingCycleAnchor time.Time  `json:"billingCycleAnchor" example:"2023-01-01T00:00:00Z" doc:"Billing cycle anchor date"`
}

// RevenueMetrics represents revenue metrics for a period
type RevenueMetrics struct {
	Period                  string                 `json:"period" example:"30d" doc:"Metrics period"`
	StartDate               time.Time              `json:"startDate" example:"2023-01-01T00:00:00Z" doc:"Period start date"`
	EndDate                 time.Time              `json:"endDate" example:"2023-01-31T23:59:59Z" doc:"Period end date"`
	TotalRevenue            int                    `json:"totalRevenue" example:"99000" doc:"Total revenue in period (cents)"`
	RecurringRevenue        int                    `json:"recurringRevenue" example:"89100" doc:"Recurring revenue in period (cents)"`
	OneTimeRevenue          int                    `json:"oneTimeRevenue" example:"9900" doc:"One-time revenue in period (cents)"`
	RefundedAmount          int                    `json:"refundedAmount" example:"1980" doc:"Refunded amount in period (cents)"`
	NetRevenue              int                    `json:"netRevenue" example:"97020" doc:"Net revenue after refunds (cents)"`
	RevenueGrowth           float64                `json:"revenueGrowth" example:"15.5" doc:"Revenue growth percentage"`
	AverageRevenuePerUser   int                    `json:"averageRevenuePerUser" example:"6600" doc:"ARPU in cents"`
	MonthlyRecurringRevenue int                    `json:"monthlyRecurringRevenue" example:"89100" doc:"MRR in cents"`
	AnnualRecurringRevenue  int                    `json:"annualRecurringRevenue" example:"1069200" doc:"ARR in cents"`
	ChurnRate               float64                `json:"churnRate" example:"2.5" doc:"Revenue churn rate percentage"`
	ExpansionRevenue        int                    `json:"expansionRevenue" example:"5940" doc:"Revenue from upgrades (cents)"`
	ContractionRevenue      int                    `json:"contractionRevenue" example:"990" doc:"Revenue lost from downgrades (cents)"`
	Currency                string                 `json:"currency" example:"usd" doc:"Currency code"`
	RevenueByPlan           map[string]PlanRevenue `json:"revenueByPlan" doc:"Revenue breakdown by plan"`
	Trends                  RevenueTrends          `json:"trends" doc:"Revenue trend analysis"`
}

// PlanRevenue represents revenue for a specific plan
type PlanRevenue struct {
	PlanID     string  `json:"planId" example:"pro" doc:"Plan ID"`
	PlanName   string  `json:"planName" example:"Pro Plan" doc:"Plan name"`
	Revenue    int     `json:"revenue" example:"59400" doc:"Revenue from this plan (cents)"`
	Customers  int     `json:"customers" example:"6" doc:"Number of customers on this plan"`
	Percentage float64 `json:"percentage" example:"60.0" doc:"Percentage of total revenue"`
}

// RevenueTrends represents revenue trend analysis
type RevenueTrends struct {
	Direction     string                `json:"direction" example:"increasing" doc:"Trend direction" enum:"increasing,decreasing,stable"`
	GrowthRate    float64               `json:"growthRate" example:"15.5" doc:"Growth rate percentage"`
	Momentum      string                `json:"momentum" example:"accelerating" doc:"Growth momentum" enum:"accelerating,steady,decelerating"`
	Seasonality   string                `json:"seasonality,omitempty" example:"q4_peak" doc:"Seasonal patterns"`
	MonthlyTrends []MonthlyRevenueTrend `json:"monthlyTrends,omitempty" doc:"Monthly trend data"`
	Forecast      *RevenueForecast      `json:"forecast,omitempty" doc:"Revenue forecast"`
}

// MonthlyRevenueTrend represents monthly revenue trend data
type MonthlyRevenueTrend struct {
	Month          string  `json:"month" example:"2023-01" doc:"Month in YYYY-MM format"`
	Revenue        int     `json:"revenue" example:"89100" doc:"Revenue for the month (cents)"`
	GrowthRate     float64 `json:"growthRate" example:"12.5" doc:"Month-over-month growth rate"`
	CustomerCount  int     `json:"customerCount" example:"15" doc:"Number of customers"`
	AverageRevenue int     `json:"averageRevenue" example:"5940" doc:"Average revenue per customer (cents)"`
}

// RevenueForecast represents revenue forecast
type RevenueForecast struct {
	NextMonth       ForecastData `json:"nextMonth" doc:"Next month forecast"`
	NextQuarter     ForecastData `json:"nextQuarter" doc:"Next quarter forecast"`
	NextYear        ForecastData `json:"nextYear" doc:"Next year forecast"`
	ConfidenceLevel float64      `json:"confidenceLevel" example:"78.5" doc:"Forecast confidence percentage"`
	Methodology     string       `json:"methodology" example:"time_series_analysis" doc:"Forecasting methodology used"`
}

// ForecastData represents forecast data
type ForecastData struct {
	Period           string  `json:"period" example:"2023-02" doc:"Forecast period"`
	PredictedRevenue int     `json:"predictedRevenue" example:"102000" doc:"Predicted revenue (cents)"`
	LowEstimate      int     `json:"lowEstimate" example:"95000" doc:"Conservative estimate (cents)"`
	HighEstimate     int     `json:"highEstimate" example:"110000" doc:"Optimistic estimate (cents)"`
	GrowthRate       float64 `json:"growthRate" example:"14.5" doc:"Predicted growth rate percentage"`
}

// ListBillingHistoryParams represents parameters for listing billing history
type ListBillingHistoryParams struct {
	PaginationParams
	EventType string     `json:"eventType,omitempty" query:"eventType" example:"payment" doc:"Filter by event type" enum:"payment,refund,chargeback,subscription_change,plan_change"`
	StartDate *time.Time `json:"startDate,omitempty" query:"startDate" example:"2023-01-01T00:00:00Z" doc:"Filter by date after"`
	EndDate   *time.Time `json:"endDate,omitempty" query:"endDate" example:"2023-12-31T23:59:59Z" doc:"Filter by date before"`
	Status    string     `json:"status,omitempty" query:"status" example:"succeeded" doc:"Filter by status" enum:"succeeded,failed,pending,cancelled"`
	MinAmount *int       `json:"minAmount,omitempty" query:"minAmount" example:"1000" doc:"Filter by minimum amount"`
	MaxAmount *int       `json:"maxAmount,omitempty" query:"maxAmount" example:"100000" doc:"Filter by maximum amount"`
}

// BillingHistoryEvent represents a billing history event
type BillingHistoryEvent struct {
	ID            string                 `json:"id" example:"evt_123456" doc:"Event ID"`
	Type          string                 `json:"type" example:"payment" doc:"Event type" enum:"payment,refund,chargeback,subscription_change,plan_change"`
	Status        string                 `json:"status" example:"succeeded" doc:"Event status" enum:"succeeded,failed,pending,cancelled"`
	Amount        int                    `json:"amount" example:"9900" doc:"Amount in cents"`
	Currency      string                 `json:"currency" example:"usd" doc:"Currency code"`
	Description   string                 `json:"description" example:"Payment for Pro Plan" doc:"Event description"`
	InvoiceID     string                 `json:"invoiceId,omitempty" example:"inv_123456" doc:"Related invoice ID"`
	PaymentID     string                 `json:"paymentId,omitempty" example:"py_123456" doc:"Related payment ID"`
	RefundID      string                 `json:"refundId,omitempty" example:"re_123456" doc:"Related refund ID"`
	FailureReason string                 `json:"failureReason,omitempty" example:"insufficient_funds" doc:"Failure reason if applicable"`
	CreatedAt     time.Time              `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Event timestamp"`
	ProcessedAt   *time.Time             `json:"processedAt,omitempty" example:"2023-01-01T12:01:00Z" doc:"Processing timestamp"`
	Metadata      map[string]interface{} `json:"metadata,omitempty" doc:"Additional event metadata"`
	Changes       map[string]interface{} `json:"changes,omitempty" doc:"Changes made (for change events)"`
}

// BillingHistoryResponse represents billing history response
type BillingHistoryResponse = PaginatedOutput[BillingHistoryEvent]

// Refund represents a billing refund
type Refund struct {
	ID             string                 `json:"id" example:"re_123456" doc:"Refund ID"`
	OrganizationID xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	PaymentID      string                 `json:"paymentId" example:"py_123456" doc:"Original payment ID"`
	InvoiceID      string                 `json:"invoiceId,omitempty" example:"inv_123456" doc:"Related invoice ID"`
	Amount         int                    `json:"amount" example:"4950" doc:"Refund amount in cents"`
	Currency       string                 `json:"currency" example:"usd" doc:"Currency code"`
	Reason         string                 `json:"reason" example:"Customer requested cancellation" doc:"Refund reason"`
	Status         string                 `json:"status" example:"succeeded" doc:"Refund status" enum:"pending,succeeded,failed,cancelled"`
	FailureReason  string                 `json:"failureReason,omitempty" example:"insufficient_funds" doc:"Failure reason if applicable"`
	RefundType     string                 `json:"refundType" example:"partial" doc:"Refund type" enum:"full,partial"`
	ProcessedBy    xid.ID                 `json:"processedBy" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User who processed the refund"`
	CreatedAt      time.Time              `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Refund creation time"`
	ProcessedAt    *time.Time             `json:"processedAt,omitempty" example:"2023-01-01T12:01:00Z" doc:"Processing timestamp"`
	ExpectedAt     *time.Time             `json:"expectedAt,omitempty" example:"2023-01-03T12:00:00Z" doc:"Expected completion time"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional refund metadata"`
}

// CreateRefundRequest represents a request to create a refund
type CreateRefundRequest struct {
	PaymentID string `json:"paymentId" example:"py_123456" doc:"Payment ID to refund" validate:"required"`
	Amount    *int   `json:"amount,omitempty" example:"4950" doc:"Refund amount in cents (omit for full refund)"`
	Reason    string `json:"reason" example:"Customer requested cancellation" doc:"Refund reason" validate:"required"`
}

// BillingNotification represents a billing notification
type BillingNotification struct {
	ID             xid.ID                 `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Notification ID"`
	OrganizationID xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Type           string                 `json:"type" example:"payment_failed" doc:"Notification type" enum:"payment_failed,invoice_due,usage_alert,plan_limit,trial_ending"`
	Title          string                 `json:"title" example:"Payment Failed" doc:"Notification title"`
	Message        string                 `json:"message" example:"Your payment could not be processed" doc:"Notification message"`
	Severity       string                 `json:"severity" example:"high" doc:"Notification severity" enum:"low,medium,high,critical"`
	ActionRequired bool                   `json:"actionRequired" example:"true" doc:"Whether action is required"`
	ActionURL      string                 `json:"actionUrl,omitempty" example:"https://billing.example.com/payment" doc:"URL for required action"`
	Status         string                 `json:"status" example:"unread" doc:"Notification status" enum:"unread,read,dismissed"`
	ReadAt         *time.Time             `json:"readAt,omitempty" example:"2023-01-01T13:00:00Z" doc:"When notification was read"`
	DismissedAt    *time.Time             `json:"dismissedAt,omitempty" example:"2023-01-01T14:00:00Z" doc:"When notification was dismissed"`
	ExpiresAt      *time.Time             `json:"expiresAt,omitempty" example:"2023-01-08T12:00:00Z" doc:"Notification expiration time"`
	CreatedAt      time.Time              `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Creation timestamp"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional notification data"`
}

// TaxConfiguration represents tax configuration for billing
type TaxConfiguration struct {
	OrganizationID   xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	TaxID            string                 `json:"taxId,omitempty" example:"US123456789" doc:"Tax identification number"`
	TaxIDType        string                 `json:"taxIdType,omitempty" example:"us_ein" doc:"Tax ID type"`
	TaxExempt        bool                   `json:"taxExempt" example:"false" doc:"Whether organization is tax exempt"`
	DefaultTaxRate   float64                `json:"defaultTaxRate" example:"8.25" doc:"Default tax rate percentage"`
	TaxRatesByRegion map[string]float64     `json:"taxRatesByRegion,omitempty" doc:"Tax rates by region/state"`
	AutoTaxEnabled   bool                   `json:"autoTaxEnabled" example:"true" doc:"Whether automatic tax calculation is enabled"`
	TaxProvider      string                 `json:"taxProvider,omitempty" example:"stripe_tax" doc:"Tax calculation provider"`
	ValidatedAt      *time.Time             `json:"validatedAt,omitempty" example:"2023-01-01T12:00:00Z" doc:"When tax info was last validated"`
	Metadata         map[string]interface{} `json:"metadata,omitempty" doc:"Additional tax configuration"`
}

// CouponCode represents a coupon/discount code
type CouponCode struct {
	ID               string                 `json:"id" example:"SAVE20" doc:"Coupon code"`
	Name             string                 `json:"name" example:"20% Off First Month" doc:"Coupon name"`
	Type             string                 `json:"type" example:"percentage" doc:"Discount type" enum:"percentage,fixed_amount"`
	Value            int                    `json:"value" example:"20" doc:"Discount value (percentage or cents)"`
	Currency         string                 `json:"currency,omitempty" example:"usd" doc:"Currency for fixed amount discounts"`
	Duration         string                 `json:"duration" example:"once" doc:"Discount duration" enum:"once,repeating,forever"`
	DurationInMonths *int                   `json:"durationInMonths,omitempty" example:"3" doc:"Duration in months for repeating"`
	MaxRedemptions   *int                   `json:"maxRedemptions,omitempty" example:"100" doc:"Maximum number of redemptions"`
	TimesRedeemed    int                    `json:"timesRedeemed" example:"25" doc:"Number of times redeemed"`
	Valid            bool                   `json:"valid" example:"true" doc:"Whether coupon is currently valid"`
	ExpiresAt        *time.Time             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Expiration date"`
	CreatedAt        time.Time              `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Creation timestamp"`
	Restrictions     CouponRestrictions     `json:"restrictions,omitempty" doc:"Coupon restrictions"`
	Metadata         map[string]interface{} `json:"metadata,omitempty" doc:"Additional coupon metadata"`
}

// CouponRestrictions represents restrictions on coupon usage
type CouponRestrictions struct {
	MinimumAmount    *int     `json:"minimumAmount,omitempty" example:"5000" doc:"Minimum order amount in cents"`
	FirstTimeOnly    bool     `json:"firstTimeOnly" example:"true" doc:"Only for first-time customers"`
	SpecificPlans    []string `json:"specificPlans,omitempty" example:"[\"pro\", \"enterprise\"]" doc:"Restricted to specific plans"`
	ExcludedPlans    []string `json:"excludedPlans,omitempty" example:"[\"free\"]" doc:"Excluded plans"`
	NewCustomersOnly bool     `json:"newCustomersOnly" example:"false" doc:"Only for new customers"`
	OnePerCustomer   bool     `json:"onePerCustomer" example:"true" doc:"One use per customer"`
}

// BillingPreferences represents billing preferences for an organization
type BillingPreferences struct {
	OrganizationID       xid.ID    `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	AutoRenew            bool      `json:"autoRenew" example:"true" doc:"Whether subscription auto-renews"`
	CollectionMethod     string    `json:"collectionMethod" example:"charge_automatically" doc:"Payment collection method" enum:"charge_automatically,send_invoice"`
	BillingCycleAnchor   int       `json:"billingCycleAnchor" example:"1" doc:"Day of month for billing (1-28)"`
	InvoiceDeliveryEmail string    `json:"invoiceDeliveryEmail" example:"billing@example.com" doc:"Email for invoice delivery"`
	SendInvoiceEmails    bool      `json:"sendInvoiceEmails" example:"true" doc:"Whether to send invoice emails"`
	SendUsageAlerts      bool      `json:"sendUsageAlerts" example:"true" doc:"Whether to send usage alerts"`
	UsageAlertThreshold  int       `json:"usageAlertThreshold" example:"80" doc:"Usage alert threshold percentage"`
	Currency             string    `json:"currency" example:"usd" doc:"Preferred billing currency"`
	Timezone             string    `json:"timezone" example:"America/New_York" doc:"Billing timezone"`
	Language             string    `json:"language" example:"en" doc:"Billing language"`
	UpdatedAt            time.Time `json:"updatedAt" example:"2023-01-01T12:00:00Z" doc:"Last update timestamp"`
}

// UpdateBillingPreferencesRequest represents a request to update billing preferences
type UpdateBillingPreferencesRequest struct {
	AutoRenew            *bool   `json:"autoRenew,omitempty" example:"true" doc:"Auto-renewal setting"`
	CollectionMethod     *string `json:"collectionMethod,omitempty" example:"charge_automatically" doc:"Collection method" enum:"charge_automatically,send_invoice"`
	BillingCycleAnchor   *int    `json:"billingCycleAnchor,omitempty" example:"15" doc:"Billing cycle anchor day"`
	InvoiceDeliveryEmail *string `json:"invoiceDeliveryEmail,omitempty" example:"finance@example.com" doc:"Invoice delivery email"`
	SendInvoiceEmails    *bool   `json:"sendInvoiceEmails,omitempty" example:"true" doc:"Send invoice emails"`
	SendUsageAlerts      *bool   `json:"sendUsageAlerts,omitempty" example:"true" doc:"Send usage alerts"`
	UsageAlertThreshold  *int    `json:"usageAlertThreshold,omitempty" example:"85" doc:"Usage alert threshold"`
	Currency             *string `json:"currency,omitempty" example:"eur" doc:"Currency preference"`
	Timezone             *string `json:"timezone,omitempty" example:"Europe/London" doc:"Timezone preference"`
	Language             *string `json:"language,omitempty" example:"fr" doc:"Language preference"`
}
