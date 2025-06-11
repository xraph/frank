package model

import (
	"time"

	"github.com/rs/xid"
)

// InvitationStatus represents the status of an invitation
type InvitationStatus string

const (
	InvitationStatusPending   InvitationStatus = "pending"
	InvitationStatusAccepted  InvitationStatus = "accepted"
	InvitationStatusDeclined  InvitationStatus = "declined"
	InvitationStatusExpired   InvitationStatus = "expired"
	InvitationStatusCancelled InvitationStatus = "cancelled"
)

// Invitation represents an organization invitation
type Invitation struct {
	Base
	Email          string                 `json:"email" example:"user@example.com" doc:"Invited user email address"`
	OrganizationID xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	RoleID         xid.ID                 `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID to assign"`
	Status         string                 `json:"status" example:"pending" doc:"Invitation status" enum:"pending,accepted,declined,expired,cancelled"`
	Token          string                 `json:"token,omitempty" example:"abc123def456" doc:"Invitation token"`
	ExpiresAt      *time.Time             `json:"expiresAt" example:"2023-01-08T12:00:00Z" doc:"Invitation expiration time"`
	InvitedBy      *xid.ID                `json:"invitedBy,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User who sent the invitation"`
	AcceptedAt     *time.Time             `json:"acceptedAt,omitempty" example:"2023-01-02T12:00:00Z" doc:"When invitation was accepted"`
	AcceptedBy     *xid.ID                `json:"acceptedBy,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User who accepted the invitation"`
	DeclinedAt     *time.Time             `json:"declinedAt,omitempty" example:"2023-01-02T12:00:00Z" doc:"When invitation was declined"`
	Message        string                 `json:"message,omitempty" example:"Welcome to our team!" doc:"Personal message from inviter"`
	RedirectURL    string                 `json:"redirectUrl,omitempty" example:"https://app.example.com/dashboard" doc:"URL to redirect to after acceptance"`
	CustomFields   map[string]interface{} `json:"customFields,omitempty" doc:"Custom invitation fields"`
	LastSentAt     *time.Time             `json:"lastSentAt,omitempty" example:"2023-01-01T12:00:00Z" doc:"When invitation was last sent"`
	SendCount      int                    `json:"sendCount" example:"1" doc:"Number of times invitation was sent"`

	// Relationships
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
	Role         *RoleSummary         `json:"role,omitempty" doc:"Role information"`
	Inviter      *UserSummary         `json:"inviter,omitempty" doc:"User who sent the invitation"`
}

// InvitationSummary represents a simplified invitation for listings
type InvitationSummary struct {
	ID              xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Invitation ID"`
	Email           string     `json:"email" example:"user@example.com" doc:"Invited email"`
	OrganizationID  xid.ID     `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	RoleID          xid.ID     `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	RoleName        string     `json:"roleName" example:"admin" doc:"Role name"`
	Status          string     `json:"status" example:"pending" doc:"Invitation status" enum:"pending,accepted,declined,expired,cancelled"`
	CreatedAt       time.Time  `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Creation timestamp"`
	ExpiresAt       *time.Time `json:"expiresAt" example:"2023-01-08T12:00:00Z" doc:"Expiration timestamp"`
	InvitedBy       *xid.ID    `json:"invitedBy,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Inviter user ID"`
	InviterName     string     `json:"inviterName,omitempty" example:"John Doe" doc:"Inviter full name"`
	InviterEmail    string     `json:"inviterEmail,omitempty" example:"inviter@example.com" doc:"Inviter email"`
	AcceptedAt      *time.Time `json:"acceptedAt,omitempty" example:"2023-01-02T12:00:00Z" doc:"Acceptance timestamp"`
	IsExpired       bool       `json:"isExpired" example:"false" doc:"Whether invitation has expired"`
	DaysUntilExpiry int        `json:"daysUntilExpiry" example:"7" doc:"Days until expiration"`
}

// CreateInvitationRequest represents a request to create an invitation
type CreateInvitationRequest struct {
	Email        string                 `json:"email" example:"user@example.com" doc:"Email address to invite" validate:"required,email"`
	RoleID       xid.ID                 `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID to assign" validate:"required"`
	Message      string                 `json:"message,omitempty" example:"Welcome to our team!" doc:"Personal invitation message"`
	ExpiresAt    *time.Time             `json:"expiresAt,omitempty" example:"2023-01-08T12:00:00Z" doc:"Custom expiration time"`
	RedirectURL  string                 `json:"redirectUrl,omitempty" example:"https://app.example.com/dashboard" doc:"Post-acceptance redirect URL"`
	SendEmail    bool                   `json:"sendEmail" example:"true" doc:"Whether to send invitation email"`
	CustomFields map[string]interface{} `json:"customFields,omitempty" doc:"Custom invitation fields"`
}

// AcceptInvitationRequest represents a request to accept an invitation
type AcceptInvitationRequest struct {
	Token       string `json:"token" example:"inv_token_123" doc:"Invitation token"`
	Password    string `json:"password,omitempty" example:"password123" doc:"Password for new user"`
	FirstName   string `json:"firstName,omitempty" example:"John" doc:"First name (if empty in invitation)"`
	LastName    string `json:"lastName,omitempty" example:"Doe" doc:"Last name (if empty in invitation)"`
	AcceptTerms bool   `json:"acceptTerms" example:"true" doc:"Accept terms and conditions"`
}

// AcceptInvitationResponse represents the response to invitation acceptance
type AcceptInvitationResponse struct {
	Success      bool                `json:"success" example:"true" doc:"Whether invitation was accepted"`
	User         User                `json:"user" doc:"User information"`
	Organization OrganizationSummary `json:"organization" doc:"Organization information"`
	Membership   Membership          `json:"membership" doc:"Created membership"`
	AccessToken  string              `json:"accessToken,omitempty" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." doc:"Access token for auto-login"`
	RefreshToken string              `json:"refreshToken,omitempty" example:"refresh_token_123" doc:"Refresh token"`
}

// UpdateInvitationRequest represents a request to update an invitation
type UpdateInvitationRequest struct {
	Message      string                 `json:"message,omitempty" example:"Updated welcome message" doc:"Updated invitation message"`
	ExpiresAt    *time.Time             `json:"expiresAt,omitempty" example:"2023-01-15T12:00:00Z" doc:"Updated expiration time"`
	RedirectURL  string                 `json:"redirectUrl,omitempty" example:"https://app.example.com/welcome" doc:"Updated redirect URL"`
	CustomFields map[string]interface{} `json:"customFields,omitempty" doc:"Updated custom fields"`
}

// DeclineInvitationRequest represents a request to decline an invitation
type DeclineInvitationRequest struct {
	Token  string `json:"token" example:"abc123def456" doc:"Invitation token" validate:"required"`
	Reason string `json:"reason,omitempty" example:"Not interested at this time" doc:"Reason for declining"`
}

// ResendInvitationRequest represents a request to resend an invitation
type ResendInvitationRequest struct {
	CustomMessage string `json:"customMessage,omitempty" example:"Reminder: Please join our team!" doc:"Custom message for resend"`
	ExtendExpiry  bool   `json:"extendExpiry" example:"true" doc:"Whether to extend expiration by 7 days"`
	InvitationID  xid.ID `json:"invitationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Invitation ID to resend" validate:"required"`
	Message       string `json:"message,omitempty" example:"Resending your invitation" doc:"Updated message for resend"`
}

// CancelInvitationRequest represents a request to cancel an invitation
type CancelInvitationRequest struct {
	Reason string `json:"reason,omitempty" example:"Position filled" doc:"Reason for cancellation"`
}

// ListInvitationsParams represents parameters for listing invitations
type ListInvitationsParams struct {
	PaginationParams
	Status         OptionalParam[InvitationStatus] `json:"status,omitempty" query:"status" example:"pending" doc:"Filter by invitation status" enum:"pending,accepted,declined,expired,cancelled"`
	Email          string                          `json:"email,omitempty" query:"email" example:"user@example.com" doc:"Filter by email address"`
	RoleID         OptionalParam[xid.ID]           `json:"roleId,omitempty" query:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by role ID"`
	InvitedBy      OptionalParam[xid.ID]           `json:"invitedBy,omitempty" query:"invitedBy" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by inviter"`
	Search         string                          `json:"search,omitempty" query:"search" example:"john" doc:"Search in email, message"`
	IncludeExpired bool                            `json:"includeExpired" query:"includeExpired" example:"false" doc:"Include expired invitations"`
	StartDate      OptionalParam[time.Time]        `json:"startDate,omitempty" query:"startDate" example:"2023-01-01T00:00:00Z" doc:"Filter from date"`
	EndDate        OptionalParam[time.Time]        `json:"endDate,omitempty" query:"endDate" example:"2023-01-31T23:59:59Z" doc:"Filter to date"`
	SortBy         string                          `json:"sortBy,omitempty" query:"sortBy" example:"createdAt" doc:"Sort field" enum:"createdAt,expiresAt,email,status"`
	SortOrder      string                          `json:"sortOrder,omitempty" query:"sortOrder" example:"desc" doc:"Sort order" enum:"asc,desc"`
}

// InvitationListResponse represents a list of invitations
type InvitationListResponse = PaginatedOutput[InvitationSummary]

// BulkInvitationInput represents input for bulk invitations
type BulkInvitationInput struct {
	Email        string                 `json:"email" example:"user@example.com" doc:"Email address to invite" validate:"required,email"`
	RoleID       xid.ID                 `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID to assign" validate:"required"`
	Message      string                 `json:"message,omitempty" example:"Welcome to our team!" doc:"Personal invitation message"`
	CustomFields map[string]interface{} `json:"customFields,omitempty" doc:"Custom invitation fields"`
}

// BulkCreateInvitationsRequest represents a request to create multiple invitations
type BulkCreateInvitationsRequest struct {
	Invitations []BulkInvitationInput `json:"invitations" doc:"List of invitations to create" validate:"required,min=1,max=100"`
	SendEmails  bool                  `json:"sendEmails" example:"true" doc:"Whether to send invitation emails"`
	ExpiresAt   *time.Time            `json:"expiresAt,omitempty" example:"2023-01-08T12:00:00Z" doc:"Expiration time for all invitations"`
	RedirectURL string                `json:"redirectUrl,omitempty" example:"https://app.example.com/dashboard" doc:"Redirect URL for all invitations"`
}

// BulkInvitationResponse represents the response to bulk invitation operations
type BulkInvitationResponse struct {
	SuccessCount int                   `json:"successCount" example:"8" doc:"Number of successful operations"`
	FailureCount int                   `json:"failureCount" example:"2" doc:"Number of failed operations"`
	TotalCount   int                   `json:"totalCount" example:"10" doc:"Total number of operations attempted"`
	Invitations  []InvitationSummary   `json:"invitations,omitempty" doc:"Successfully created invitations"`
	Errors       []BulkInvitationError `json:"errors,omitempty" doc:"Errors encountered during bulk operation"`
	ProcessedAt  time.Time             `json:"processedAt" example:"2023-01-01T12:00:00Z" doc:"When bulk operation was processed"`
}

// BulkInvitationError represents an error in bulk invitation processing
type BulkInvitationError struct {
	Email        string `json:"email" example:"invalid@email" doc:"Email that caused the error"`
	RoleID       xid.ID `json:"roleId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID that caused the error"`
	InvitationID xid.ID `json:"invitationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Invitation ID that caused the error"`
	Error        string `json:"error" example:"Invalid email address" doc:"Error message"`
	Code         string `json:"code" example:"INVALID_EMAIL" doc:"Error code"`
	Field        string `json:"field,omitempty" example:"email" doc:"Field that caused the error"`
}

// BulkResendInvitationsRequest represents a request to resend multiple invitations
type BulkResendInvitationsRequest struct {
	InvitationIDs []xid.ID `json:"invitationIds" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"List of invitation IDs to resend" validate:"required,min=1,max=50"`
	Message       string   `json:"message,omitempty" example:"Reminder: Please join our team" doc:"Updated message for all resends"`
}

// BulkCancelInvitationsRequest represents a request to cancel multiple invitations
type BulkCancelInvitationsRequest struct {
	InvitationIDs []xid.ID `json:"invitationIds" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"List of invitation IDs to cancel" validate:"required,min=1,max=50"`
	Reason        string   `json:"reason,omitempty" example:"Position no longer available" doc:"Reason for cancellation"`
}

// InvitationStats represents invitation statistics
type InvitationStats struct {
	TotalSent       int     `json:"totalSent" example:"150" doc:"Total invitations sent"`
	TotalAccepted   int     `json:"totalAccepted" example:"120" doc:"Total invitations accepted"`
	TotalDeclined   int     `json:"totalDeclined" example:"15" doc:"Total invitations declined"`
	TotalPending    int     `json:"totalPending" example:"10" doc:"Total pending invitations"`
	TotalExpired    int     `json:"totalExpired" example:"5" doc:"Total expired invitations"`
	TotalCancelled  int     `json:"totalCancelled" example:"8" doc:"Total cancelled invitations"`
	AcceptanceRate  float64 `json:"acceptanceRate" example:"85.7" doc:"Acceptance rate percentage"`
	DeclineRate     float64 `json:"declineRate" example:"10.7" doc:"Decline rate percentage"`
	ExpiryRate      float64 `json:"expiryRate" example:"3.6" doc:"Expiry rate percentage"`
	RecentSent      int     `json:"recentSent" example:"25" doc:"Invitations sent in last 30 days"`
	RecentAccepted  int     `json:"recentAccepted" example:"20" doc:"Invitations accepted in last 30 days"`
	AvgResponseTime float64 `json:"avgResponseTime" example:"2.5" doc:"Average response time in days"`
	FastestResponse float64 `json:"fastestResponse" example:"0.2" doc:"Fastest response time in days"`
	SlowestResponse float64 `json:"slowestResponse" example:"6.8" doc:"Slowest response time in days"`

	// Breakdown by status
	StatusBreakdown map[string]int `json:"statusBreakdown" example:"{\"pending\":10,\"accepted\":120}" doc:"Breakdown by status"`

	// Breakdown by role
	RoleBreakdown map[string]InvitationRoleStats `json:"roleBreakdown,omitempty" doc:"Breakdown by role"`

	// Time-based stats
	MonthlyStats []MonthlyInvitationStats `json:"monthlyStats,omitempty" doc:"Monthly invitation statistics"`
}

// InvitationRoleStats represents invitation statistics by role
type InvitationRoleStats struct {
	RoleID         xid.ID  `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	RoleName       string  `json:"roleName" example:"admin" doc:"Role name"`
	TotalSent      int     `json:"totalSent" example:"25" doc:"Total sent for this role"`
	TotalAccepted  int     `json:"totalAccepted" example:"20" doc:"Total accepted for this role"`
	AcceptanceRate float64 `json:"acceptanceRate" example:"80.0" doc:"Acceptance rate for this role"`
}

// MonthlyInvitationStats represents monthly invitation statistics
type MonthlyInvitationStats struct {
	Month          string  `json:"month" example:"2023-01" doc:"Month in YYYY-MM format"`
	TotalSent      int     `json:"totalSent" example:"45" doc:"Total sent in this month"`
	TotalAccepted  int     `json:"totalAccepted" example:"38" doc:"Total accepted in this month"`
	AcceptanceRate float64 `json:"acceptanceRate" example:"84.4" doc:"Acceptance rate for this month"`
}

// InvitationMetrics represents invitation metrics for a specific period
type InvitationMetrics struct {
	Period             string                      `json:"period" example:"30d" doc:"Metrics period"`
	StartDate          time.Time                   `json:"startDate" example:"2023-01-01T00:00:00Z" doc:"Period start date"`
	EndDate            time.Time                   `json:"endDate" example:"2023-01-31T23:59:59Z" doc:"Period end date"`
	TotalSent          int                         `json:"totalSent" example:"75" doc:"Total invitations sent in period"`
	TotalAccepted      int                         `json:"totalAccepted" example:"60" doc:"Total invitations accepted in period"`
	TotalDeclined      int                         `json:"totalDeclined" example:"8" doc:"Total invitations declined in period"`
	TotalExpired       int                         `json:"totalExpired" example:"7" doc:"Total invitations expired in period"`
	AcceptanceRate     float64                     `json:"acceptanceRate" example:"80.0" doc:"Acceptance rate percentage"`
	DeclineRate        float64                     `json:"declineRate" example:"10.7" doc:"Decline rate percentage"`
	ExpiryRate         float64                     `json:"expiryRate" example:"9.3" doc:"Expiry rate percentage"`
	AvgResponseTime    float64                     `json:"avgResponseTime" example:"2.3" doc:"Average response time in days"`
	MedianResponseTime float64                     `json:"medianResponseTime" example:"1.8" doc:"Median response time in days"`
	ConversionFunnel   ConversionFunnel            `json:"conversionFunnel" doc:"Invitation conversion funnel"`
	TrendAnalysis      InvitationTrend             `json:"trendAnalysis" doc:"Trend analysis"`
	TopInviters        []InviterStats              `json:"topInviters,omitempty" doc:"Top inviters in period"`
	RolePerformance    []RoleInvitationPerformance `json:"rolePerformance,omitempty" doc:"Performance by role"`
}

// ConversionFunnel represents the invitation conversion funnel
type ConversionFunnel struct {
	Sent      int `json:"sent" example:"100" doc:"Total invitations sent"`
	Delivered int `json:"delivered" example:"98" doc:"Invitations successfully delivered"`
	Opened    int `json:"opened" example:"85" doc:"Invitations opened (if tracking available)"`
	Clicked   int `json:"clicked" example:"70" doc:"Invitation links clicked"`
	Accepted  int `json:"accepted" example:"60" doc:"Invitations accepted"`

	DeliveryRate   float64 `json:"deliveryRate" example:"98.0" doc:"Delivery rate percentage"`
	OpenRate       float64 `json:"openRate" example:"86.7" doc:"Open rate percentage"`
	ClickRate      float64 `json:"clickRate" example:"82.4" doc:"Click rate percentage"`
	ConversionRate float64 `json:"conversionRate" example:"85.7" doc:"Click to acceptance rate"`
}

// InvitationTrend represents invitation trend analysis
type InvitationTrend struct {
	Direction        string             `json:"direction" example:"increasing" doc:"Trend direction" enum:"increasing,decreasing,stable"`
	ChangePercentage float64            `json:"changePercentage" example:"15.5" doc:"Change percentage from previous period"`
	Velocity         float64            `json:"velocity" example:"2.5" doc:"Rate of change per day"`
	Seasonality      string             `json:"seasonality,omitempty" example:"weekday_peak" doc:"Detected seasonal patterns"`
	Forecast         InvitationForecast `json:"forecast,omitempty" doc:"Next period forecast"`
}

// InvitationForecast represents forecasted invitation metrics
type InvitationForecast struct {
	NextPeriod        string   `json:"nextPeriod" example:"next_30d" doc:"Forecast period"`
	PredictedSent     int      `json:"predictedSent" example:"85" doc:"Predicted invitations to be sent"`
	PredictedAccepted int      `json:"predictedAccepted" example:"68" doc:"Predicted acceptances"`
	ConfidenceLevel   float64  `json:"confidenceLevel" example:"78.5" doc:"Forecast confidence percentage"`
	FactorsConsidered []string `json:"factorsConsidered" example:"[\"historical_trend\", \"seasonal_patterns\"]" doc:"Factors used in forecast"`
}

// InviterStats represents statistics for individual inviters
type InviterStats struct {
	UserID          xid.ID  `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Inviter user ID"`
	Name            string  `json:"name" example:"John Doe" doc:"Inviter name"`
	Email           string  `json:"email" example:"john@example.com" doc:"Inviter email"`
	TotalSent       int     `json:"totalSent" example:"25" doc:"Total invitations sent"`
	TotalAccepted   int     `json:"totalAccepted" example:"22" doc:"Total invitations accepted"`
	AcceptanceRate  float64 `json:"acceptanceRate" example:"88.0" doc:"Personal acceptance rate"`
	AvgResponseTime float64 `json:"avgResponseTime" example:"1.8" doc:"Average response time for their invitations"`
}

// RoleInvitationPerformance represents invitation performance by role
type RoleInvitationPerformance struct {
	RoleID          xid.ID  `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	RoleName        string  `json:"roleName" example:"developer" doc:"Role name"`
	TotalSent       int     `json:"totalSent" example:"30" doc:"Total invitations sent for this role"`
	TotalAccepted   int     `json:"totalAccepted" example:"25" doc:"Total invitations accepted for this role"`
	AcceptanceRate  float64 `json:"acceptanceRate" example:"83.3" doc:"Acceptance rate for this role"`
	AvgResponseTime float64 `json:"avgResponseTime" example:"2.1" doc:"Average response time for this role"`
	PopularityRank  int     `json:"popularityRank" example:"3" doc:"Rank by acceptance rate"`
}

// InvitationValidationRequest represents a request to validate an invitation token
type InvitationValidationRequest struct {
	Token string `json:"token" example:"abc123def456" doc:"Invitation token to validate" validate:"required"`
}

// InvitationValidationResponse represents the response to invitation validation
type InvitationValidationResponse struct {
	Valid         bool        `json:"valid" example:"true" doc:"Whether the invitation is valid"`
	Expired       bool        `json:"expired" example:"false" doc:"Whether the invitation has expired"`
	AlreadyUsed   bool        `json:"alreadyUsed" example:"false" doc:"Whether the invitation was already used"`
	Invitation    *Invitation `json:"invitation,omitempty" doc:"Invitation details if valid"`
	Error         string      `json:"error,omitempty" example:"Invitation has expired" doc:"Error message if invalid"`
	ExpiresAt     *time.Time  `json:"expiresAt,omitempty" example:"2023-01-08T12:00:00Z" doc:"Expiration time"`
	TimeRemaining string      `json:"timeRemaining,omitempty" example:"5d 14h 30m" doc:"Time remaining until expiration"`
}

// InvitationLinkRequest represents a request to generate an invitation link
type InvitationLinkRequest struct {
	Token        string `json:"token" example:"abc123def456" doc:"Invitation token" validate:"required"`
	CustomDomain string `json:"customDomain,omitempty" example:"auth.company.com" doc:"Custom domain for invitation link"`
}

// InvitationLinkResponse represents the response with invitation link
type InvitationLinkResponse struct {
	InvitationLink string    `json:"invitationLink" example:"https://auth.example.com/accept-invitation?token=abc123" doc:"Complete invitation link"`
	ShortLink      string    `json:"shortLink,omitempty" example:"https://short.ly/inv123" doc:"Shortened invitation link"`
	QRCode         string    `json:"qrCode,omitempty" example:"data:image/png;base64,..." doc:"QR code image data URL"`
	ExpiresAt      time.Time `json:"expiresAt" example:"2023-01-08T12:00:00Z" doc:"Link expiration time"`
}

// InvitationPreviewRequest represents a request to preview an invitation
type InvitationPreviewRequest struct {
	Email        string `json:"email" example:"user@example.com" doc:"Recipient email" validate:"required,email"`
	RoleID       xid.ID `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID" validate:"required"`
	Message      string `json:"message,omitempty" example:"Welcome to our team!" doc:"Custom message"`
	TemplateType string `json:"templateType" example:"default" doc:"Email template type" enum:"default,welcome,urgent"`
}

// InvitationPreviewResponse represents the preview of an invitation email
type InvitationPreviewResponse struct {
	Subject     string                  `json:"subject" example:"You're invited to join Acme Corp" doc:"Email subject"`
	HtmlContent string                  `json:"htmlContent" doc:"HTML email content"`
	TextContent string                  `json:"textContent" doc:"Plain text email content"`
	Recipient   InvitationRecipientInfo `json:"recipient" doc:"Recipient information"`
}

// InvitationRecipientInfo represents information about the invitation recipient
type InvitationRecipientInfo struct {
	Email            string `json:"email" example:"user@example.com" doc:"Recipient email"`
	RoleName         string `json:"roleName" example:"Developer" doc:"Role name they're being invited to"`
	OrganizationName string `json:"organizationName" example:"Acme Corp" doc:"Organization name"`
	InviterName      string `json:"inviterName" example:"John Doe" doc:"Name of person sending invitation"`
	InviterEmail     string `json:"inviterEmail" example:"john@example.com" doc:"Email of person sending invitation"`
}

// InvitationCleanupRequest represents a request to cleanup expired invitations
type InvitationCleanupRequest struct {
	DryRun    bool               `json:"dryRun" example:"true" doc:"Whether to perform a dry run"`
	OlderThan time.Time          `json:"olderThan,omitempty" example:"2023-01-01T00:00:00Z" doc:"Clean up invitations older than this date"`
	Status    []InvitationStatus `json:"status,omitempty" example:"[\"expired\",\"declined\"]" doc:"Statuses to clean up"`
	MaxCount  int                `json:"maxCount,omitempty" example:"1000" doc:"Maximum number of invitations to clean up"`
}

// InvitationCleanupResponse represents the response to cleanup operation
type InvitationCleanupResponse struct {
	CleanedCount int       `json:"cleanedCount" example:"150" doc:"Number of invitations cleaned up"`
	TotalFound   int       `json:"totalFound" example:"200" doc:"Total number of invitations found for cleanup"`
	DryRun       bool      `json:"dryRun" example:"false" doc:"Whether this was a dry run"`
	CleanedIDs   []xid.ID  `json:"cleanedIds,omitempty" doc:"IDs of cleaned up invitations (if requested)"`
	ProcessedAt  time.Time `json:"processedAt" example:"2023-01-01T12:00:00Z" doc:"When cleanup was processed"`
	TimeElapsed  string    `json:"timeElapsed" example:"1.25s" doc:"Time taken for cleanup operation"`
}

// InvitationReminderRequest represents a request to send invitation reminders
type InvitationReminderRequest struct {
	InvitationIDs    []xid.ID `json:"invitationIds,omitempty" doc:"Specific invitation IDs to remind (if empty, will find pending invitations)"`
	DaysBeforeExpiry int      `json:"daysBeforeExpiry" example:"2" doc:"Send reminders to invitations expiring within this many days"`
	CustomMessage    string   `json:"customMessage,omitempty" example:"Just a friendly reminder about your invitation" doc:"Custom reminder message"`
	MaxReminders     int      `json:"maxReminders" example:"100" doc:"Maximum number of reminders to send"`
}

// InvitationReminderResponse represents the response to reminder operation
type InvitationReminderResponse struct {
	SentCount    int       `json:"sentCount" example:"25" doc:"Number of reminders sent"`
	SkippedCount int       `json:"skippedCount" example:"5" doc:"Number of invitations skipped"`
	FailedCount  int       `json:"failedCount" example:"2" doc:"Number of failed reminder sends"`
	Errors       []string  `json:"errors,omitempty" doc:"Error messages for failed sends"`
	ProcessedAt  time.Time `json:"processedAt" example:"2023-01-01T12:00:00Z" doc:"When reminders were processed"`
}
