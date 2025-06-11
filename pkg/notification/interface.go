package notification

import (
	"time"

	"github.com/rs/xid"
)

// EmailService defines the interface for email operations
type EmailService interface {
	// Basic email sending
	SendEmail(ctx context.Context, email EmailRequest) error
	SendBulkEmails(ctx context.Context, emails []EmailRequest) (*BulkEmailResult, error)

	// Template-based emails
	SendTemplateEmail(ctx context.Context, templateID string, to []string, data map[string]interface{}) error
	SendSystemEmail(ctx context.Context, templateType, to string, data map[string]interface{}) error

	// Authentication-related emails
	SendWelcomeEmail(ctx context.Context, user *ent.User, organizationName string) error
	SendVerificationEmail(ctx context.Context, user *ent.User, token string, redirectURL string) error
	SendPasswordResetEmail(ctx context.Context, user *ent.User, token string, redirectURL string) error
	SendMagicLinkEmail(ctx context.Context, user *ent.User, token string, redirectURL string) error
	SendMFACodeEmail(ctx context.Context, user *ent.User, code string) error

	// Organization-related emails
	SendInvitationEmail(ctx context.Context, invitation EmailInvitation) error
	SendInvitationReminderEmail(ctx context.Context, invitation EmailInvitation) error
	SendOrganizationUpdateEmail(ctx context.Context, members []string, update OrganizationUpdate) error

	// Security-related emails
	SendSecurityAlertEmail(ctx context.Context, user *ent.User, alert SecurityAlert) error
	SendLoginNotificationEmail(ctx context.Context, user *ent.User, login LoginNotification) error
	SendPasswordChangedEmail(ctx context.Context, user *ent.User) error
	SendAccountLockedEmail(ctx context.Context, user *ent.User, reason string) error

	// Billing and subscription emails
	SendBillingEmail(ctx context.Context, organizationID xid.ID, billingEvent BillingEvent) error
	SendUsageAlertEmail(ctx context.Context, organizationID xid.ID, usage UsageAlert) error

	// Template management
	CreateTemplate(ctx context.Context, template EmailTemplate) (*ent.EmailTemplate, error)
	UpdateTemplate(ctx context.Context, templateID xid.ID, template EmailTemplate) (*ent.EmailTemplate, error)
	GetTemplate(ctx context.Context, templateID xid.ID) (*ent.EmailTemplate, error)
	ListTemplates(ctx context.Context, organizationID *xid.ID) ([]*ent.EmailTemplate, error)
	RenderTemplate(ctx context.Context, templateID string, data map[string]interface{}) (*RenderedEmail, error)

	// Email delivery tracking
	TrackDelivery(ctx context.Context, messageID string, status DeliveryStatus) error
	GetDeliveryStatus(ctx context.Context, messageID string) (*DeliveryInfo, error)
	GetDeliveryStats(ctx context.Context, organizationID *xid.ID, period string) (*DeliveryStats, error)

	// Email validation and testing
	ValidateEmail(ctx context.Context, email string) (*EmailValidation, error)
	TestEmailConfiguration(ctx context.Context, config EmailConfig) error
	SendTestEmail(ctx context.Context, config EmailConfig, recipient string) error
}

// Email structures

type EmailRequest struct {
	MessageID   string                 `json:"message_id,omitempty"`
	From        string                 `json:"from"`
	FromName    string                 `json:"from_name,omitempty"`
	To          []string               `json:"to"`
	CC          []string               `json:"cc,omitempty"`
	BCC         []string               `json:"bcc,omitempty"`
	ReplyTo     string                 `json:"reply_to,omitempty"`
	Subject     string                 `json:"subject"`
	HTMLContent string                 `json:"html_content,omitempty"`
	TextContent string                 `json:"text_content,omitempty"`
	Attachments []EmailAttachment      `json:"attachments,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	ScheduledAt *time.Time             `json:"scheduled_at,omitempty"`
	TrackOpens  bool                   `json:"track_opens"`
	TrackClicks bool                   `json:"track_clicks"`
	Priority    string                 `json:"priority,omitempty"` // high, normal, low
	Provider    string                 `json:"provider,omitempty"` // smtp, sendgrid, ses, etc.
}

type EmailAttachment struct {
	Filename    string `json:"filename"`
	Content     []byte `json:"content"`
	ContentType string `json:"content_type"`
	Disposition string `json:"disposition,omitempty"` // attachment, inline
	ContentID   string `json:"content_id,omitempty"`
}

type BulkEmailResult struct {
	Successful   []string      `json:"successful"`
	Failed       []FailedEmail `json:"failed"`
	SuccessCount int           `json:"success_count"`
	FailureCount int           `json:"failure_count"`
	ProcessedAt  time.Time     `json:"processed_at"`
}

type FailedEmail struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
	Error  string `json:"error"`
}

type EmailInvitation struct {
	InviterName      string                 `json:"inviter_name"`
	InviterEmail     string                 `json:"inviter_email"`
	InviteeEmail     string                 `json:"invitee_email"`
	InviteeName      string                 `json:"invitee_name,omitempty"`
	OrganizationName string                 `json:"organization_name"`
	RoleName         string                 `json:"role_name"`
	InvitationURL    string                 `json:"invitation_url"`
	ExpiresAt        time.Time              `json:"expires_at"`
	Message          string                 `json:"message,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

type OrganizationUpdate struct {
	Type             string                 `json:"type"` // name_change, plan_upgrade, etc.
	Title            string                 `json:"title"`
	Description      string                 `json:"description"`
	OrganizationName string                 `json:"organization_name"`
	UpdatedBy        string                 `json:"updated_by"`
	UpdatedAt        time.Time              `json:"updated_at"`
	ActionRequired   bool                   `json:"action_required"`
	ActionURL        string                 `json:"action_url,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

type SecurityAlert struct {
	Type        string    `json:"type"` // login_attempt, password_change, etc.
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // low, medium, high, critical
	Timestamp   time.Time `json:"timestamp"`
	IPAddress   string    `json:"ip_address,omitempty"`
	Location    string    `json:"location,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	ActionTaken string    `json:"action_taken,omitempty"`
	ActionURL   string    `json:"action_url,omitempty"`
}

type LoginNotification struct {
	Timestamp  time.Time `json:"timestamp"`
	IPAddress  string    `json:"ip_address"`
	Location   string    `json:"location"`
	DeviceType string    `json:"device_type"`
	Browser    string    `json:"browser"`
	Suspicious bool      `json:"suspicious"`
	ActionURL  string    `json:"action_url,omitempty"`
}

type BillingEvent struct {
	Type             string                 `json:"type"` // invoice, payment, failure, etc.
	Amount           float64                `json:"amount"`
	Currency         string                 `json:"currency"`
	InvoiceNumber    string                 `json:"invoice_number,omitempty"`
	DueDate          *time.Time             `json:"due_date,omitempty"`
	PaymentDate      *time.Time             `json:"payment_date,omitempty"`
	Description      string                 `json:"description"`
	PaymentMethod    string                 `json:"payment_method,omitempty"`
	FailureReason    string                 `json:"failure_reason,omitempty"`
	ActionRequired   bool                   `json:"action_required"`
	ActionURL        string                 `json:"action_url,omitempty"`
	OrganizationName string                 `json:"organization_name"`
	BillingContact   string                 `json:"billing_contact"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

type UsageAlert struct {
	ResourceType      string    `json:"resource_type"` // api_calls, storage, users
	CurrentUsage      int       `json:"current_usage"`
	Limit             int       `json:"limit"`
	PercentageUsed    float64   `json:"percentage_used"`
	ThresholdType     string    `json:"threshold_type"` // warning, critical
	BillingPeriodEnd  time.Time `json:"billing_period_end"`
	OrganizationName  string    `json:"organization_name"`
	ActionRecommended string    `json:"action_recommended"`
	UpgradeURL        string    `json:"upgrade_url,omitempty"`
}

type EmailTemplate struct {
	ID             xid.ID                 `json:"id,omitempty"`
	Name           string                 `json:"name"`
	DisplayName    string                 `json:"display_name"`
	Description    string                 `json:"description,omitempty"`
	TemplateType   string                 `json:"template_type"`
	OrganizationID *xid.ID                `json:"organization_id,omitempty"`
	Subject        string                 `json:"subject"`
	HTMLContent    string                 `json:"html_content"`
	TextContent    string                 `json:"text_content,omitempty"`
	Variables      []TemplateVariable     `json:"variables"`
	Locale         string                 `json:"locale"`
	Active         bool                   `json:"active"`
	IsSystem       bool                   `json:"is_system"`
	Category       string                 `json:"category,omitempty"`
	Tags           []string               `json:"tags,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	Version        int                    `json:"version"`
	CreatedBy      *xid.ID                `json:"created_by,omitempty"`
}

type TemplateVariable struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"` // string, number, boolean, date, object
	Required     bool        `json:"required"`
	DefaultValue interface{} `json:"default_value,omitempty"`
	Description  string      `json:"description,omitempty"`
}

type RenderedEmail struct {
	Subject     string            `json:"subject"`
	HTMLContent string            `json:"html_content"`
	TextContent string            `json:"text_content"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type DeliveryStatus struct {
	MessageID  string                 `json:"message_id"`
	Status     string                 `json:"status"` // sent, delivered, bounced, complained, opened, clicked
	Timestamp  time.Time              `json:"timestamp"`
	Reason     string                 `json:"reason,omitempty"`
	BounceType string                 `json:"bounce_type,omitempty"`
	Recipient  string                 `json:"recipient"`
	Provider   string                 `json:"provider"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type DeliveryInfo struct {
	MessageID    string                 `json:"message_id"`
	Status       string                 `json:"status"`
	SentAt       time.Time              `json:"sent_at"`
	DeliveredAt  *time.Time             `json:"delivered_at,omitempty"`
	OpenedAt     *time.Time             `json:"opened_at,omitempty"`
	ClickedAt    *time.Time             `json:"clicked_at,omitempty"`
	BouncedAt    *time.Time             `json:"bounced_at,omitempty"`
	BounceReason string                 `json:"bounce_reason,omitempty"`
	Opens        int                    `json:"opens"`
	Clicks       int                    `json:"clicks"`
	Provider     string                 `json:"provider"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type DeliveryStats struct {
	Period         string         `json:"period"`
	TotalSent      int            `json:"total_sent"`
	TotalDelivered int            `json:"total_delivered"`
	TotalBounced   int            `json:"total_bounced"`
	TotalOpened    int            `json:"total_opened"`
	TotalClicked   int            `json:"total_clicked"`
	DeliveryRate   float64        `json:"delivery_rate"`
	OpenRate       float64        `json:"open_rate"`
	ClickRate      float64        `json:"click_rate"`
	BounceRate     float64        `json:"bounce_rate"`
	ByProvider     map[string]int `json:"by_provider"`
	ByType         map[string]int `json:"by_type"`
	GeneratedAt    time.Time      `json:"generated_at"`
}

type EmailValidation struct {
	Email       string   `json:"email"`
	Valid       bool     `json:"valid"`
	Reason      string   `json:"reason,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
	RiskLevel   string   `json:"risk_level"` // low, medium, high
	Deliverable bool     `json:"deliverable"`
	Disposable  bool     `json:"disposable"`
	RoleAccount bool     `json:"role_account"`
}

type EmailConfig struct {
	Provider      string                 `json:"provider"`
	FromEmail     string                 `json:"from_email"`
	FromName      string                 `json:"from_name"`
	ReplyTo       string                 `json:"reply_to,omitempty"`
	Settings      map[string]interface{} `json:"settings"`
	TestRecipient string                 `json:"test_recipient,omitempty"`
}

// SMSService defines the interface for SMS operations
type SMSService interface {
	// Basic SMS sending
	SendSMS(ctx context.Context, sms SMSRequest) error
	SendBulkSMS(ctx context.Context, messages []SMSRequest) (*BulkSMSResult, error)

	// Template-based SMS
	SendTemplateSMS(ctx context.Context, templateID string, to []string, data map[string]interface{}) error
	SendSystemSMS(ctx context.Context, templateType, to string, data map[string]interface{}) error

	// Authentication-related SMS
	SendWelcomeSMS(ctx context.Context, user *ent.User, organizationName string) error
	SendVerificationSMS(ctx context.Context, user *ent.User, code string) error
	SendPasswordResetSMS(ctx context.Context, user *ent.User, code string) error
	SendMagicLinkSMS(ctx context.Context, user *ent.User, code, redirectURL string) error
	SendMFACodeSMS(ctx context.Context, user *ent.User, code string) error
	SendLoginVerificationSMS(ctx context.Context, user *ent.User, code string) error

	// Organization-related SMS
	SendInvitationSMS(ctx context.Context, invitation SMSInvitation) error
	SendInvitationReminderSMS(ctx context.Context, invitation SMSInvitation) error
	SendOrganizationUpdateSMS(ctx context.Context, phoneNumbers []string, update OrganizationUpdate) error

	// Security-related SMS
	SendSecurityAlertSMS(ctx context.Context, user *ent.User, alert SecurityAlert) error
	SendLoginNotificationSMS(ctx context.Context, user *ent.User, login LoginNotification) error
	SendPasswordChangedSMS(ctx context.Context, user *ent.User) error
	SendAccountLockedSMS(ctx context.Context, user *ent.User, reason string) error
	SendSuspiciousActivitySMS(ctx context.Context, user *ent.User, activity SuspiciousActivity) error

	// Billing and subscription SMS
	SendBillingSMS(ctx context.Context, organizationID xid.ID, billingEvent BillingEvent) error
	SendUsageAlertSMS(ctx context.Context, organizationID xid.ID, usage UsageAlert) error
	SendPaymentFailedSMS(ctx context.Context, organizationID xid.ID, paymentInfo PaymentFailure) error

	// Template management
	CreateSMSTemplate(ctx context.Context, template SMSTemplate) (*ent.SMSTemplate, error)
	UpdateSMSTemplate(ctx context.Context, templateID xid.ID, template SMSTemplate) (*ent.SMSTemplate, error)
	GetSMSTemplate(ctx context.Context, templateID xid.ID) (*ent.SMSTemplate, error)
	ListSMSTemplates(ctx context.Context, organizationID *xid.ID) ([]*ent.SMSTemplate, error)
	RenderSMSTemplate(ctx context.Context, templateID string, data map[string]interface{}) (*RenderedSMS, error)

	// SMS delivery tracking
	TrackSMSDelivery(ctx context.Context, messageID string, status SMSDeliveryStatus) error
	GetSMSDeliveryStatus(ctx context.Context, messageID string) (*SMSDeliveryInfo, error)
	GetSMSDeliveryStats(ctx context.Context, organizationID *xid.ID, period string) (*SMSDeliveryStats, error)

	// Phone number validation and testing
	ValidatePhoneNumber(ctx context.Context, phoneNumber string) (*PhoneValidation, error)
	TestSMSConfiguration(ctx context.Context, config SMSConfig) error
	SendTestSMS(ctx context.Context, config SMSConfig, recipient string) error

	// Rate limiting and compliance
	CheckSendingLimits(ctx context.Context, organizationID xid.ID, phoneNumber string) (*SendingLimits, error)
	GetOptOutStatus(ctx context.Context, phoneNumber string) (*OptOutStatus, error)
	ProcessOptOut(ctx context.Context, phoneNumber string, reason string) error
	ProcessOptIn(ctx context.Context, phoneNumber string) error

	// Carrier and routing
	GetCarrierInfo(ctx context.Context, phoneNumber string) (*CarrierInfo, error)
	GetOptimalRoute(ctx context.Context, phoneNumber, messageType string) (*SMSRoute, error)
}

// SMSRequest represents a basic SMS request
type SMSRequest struct {
	To              string                 `json:"to" example:"+1234567890" doc:"Recipient phone number"`
	Message         string                 `json:"message" example:"Your verification code is 123456" doc:"SMS message content"`
	From            string                 `json:"from,omitempty" example:"+1987654321" doc:"Sender phone number"`
	MessageType     string                 `json:"messageType,omitempty" example:"transactional" doc:"Message type (transactional, promotional, etc.)"`
	Priority        string                 `json:"priority,omitempty" example:"high" doc:"Message priority"`
	ScheduledFor    *time.Time             `json:"scheduledFor,omitempty" doc:"Schedule message for later"`
	Tags            []string               `json:"tags,omitempty" doc:"Message tags for tracking"`
	Metadata        map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
	OrganizationID  xid.ID                 `json:"organizationId" doc:"Organization ID"`
	UserID          *xid.ID                `json:"userId,omitempty" doc:"User ID if applicable"`
	TTL             int                    `json:"ttl,omitempty" doc:"Time to live in seconds"`
	CallbackURL     string                 `json:"callbackUrl,omitempty" doc:"Delivery callback URL"`
	ValidityPeriod  int                    `json:"validityPeriod,omitempty" doc:"Validity period in seconds"`
	RequireDelivery bool                   `json:"requireDelivery" doc:"Require delivery confirmation"`
	AllowOptOut     bool                   `json:"allowOptOut" doc:"Allow opt-out responses"`
}

// BulkSMSResult represents the result of bulk SMS sending
type BulkSMSResult struct {
	BatchID        string              `json:"batchId" doc:"Bulk send batch ID"`
	TotalMessages  int                 `json:"totalMessages" doc:"Total messages in batch"`
	QueuedMessages int                 `json:"queuedMessages" doc:"Successfully queued messages"`
	FailedMessages int                 `json:"failedMessages" doc:"Failed messages"`
	EstimatedCost  float64             `json:"estimatedCost" doc:"Estimated cost"`
	Currency       string              `json:"currency" doc:"Cost currency"`
	Results        []BulkSMSItemResult `json:"results" doc:"Individual message results"`
	Errors         []string            `json:"errors,omitempty" doc:"Error messages"`
}

// BulkSMSItemResult represents individual message result in bulk send
type BulkSMSItemResult struct {
	PhoneNumber string  `json:"phoneNumber" doc:"Recipient phone number"`
	MessageID   string  `json:"messageId,omitempty" doc:"Message ID if successful"`
	Status      string  `json:"status" doc:"Send status"`
	Error       string  `json:"error,omitempty" doc:"Error message if failed"`
	Cost        float64 `json:"cost,omitempty" doc:"Message cost"`
}

// SMSInvitation represents an SMS invitation
type SMSInvitation struct {
	InviterName      string                 `json:"inviterName" doc:"Name of person sending invitation"`
	OrganizationName string                 `json:"organizationName" doc:"Organization name"`
	PhoneNumber      string                 `json:"phoneNumber" doc:"Recipient phone number"`
	InvitationToken  string                 `json:"invitationToken" doc:"Invitation token"`
	Role             string                 `json:"role" doc:"Role being invited to"`
	ExpiresAt        time.Time              `json:"expiresAt" doc:"Invitation expiration"`
	CustomMessage    string                 `json:"customMessage,omitempty" doc:"Custom invitation message"`
	Metadata         map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
	JoinURL          string                 `json:"joinUrl" doc:"URL to join organization"`
}

// SuspiciousActivity represents suspicious activity alert
type SuspiciousActivity struct {
	ActivityType string                 `json:"activityType" doc:"Type of suspicious activity"`
	Description  string                 `json:"description" doc:"Activity description"`
	IPAddress    string                 `json:"ipAddress,omitempty" doc:"IP address involved"`
	Location     string                 `json:"location,omitempty" doc:"Geographic location"`
	Timestamp    time.Time              `json:"timestamp" doc:"Activity timestamp"`
	RiskLevel    string                 `json:"riskLevel" doc:"Risk level (low, medium, high)"`
	ActionTaken  string                 `json:"actionTaken,omitempty" doc:"Action taken"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" doc:"Additional details"`
}

// PaymentFailure represents payment failure information
type PaymentFailure struct {
	Amount         float64    `json:"amount" doc:"Failed payment amount"`
	Currency       string     `json:"currency" doc:"Payment currency"`
	PaymentMethod  string     `json:"paymentMethod" doc:"Payment method that failed"`
	FailureReason  string     `json:"failureReason" doc:"Reason for failure"`
	AttemptCount   int        `json:"attemptCount" doc:"Number of retry attempts"`
	NextRetryAt    *time.Time `json:"nextRetryAt,omitempty" doc:"Next retry timestamp"`
	InvoiceID      string     `json:"invoiceId" doc:"Invoice ID"`
	SubscriptionID string     `json:"subscriptionId" doc:"Subscription ID"`
}

// SMSTemplate represents an SMS template
type SMSTemplate struct {
	Name           string                 `json:"name" doc:"Template name"`
	Content        string                 `json:"content" doc:"SMS content with variables"`
	Type           string                 `json:"type" doc:"Template type"`
	OrganizationID *xid.ID                `json:"organizationId,omitempty" doc:"Organization ID"`
	Active         bool                   `json:"active" doc:"Whether template is active"`
	System         bool                   `json:"system" doc:"Whether template is system-managed"`
	Locale         string                 `json:"locale" doc:"Template locale"`
	Variables      []SMSTemplateVariable  `json:"variables,omitempty" doc:"Available variables"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
	MaxLength      int                    `json:"maxLength" doc:"Maximum message length"`
	MessageType    string                 `json:"messageType" doc:"Message type (transactional, promotional)"`
}

// SMSTemplateVariable represents an SMS template variable
type SMSTemplateVariable struct {
	Name        string `json:"name" doc:"Variable name"`
	Type        string `json:"type" doc:"Variable type"`
	Required    bool   `json:"required" doc:"Whether variable is required"`
	Description string `json:"description" doc:"Variable description"`
	Example     string `json:"example,omitempty" doc:"Example value"`
	MaxLength   int    `json:"maxLength,omitempty" doc:"Maximum variable length"`
}

// RenderedSMS represents a rendered SMS message
type RenderedSMS struct {
	Content   string                 `json:"content" doc:"Rendered SMS content"`
	Length    int                    `json:"length" doc:"Message length"`
	Segments  int                    `json:"segments" doc:"Number of SMS segments"`
	Variables map[string]interface{} `json:"variables" doc:"Variables used"`
	Cost      float64                `json:"cost,omitempty" doc:"Estimated cost"`
	Currency  string                 `json:"currency,omitempty" doc:"Cost currency"`
}
