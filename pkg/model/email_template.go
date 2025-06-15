package model

import (
	"time"

	"github.com/rs/xid"
)

// EmailTemplate represents an email template
type EmailTemplate struct {
	Base
	AuditBase
	Name           string                 `json:"name" example:"Welcome Email" doc:"Template name"`
	Subject        string                 `json:"subject" example:"Welcome to {{.OrganizationName}}" doc:"Email subject line"`
	Type           string                 `json:"type" example:"verification" doc:"Template type (verification, password_reset, invitation, etc.)"`
	HTMLContent    string                 `json:"htmlContent" doc:"HTML email content"`
	TextContent    string                 `json:"textContent,omitempty" doc:"Plain text email content"`
	OrganizationID *xid.ID                `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID (null for system templates)"`
	Active         bool                   `json:"active" example:"true" doc:"Whether template is active"`
	System         bool                   `json:"system" example:"false" doc:"Whether template is system-managed"`
	Locale         string                 `json:"locale" example:"en" doc:"Template locale"`
	Variables      []TemplateVariable     `json:"variables,omitempty" doc:"Available template variables"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional template metadata"`

	// Relationships
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
	Usage        *TemplateUsageStats  `json:"usage,omitempty" doc:"Template usage statistics"`
}

// EmailTemplateSummary represents a simplified email template for listings
type EmailTemplateSummary struct {
	ID         xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Template ID"`
	Name       string     `json:"name" example:"Welcome Email" doc:"Template name"`
	Type       string     `json:"type" example:"verification" doc:"Template type"`
	Subject    string     `json:"subject" example:"Welcome to {{.OrganizationName}}" doc:"Email subject"`
	Locale     string     `json:"locale" example:"en" doc:"Template locale"`
	Active     bool       `json:"active" example:"true" doc:"Whether template is active"`
	System     bool       `json:"system" example:"false" doc:"Whether template is system-managed"`
	LastUsed   *time.Time `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
	UsageCount int        `json:"usageCount" example:"150" doc:"Total usage count"`
	CreatedAt  time.Time  `json:"createdAt" example:"2023-01-01T10:00:00Z" doc:"Creation timestamp"`
}

// TemplateVariable represents a template variable
type TemplateVariable struct {
	Name        string `json:"name" example:"userName" doc:"Variable name"`
	Type        string `json:"type" example:"string" doc:"Variable type"`
	Required    bool   `json:"required" example:"true" doc:"Whether variable is required"`
	Description string `json:"description" example:"User's display name" doc:"Variable description"`
	Example     string `json:"example,omitempty" example:"John Doe" doc:"Example value"`
}

// TemplateUsageStats represents template usage statistics
type TemplateUsageStats struct {
	TotalSent    int        `json:"totalSent" example:"1500" doc:"Total emails sent"`
	SentToday    int        `json:"sentToday" example:"25" doc:"Emails sent today"`
	SentWeek     int        `json:"sentWeek" example:"180" doc:"Emails sent this week"`
	SentMonth    int        `json:"sentMonth" example:"750" doc:"Emails sent this month"`
	DeliveryRate float64    `json:"deliveryRate" example:"98.5" doc:"Delivery rate percentage"`
	OpenRate     float64    `json:"openRate,omitempty" example:"45.2" doc:"Open rate percentage"`
	ClickRate    float64    `json:"clickRate,omitempty" example:"12.8" doc:"Click rate percentage"`
	BounceRate   float64    `json:"bounceRate" example:"1.2" doc:"Bounce rate percentage"`
	LastUsed     *time.Time `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`

	TemplateKey       string  `json:"templateKey" example:"google" doc:"Template key"`
	TemplateName      string  `json:"templateName" example:"Google" doc:"Template name"`
	OrganizationCount int     `json:"organizationCount" example:"150" doc:"Number of organizations using this template"`
	TotalLogins       int     `json:"totalLogins" example:"5000" doc:"Total logins across all organizations"`
	AverageSetupTime  float64 `json:"averageSetupTime" example:"12.5" doc:"Average setup time in minutes"`
	SuccessRate       float64 `json:"successRate" example:"98.5" doc:"Setup success rate percentage"`
	PopularityRank    int     `json:"popularityRank" example:"1" doc:"Popularity ranking"`
}

// CreateEmailTemplateRequest represents a request to create an email template
type CreateEmailTemplateRequest struct {
	Name        string                 `json:"name" example:"Custom Welcome" doc:"Template name"`
	Subject     string                 `json:"subject" example:"Welcome to {{.OrganizationName}}!" doc:"Email subject"`
	Type        string                 `json:"type" example:"custom" doc:"Template type"`
	HTMLContent string                 `json:"htmlContent" doc:"HTML email content"`
	TextContent string                 `json:"textContent,omitempty" doc:"Plain text content"`
	Locale      string                 `json:"locale,omitempty" example:"en" doc:"Template locale"`
	Variables   []TemplateVariable     `json:"variables,omitempty" doc:"Template variables"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
}

// UpdateEmailTemplateRequest represents a request to update an email template
type UpdateEmailTemplateRequest struct {
	Name        string                 `json:"name,omitempty" example:"Updated Welcome" doc:"Updated name"`
	Subject     string                 `json:"subject,omitempty" example:"Updated subject" doc:"Updated subject"`
	HTMLContent string                 `json:"htmlContent,omitempty" doc:"Updated HTML content"`
	TextContent string                 `json:"textContent,omitempty" doc:"Updated text content"`
	Active      bool                   `json:"active,omitempty" example:"true" doc:"Updated active status"`
	Variables   []TemplateVariable     `json:"variables,omitempty" doc:"Updated variables"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" doc:"Updated metadata"`
}

// EmailTemplateListRequest represents a request to list email templates
type EmailTemplateListRequest struct {
	PaginationParams
	OrganizationID OptionalParam[xid.ID] `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization" query:"organizationId"`
	Type           string                `json:"type,omitempty" example:"verification" doc:"Filter by template type" query:"type"`
	Locale         string                `json:"locale,omitempty" example:"en" doc:"Filter by locale" query:"locale"`
	Active         OptionalParam[bool]   `json:"active,omitempty" example:"true" doc:"Filter by active status" query:"active"`
	System         OptionalParam[bool]   `json:"system,omitempty" example:"false" doc:"Filter by system status" query:"system"`
	Search         string                `json:"search,omitempty" example:"welcome" doc:"Search in name/subject" query:"search"`
}

// EmailTemplateListResponse represents a list of email templates
type EmailTemplateListResponse = PaginatedOutput[EmailTemplateSummary]

// PreviewEmailTemplateRequest represents a request to preview an email template
type PreviewEmailTemplateRequest struct {
	TemplateID xid.ID                 `json:"templateId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Template ID"`
	Variables  map[string]interface{} `json:"variables,omitempty" doc:"Variable values for preview"`
	Format     string                 `json:"format,omitempty" example:"html" doc:"Preview format (html, text, both)"`
}

// PreviewEmailTemplateResponse represents email template preview response
type PreviewEmailTemplateResponse struct {
	Subject     string                 `json:"subject" example:"Welcome to Acme Corp!" doc:"Rendered subject"`
	HTMLContent string                 `json:"htmlContent,omitempty" doc:"Rendered HTML content"`
	TextContent string                 `json:"textContent,omitempty" doc:"Rendered text content"`
	Variables   map[string]interface{} `json:"variables" doc:"Variables used in preview"`
}

// TestEmailTemplateRequest represents a request to send a test email
type TestEmailTemplateRequest struct {
	TemplateID   xid.ID                 `json:"templateId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Template ID"`
	ToEmail      string                 `json:"toEmail" example:"test@example.com" doc:"Test recipient email"`
	Variables    map[string]interface{} `json:"variables,omitempty" doc:"Variable values for test"`
	OverrideFrom string                 `json:"overrideFrom,omitempty" example:"test@myapp.com" doc:"Override sender email"`
}

// TestEmailTemplateResponse represents test email response
type TestEmailTemplateResponse struct {
	Success   bool   `json:"success" example:"true" doc:"Whether test email was sent"`
	MessageID string `json:"messageId,omitempty" example:"msg_123456" doc:"Email message ID"`
	Message   string `json:"message" example:"Test email sent successfully" doc:"Response message"`
	Error     string `json:"error,omitempty" example:"Invalid template variables" doc:"Error message if failed"`
}

// SendEmailRequest represents a request to send an email using a template
type SendEmailRequest struct {
	TemplateID   xid.ID                 `json:"templateId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Template ID"`
	ToEmail      string                 `json:"toEmail" example:"user@example.com" doc:"Recipient email"`
	ToName       string                 `json:"toName,omitempty" example:"John Doe" doc:"Recipient name"`
	Variables    map[string]interface{} `json:"variables,omitempty" doc:"Template variables"`
	FromEmail    string                 `json:"fromEmail,omitempty" example:"noreply@myapp.com" doc:"Override sender email"`
	FromName     string                 `json:"fromName,omitempty" example:"MyApp Team" doc:"Override sender name"`
	ReplyTo      string                 `json:"replyTo,omitempty" example:"support@myapp.com" doc:"Reply-to email"`
	Priority     string                 `json:"priority,omitempty" example:"normal" doc:"Email priority (low, normal, high)"`
	ScheduledFor *time.Time             `json:"scheduledFor,omitempty" example:"2023-01-01T13:00:00Z" doc:"Schedule email for later"`
	Tags         []string               `json:"tags,omitempty" example:"[\"welcome\", \"onboarding\"]" doc:"Email tags for tracking"`
}

// SendEmailResponse represents email send response
type SendEmailResponse struct {
	Success      bool       `json:"success" example:"true" doc:"Whether email was sent/scheduled"`
	MessageID    string     `json:"messageId,omitempty" example:"msg_123456" doc:"Email message ID"`
	ScheduledID  string     `json:"scheduledId,omitempty" example:"sched_789" doc:"Scheduled email ID"`
	Message      string     `json:"message" example:"Email sent successfully" doc:"Response message"`
	ScheduledFor *time.Time `json:"scheduledFor,omitempty" example:"2023-01-01T13:00:00Z" doc:"Scheduled send time"`
	Error        string     `json:"error,omitempty" example:"Template not found" doc:"Error message if failed"`
}

// BulkSendEmailRequest represents a bulk email send request
type BulkSendEmailRequest struct {
	TemplateID xid.ID           `json:"templateId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Template ID"`
	Recipients []EmailRecipient `json:"recipients" doc:"List of recipients"`
	FromEmail  string           `json:"fromEmail,omitempty" example:"noreply@myapp.com" doc:"Sender email"`
	FromName   string           `json:"fromName,omitempty" example:"MyApp Team" doc:"Sender name"`
	BatchSize  int              `json:"batchSize,omitempty" example:"100" doc:"Batch size for sending"`
	DelayMs    int              `json:"delayMs,omitempty" example:"1000" doc:"Delay between batches in milliseconds"`
	Tags       []string         `json:"tags,omitempty" example:"[\"newsletter\", \"announcement\"]" doc:"Email tags"`
}

// EmailRecipient represents a bulk email recipient
type EmailRecipient struct {
	Email     string                 `json:"email" example:"user@example.com" doc:"Recipient email"`
	Name      string                 `json:"name,omitempty" example:"John Doe" doc:"Recipient name"`
	Variables map[string]interface{} `json:"variables,omitempty" doc:"Personalized variables"`
}

// BulkSendEmailResponse represents bulk email send response
type BulkSendEmailResponse struct {
	Success       []string `json:"success" example:"[\"user1@example.com\", \"user2@example.com\"]" doc:"Successfully queued emails"`
	Failed        []string `json:"failed,omitempty" example:"[\"invalid@email\"]" doc:"Failed email addresses"`
	SuccessCount  int      `json:"successCount" example:"150" doc:"Number of successful emails"`
	FailureCount  int      `json:"failureCount" example:"2" doc:"Number of failed emails"`
	BatchID       string   `json:"batchId" example:"batch_123456" doc:"Bulk send batch ID"`
	EstimatedTime int      `json:"estimatedTime" example:"300" doc:"Estimated completion time in seconds"`
	Errors        []string `json:"errors,omitempty" example:"[\"Invalid email format\"]" doc:"Error messages"`
}

// EmailTemplateStats represents email template statistics
type EmailTemplateStats struct {
	TotalTemplates      int                    `json:"totalTemplates" example:"25" doc:"Total templates"`
	ActiveTemplates     int                    `json:"activeTemplates" example:"20" doc:"Active templates"`
	SystemTemplates     int                    `json:"systemTemplates" example:"10" doc:"System templates"`
	CustomTemplates     int                    `json:"customTemplates" example:"15" doc:"Custom templates"`
	TemplatesByType     map[string]int         `json:"templatesByType" example:"{\"verification\": 5, \"welcome\": 3}" doc:"Templates by type"`
	TemplatesByLocale   map[string]int         `json:"templatesByLocale" example:"{\"en\": 20, \"es\": 5}" doc:"Templates by locale"`
	TotalEmailsSent     int                    `json:"totalEmailsSent" example:"50000" doc:"Total emails sent"`
	EmailsSentToday     int                    `json:"emailsSentToday" example:"150" doc:"Emails sent today"`
	EmailsSentWeek      int                    `json:"emailsSentWeek" example:"1050" doc:"Emails sent this week"`
	EmailsSentMonth     int                    `json:"emailsSentMonth" example:"4500" doc:"Emails sent this month"`
	AverageDeliveryRate float64                `json:"averageDeliveryRate" example:"98.2" doc:"Average delivery rate"`
	AverageOpenRate     float64                `json:"averageOpenRate" example:"42.5" doc:"Average open rate"`
	AverageBounceRate   float64                `json:"averageBounceRate" example:"1.8" doc:"Average bounce rate"`
	TopTemplates        []TemplateUsageSummary `json:"topTemplates" doc:"Most used templates"`
}

// TemplateUsageSummary represents template usage summary
type TemplateUsageSummary struct {
	TemplateID   xid.ID  `json:"templateId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Template ID"`
	Name         string  `json:"name" example:"Welcome Email" doc:"Template name"`
	Type         string  `json:"type" example:"welcome" doc:"Template type"`
	SentCount    int     `json:"sentCount" example:"1500" doc:"Emails sent"`
	DeliveryRate float64 `json:"deliveryRate" example:"99.1" doc:"Delivery rate percentage"`
	OpenRate     float64 `json:"openRate,omitempty" example:"48.3" doc:"Open rate percentage"`
}

// CloneEmailTemplateRequest represents a request to clone a template
type CloneEmailTemplateRequest struct {
	SourceTemplateID xid.ID `json:"sourceTemplateId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Source template ID"`
	NewName          string `json:"newName" example:"Cloned Welcome Email" doc:"New template name"`
	NewType          string `json:"newType,omitempty" example:"custom" doc:"New template type"`
	NewLocale        string `json:"newLocale,omitempty" example:"es" doc:"New template locale"`
}

// ImportEmailTemplatesRequest represents a request to import templates
type ImportEmailTemplatesRequest struct {
	Templates []EmailTemplateImport `json:"templates" doc:"Templates to import"`
	Overwrite bool                  `json:"overwrite" example:"false" doc:"Whether to overwrite existing templates"`
	Validate  bool                  `json:"validate" example:"true" doc:"Whether to validate templates before import"`
}

// EmailTemplateImport represents a template for import
type EmailTemplateImport struct {
	Name        string                 `json:"name" example:"Imported Template" doc:"Template name"`
	Subject     string                 `json:"subject" example:"Imported Subject" doc:"Email subject"`
	Type        string                 `json:"type" example:"custom" doc:"Template type"`
	HTMLContent string                 `json:"htmlContent" doc:"HTML content"`
	TextContent string                 `json:"textContent,omitempty" doc:"Text content"`
	Locale      string                 `json:"locale" example:"en" doc:"Template locale"`
	Variables   []TemplateVariable     `json:"variables,omitempty" doc:"Template variables"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" doc:"Template metadata"`
}

// ImportEmailTemplatesResponse represents template import response
type ImportEmailTemplatesResponse struct {
	Imported     []string `json:"imported" example:"[\"Welcome Email\", \"Reset Password\"]" doc:"Successfully imported templates"`
	Failed       []string `json:"failed,omitempty" example:"[\"Invalid Template\"]" doc:"Failed template imports"`
	Skipped      []string `json:"skipped,omitempty" example:"[\"Existing Template\"]" doc:"Skipped templates"`
	ImportCount  int      `json:"importCount" example:"8" doc:"Number of imported templates"`
	FailureCount int      `json:"failureCount" example:"1" doc:"Number of failed imports"`
	SkipCount    int      `json:"skipCount" example:"2" doc:"Number of skipped templates"`
	Errors       []string `json:"errors,omitempty" example:"[\"Invalid HTML syntax\"]" doc:"Error messages"`
}

// EmailTemplateExportRequest represents a request to export templates
type EmailTemplateExportRequest struct {
	TemplateIDs    []xid.ID `json:"templateIds,omitempty" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Specific template IDs to export"`
	OrganizationID *xid.ID  `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Export templates for organization"`
	Type           string   `json:"type,omitempty" example:"custom" doc:"Filter by template type"`
	Locale         string   `json:"locale,omitempty" example:"en" doc:"Filter by locale"`
	Format         string   `json:"format" example:"json" doc:"Export format (json, yaml)"`
	IncludeUsage   bool     `json:"includeUsage" example:"true" doc:"Include usage statistics"`
}

// EmailTemplateExportResponse represents template export response
type EmailTemplateExportResponse struct {
	DownloadURL   string    `json:"downloadUrl" example:"https://api.example.com/downloads/templates-export-123.json" doc:"Download URL"`
	ExpiresAt     time.Time `json:"expiresAt" example:"2023-01-01T13:00:00Z" doc:"Download URL expiration"`
	Format        string    `json:"format" example:"json" doc:"Export format"`
	TemplateCount int       `json:"templateCount" example:"15" doc:"Number of templates exported"`
	FileSize      int       `json:"fileSize" example:"1048576" doc:"File size in bytes"`
}

type EmailCodeResponse struct {
	Message   string `json:"message" example:"SMS verification code"`
	ExpiresIn int    `json:"expiresIn" example:"3600" doc:"Expiration time in seconds"`
}

type SMSCodeResponse struct {
	Message   string `json:"message" example:"SMS verification code"`
	ExpiresIn int    `json:"expiresIn" example:"3600" doc:"Expiration time in seconds"`
}
