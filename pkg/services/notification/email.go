package notification

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/contexts"
	"github.com/juicycleff/frank/pkg/email"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// EmailService defines the interface for email operations
type EmailService interface {
	// Basic email sending
	SendEmail(ctx context.Context, email email.Email) error
	SendBulkEmails(ctx context.Context, emails []email.Email) (*email.BulkEmailResult, error)

	// Template-based emails
	SendTemplateEmail(ctx context.Context, templateID string, to []string, data map[string]interface{}) error
	SendSystemEmail(ctx context.Context, templateType, to string, data map[string]interface{}) error

	// Authentication-related emails
	SendWelcomeEmail(ctx context.Context, user *model.User, organizationName string) error
	SendVerificationEmail(ctx context.Context, user *model.User, token, code string, redirectURL string) error
	SendPasswordResetEmail(ctx context.Context, user *model.User, token string, redirectURL string) error
	SendMagicLinkEmail(ctx context.Context, user *model.User, token string, redirectURL string) error
	SendMFACodeEmail(ctx context.Context, user *model.User, code string) error

	// Organization-related emails
	SendInvitationEmail(ctx context.Context, invitation EmailInvitation) error
	SendInvitationReminderEmail(ctx context.Context, invitation EmailInvitation) error
	SendOrganizationUpdateEmail(ctx context.Context, members []string, update OrganizationUpdate) error

	// Security-related emails
	SendSecurityAlertEmail(ctx context.Context, user *model.User, alert SecurityAlert) error
	SendLoginNotificationEmail(ctx context.Context, user *model.User, login LoginNotification) error
	SendPasswordChangedEmail(ctx context.Context, user *model.User) error
	SendAccountLockedEmail(ctx context.Context, user *model.User, reason string) error

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
	GetDeliveryStatus(ctx context.Context, messageID string) (*email.DeliveryInfo, error)
	GetDeliveryStats(ctx context.Context, organizationID *xid.ID, period string) (*DeliveryStats, error)

	// Email validation and testing
	ValidateEmail(ctx context.Context, email string) (*EmailValidation, error)
	TestEmailConfiguration(ctx context.Context, config EmailConfig) error
	SendTestEmail(ctx context.Context, config EmailConfig, recipient string) error
}

// Email structures

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
	Timestamp     time.Time `json:"timestamp"`
	IPAddress     string    `json:"ip_address"`
	Location      string    `json:"location"`
	DeviceType    string    `json:"device_type"`
	DeviceName    string    `json:"device_name"`
	Browser       string    `json:"browser"`
	Suspicious    bool      `json:"suspicious"`
	ActionURL     string    `json:"action_url,omitempty"`
	IsNewDevice   bool      `json:"is_new_device,omitempty"`
	IsNewLocation bool      `json:"is_new_location,omitempty"`
}

type BillingEvent struct {
	Type             string                 `json:"type"` // invoice, payment, failure, etc.
	Amount           float64                `json:"amount"`
	Currency         string                 `json:"currency"`
	InvoiceID        string                 `json:"invoice_id"`
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
	ResourceType      string     `json:"resource_type"` // api_calls, storage, users
	CurrentUsage      int        `json:"current_usage"`
	Limit             int        `json:"limit"`
	PercentageUsed    float64    `json:"percentage_used"`
	ThresholdType     string     `json:"threshold_type"` // warning, critical
	BillingPeriodEnd  *time.Time `json:"billing_period_end"`
	OrganizationName  string     `json:"organization_name"`
	ActionRecommended string     `json:"action_recommended"`
	UpgradeURL        string     `json:"upgrade_url,omitempty"`
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

// emailService implements the EmailService interface
type emailService struct {
	templateRepo  repository.EmailTemplateRepository
	orgRepo       repository.OrganizationRepository
	userRepo      repository.UserRepository
	logger        logging.Logger
	config        *EmailServiceConfig
	defaultSender email.Sender
	templateCache map[string]*template.Template
}

// EmailServiceConfig holds email service configuration
type EmailServiceConfig struct {
	DefaultProvider     string         `json:"default_provider"`
	FromEmail           string         `json:"from_email"`
	FromName            string         `json:"from_name"`
	ReplyTo             string         `json:"reply_to"`
	TrackOpens          bool           `json:"track_opens"`
	TrackClicks         bool           `json:"track_clicks"`
	RetryAttempts       int            `json:"retry_attempts"`
	RetryDelay          time.Duration  `json:"retry_delay"`
	RateLimits          map[string]int `json:"rate_limits"`
	TemplateDirectory   string         `json:"template_directory"`
	EnableTemplateCache bool           `json:"enable_template_cache"`
	MaxBulkSize         int            `json:"max_bulk_size"`
	AppName             string         `json:"app_name"`
}

type ProviderConfig struct {
	Enabled  bool                   `json:"enabled"`
	Settings map[string]interface{} `json:"settings"`
	Priority int                    `json:"priority"`
}

// NewEmailService creates a new email service
func NewEmailService(
	sender email.Sender,
	templateRepo repository.EmailTemplateRepository,
	orgRepo repository.OrganizationRepository,
	userRepo repository.UserRepository,
	logger logging.Logger,
	config *EmailServiceConfig,
) EmailService {
	if config == nil {
		config = defaultEmailConfig()
	}

	service := &emailService{
		templateRepo:  templateRepo,
		orgRepo:       orgRepo,
		userRepo:      userRepo,
		logger:        logger,
		config:        config,
		defaultSender: sender,
		templateCache: make(map[string]*template.Template),
	}

	return service
}

func defaultEmailConfig() *EmailServiceConfig {
	return &EmailServiceConfig{
		DefaultProvider:     "smtp",
		FromEmail:           "noreply@example.com",
		FromName:            "Frank Auth",
		AppName:             "Frank Auth",
		TrackOpens:          true,
		TrackClicks:         true,
		RetryAttempts:       3,
		RetryDelay:          5 * time.Second,
		RateLimits:          map[string]int{"default": 100},
		MaxBulkSize:         100,
		EnableTemplateCache: true,
		TemplateDirectory:   "./templates/email",
	}
}

func (s *emailService) PreloadTemplates(ctx context.Context) (email.Sender, error) {
	return s.defaultSender, nil
}

// Basic email sending

func (s *emailService) getSender(ctx context.Context) (email.Sender, error) {
	return s.defaultSender, nil
}

func (s *emailService) SendEmail(ctx context.Context, email email.Email) error {
	// Set defaults
	if email.From == "" {
		email.From = s.config.FromEmail
	}
	if email.FromName == "" {
		email.FromName = s.config.FromName
	}
	if email.MessageID == "" {
		email.MessageID = s.generateMessageID()
	}
	if email.Provider == "" {
		email.Provider = s.config.DefaultProvider
	}

	// Validate email request
	if err := s.validateEmailRequest(email); err != nil {
		return errors.Wrap(err, errors.CodeBadRequest, "invalid email request")
	}

	// Get provider
	provider, err := s.getSender(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeBadRequest, fmt.Sprintf("unknown email provider: %s", email.Provider))
	}

	// Send email with retry logic
	var lastErr error
	for attempt := 0; attempt <= s.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			// Wait before retry
			time.Sleep(s.config.RetryDelay * time.Duration(attempt))
		}

		err := provider.Send(ctx, email)
		if err == nil {
			// Success
			s.logger.Info("email sent successfully",
				logging.String("message_id", email.MessageID),
				logging.String("provider", email.Provider),
				logging.String("to", strings.Join(email.To, ",")))
			return nil
		}

		lastErr = err
		s.logger.Warn("email send attempt failed",
			logging.String("message_id", email.MessageID),
			logging.Int("attempt", attempt+1),
			logging.Error(err))
	}

	return errors.Wrap(lastErr, errors.CodeInternalServer, "failed to send email after retries")
}

func (s *emailService) SendBulkEmails(ctx context.Context, emails []email.Email) (*email.BulkEmailResult, error) {
	if len(emails) > s.config.MaxBulkSize {
		return nil, errors.New(errors.CodeBadRequest,
			fmt.Sprintf("bulk size exceeds limit of %d", s.config.MaxBulkSize))
	}

	result := &email.BulkEmailResult{
		ProcessedAt: time.Now(),
	}

	// Group emails by provider
	providerGroups := make(map[string][]email.Email)
	for _, email := range emails {
		if email.Provider == "" {
			email.Provider = s.config.DefaultProvider
		}
		providerGroups[email.Provider] = append(providerGroups[email.Provider], email)
	}

	// Send emails by provider
	for providerName, providerEmails := range providerGroups {
		provider, err := s.getSender(ctx)
		if err != nil {
			// Mark all emails as failed
			for _, em := range providerEmails {
				result.Failed = append(result.Failed, email.FailedEmail{
					Email:  strings.Join(em.To, ","),
					Reason: "unknown_provider",
					Error:  fmt.Sprintf("unknown email provider: %s", providerName),
				})
			}
			continue
		}

		// Try bulk send first
		bulkResult, err := provider.SendBulkEmails(ctx, providerEmails)
		if err != nil {
			// Fall back to individual sends
			for _, em := range providerEmails {
				if sendErr := s.SendEmail(ctx, em); sendErr != nil {
					result.Failed = append(result.Failed, email.FailedEmail{
						Email:  strings.Join(em.To, ","),
						Reason: "send_failed",
						Error:  sendErr.Error(),
					})
				} else {
					result.Successful = append(result.Successful, strings.Join(em.To, ","))
				}
			}
		} else {
			// Use provider's bulk result
			result.Successful = append(result.Successful, bulkResult.Successful...)
			result.Failed = append(result.Failed, bulkResult.Failed...)
		}
	}

	result.SuccessCount = len(result.Successful)
	result.FailureCount = len(result.Failed)

	return result, nil
}

// Template-based emails

func (s *emailService) SendTemplateEmail(ctx context.Context, templateID string, to []string, data map[string]interface{}) error {
	// Render template
	rendered, err := s.RenderTemplate(ctx, templateID, data)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to render template")
	}

	// Send email
	em := email.Email{
		To:          to,
		Subject:     rendered.Subject,
		HTMLContent: rendered.HTMLContent,
		TextContent: rendered.TextContent,
		Headers:     rendered.Headers,
		TrackOpens:  s.config.TrackOpens,
		TrackClicks: s.config.TrackClicks,
	}

	return s.SendEmail(ctx, em)
}

func (s *emailService) SendSystemEmail(ctx context.Context, templateType, to string, data map[string]interface{}) error {
	// Get system template
	template, err := s.templateRepo.GetSystemTemplate(ctx, templateType, "en")
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "system template not found")
	}

	return s.SendTemplateEmail(ctx, template.ID.String(), []string{to}, data)
}

// Authentication-related emails

func (s *emailService) SendWelcomeEmail(ctx context.Context, user *model.User, organizationName string) error {
	data := map[string]interface{}{
		"UserName":         s.getUserDisplayName(user),
		"UserEmail":        user.Email,
		"OrganizationName": organizationName,
		"LoginUrl":         s.getLoginURL(),
	}

	return s.SendSystemEmail(ctx, "welcome", user.Email, data)
}

func (s *emailService) SendVerificationEmail(ctx context.Context, user *model.User, token string, code string, redirectURL string) error {
	verificationURL := s.buildVerificationURL(token, redirectURL)

	data := map[string]interface{}{
		"user_name":         s.getUserDisplayName(user),
		"verification_url":  verificationURL,
		"token":             token,
		"Code":              code,
		"verification_code": code,
		"has_both":          true,
		"app_name":          s.config.AppName,
		"expires_in":        "24 hours",
		"ExpiryTime":        "24 hours",
		"request_time":      time.Now().Format("2006-01-02 15:04:05"),
		"device_info":       time.Now().Format("2006-01-02 15:04:05"),
	}

	return s.SendSystemEmail(ctx, "email_verification", user.Email, data)
}

func (s *emailService) SendPasswordResetEmail(ctx context.Context, user *model.User, token string, redirectURL string) error {
	resetURL := s.buildPasswordResetURL(token, redirectURL)

	data := map[string]interface{}{
		"UserName":    s.getUserDisplayName(user),
		"FirstName":   s.getUserDisplayName(user),
		"ResetURL":    resetURL,
		"token":       token,
		"ExpiryTime":  "15 minutes",
		"RequestTime": time.Now().Format("2006-01-02 15:04:05"),
		"DeviceInfo":  time.Now().Format("2006-01-02 15:04:05"),
	}

	return s.SendSystemEmail(ctx, "password_reset", user.Email, data)
}

func (s *emailService) SendMagicLinkEmail(ctx context.Context, user *model.User, token string, redirectURL string) error {
	magicURL := s.buildMagicLinkURL(token, redirectURL)

	data := map[string]interface{}{
		"UserName":     s.getUserDisplayName(user),
		"FirstName":    s.getUserDisplayName(user),
		"MagicLinkURL": magicURL,
		"ExpiresIn":    "15 minutes",
		"ExpiryTime":   "15 minutes",
	}

	return s.SendSystemEmail(ctx, "magic_link", user.Email, data)
}

func (s *emailService) SendMFACodeEmail(ctx context.Context, user *model.User, code string) error {
	data := map[string]interface{}{
		"UserName":   s.getUserDisplayName(user),
		"MfaCode":    code,
		"ExpiresIn":  "10 minutes",
		"ExpiryTime": "10 minutes",
	}

	return s.SendSystemEmail(ctx, "mfa_code", user.Email, data)
}

// Organization-related emails

func (s *emailService) SendInvitationEmail(ctx context.Context, invitation EmailInvitation) error {
	data := map[string]interface{}{
		"inviter_name":      invitation.InviterName,
		"invitee_name":      invitation.InviteeName,
		"organization_name": invitation.OrganizationName,
		"role_name":         invitation.RoleName,
		"invitation_url":    invitation.InvitationURL,
		"expires_at":        invitation.ExpiresAt.Format("January 2, 2006"),
		"message":           invitation.Message,
	}

	return s.SendSystemEmail(ctx, "organization_invitation", invitation.InviteeEmail, data)
}

func (s *emailService) SendInvitationReminderEmail(ctx context.Context, invitation EmailInvitation) error {
	data := map[string]interface{}{
		"inviter_name":      invitation.InviterName,
		"invitee_name":      invitation.InviteeName,
		"organization_name": invitation.OrganizationName,
		"role_name":         invitation.RoleName,
		"invitation_url":    invitation.InvitationURL,
		"expires_at":        invitation.ExpiresAt.Format("January 2, 2006"),
	}

	return s.SendSystemEmail(ctx, "invitation_reminder", invitation.InviteeEmail, data)
}

func (s *emailService) SendOrganizationUpdateEmail(ctx context.Context, members []string, update OrganizationUpdate) error {
	data := map[string]interface{}{
		"update_type":       update.Type,
		"title":             update.Title,
		"description":       update.Description,
		"organization_name": update.OrganizationName,
		"updated_by":        update.UpdatedBy,
		"updated_at":        update.UpdatedAt.Format("January 2, 2006 at 3:04 PM"),
		"action_required":   update.ActionRequired,
		"action_url":        update.ActionURL,
	}

	em := email.Email{
		To:          members,
		Subject:     update.Title,
		TrackOpens:  s.config.TrackOpens,
		TrackClicks: s.config.TrackClicks,
	}

	// Render template
	rendered, err := s.renderSystemTemplate("organization_update", data)
	if err != nil {
		return err
	}

	em.HTMLContent = rendered.HTMLContent
	em.TextContent = rendered.TextContent

	return s.SendEmail(ctx, em)
}

// Security-related emails

func (s *emailService) SendSecurityAlertEmail(ctx context.Context, user *model.User, alert SecurityAlert) error {
	data := map[string]interface{}{
		"user_name":    s.getUserDisplayName(user),
		"alert_type":   alert.Type,
		"title":        alert.Title,
		"description":  alert.Description,
		"severity":     alert.Severity,
		"timestamp":    alert.Timestamp.Format("January 2, 2006 at 3:04 PM MST"),
		"ip_address":   alert.IPAddress,
		"location":     alert.Location,
		"user_agent":   alert.UserAgent,
		"action_taken": alert.ActionTaken,
		"action_url":   alert.ActionURL,
	}

	return s.SendSystemEmail(ctx, "security_alert", user.Email, data)
}

func (s *emailService) SendLoginNotificationEmail(ctx context.Context, user *model.User, login LoginNotification) error {
	data := map[string]interface{}{
		"user_name":   s.getUserDisplayName(user),
		"timestamp":   login.Timestamp.Format("January 2, 2006 at 3:04 PM MST"),
		"ip_address":  login.IPAddress,
		"location":    login.Location,
		"device_type": login.DeviceType,
		"browser":     login.Browser,
		"suspicious":  login.Suspicious,
		"action_url":  login.ActionURL,
	}

	templateType := "login_notification"
	if login.Suspicious {
		templateType = "suspicious_login"
	}

	return s.SendSystemEmail(ctx, templateType, user.Email, data)
}

func (s *emailService) SendPasswordChangedEmail(ctx context.Context, user *model.User) error {
	data := map[string]interface{}{
		"user_name": s.getUserDisplayName(user),
		"timestamp": time.Now().Format("January 2, 2006 at 3:04 PM MST"),
	}

	return s.SendSystemEmail(ctx, "password_changed", user.Email, data)
}

func (s *emailService) SendAccountLockedEmail(ctx context.Context, user *model.User, reason string) error {
	data := map[string]interface{}{
		"user_name": s.getUserDisplayName(user),
		"reason":    reason,
		"timestamp": time.Now().Format("January 2, 2006 at 3:04 PM MST"),
	}

	return s.SendSystemEmail(ctx, "account_locked", user.Email, data)
}

// Helper methods

func (s *emailService) generateMessageID() string {
	return fmt.Sprintf("frank_%s_%d", xid.New().String(), time.Now().Unix())
}

func (s *emailService) validateEmailRequest(email email.Email) error {
	if len(email.To) == 0 {
		return fmt.Errorf("recipient list cannot be empty")
	}

	if email.Subject == "" {
		return fmt.Errorf("subject cannot be empty")
	}

	if email.HTMLContent == "" && email.TextContent == "" {
		return fmt.Errorf("email must have either HTML or text content")
	}

	// Validate email addresses
	for _, addr := range email.To {
		if !s.isValidEmail(addr) {
			return fmt.Errorf("invalid email address: %s", addr)
		}
	}

	return nil
}

func (s *emailService) isValidEmail(email string) bool {
	// Simple email validation - in production, use a proper library
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

func (s *emailService) getUserDisplayName(user *model.User) string {
	if user.FirstName != "" && user.LastName != "" {
		return fmt.Sprintf("%s %s", user.FirstName, user.LastName)
	}
	if user.FirstName != "" {
		return user.FirstName
	}
	if user.Username != "" {
		return user.Username
	}
	return user.Email
}

func (s *emailService) getLoginURL() string {
	// Return login URL - should come from config
	return "https://app.frank.com/login"
}

func (s *emailService) buildVerificationURL(token, redirectURL string) string {
	baseURL := "https://app.frank.com/verify"
	if redirectURL != "" {
		return fmt.Sprintf("%s?token=%s&redirect=%s", baseURL, token, redirectURL)
	}
	return fmt.Sprintf("%s?token=%s", baseURL, token)
}

func (s *emailService) buildPasswordResetURL(token, redirectURL string) string {
	baseURL := "https://app.frank.com/reset-password"
	if redirectURL != "" {
		return fmt.Sprintf("%s?token=%s&redirect=%s", baseURL, token, redirectURL)
	}
	return fmt.Sprintf("%s?token=%s", baseURL, token)
}

func (s *emailService) buildMagicLinkURL(token, redirectURL string) string {
	baseURL := "https://app.frank.com/magic-link"
	if redirectURL != "" {
		return fmt.Sprintf("%s?token=%s&redirect=%s", baseURL, token, redirectURL)
	}
	return fmt.Sprintf("%s?token=%s", baseURL, token)
}

func (s *emailService) renderSystemTemplate(templateType string, data map[string]interface{}) (*RenderedEmail, error) {
	template, err := s.templateRepo.GetSystemTemplate(context.Background(), templateType, "en")
	if err != nil {
		return nil, err
	}

	return s.renderTemplate(template, data)
}

func (s *emailService) renderTemplate(template *ent.EmailTemplate, data map[string]interface{}) (*RenderedEmail, error) {
	// Parse and execute HTML template
	htmlTemplate, err := s.parseTemplate(template.HTMLContent)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to parse HTML template")
	}

	var htmlBuf bytes.Buffer
	if err := htmlTemplate.Execute(&htmlBuf, data); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to execute HTML template")
	}

	// Parse and execute text template if available
	var textContent string
	if template.TextContent != "" {
		textTemplate, err := s.parseTemplate(template.TextContent)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to parse text template")
		}

		var textBuf bytes.Buffer
		if err := textTemplate.Execute(&textBuf, data); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to execute text template")
		}
		textContent = textBuf.String()
	}

	// Parse and execute subject template
	subjectTemplate, err := s.parseTemplate(template.Subject)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to parse subject template")
	}

	var subjectBuf bytes.Buffer
	if err := subjectTemplate.Execute(&subjectBuf, data); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to execute subject template")
	}

	return &RenderedEmail{
		Subject:     subjectBuf.String(),
		HTMLContent: htmlBuf.String(),
		TextContent: textContent,
		Headers:     make(map[string]string),
	}, nil
}

func (s *emailService) parseTemplate(content string) (*template.Template, error) {
	return template.New("email").Parse(content)
}

// Placeholder implementations for remaining interface methods

func (s *emailService) SendBillingEmail(ctx context.Context, organizationID xid.ID, billingEvent BillingEvent) error {
	// TODO: Implement billing email
	return nil
}

func (s *emailService) SendUsageAlertEmail(ctx context.Context, organizationID xid.ID, usage UsageAlert) error {
	// TODO: Implement usage alert email
	return nil
}

func (s *emailService) CreateTemplate(ctx context.Context, template EmailTemplate) (*ent.EmailTemplate, error) {
	// TODO: Implement template creation
	return nil, errors.New(errors.CodeNotImplemented, "not implemented")
}

func (s *emailService) UpdateTemplate(ctx context.Context, templateID xid.ID, template EmailTemplate) (*ent.EmailTemplate, error) {
	// TODO: Implement template update
	return nil, errors.New(errors.CodeNotImplemented, "not implemented")
}

func (s *emailService) GetTemplate(ctx context.Context, templateID xid.ID) (*ent.EmailTemplate, error) {
	return s.templateRepo.GetByID(ctx, templateID)
}

func (s *emailService) ListTemplates(ctx context.Context, organizationID *xid.ID) ([]*ent.EmailTemplate, error) {
	// TODO: Implement template listing
	return []*ent.EmailTemplate{}, nil
}

func (s *emailService) RenderTemplate(ctx context.Context, templateID string, data map[string]interface{}) (*RenderedEmail, error) {
	// Parse template ID
	id, err := xid.FromString(templateID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBadRequest, "invalid template ID")
	}

	userAgent, _ := contexts.GetUserAgentFromContext(ctx)

	if data == nil {
		data = map[string]interface{}{}
	}

	if _, ok := data["DeviceInfo"]; !ok {
		data["DeviceInfo"] = userAgent
	}
	if _, ok := data["RequestTime"]; !ok {
		data["RequestTime"] = time.Now().UTC().Format(time.RFC3339)
	}
	if _, ok := data["CurrentYear"]; !ok {
		data["CurrentYear"] = time.Now().UTC().Format("2006")
	}

	template, err := s.templateRepo.GetByID(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "template not found")
	}

	return s.renderTemplate(template, data)
}

func (s *emailService) TrackDelivery(ctx context.Context, messageID string, status DeliveryStatus) error {
	// TODO: Implement delivery tracking
	return nil
}

func (s *emailService) GetDeliveryStatus(ctx context.Context, messageID string) (*email.DeliveryInfo, error) {
	// TODO: Implement delivery status retrieval
	return &email.DeliveryInfo{
		MessageID: messageID,
		Status:    "delivered",
		SentAt:    time.Now().Add(-time.Hour),
	}, nil
}

func (s *emailService) GetDeliveryStats(ctx context.Context, organizationID *xid.ID, period string) (*DeliveryStats, error) {
	// TODO: Implement delivery statistics
	return &DeliveryStats{
		Period:         period,
		TotalSent:      100,
		TotalDelivered: 95,
		DeliveryRate:   95.0,
		GeneratedAt:    time.Now(),
	}, nil
}

func (s *emailService) ValidateEmail(ctx context.Context, email string) (*EmailValidation, error) {
	// Simple email validation - in production, use a proper service
	valid := s.isValidEmail(email)

	return &EmailValidation{
		Email:       email,
		Valid:       valid,
		RiskLevel:   "low",
		Deliverable: valid,
		Disposable:  false,
		RoleAccount: false,
	}, nil
}

func (s *emailService) TestEmailConfiguration(ctx context.Context, config EmailConfig) error {
	// TODO: Implement configuration testing
	return nil
}

func (s *emailService) SendTestEmail(ctx context.Context, config EmailConfig, recipient string) error {
	// TODO: Implement test email sending
	return nil
}
