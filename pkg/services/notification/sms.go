package notification

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/juicycleff/frank/pkg/sms"
	"github.com/rs/xid"
	"go.uber.org/zap"
)

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
type SMSRequest = sms.SMS

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

// SMSDeliveryStatus represents SMS delivery status
type SMSDeliveryStatus string

const (
	SMSStatusPending   SMSDeliveryStatus = "pending"
	SMSStatusQueued    SMSDeliveryStatus = "queued"
	SMSStatusSent      SMSDeliveryStatus = "sent"
	SMSStatusDelivered SMSDeliveryStatus = "delivered"
	SMSStatusFailed    SMSDeliveryStatus = "failed"
	SMSStatusRejected  SMSDeliveryStatus = "rejected"
	SMSStatusExpired   SMSDeliveryStatus = "expired"
	SMSStatusUnknown   SMSDeliveryStatus = "unknown"
)

// SMSDeliveryInfo represents SMS delivery information
type SMSDeliveryInfo struct {
	MessageID     string                 `json:"messageId" doc:"Message ID"`
	Status        SMSDeliveryStatus      `json:"status" doc:"Delivery status"`
	StatusMessage string                 `json:"statusMessage,omitempty" doc:"Status description"`
	SentAt        *time.Time             `json:"sentAt,omitempty" doc:"Send timestamp"`
	DeliveredAt   *time.Time             `json:"deliveredAt,omitempty" doc:"Delivery timestamp"`
	FailedAt      *time.Time             `json:"failedAt,omitempty" doc:"Failure timestamp"`
	ErrorCode     string                 `json:"errorCode,omitempty" doc:"Error code if failed"`
	ErrorMessage  string                 `json:"errorMessage,omitempty" doc:"Error message if failed"`
	Segments      int                    `json:"segments" doc:"Number of segments"`
	Cost          float64                `json:"cost" doc:"Message cost"`
	Currency      string                 `json:"currency" doc:"Cost currency"`
	Carrier       string                 `json:"carrier,omitempty" doc:"Carrier network"`
	Country       string                 `json:"country,omitempty" doc:"Destination country"`
	Region        string                 `json:"region,omitempty" doc:"Destination region"`
	Metadata      map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
}

// SMSDeliveryStats represents SMS delivery statistics
type SMSDeliveryStats struct {
	TotalSent      int                     `json:"totalSent" doc:"Total messages sent"`
	TotalDelivered int                     `json:"totalDelivered" doc:"Total messages delivered"`
	TotalFailed    int                     `json:"totalFailed" doc:"Total messages failed"`
	DeliveryRate   float64                 `json:"deliveryRate" doc:"Delivery rate percentage"`
	FailureRate    float64                 `json:"failureRate" doc:"Failure rate percentage"`
	AverageCost    float64                 `json:"averageCost" doc:"Average cost per message"`
	TotalCost      float64                 `json:"totalCost" doc:"Total cost"`
	Currency       string                  `json:"currency" doc:"Cost currency"`
	ByCarrier      map[string]CarrierStats `json:"byCarrier,omitempty" doc:"Stats by carrier"`
	ByCountry      map[string]CountryStats `json:"byCountry,omitempty" doc:"Stats by country"`
	ByStatus       map[string]int          `json:"byStatus" doc:"Messages by status"`
	Period         string                  `json:"period" doc:"Statistics period"`
}

// CarrierStats represents statistics by carrier
type CarrierStats struct {
	Sent         int     `json:"sent" doc:"Messages sent"`
	Delivered    int     `json:"delivered" doc:"Messages delivered"`
	Failed       int     `json:"failed" doc:"Messages failed"`
	DeliveryRate float64 `json:"deliveryRate" doc:"Delivery rate"`
	AverageCost  float64 `json:"averageCost" doc:"Average cost"`
}

// // CountryStats represents statistics by country
// type CountryStats struct {
// 	Sent         int     `json:"sent" doc:"Messages sent"`
// 	Delivered    int     `json:"delivered" doc:"Messages delivered"`
// 	Failed       int     `json:"failed" doc:"Messages failed"`
// 	DeliveryRate float64 `json:"deliveryRate" doc:"Delivery rate"`
// 	AverageCost  float64 `json:"averageCost" doc:"Average cost"`
// }

// PhoneValidation represents phone number validation result
type PhoneValidation struct {
	PhoneNumber    string                 `json:"phoneNumber" doc:"Original phone number"`
	IsValid        bool                   `json:"isValid" doc:"Whether number is valid"`
	FormattedE164  string                 `json:"formattedE164,omitempty" doc:"E164 formatted number"`
	CountryCode    string                 `json:"countryCode,omitempty" doc:"Country code"`
	CountryName    string                 `json:"countryName,omitempty" doc:"Country name"`
	Carrier        string                 `json:"carrier,omitempty" doc:"Carrier network"`
	LineType       string                 `json:"lineType,omitempty" doc:"Line type (mobile, landline, voip)"`
	IsRoaming      bool                   `json:"isRoaming" doc:"Whether number is roaming"`
	IsReachable    bool                   `json:"isReachable" doc:"Whether number is reachable"`
	RiskScore      float64                `json:"riskScore" doc:"Risk score (0-1)"`
	Reputation     string                 `json:"reputation,omitempty" doc:"Number reputation"`
	Timezone       string                 `json:"timezone,omitempty" doc:"Timezone"`
	ValidationTime time.Time              `json:"validationTime" doc:"Validation timestamp"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
}

// SMSConfig represents SMS configuration
type SMSConfig struct {
	Provider       string                 `json:"provider" doc:"SMS provider"`
	APIKey         string                 `json:"apiKey" doc:"Provider API key"`
	APISecret      string                 `json:"apiSecret,omitempty" doc:"Provider API secret"`
	SenderID       string                 `json:"senderId,omitempty" doc:"Sender ID"`
	WebhookURL     string                 `json:"webhookUrl,omitempty" doc:"Webhook URL for delivery reports"`
	DefaultRouting string                 `json:"defaultRouting,omitempty" doc:"Default routing preference"`
	RateLimits     map[string]int         `json:"rateLimits,omitempty" doc:"Rate limits by destination"`
	EnableUnicode  bool                   `json:"enableUnicode" doc:"Enable unicode messages"`
	EnableDelivery bool                   `json:"enableDelivery" doc:"Enable delivery reports"`
	MaxRetries     int                    `json:"maxRetries" doc:"Maximum retry attempts"`
	RetryDelay     int                    `json:"retryDelay" doc:"Retry delay in seconds"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional configuration"`
}

// SendingLimits represents sending limits and current usage
type SendingLimits struct {
	OrganizationID   xid.ID    `json:"organizationId" doc:"Organization ID"`
	PhoneNumber      string    `json:"phoneNumber,omitempty" doc:"Phone number if number-specific"`
	HourlyLimit      int       `json:"hourlyLimit" doc:"Messages per hour limit"`
	DailyLimit       int       `json:"dailyLimit" doc:"Messages per day limit"`
	MonthlyLimit     int       `json:"monthlyLimit" doc:"Messages per month limit"`
	HourlyUsed       int       `json:"hourlyUsed" doc:"Messages sent this hour"`
	DailyUsed        int       `json:"dailyUsed" doc:"Messages sent today"`
	MonthlyUsed      int       `json:"monthlyUsed" doc:"Messages sent this month"`
	CanSend          bool      `json:"canSend" doc:"Whether more messages can be sent"`
	NextResetAt      time.Time `json:"nextResetAt" doc:"When limits reset"`
	RemainingHourly  int       `json:"remainingHourly" doc:"Remaining hourly messages"`
	RemainingDaily   int       `json:"remainingDaily" doc:"Remaining daily messages"`
	RemainingMonthly int       `json:"remainingMonthly" doc:"Remaining monthly messages"`
}

// OptOutStatus represents opt-out status for a phone number
type OptOutStatus struct {
	PhoneNumber  string                 `json:"phoneNumber" doc:"Phone number"`
	IsOptedOut   bool                   `json:"isOptedOut" doc:"Whether number is opted out"`
	OptedOutAt   *time.Time             `json:"optedOutAt,omitempty" doc:"Opt-out timestamp"`
	OptInAt      *time.Time             `json:"optInAt,omitempty" doc:"Opt-in timestamp"`
	Reason       string                 `json:"reason,omitempty" doc:"Opt-out reason"`
	Source       string                 `json:"source,omitempty" doc:"Opt-out source (reply, api, manual)"`
	MessageTypes []string               `json:"messageTypes,omitempty" doc:"Opted out message types"`
	CanReceive   map[string]bool        `json:"canReceive" doc:"Can receive by message type"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
}

// CarrierInfo represents carrier information for a phone number
type CarrierInfo struct {
	PhoneNumber string    `json:"phoneNumber" doc:"Phone number"`
	CarrierName string    `json:"carrierName" doc:"Carrier name"`
	CountryCode string    `json:"countryCode" doc:"Country code"`
	CountryName string    `json:"countryName" doc:"Country name"`
	NetworkType string    `json:"networkType" doc:"Network type (GSM, CDMA, etc.)"`
	LineType    string    `json:"lineType" doc:"Line type (mobile, landline, voip)"`
	IsPortedIn  bool      `json:"isPortedIn" doc:"Whether number is ported in"`
	IsPortedOut bool      `json:"isPortedOut" doc:"Whether number is ported out"`
	MCC         string    `json:"mcc,omitempty" doc:"Mobile Country Code"`
	MNC         string    `json:"mnc,omitempty" doc:"Mobile Network Code"`
	LastUpdated time.Time `json:"lastUpdated" doc:"Last update timestamp"`
}

// SMSRoute represents optimal routing information
type SMSRoute struct {
	Provider         string    `json:"provider" doc:"Recommended SMS provider"`
	Route            string    `json:"route" doc:"Routing path"`
	EstimatedCost    float64   `json:"estimatedCost" doc:"Estimated cost"`
	Currency         string    `json:"currency" doc:"Cost currency"`
	DeliveryTime     int       `json:"deliveryTime" doc:"Estimated delivery time in seconds"`
	ReliabilityScore float64   `json:"reliabilityScore" doc:"Route reliability score"`
	Features         []string  `json:"features" doc:"Supported features"`
	Restrictions     []string  `json:"restrictions,omitempty" doc:"Route restrictions"`
	LastUpdated      time.Time `json:"lastUpdated" doc:"Route info last updated"`
}

// smsService implements the SMSService interface
type smsService struct {
	defaultProvider sms.Provider                     // SMS providers (Twilio, AWS SNS, etc.)
	templateRepo    repository.SMSTemplateRepository // Template repository
	deliveryRepo    SMSDeliveryRepository            // Delivery tracking repository
	rateLimiter     RateLimiter                      // Rate limiting service
	validator       PhoneValidator                   // Phone number validator
	logger          logging.Logger                   // Logger
	defaultConfig   SMSConfig                        // Default SMS configuration
}

// SMSServiceConfig represents SMS service configuration
type SMSServiceConfig struct {
	Providers     map[string]SMSProviderConfig `json:"providers"`
	DefaultConfig SMSConfig                    `json:"defaultConfig"`
	RateLimits    RateLimitConfig              `json:"rateLimits"`
}

// SMSProviderConfig represents provider-specific configuration
type SMSProviderConfig struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"` // twilio, aws-sns, messagebird, etc.
	Config   map[string]interface{} `json:"config"`
	Priority int                    `json:"priority"`
	Enabled  bool                   `json:"enabled"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	DefaultHourlyLimit  int `json:"defaultHourlyLimit"`
	DefaultDailyLimit   int `json:"defaultDailyLimit"`
	DefaultMonthlyLimit int `json:"defaultMonthlyLimit"`
}

// NewSMSService creates a new SMS service instance
func NewSMSService(
	provider sms.Provider,
	config SMSServiceConfig,
	templateRepo repository.SMSTemplateRepository,
	deliveryRepo SMSDeliveryRepository,
	rateLimiter RateLimiter,
	validator PhoneValidator,
	logger logging.Logger,
) (SMSService, error) {

	if provider == nil {
		return nil, errors.New(errors.CodeInternalServer, "no SMS providers configured")
	}

	return &smsService{
		defaultProvider: provider,
		templateRepo:    templateRepo,
		deliveryRepo:    deliveryRepo,
		rateLimiter:     rateLimiter,
		validator:       validator,
		logger:          logger,
		defaultConfig:   config.DefaultConfig,
	}, nil
}

func (s *smsService) getProvider(ctx context.Context, orgID xid.ID) (sms.Provider, error) {
	return s.defaultProvider, nil
}

func (s *smsService) getDefaultProvider() sms.Provider {
	return s.defaultProvider
}

// SendSMS sends a single SMS message
func (s *smsService) SendSMS(ctx context.Context, sms sms.SMS) error {
	// Validate phone number
	validation, err := s.ValidatePhoneNumber(ctx, sms.To)
	if err != nil {
		return fmt.Errorf("phone validation failed: %w", err)
	}

	if !validation.IsValid {
		return errors.New(errors.CodeBadRequest, "invalid phone number")
	}

	// Check rate limits
	limits, err := s.CheckSendingLimits(ctx, *sms.OrganizationID, sms.To)
	if err != nil {
		return fmt.Errorf("rate limit check failed: %w", err)
	}

	if !limits.CanSend {
		return errors.New(errors.CodeTooManyRequests, "sending limits exceeded")
	}

	// Check opt-out status
	optOut, err := s.GetOptOutStatus(ctx, sms.To)
	if err != nil {
		return fmt.Errorf("opt-out check failed: %w", err)
	}

	if optOut.IsOptedOut {
		canReceive, exists := optOut.CanReceive[sms.MessageType]
		if !exists || !canReceive {
			return errors.New(errors.CodeBadRequest, "recipient has opted out")
		}
	}

	// Get optimal route
	route, err := s.GetOptimalRoute(ctx, sms.To, sms.MessageType)
	if err != nil {
		s.logger.Warn("failed to get optimal route, using default", zap.Error(err))
		route = &SMSRoute{Provider: s.getDefaultProvider().Name()}
	}

	// Get provider
	provider, err := s.getProvider(ctx, *sms.OrganizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeConfigurationError, "get provider failed")
	}

	// Send SMS
	err = provider.Send(ctx, sms)
	if err != nil {
		s.logger.Error("SMS send failed", zap.Error(err), zap.String("to", sms.To), zap.Any("provider", route.Provider))

		// Track failed delivery
		_ = s.TrackSMSDelivery(ctx, "", SMSStatusFailed)

		return fmt.Errorf("SMS send failed: %w", err)
	}

	// // Track delivery
	// err = s.TrackSMSDelivery(ctx, result.MessageID, SMSStatusSent)
	// if err != nil {
	// 	s.logger.Warn("failed to track SMS delivery", zap.String("messageId", result.MessageID), zap.Error(err))
	// }

	s.logger.Info("SMS sent successfully", zap.String("to", sms.To), zap.String("provider", route.Provider))

	return nil
}

// SendBulkSMS sends multiple SMS messages
func (s *smsService) SendBulkSMS(ctx context.Context, messages []sms.SMS) (*BulkSMSResult, error) {
	if len(messages) == 0 {
		return nil, errors.New(errors.CodeBadRequest, "no messages to send")
	}

	batchID := xid.New().String()
	results := make([]BulkSMSItemResult, len(messages))
	queuedCount := 0
	failedCount := 0
	var totalCost float64
	var errorMessages []string

	for i, smsi := range messages {
		result := BulkSMSItemResult{
			PhoneNumber: smsi.To,
			Status:      "failed",
		}

		// Send individual SMS
		err := s.SendSMS(ctx, smsi)
		if err != nil {
			result.Error = err.Error()
			errorMessages = append(errorMessages, fmt.Sprintf("%s: %s", smsi.To, err.Error()))
			failedCount++
		} else {
			result.Status = "queued"
			result.MessageID = xid.New().String() // This would come from the provider
			queuedCount++
		}

		results[i] = result
	}

	return &BulkSMSResult{
		BatchID:        batchID,
		TotalMessages:  len(messages),
		QueuedMessages: queuedCount,
		FailedMessages: failedCount,
		EstimatedCost:  totalCost,
		Currency:       "USD",
		Results:        results,
		Errors:         errorMessages,
	}, nil
}

// SendTemplateSMS sends SMS using a template
func (s *smsService) SendTemplateSMS(ctx context.Context, templateID string, to []string, data map[string]interface{}) error {
	// Get template
	tid, err := xid.FromString(templateID)
	if err != nil {
		return errors.New(errors.CodeBadRequest, "invalid template ID")
	}

	template, err := s.GetSMSTemplate(ctx, tid)
	if err != nil {
		return fmt.Errorf("failed to get template: %w", err)
	}

	if !template.Active {
		return errors.New(errors.CodeBadRequest, "template is not active")
	}

	// Render template
	rendered, err := s.RenderSMSTemplate(ctx, templateID, data)
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	// Send to all recipients
	for _, recipient := range to {
		smsi := sms.SMS{
			To:             recipient,
			Message:        rendered.Content,
			MessageType:    template.MessageType,
			OrganizationID: &template.OrganizationID,
		}

		err := s.SendSMS(ctx, smsi)
		if err != nil {
			s.logger.Error("failed to send template SMS", zap.String("to", recipient), zap.String("templateId", templateID), zap.Error(err))
			// Continue sending to other recipients
		}
	}

	// Update template usage
	err = s.updateTemplateUsage(ctx, tid)
	if err != nil {
		s.logger.Warn("failed to update template usage", zap.String("templateId", templateID), zap.Error(err))
	}

	return nil
}

// SendSystemSMS sends system SMS using template type
func (s *smsService) SendSystemSMS(ctx context.Context, templateType, to string, data map[string]interface{}) error {
	// Find system template by type
	template, err := s.templateRepo.GetSystemTemplate(ctx, templateType, "en")
	if err != nil {
		return fmt.Errorf("failed to get system template: %w", err)
	}

	return s.SendTemplateSMS(ctx, template.ID.String(), []string{to}, data)
}

// SendVerificationSMS sends verification code SMS
func (s *smsService) SendVerificationSMS(ctx context.Context, user *ent.User, code string) error {
	data := map[string]interface{}{
		"userName": getUserDisplayName(user),
		"code":     code,
		"appName":  "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "verification", user.PhoneNumber, data)
}

// SendMFACodeSMS sends MFA code SMS
func (s *smsService) SendMFACodeSMS(ctx context.Context, user *ent.User, code string) error {
	data := map[string]interface{}{
		"userName": getUserDisplayName(user),
		"code":     code,
		"appName":  "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "mfa_code", user.PhoneNumber, data)
}

// SendPasswordResetSMS sends password reset SMS
func (s *smsService) SendPasswordResetSMS(ctx context.Context, user *ent.User, code string) error {
	data := map[string]interface{}{
		"userName": getUserDisplayName(user),
		"code":     code,
		"appName":  "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "password_reset", user.PhoneNumber, data)
}

// SendWelcomeSMS sends welcome SMS
func (s *smsService) SendWelcomeSMS(ctx context.Context, user *ent.User, organizationName string) error {
	data := map[string]interface{}{
		"userName":         getUserDisplayName(user),
		"organizationName": organizationName,
		"appName":          "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "welcome", user.PhoneNumber, data)
}

// SendMagicLinkSMS sends magic link SMS
func (s *smsService) SendMagicLinkSMS(ctx context.Context, user *ent.User, code, redirectURL string) error {
	data := map[string]interface{}{
		"userName":    getUserDisplayName(user),
		"code":        code,
		"redirectUrl": redirectURL,
		"appName":     "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "magic_link", user.PhoneNumber, data)
}

// SendLoginVerificationSMS sends login verification code
func (s *smsService) SendLoginVerificationSMS(ctx context.Context, user *ent.User, code string) error {
	data := map[string]interface{}{
		"userName": getUserDisplayName(user),
		"code":     code,
		"appName":  "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "login_verification", user.PhoneNumber, data)
}

// SendSecurityAlertSMS sends security alert SMS
func (s *smsService) SendSecurityAlertSMS(ctx context.Context, user *ent.User, alert SecurityAlert) error {
	data := map[string]interface{}{
		"userName":    getUserDisplayName(user),
		"alertType":   alert.Type,
		"description": alert.Description,
		"ipAddress":   alert.IPAddress,
		"location":    alert.Location,
		"timestamp":   alert.Timestamp.Format("Jan 2, 2006 15:04"),
		"appName":     "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "security_alert", user.PhoneNumber, data)
}

// ValidatePhoneNumber validates a phone number
func (s *smsService) ValidatePhoneNumber(ctx context.Context, phoneNumber string) (*PhoneValidation, error) {
	if s.validator == nil {
		// Basic validation if no validator configured
		return s.basicPhoneValidation(phoneNumber), nil
	}

	return s.validator.Validate(ctx, phoneNumber)
}

// CreateSMSTemplate creates a new SMS template
func (s *smsService) CreateSMSTemplate(ctx context.Context, template SMSTemplate) (*ent.SMSTemplate, error) {
	// Validate template
	if err := s.validateSMSTemplate(template); err != nil {
		return nil, err
	}

	// Create template entity
	input := repository.CreateSMSTemplateInput{
		Name:           template.Name,
		Content:        template.Content,
		Type:           template.Type,
		OrganizationID: template.OrganizationID,
		Active:         template.Active,
		System:         template.System,
		Locale:         template.Locale,
		MaxLength:      template.MaxLength,
		MessageType:    template.MessageType,
		// Variables:      template.Variables,
		Metadata: template.Metadata,
	}

	return s.templateRepo.Create(ctx, input)
}

// GetSMSTemplate gets an SMS template by ID
func (s *smsService) GetSMSTemplate(ctx context.Context, templateID xid.ID) (*ent.SMSTemplate, error) {
	return s.templateRepo.GetByID(ctx, templateID)
}

// RenderSMSTemplate renders an SMS template with data
func (s *smsService) RenderSMSTemplate(ctx context.Context, templateID string, data map[string]interface{}) (*RenderedSMS, error) {
	tid, err := xid.FromString(templateID)
	if err != nil {
		return nil, errors.New(errors.CodeBadRequest, "invalid template ID")
	}

	template, err := s.GetSMSTemplate(ctx, tid)
	if err != nil {
		return nil, err
	}

	// Render template content
	content, err := s.renderTemplateContent(template.Content, data)
	if err != nil {
		return nil, fmt.Errorf("failed to render template: %w", err)
	}

	// Calculate segments
	segments := s.calculateSMSSegments(content)

	return &RenderedSMS{
		Content:   content,
		Length:    len(content),
		Segments:  segments,
		Variables: data,
		Cost:      float64(segments) * 0.075, // Example cost calculation
		Currency:  "USD",
	}, nil
}

// CheckSendingLimits checks if sending is allowed
func (s *smsService) CheckSendingLimits(ctx context.Context, organizationID xid.ID, phoneNumber string) (*SendingLimits, error) {
	if s.rateLimiter == nil {
		// Return unlimited if no rate limiter
		return &SendingLimits{
			OrganizationID:   organizationID,
			PhoneNumber:      phoneNumber,
			CanSend:          true,
			HourlyLimit:      1000,
			DailyLimit:       10000,
			MonthlyLimit:     100000,
			RemainingHourly:  1000,
			RemainingDaily:   10000,
			RemainingMonthly: 100000,
			NextResetAt:      time.Now().Add(time.Hour),
		}, nil
	}

	return s.rateLimiter.CheckLimits(ctx, organizationID, phoneNumber)
}

// GetOptOutStatus gets opt-out status for a phone number
func (s *smsService) GetOptOutStatus(ctx context.Context, phoneNumber string) (*OptOutStatus, error) {
	// This would typically query a database
	// For now, return default (opted in)
	return &OptOutStatus{
		PhoneNumber: phoneNumber,
		IsOptedOut:  false,
		CanReceive: map[string]bool{
			"transactional": true,
			"promotional":   true,
			"marketing":     false, // Default to false for marketing
		},
	}, nil
}

// GetCarrierInfo gets carrier information for a phone number
func (s *smsService) GetCarrierInfo(ctx context.Context, phoneNumber string) (*CarrierInfo, error) {
	// This would typically query a carrier lookup service
	// For now, we'll return basic information
	validation, err := s.ValidatePhoneNumber(ctx, phoneNumber)
	if err != nil {
		return nil, err
	}

	if !validation.IsValid {
		return nil, errors.New(errors.CodeBadRequest, "invalid phone number")
	}

	return &CarrierInfo{
		PhoneNumber: phoneNumber,
		CarrierName: validation.Carrier,
		CountryCode: validation.CountryCode,
		CountryName: validation.CountryName,
		NetworkType: "GSM",
		LineType:    validation.LineType,
		IsPortedIn:  false,
		IsPortedOut: false,
		LastUpdated: time.Now(),
	}, nil
}

// SendInvitationSMS sends organization invitation SMS
func (s *smsService) SendInvitationSMS(ctx context.Context, invitation SMSInvitation) error {
	data := map[string]interface{}{
		"inviterName":      invitation.InviterName,
		"organizationName": invitation.OrganizationName,
		"role":             invitation.Role,
		"joinUrl":          invitation.JoinURL,
		"expiresAt":        invitation.ExpiresAt.Format("Jan 2, 2006 15:04"),
		"customMessage":    invitation.CustomMessage,
		"appName":          "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "invitation", invitation.PhoneNumber, data)
}

// SendInvitationReminderSMS sends invitation reminder SMS
func (s *smsService) SendInvitationReminderSMS(ctx context.Context, invitation SMSInvitation) error {
	data := map[string]interface{}{
		"inviterName":      invitation.InviterName,
		"organizationName": invitation.OrganizationName,
		"role":             invitation.Role,
		"joinUrl":          invitation.JoinURL,
		"expiresAt":        invitation.ExpiresAt.Format("Jan 2, 2006 15:04"),
		"customMessage":    invitation.CustomMessage,
		"appName":          "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "invitation_reminder", invitation.PhoneNumber, data)
}

// SendOrganizationUpdateSMS sends organization update SMS to multiple recipients
func (s *smsService) SendOrganizationUpdateSMS(ctx context.Context, phoneNumbers []string, update OrganizationUpdate) error {
	data := map[string]interface{}{
		"organizationName": update.OrganizationName,
		"title":            update.Title,
		// "updateType":       update.UpdateType,
		// "message":          update.Message,
		"actionRequired": update.ActionRequired,
		"actionUrl":      update.ActionURL,
		"actionDeadline": "",
		"appName":        "Frank Auth",
	}

	// // Format deadline if provided
	// if update.ActionDeadline != nil {
	// 	data["actionDeadline"] = update.ActionDeadline.Format("Jan 2, 2006 15:04")
	// }

	// Send to all phone numbers
	for _, phoneNumber := range phoneNumbers {
		err := s.SendSystemSMS(ctx, "organization_update", phoneNumber, data)
		if err != nil {
			s.logger.Error("failed to send organization update SMS",
				zap.String("phoneNumber", phoneNumber),
				// zap.String("updateType", update.UpdateType),
				zap.Error(err),
			)
			// Continue sending to other recipients
		}
	}

	return nil
}

// SendLoginNotificationSMS sends login notification SMS
func (s *smsService) SendLoginNotificationSMS(ctx context.Context, user *ent.User, login LoginNotification) error {
	data := map[string]interface{}{
		"userName":      getUserDisplayName(user),
		"ipAddress":     login.IPAddress,
		"location":      login.Location,
		"deviceType":    login.DeviceType,
		"deviceName":    login.DeviceName,
		"timestamp":     login.Timestamp.Format("Jan 2, 2006 15:04"),
		"isNewDevice":   login.IsNewDevice,
		"isNewLocation": login.IsNewLocation,
		"appName":       "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "login_notification", user.PhoneNumber, data)
}

// SendPasswordChangedSMS sends password changed notification SMS
func (s *smsService) SendPasswordChangedSMS(ctx context.Context, user *ent.User) error {
	data := map[string]interface{}{
		"userName":  getUserDisplayName(user),
		"timestamp": time.Now().Format("Jan 2, 2006 15:04"),
		"appName":   "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "password_changed", user.PhoneNumber, data)
}

// SendAccountLockedSMS sends account locked notification SMS
func (s *smsService) SendAccountLockedSMS(ctx context.Context, user *ent.User, reason string) error {
	data := map[string]interface{}{
		"userName":  getUserDisplayName(user),
		"reason":    reason,
		"timestamp": time.Now().Format("Jan 2, 2006 15:04"),
		"appName":   "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "account_locked", user.PhoneNumber, data)
}

// SendSuspiciousActivitySMS sends suspicious activity alert SMS
func (s *smsService) SendSuspiciousActivitySMS(ctx context.Context, user *ent.User, activity SuspiciousActivity) error {
	data := map[string]interface{}{
		"userName":     getUserDisplayName(user),
		"activityType": activity.ActivityType,
		"description":  activity.Description,
		"ipAddress":    activity.IPAddress,
		"location":     activity.Location,
		"timestamp":    activity.Timestamp.Format("Jan 2, 2006 15:04"),
		"riskLevel":    activity.RiskLevel,
		"actionTaken":  activity.ActionTaken,
		"appName":      "Frank Auth",
	}

	return s.SendSystemSMS(ctx, "suspicious_activity", user.PhoneNumber, data)
}

// SendBillingSMS sends billing-related SMS
func (s *smsService) SendBillingSMS(ctx context.Context, organizationID xid.ID, billingEvent BillingEvent) error {
	// This would typically get organization members' phone numbers from the repository
	// For now, we'll use a placeholder implementation

	data := map[string]interface{}{
		"eventType":      billingEvent.Type,
		"description":    billingEvent.Description,
		"amount":         billingEvent.Amount,
		"currency":       billingEvent.Currency,
		"invoiceId":      billingEvent.InvoiceID,
		"actionRequired": billingEvent.ActionRequired,
		"actionUrl":      billingEvent.ActionURL,
		"appName":        "Frank Auth",
	}

	if billingEvent.DueDate != nil {
		data["dueDate"] = billingEvent.DueDate.Format("Jan 2, 2006")
	}

	// TODO: Get billing contacts' phone numbers from organization
	// For now, this is a placeholder
	phoneNumbers := []string{} // Would be populated from organization repository

	for _, phoneNumber := range phoneNumbers {
		err := s.SendSystemSMS(ctx, "billing_event", phoneNumber, data)
		if err != nil {
			s.logger.Error("failed to send billing SMS",
				zap.String("phoneNumber", phoneNumber),
				zap.String("eventType", billingEvent.Type),
				zap.Error(err),
			)
		}
	}

	return nil
}

// SendUsageAlertSMS sends usage alert SMS
func (s *smsService) SendUsageAlertSMS(ctx context.Context, organizationID xid.ID, usage UsageAlert) error {
	data := map[string]interface{}{
		"alertType":      usage.ThresholdType,
		"resource":       usage.ResourceType,
		"currentUsage":   usage.CurrentUsage,
		"limit":          usage.Limit,
		"percentage":     usage.PercentageUsed,
		"period":         usage.BillingPeriodEnd,
		"actionRequired": usage.ActionRecommended,
		"actionUrl":      usage.UpgradeURL,
		"appName":        "Frank Auth",
	}

	if usage.BillingPeriodEnd != nil {
		data["resetDate"] = usage.BillingPeriodEnd.Format("Jan 2, 2006 15:04")
	}

	// TODO: Get organization admins' phone numbers
	// For now, this is a placeholder
	phoneNumbers := []string{} // Would be populated from organization repository

	for _, phoneNumber := range phoneNumbers {
		err := s.SendSystemSMS(ctx, "usage_alert", phoneNumber, data)
		if err != nil {
			s.logger.Error("failed to send usage alert SMS",
				zap.String("phoneNumber", phoneNumber),
				zap.String("alertType", usage.ThresholdType),
				zap.Error(err),
			)
		}
	}

	return nil
}

// SendPaymentFailedSMS sends payment failed notification SMS
func (s *smsService) SendPaymentFailedSMS(ctx context.Context, organizationID xid.ID, paymentInfo PaymentFailure) error {
	data := map[string]interface{}{
		"amount":         paymentInfo.Amount,
		"currency":       paymentInfo.Currency,
		"paymentMethod":  paymentInfo.PaymentMethod,
		"failureReason":  paymentInfo.FailureReason,
		"attemptCount":   paymentInfo.AttemptCount,
		"invoiceId":      paymentInfo.InvoiceID,
		"subscriptionId": paymentInfo.SubscriptionID,
		"appName":        "Frank Auth",
	}

	if paymentInfo.NextRetryAt != nil {
		data["nextRetryAt"] = paymentInfo.NextRetryAt.Format("Jan 2, 2006 15:04")
	}

	// TODO: Get billing contacts' phone numbers
	// For now, this is a placeholder
	phoneNumbers := []string{} // Would be populated from organization repository

	for _, phoneNumber := range phoneNumbers {
		err := s.SendSystemSMS(ctx, "payment_failed", phoneNumber, data)
		if err != nil {
			s.logger.Error("failed to send payment failed SMS",
				zap.String("phoneNumber", phoneNumber),
				zap.Error(err),
			)
		}
	}

	return nil
}

// UpdateSMSTemplate updates an existing SMS template
func (s *smsService) UpdateSMSTemplate(ctx context.Context, templateID xid.ID, template SMSTemplate) (*ent.SMSTemplate, error) {
	// Validate template
	if err := s.validateSMSTemplate(template); err != nil {
		return nil, err
	}

	// Create update input
	input := repository.UpdateSMSTemplateInput{
		Name:        &template.Name,
		Content:     &template.Content,
		Active:      &template.Active,
		MaxLength:   &template.MaxLength,
		MessageType: &template.MessageType,
		// Variables:   template.Variables,
		Metadata: template.Metadata,
	}

	return s.templateRepo.Update(ctx, templateID, input)
}

// ListSMSTemplates lists SMS templates for an organization
func (s *smsService) ListSMSTemplates(ctx context.Context, organizationID *xid.ID) ([]*ent.SMSTemplate, error) {
	if organizationID == nil {
		// Return system templates
		result, err := s.templateRepo.ListSystem(ctx, model.PaginationParams{Limit: 100})
		if err != nil {
			return nil, err
		}
		return result.Data, nil
	}

	// Return organization templates
	result, err := s.templateRepo.ListByOrganizationID(ctx, *organizationID, model.PaginationParams{Limit: 100})
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

// GetSMSDeliveryStatus gets delivery status for a message
func (s *smsService) GetSMSDeliveryStatus(ctx context.Context, messageID string) (*SMSDeliveryInfo, error) {
	if s.deliveryRepo == nil {
		return nil, errors.New(errors.CodeNotImplemented, "delivery tracking not configured")
	}

	return s.deliveryRepo.GetStatus(ctx, messageID)
}

// GetSMSDeliveryStats gets delivery statistics
func (s *smsService) GetSMSDeliveryStats(ctx context.Context, organizationID *xid.ID, period string) (*SMSDeliveryStats, error) {
	if s.deliveryRepo == nil {
		return nil, errors.New(errors.CodeNotImplemented, "delivery tracking not configured")
	}

	return s.deliveryRepo.GetStats(ctx, organizationID, period)
}

// ProcessOptOut processes an opt-out request
func (s *smsService) ProcessOptOut(ctx context.Context, phoneNumber string, reason string) error {
	// This would typically update a database record
	// For now, we'll log the opt-out
	s.logger.Info("processing SMS opt-out",
		zap.String("phoneNumber", phoneNumber),
		zap.Time("timestamp", time.Now()),
		zap.String("reason", reason),
	)

	// TODO: Update opt-out database
	// - Mark phone number as opted out
	// - Record reason and timestamp
	// - Send confirmation SMS if required by regulations

	return nil
}

// ProcessOptIn processes an opt-in request
func (s *smsService) ProcessOptIn(ctx context.Context, phoneNumber string) error {
	// This would typically update a database record
	// For now, we'll log the opt-in
	s.logger.Info("processing SMS opt-in",
		zap.String("phoneNumber", phoneNumber),
		zap.Time("timestamp", time.Now()),
	)

	// TODO: Update opt-out database
	// - Mark phone number as opted in
	// - Record timestamp
	// - Send confirmation SMS

	return nil
}

// GetOptimalRoute gets optimal routing for a phone number
func (s *smsService) GetOptimalRoute(ctx context.Context, phoneNumber, messageType string) (*SMSRoute, error) {
	// Simple routing logic - could be enhanced with carrier lookup, cost optimization, etc.
	defaultProvider := s.getDefaultProvider()

	return &SMSRoute{
		Provider:         defaultProvider.Name(),
		Route:            "direct",
		EstimatedCost:    0.075,
		Currency:         "USD",
		DeliveryTime:     30,
		ReliabilityScore: 0.98,
		Features:         []string{"delivery_receipt", "unicode"},
		LastUpdated:      time.Now(),
	}, nil
}

// TestSMSConfiguration tests SMS configuration
func (s *smsService) TestSMSConfiguration(ctx context.Context, config SMSConfig) error {
	// // Create a test provider with the given configuration
	// provider, err := createSMSProvider(config.Provider, map[string]interface{}{
	// 	"apiKey":    config.APIKey,
	// 	"apiSecret": config.APISecret,
	// 	"senderId":  config.SenderID,
	// })
	// if err != nil {
	// 	return fmt.Errorf("failed to create test provider: %w", err)
	// }
	//
	// // Test provider connection
	// testSMS := SMSRequest{
	// 	To:      "+1234567890", // Test number
	// 	Message: "Test configuration",
	// 	From:    config.SenderID,
	// }
	//
	// // This would be a dry run or test mode
	// _, err = provider.SendSMS(ctx, testSMS)
	// if err != nil {
	// 	return fmt.Errorf("SMS configuration test failed: %w", err)
	// }

	return nil
}

// SendTestSMS sends a test SMS
func (s *smsService) SendTestSMS(ctx context.Context, config SMSConfig, recipient string) error {
	// // Validate recipient phone number
	// validation, err := s.ValidatePhoneNumber(ctx, recipient)
	// if err != nil || !validation.IsValid {
	// 	return errors.New(errors.CodeBadRequest, "invalid recipient phone number")
	// }
	//
	// // Create test SMS
	// testSMS := SMSRequest{
	// 	To:             recipient,
	// 	Message:        "This is a test SMS from Frank Auth. Configuration is working correctly.",
	// 	From:           config.SenderID,
	// 	OrganizationID: xid.New(), // Placeholder organization ID
	// 	MessageType:    "transactional",
	// }
	//
	// // Send using specified configuration
	// provider, err := createSMSProvider(config.Provider, map[string]interface{}{
	// 	"apiKey":    config.APIKey,
	// 	"apiSecret": config.APISecret,
	// 	"senderId":  config.SenderID,
	// })
	// if err != nil {
	// 	return fmt.Errorf("failed to create provider: %w", err)
	// }
	//
	// result, err := provider.SendSMS(ctx, testSMS)
	// if err != nil {
	// 	return fmt.Errorf("test SMS send failed: %w", err)
	// }
	//
	// s.logger.Info("test SMS sent successfully", "recipient", recipient, "messageId", result.MessageID)

	return nil
}

// TrackSMSDelivery tracks SMS delivery status
func (s *smsService) TrackSMSDelivery(ctx context.Context, messageID string, status SMSDeliveryStatus) error {
	if s.deliveryRepo == nil {
		return nil
	}

	return s.deliveryRepo.UpdateStatus(ctx, messageID, status)
}

func (s *smsService) basicPhoneValidation(phoneNumber string) *PhoneValidation {
	// Basic E.164 format validation
	e164Regex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	isValid := e164Regex.MatchString(phoneNumber)

	return &PhoneValidation{
		PhoneNumber:    phoneNumber,
		IsValid:        isValid,
		FormattedE164:  phoneNumber,
		ValidationTime: time.Now(),
	}
}

func (s *smsService) containsUnicode(content string) bool {
	for _, r := range content {
		if r > 127 {
			return true
		}
	}
	return false
}

func getUserDisplayName(user *ent.User) string {
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

type SMSDeliveryRepository interface {
	UpdateStatus(ctx context.Context, messageID string, status SMSDeliveryStatus) error
	GetStatus(ctx context.Context, messageID string) (*SMSDeliveryInfo, error)
	GetStats(ctx context.Context, organizationID *xid.ID, period string) (*SMSDeliveryStats, error)
}

func (s *smsService) validateSMSTemplate(template SMSTemplate) error {
	if template.Name == "" {
		return errors.New(errors.CodeBadRequest, "template name is required")
	}

	if template.Content == "" {
		return errors.New(errors.CodeBadRequest, "template content is required")
	}

	if template.Type == "" {
		return errors.New(errors.CodeBadRequest, "template type is required")
	}

	if template.MaxLength <= 0 {
		template.MaxLength = 160
	}

	if len(template.Content) > template.MaxLength {
		return errors.New(errors.CodeBadRequest, "template content exceeds maximum length")
	}

	return nil
}

func (s *smsService) renderTemplateContent(content string, data map[string]interface{}) (string, error) {
	result := content

	// Simple template variable replacement
	for key, value := range data {
		placeholder := fmt.Sprintf("{{.%s}}", key)
		result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%v", value))
	}

	return result, nil
}

func (s *smsService) calculateSMSSegments(content string) int {
	// Basic segment calculation
	// GSM 7-bit: 160 chars per segment
	// Unicode: 70 chars per segment

	if s.containsUnicode(content) {
		return (len(content) + 69) / 70 // Ceiling division
	}

	return (len(content) + 159) / 160 // Ceiling division
}

func (s *smsService) updateTemplateUsage(ctx context.Context, templateID xid.ID) error {
	if s.templateRepo == nil {
		return nil
	}

	now := time.Now()
	input := repository.UpdateSMSTemplateInput{
		LastUsedAt: &now,
		UsageCount: nil, // This would increment in the repository
	}

	_, err := s.templateRepo.Update(ctx, templateID, input)
	return err
}
