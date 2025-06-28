package repository

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/smstemplate"
	"github.com/xraph/frank/pkg/model"

	"github.com/xraph/frank/pkg/errors"
)

// SMSTemplateRepository defines the interface for SMS template data operations
type SMSTemplateRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateSMSTemplateInput) (*ent.SMSTemplate, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.SMSTemplate, error)
	Update(ctx context.Context, id xid.ID, input UpdateSMSTemplateInput) (*ent.SMSTemplate, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	List(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error)
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error)
	ListByType(ctx context.Context, templateType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error)
	ListByLocale(ctx context.Context, locale string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error)
	ListByMessageType(ctx context.Context, messageType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error)
	ListActive(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error)
	ListSystem(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error)

	// Template retrieval operations
	GetByTypeAndOrganization(ctx context.Context, templateType string, orgID *xid.ID, locale string) (*ent.SMSTemplate, error)
	GetByTypeAndLocale(ctx context.Context, templateType, locale string) (*ent.SMSTemplate, error)
	GetSystemTemplate(ctx context.Context, templateType, locale string) (*ent.SMSTemplate, error)
	GetOrganizationTemplate(ctx context.Context, templateType string, orgID xid.ID, locale string) (*ent.SMSTemplate, error)

	// Template management operations
	ActivateTemplate(ctx context.Context, id xid.ID) error
	DeactivateTemplate(ctx context.Context, id xid.ID) error
	CloneTemplate(ctx context.Context, id xid.ID, newName string, orgID *xid.ID) (*ent.SMSTemplate, error)

	// Usage tracking operations
	IncrementUsage(ctx context.Context, id xid.ID) error
	UpdateLastUsed(ctx context.Context, id xid.ID, timestamp time.Time) error
	GetUsageStats(ctx context.Context, id xid.ID, period string) (*SMSTemplateUsageStats, error)
	ResetUsageStats(ctx context.Context, id xid.ID) error

	// Utility operations
	CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)
	CountByType(ctx context.Context, templateType string) (int, error)
	CountByMessageType(ctx context.Context, messageType string) (int, error)
	ListTemplateTypes(ctx context.Context) ([]string, error)
	ListMessageTypes(ctx context.Context) ([]string, error)
	ListLocales(ctx context.Context) ([]string, error)

	// Advanced queries
	ListByOrganizationAndType(ctx context.Context, orgID xid.ID, templateType string) ([]*ent.SMSTemplate, error)
	ListByOrganizationAndMessageType(ctx context.Context, orgID xid.ID, messageType string) ([]*ent.SMSTemplate, error)
	GetTemplateHierarchy(ctx context.Context, templateType string, orgID *xid.ID, locale string) ([]*ent.SMSTemplate, error)
	SearchTemplates(ctx context.Context, query string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error)
	ListMostUsed(ctx context.Context, orgID *xid.ID, limit int) ([]*ent.SMSTemplate, error)
	ListRecentlyUsed(ctx context.Context, orgID *xid.ID, limit int) ([]*ent.SMSTemplate, error)
	ListUnused(ctx context.Context, orgID *xid.ID, since time.Time) ([]*ent.SMSTemplate, error)

	// Template validation operations
	ValidateTemplate(ctx context.Context, content string, maxLength int) error
	ValidateVariables(ctx context.Context, content string, variables []string) error
	GetTemplateVariables(ctx context.Context, templateType string) ([]string, error)
	EstimateCost(ctx context.Context, content string, recipientCount int) (*SMSCostEstimate, error)
	EstimateSegments(ctx context.Context, content string) (int, error)

	// Bulk operations
	BulkCreate(ctx context.Context, inputs []CreateSMSTemplateInput) ([]*ent.SMSTemplate, error)
	BulkUpdate(ctx context.Context, updates []BulkSMSTemplateUpdate) ([]*ent.SMSTemplate, error)
	BulkDelete(ctx context.Context, ids []xid.ID) error
	BulkActivate(ctx context.Context, ids []xid.ID) error
	BulkDeactivate(ctx context.Context, ids []xid.ID) error

	// Import/Export operations
	ImportTemplates(ctx context.Context, templates []ImportSMSTemplate, overwrite bool) (*ImportResult, error)
	ExportTemplates(ctx context.Context, filters ExportFilters) ([]*ent.SMSTemplate, error)

	// Analytics and reporting
	GetTemplateStats(ctx context.Context, orgID *xid.ID) (*SMSTemplateStats, error)
	GetUsageReport(ctx context.Context, orgID *xid.ID, period string) (*SMSUsageReport, error)
	GetCostReport(ctx context.Context, orgID *xid.ID, period string) (*SMSCostReport, error)
	GetPerformanceMetrics(ctx context.Context, orgID *xid.ID, templateIDs []xid.ID) ([]*SMSTemplateMetrics, error)

	// Compliance and audit operations
	GetAuditLog(ctx context.Context, templateID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*SMSTemplateAuditEntry], error)
	LogTemplateUsage(ctx context.Context, templateID xid.ID, usage SMSTemplateUsageLog) error
	GetComplianceReport(ctx context.Context, orgID xid.ID, from, to time.Time) (*SMSComplianceReport, error)

	// Template optimization
	AnalyzeTemplate(ctx context.Context, id xid.ID) (*SMSTemplateAnalysis, error)
	GetOptimizationSuggestions(ctx context.Context, id xid.ID) ([]*SMSOptimizationSuggestion, error)
	OptimizeTemplate(ctx context.Context, id xid.ID, optimizations []string) (*ent.SMSTemplate, error)
}

// Input structures for SMS template operations

// CreateSMSTemplateInput represents input for creating an SMS template
type CreateSMSTemplateInput struct {
	Name              string                 `json:"name"`
	Content           string                 `json:"content"`
	Type              string                 `json:"type"`
	OrganizationID    *xid.ID                `json:"organizationId,omitempty"`
	Active            bool                   `json:"active"`
	System            bool                   `json:"system"`
	Locale            string                 `json:"locale"`
	MaxLength         int                    `json:"maxLength"`
	MessageType       string                 `json:"messageType"`
	EstimatedSegments int                    `json:"estimatedSegments,omitempty"`
	EstimatedCost     float64                `json:"estimatedCost,omitempty"`
	Currency          string                 `json:"currency,omitempty"`
	Variables         []string               `json:"variables,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateSMSTemplateInput represents input for updating an SMS template
type UpdateSMSTemplateInput struct {
	Name              *string                `json:"name,omitempty"`
	Content           *string                `json:"content,omitempty"`
	Active            *bool                  `json:"active,omitempty"`
	MaxLength         *int                   `json:"maxLength,omitempty"`
	MessageType       *string                `json:"messageType,omitempty"`
	EstimatedSegments *int                   `json:"estimatedSegments,omitempty"`
	EstimatedCost     *float64               `json:"estimatedCost,omitempty"`
	Currency          *string                `json:"currency,omitempty"`
	Variables         []string               `json:"variables,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	LastUsedAt        *time.Time             `json:"lastUsedAt,omitempty"`
	UsageCount        *int                   `json:"usageCount,omitempty"`
}

// BulkSMSTemplateUpdate represents bulk update input
type BulkSMSTemplateUpdate struct {
	ID    xid.ID                 `json:"id"`
	Input UpdateSMSTemplateInput `json:"input"`
}

// ImportSMSTemplate represents template import input
type ImportSMSTemplate struct {
	Name        string                 `json:"name"`
	Content     string                 `json:"content"`
	Type        string                 `json:"type"`
	Locale      string                 `json:"locale"`
	MaxLength   int                    `json:"maxLength"`
	MessageType string                 `json:"messageType"`
	Variables   []string               `json:"variables,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ExportFilters represents template export filters
type ExportFilters struct {
	OrganizationID *xid.ID    `json:"organizationId,omitempty"`
	TemplateIDs    []xid.ID   `json:"templateIds,omitempty"`
	Type           string     `json:"type,omitempty"`
	MessageType    string     `json:"messageType,omitempty"`
	Locale         string     `json:"locale,omitempty"`
	Active         *bool      `json:"active,omitempty"`
	System         *bool      `json:"system,omitempty"`
	CreatedAfter   *time.Time `json:"createdAfter,omitempty"`
	CreatedBefore  *time.Time `json:"createdBefore,omitempty"`
}

// ImportResult represents template import results
type ImportResult struct {
	Total       int      `json:"total"`
	Imported    int      `json:"imported"`
	Updated     int      `json:"updated"`
	Skipped     int      `json:"skipped"`
	Failed      int      `json:"failed"`
	Errors      []string `json:"errors,omitempty"`
	ImportedIDs []xid.ID `json:"importedIds,omitempty"`
	UpdatedIDs  []xid.ID `json:"updatedIds,omitempty"`
}

// Statistics and reporting structures

// SMSTemplateUsageStats represents template usage statistics
type SMSTemplateUsageStats struct {
	TemplateID      xid.ID     `json:"templateId"`
	TotalUsage      int        `json:"totalUsage"`
	UsageToday      int        `json:"usageToday"`
	UsageWeek       int        `json:"usageWeek"`
	UsageMonth      int        `json:"usageMonth"`
	LastUsed        *time.Time `json:"lastUsed,omitempty"`
	AverageSegments float64    `json:"averageSegments"`
	TotalCost       float64    `json:"totalCost"`
	Currency        string     `json:"currency"`
}

// SMSTemplateStats represents overall template statistics
type SMSTemplateStats struct {
	TotalTemplates         int                    `json:"totalTemplates"`
	ActiveTemplates        int                    `json:"activeTemplates"`
	SystemTemplates        int                    `json:"systemTemplates"`
	CustomTemplates        int                    `json:"customTemplates"`
	TemplatesByType        map[string]int         `json:"templatesByType"`
	TemplatesByMessageType map[string]int         `json:"templatesByMessageType"`
	TemplatesByLocale      map[string]int         `json:"templatesByLocale"`
	TotalSMSSent           int                    `json:"totalSmsSent"`
	SMSSentToday           int                    `json:"smsSentToday"`
	SMSSentWeek            int                    `json:"smsSentWeek"`
	SMSSentMonth           int                    `json:"smsSentMonth"`
	AverageDeliveryRate    float64                `json:"averageDeliveryRate"`
	TotalCost              float64                `json:"totalCost"`
	Currency               string                 `json:"currency"`
	TopTemplates           []TemplateUsageSummary `json:"topTemplates"`
}

// TemplateUsageSummary represents template usage summary
type TemplateUsageSummary struct {
	TemplateID   xid.ID  `json:"templateId"`
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	SentCount    int     `json:"sentCount"`
	DeliveryRate float64 `json:"deliveryRate"`
	AverageCost  float64 `json:"averageCost"`
}

// SMSUsageReport represents SMS usage report
type SMSUsageReport struct {
	Period        string                 `json:"period"`
	TotalMessages int                    `json:"totalMessages"`
	TotalSegments int                    `json:"totalSegments"`
	TotalCost     float64                `json:"totalCost"`
	Currency      string                 `json:"currency"`
	ByTemplate    []TemplateUsageDetail  `json:"byTemplate"`
	ByMessageType map[string]UsageDetail `json:"byMessageType"`
	ByDay         []DailyUsage           `json:"byDay"`
	DeliveryStats SMSDeliveryReport      `json:"deliveryStats"`
}

// TemplateUsageDetail represents detailed template usage
type TemplateUsageDetail struct {
	TemplateID   xid.ID  `json:"templateId"`
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	Messages     int     `json:"messages"`
	Segments     int     `json:"segments"`
	Cost         float64 `json:"cost"`
	DeliveryRate float64 `json:"deliveryRate"`
}

// UsageDetail represents usage detail by category
type UsageDetail struct {
	Messages int     `json:"messages"`
	Segments int     `json:"segments"`
	Cost     float64 `json:"cost"`
}

// SMSDeliveryReport represents delivery statistics
type SMSDeliveryReport struct {
	TotalSent      int            `json:"totalSent"`
	TotalDelivered int            `json:"totalDelivered"`
	TotalFailed    int            `json:"totalFailed"`
	DeliveryRate   float64        `json:"deliveryRate"`
	FailureRate    float64        `json:"failureRate"`
	ByStatus       map[string]int `json:"byStatus"`
}

// SMSCostReport represents cost analysis report
type SMSCostReport struct {
	Period         string               `json:"period"`
	TotalCost      float64              `json:"totalCost"`
	Currency       string               `json:"currency"`
	AverageCost    float64              `json:"averageCost"`
	CostByTemplate []TemplateCostDetail `json:"costByTemplate"`
	CostByCountry  []CountryCostDetail  `json:"costByCountry"`
	CostTrend      []CostTrendPoint     `json:"costTrend"`
	Savings        *CostSavings         `json:"savings,omitempty"`
}

// TemplateCostDetail represents cost detail by template
type TemplateCostDetail struct {
	TemplateID xid.ID  `json:"templateId"`
	Name       string  `json:"name"`
	Messages   int     `json:"messages"`
	Cost       float64 `json:"cost"`
	Percentage float64 `json:"percentage"`
}

// CountryCostDetail represents cost detail by country
type CountryCostDetail struct {
	CountryCode string  `json:"countryCode"`
	CountryName string  `json:"countryName"`
	Messages    int     `json:"messages"`
	Cost        float64 `json:"cost"`
	AverageCost float64 `json:"averageCost"`
}

// CostTrendPoint represents cost trend data point
type CostTrendPoint struct {
	Date     time.Time `json:"date"`
	Cost     float64   `json:"cost"`
	Messages int       `json:"messages"`
}

// CostSavings represents potential cost savings
type CostSavings struct {
	PotentialSavings   float64  `json:"potentialSavings"`
	OptimizationTips   []string `json:"optimizationTips"`
	UnusedTemplates    int      `json:"unusedTemplates"`
	DuplicateTemplates int      `json:"duplicateTemplates"`
}

// SMSTemplateMetrics represents template performance metrics
type SMSTemplateMetrics struct {
	TemplateID      xid.ID     `json:"templateId"`
	Name            string     `json:"name"`
	TotalSent       int        `json:"totalSent"`
	DeliveryRate    float64    `json:"deliveryRate"`
	FailureRate     float64    `json:"failureRate"`
	AverageSegments float64    `json:"averageSegments"`
	AverageCost     float64    `json:"averageCost"`
	OptOutRate      float64    `json:"optOutRate"`
	ResponseRate    float64    `json:"responseRate,omitempty"`
	ConversionRate  float64    `json:"conversionRate,omitempty"`
	LastUsed        *time.Time `json:"lastUsed,omitempty"`
	TrendDirection  string     `json:"trendDirection"` // up, down, stable
}

// Audit and compliance structures

// SMSTemplateAuditEntry represents an audit log entry
type SMSTemplateAuditEntry struct {
	ID         xid.ID                 `json:"id"`
	TemplateID xid.ID                 `json:"templateId"`
	Action     string                 `json:"action"`
	UserID     *xid.ID                `json:"userId,omitempty"`
	Changes    map[string]interface{} `json:"changes,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	IPAddress  string                 `json:"ipAddress,omitempty"`
	UserAgent  string                 `json:"userAgent,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// SMSTemplateUsageLog represents usage logging
type SMSTemplateUsageLog struct {
	TemplateID     xid.ID                 `json:"templateId"`
	RecipientCount int                    `json:"recipientCount"`
	TotalSegments  int                    `json:"totalSegments"`
	TotalCost      float64                `json:"totalCost"`
	MessageType    string                 `json:"messageType"`
	Timestamp      time.Time              `json:"timestamp"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// SMSComplianceReport represents compliance report
type SMSComplianceReport struct {
	Period               string                  `json:"period"`
	TotalMessages        int                     `json:"totalMessages"`
	TransactionalCount   int                     `json:"transactionalCount"`
	PromotionalCount     int                     `json:"promotionalCount"`
	MarketingCount       int                     `json:"marketingCount"`
	OptOutsReceived      int                     `json:"optOutsReceived"`
	OptInConfirmations   int                     `json:"optInConfirmations"`
	ComplianceViolations []ComplianceViolation   `json:"complianceViolations,omitempty"`
	AuditTrail           []SMSTemplateAuditEntry `json:"auditTrail"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	TemplateID  *xid.ID   `json:"templateId,omitempty"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
	Resolved    bool      `json:"resolved"`
}

// Template analysis and optimization structures

// SMSCostEstimate represents cost estimation
type SMSCostEstimate struct {
	EstimatedSegments int     `json:"estimatedSegments"`
	EstimatedCost     float64 `json:"estimatedCost"`
	Currency          string  `json:"currency"`
	CostPerSegment    float64 `json:"costPerSegment"`
	TotalRecipients   int     `json:"totalRecipients"`
	TotalCost         float64 `json:"totalCost"`
}

// SMSTemplateAnalysis represents template analysis
type SMSTemplateAnalysis struct {
	TemplateID        xid.ID          `json:"templateId"`
	ContentLength     int             `json:"contentLength"`
	SegmentCount      int             `json:"segmentCount"`
	CharacterType     string          `json:"characterType"` // gsm7, unicode
	VariableCount     int             `json:"variableCount"`
	Issues            []TemplateIssue `json:"issues,omitempty"`
	Suggestions       []string        `json:"suggestions,omitempty"`
	OptimizationScore float64         `json:"optimizationScore"`
	ReadabilityScore  float64         `json:"readabilityScore"`
}

// TemplateIssue represents a template issue
type TemplateIssue struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Line        int    `json:"line,omitempty"`
	Column      int    `json:"column,omitempty"`
}

// SMSOptimizationSuggestion represents optimization suggestion
type SMSOptimizationSuggestion struct {
	Type             string  `json:"type"`
	Title            string  `json:"title"`
	Description      string  `json:"description"`
	Impact           string  `json:"impact"` // high, medium, low
	Effort           string  `json:"effort"` // high, medium, low
	EstimatedSavings float64 `json:"estimatedSavings,omitempty"`
	Implementation   string  `json:"implementation,omitempty"`
}

// smsTemplateRepository implements the SMSTemplateRepository interface
type smsTemplateRepository struct {
	client *ent.Client
}

// NewSMSTemplateRepository creates a new SMS template repository
func NewSMSTemplateRepository(client *ent.Client) SMSTemplateRepository {
	return &smsTemplateRepository{
		client: client,
	}
}

// Basic CRUD operations

func (r *smsTemplateRepository) Create(ctx context.Context, input CreateSMSTemplateInput) (*ent.SMSTemplate, error) {
	builder := r.client.SMSTemplate.Create().
		SetName(input.Name).
		SetContent(input.Content).
		SetType(input.Type).
		SetActive(input.Active).
		SetSystem(input.System).
		SetLocale(input.Locale).
		SetMaxLength(input.MaxLength).
		SetMessageType(input.MessageType)

	if input.OrganizationID != nil {
		builder = builder.SetOrganizationID(*input.OrganizationID)
	}

	if input.EstimatedSegments > 0 {
		builder = builder.SetEstimatedSegments(input.EstimatedSegments)
	}

	if input.EstimatedCost > 0 {
		builder = builder.SetEstimatedCost(input.EstimatedCost)
	}

	if input.Currency != "" {
		builder = builder.SetCurrency(input.Currency)
	}

	if len(input.Variables) > 0 {
		builder = builder.SetVariables(input.Variables)
	}

	if input.Metadata != nil {
		builder = builder.SetMetadata(input.Metadata)
	}

	template, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "SMS template with this type and locale already exists for organization")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create SMS template")
	}

	return template, nil
}

func (r *smsTemplateRepository) GetByID(ctx context.Context, id xid.ID) (*ent.SMSTemplate, error) {
	template, err := r.client.SMSTemplate.Query().
		Where(smstemplate.ID(id)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "SMS template not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get SMS template")
	}

	return template, nil
}

func (r *smsTemplateRepository) Update(ctx context.Context, id xid.ID, input UpdateSMSTemplateInput) (*ent.SMSTemplate, error) {
	builder := r.client.SMSTemplate.UpdateOneID(id)

	if input.Name != nil {
		builder = builder.SetName(*input.Name)
	}
	if input.Content != nil {
		builder = builder.SetContent(*input.Content)
	}
	if input.Active != nil {
		builder = builder.SetActive(*input.Active)
	}
	if input.MaxLength != nil {
		builder = builder.SetMaxLength(*input.MaxLength)
	}
	if input.MessageType != nil {
		builder = builder.SetMessageType(*input.MessageType)
	}
	if input.EstimatedSegments != nil {
		builder = builder.SetEstimatedSegments(*input.EstimatedSegments)
	}
	if input.EstimatedCost != nil {
		builder = builder.SetEstimatedCost(*input.EstimatedCost)
	}
	if input.Currency != nil {
		builder = builder.SetCurrency(*input.Currency)
	}
	if input.Variables != nil {
		builder = builder.SetVariables(input.Variables)
	}
	if input.Metadata != nil {
		builder = builder.SetMetadata(input.Metadata)
	}
	if input.LastUsedAt != nil {
		builder = builder.SetLastUsedAt(*input.LastUsedAt)
	}
	if input.UsageCount != nil {
		builder = builder.SetUsageCount(*input.UsageCount)
	}

	template, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "SMS template not found")
		}
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "SMS template constraint violation")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update SMS template")
	}

	return template, nil
}

func (r *smsTemplateRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.SMSTemplate.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "SMS template not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete SMS template")
	}

	return nil
}

// Query operations

func (r *smsTemplateRepository) List(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error) {
	query := r.client.SMSTemplate.Query()
	return model.WithPaginationAndOptions[*ent.SMSTemplate, *ent.SMSTemplateQuery](ctx, query, opts)
}

func (r *smsTemplateRepository) ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error) {
	query := r.client.SMSTemplate.Query().
		Where(smstemplate.OrganizationID(orgID))
	return model.WithPaginationAndOptions[*ent.SMSTemplate, *ent.SMSTemplateQuery](ctx, query, opts)
}

func (r *smsTemplateRepository) ListByType(ctx context.Context, templateType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error) {
	query := r.client.SMSTemplate.Query().
		Where(smstemplate.Type(templateType))
	return model.WithPaginationAndOptions[*ent.SMSTemplate, *ent.SMSTemplateQuery](ctx, query, opts)
}

func (r *smsTemplateRepository) ListByLocale(ctx context.Context, locale string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error) {
	query := r.client.SMSTemplate.Query().
		Where(smstemplate.Locale(locale))
	return model.WithPaginationAndOptions[*ent.SMSTemplate, *ent.SMSTemplateQuery](ctx, query, opts)
}

func (r *smsTemplateRepository) ListByMessageType(ctx context.Context, messageType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error) {
	query := r.client.SMSTemplate.Query().
		Where(smstemplate.MessageType(messageType))
	return model.WithPaginationAndOptions[*ent.SMSTemplate, *ent.SMSTemplateQuery](ctx, query, opts)
}

func (r *smsTemplateRepository) ListActive(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error) {
	query := r.client.SMSTemplate.Query().
		Where(smstemplate.Active(true))
	return model.WithPaginationAndOptions[*ent.SMSTemplate, *ent.SMSTemplateQuery](ctx, query, opts)
}

func (r *smsTemplateRepository) ListSystem(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error) {
	query := r.client.SMSTemplate.Query().
		Where(smstemplate.System(true))
	return model.WithPaginationAndOptions[*ent.SMSTemplate, *ent.SMSTemplateQuery](ctx, query, opts)
}

// Template retrieval operations

func (r *smsTemplateRepository) GetByTypeAndOrganization(ctx context.Context, templateType string, orgID *xid.ID, locale string) (*ent.SMSTemplate, error) {
	query := r.client.SMSTemplate.Query().
		Where(
			smstemplate.Type(templateType),
			smstemplate.Locale(locale),
			smstemplate.Active(true),
		)

	if orgID != nil {
		query = query.Where(smstemplate.OrganizationID(*orgID))
	} else {
		query = query.Where(smstemplate.OrganizationIDIsNil())
	}

	template, err := query.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "SMS template not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get SMS template")
	}

	return template, nil
}

func (r *smsTemplateRepository) GetByTypeAndLocale(ctx context.Context, templateType, locale string) (*ent.SMSTemplate, error) {
	template, err := r.client.SMSTemplate.Query().
		Where(
			smstemplate.Type(templateType),
			smstemplate.Locale(locale),
			smstemplate.Active(true),
		).
		Order(smstemplate.BySystem(sql.OrderAsc())). // Prefer custom templates over system
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "SMS template not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get SMS template")
	}

	return template, nil
}

func (r *smsTemplateRepository) GetSystemTemplate(ctx context.Context, templateType, locale string) (*ent.SMSTemplate, error) {
	template, err := r.client.SMSTemplate.Query().
		Where(
			smstemplate.Type(templateType),
			smstemplate.Locale(locale),
			smstemplate.System(true),
			smstemplate.Active(true),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "System SMS template not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get system SMS template")
	}

	return template, nil
}

func (r *smsTemplateRepository) GetOrganizationTemplate(ctx context.Context, templateType string, orgID xid.ID, locale string) (*ent.SMSTemplate, error) {
	template, err := r.client.SMSTemplate.Query().
		Where(
			smstemplate.Type(templateType),
			smstemplate.OrganizationID(orgID),
			smstemplate.Locale(locale),
			smstemplate.Active(true),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Organization SMS template not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization SMS template")
	}

	return template, nil
}

// Template management operations

func (r *smsTemplateRepository) ActivateTemplate(ctx context.Context, id xid.ID) error {
	err := r.client.SMSTemplate.UpdateOneID(id).
		SetActive(true).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "SMS template not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to activate SMS template")
	}

	return nil
}

func (r *smsTemplateRepository) DeactivateTemplate(ctx context.Context, id xid.ID) error {
	err := r.client.SMSTemplate.UpdateOneID(id).
		SetActive(false).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "SMS template not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to deactivate SMS template")
	}

	return nil
}

func (r *smsTemplateRepository) CloneTemplate(ctx context.Context, id xid.ID, newName string, orgID *xid.ID) (*ent.SMSTemplate, error) {
	// Get the original template
	original, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Create the clone
	builder := r.client.SMSTemplate.Create().
		SetName(newName).
		SetContent(original.Content).
		SetType(original.Type).
		SetActive(original.Active).
		SetSystem(false). // Clones are never system templates
		SetLocale(original.Locale).
		SetMaxLength(original.MaxLength).
		SetMessageType(original.MessageType).
		SetEstimatedSegments(original.EstimatedSegments).
		SetEstimatedCost(original.EstimatedCost).
		SetCurrency(original.Currency).
		SetVariables(original.Variables).
		SetMetadata(original.Metadata)

	if orgID != nil {
		builder = builder.SetOrganizationID(*orgID)
	}

	clone, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "SMS template with this type and locale already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to clone SMS template")
	}

	return clone, nil
}

// Usage tracking operations

func (r *smsTemplateRepository) IncrementUsage(ctx context.Context, id xid.ID) error {
	err := r.client.SMSTemplate.UpdateOneID(id).
		AddUsageCount(1).
		SetLastUsedAt(time.Now()).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "SMS template not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to increment usage count")
	}

	return nil
}

func (r *smsTemplateRepository) UpdateLastUsed(ctx context.Context, id xid.ID, timestamp time.Time) error {
	err := r.client.SMSTemplate.UpdateOneID(id).
		SetLastUsedAt(timestamp).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "SMS template not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update last used timestamp")
	}

	return nil
}

func (r *smsTemplateRepository) GetUsageStats(ctx context.Context, id xid.ID, period string) (*SMSTemplateUsageStats, error) {
	template, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// For now, return basic stats from the template
	// In a real implementation, you'd query actual usage logs
	stats := &SMSTemplateUsageStats{
		TemplateID:      id,
		TotalUsage:      template.UsageCount,
		UsageToday:      0, // Would query actual logs
		UsageWeek:       0, // Would query actual logs
		UsageMonth:      0, // Would query actual logs
		LastUsed:        &template.LastUsedAt,
		AverageSegments: float64(template.EstimatedSegments),
		TotalCost:       float64(template.UsageCount) * template.EstimatedCost,
		Currency:        template.Currency,
	}

	return stats, nil
}

func (r *smsTemplateRepository) ResetUsageStats(ctx context.Context, id xid.ID) error {
	err := r.client.SMSTemplate.UpdateOneID(id).
		SetUsageCount(0).
		ClearLastUsedAt().
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "SMS template not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to reset usage stats")
	}

	return nil
}

// Utility operations

func (r *smsTemplateRepository) CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error) {
	count, err := r.client.SMSTemplate.Query().
		Where(smstemplate.OrganizationID(orgID)).
		Count(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count SMS templates")
	}

	return count, nil
}

func (r *smsTemplateRepository) CountByType(ctx context.Context, templateType string) (int, error) {
	count, err := r.client.SMSTemplate.Query().
		Where(smstemplate.Type(templateType)).
		Count(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count SMS templates")
	}

	return count, nil
}

func (r *smsTemplateRepository) CountByMessageType(ctx context.Context, messageType string) (int, error) {
	count, err := r.client.SMSTemplate.Query().
		Where(smstemplate.MessageType(messageType)).
		Count(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count SMS templates")
	}

	return count, nil
}

func (r *smsTemplateRepository) ListTemplateTypes(ctx context.Context) ([]string, error) {
	var types []string
	err := r.client.SMSTemplate.Query().
		Modify(func(s *sql.Selector) {
			s.Select("DISTINCT type")
		}).
		Scan(ctx, &types)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list template types")
	}

	return types, nil
}

func (r *smsTemplateRepository) ListMessageTypes(ctx context.Context) ([]string, error) {
	var types []string
	err := r.client.SMSTemplate.Query().
		Modify(func(s *sql.Selector) {
			s.Select("DISTINCT message_type")
		}).
		Scan(ctx, &types)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list message types")
	}

	return types, nil
}

func (r *smsTemplateRepository) ListLocales(ctx context.Context) ([]string, error) {
	var locales []string
	err := r.client.SMSTemplate.Query().
		Modify(func(s *sql.Selector) {
			s.Select("DISTINCT locale")
		}).
		Scan(ctx, &locales)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list locales")
	}

	return locales, nil
}

// Advanced queries

func (r *smsTemplateRepository) ListByOrganizationAndType(ctx context.Context, orgID xid.ID, templateType string) ([]*ent.SMSTemplate, error) {
	templates, err := r.client.SMSTemplate.Query().
		Where(
			smstemplate.OrganizationID(orgID),
			smstemplate.Type(templateType),
		).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list SMS templates")
	}

	return templates, nil
}

func (r *smsTemplateRepository) ListByOrganizationAndMessageType(ctx context.Context, orgID xid.ID, messageType string) ([]*ent.SMSTemplate, error) {
	templates, err := r.client.SMSTemplate.Query().
		Where(
			smstemplate.OrganizationID(orgID),
			smstemplate.MessageType(messageType),
		).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list SMS templates")
	}

	return templates, nil
}

func (r *smsTemplateRepository) GetTemplateHierarchy(ctx context.Context, templateType string, orgID *xid.ID, locale string) ([]*ent.SMSTemplate, error) {
	var templates []*ent.SMSTemplate

	// First try organization-specific template
	if orgID != nil {
		orgTemplate, err := r.GetOrganizationTemplate(ctx, templateType, *orgID, locale)
		if err == nil {
			templates = append(templates, orgTemplate)
		}
	}

	// Then try system template
	systemTemplate, err := r.GetSystemTemplate(ctx, templateType, locale)
	if err == nil {
		templates = append(templates, systemTemplate)
	}

	return templates, nil
}

func (r *smsTemplateRepository) SearchTemplates(ctx context.Context, query string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SMSTemplate], error) {
	searchQuery := r.client.SMSTemplate.Query().
		Where(
			smstemplate.Or(
				smstemplate.NameContains(query),
				smstemplate.ContentContains(query),
				smstemplate.TypeContains(query),
			),
		)
	return model.WithPaginationAndOptions[*ent.SMSTemplate, *ent.SMSTemplateQuery](ctx, searchQuery, opts)
}

func (r *smsTemplateRepository) ListMostUsed(ctx context.Context, orgID *xid.ID, limit int) ([]*ent.SMSTemplate, error) {
	query := r.client.SMSTemplate.Query().
		Order(smstemplate.ByUsageCount(sql.OrderDesc())).
		Limit(limit)

	if orgID != nil {
		query = query.Where(smstemplate.OrganizationID(*orgID))
	}

	templates, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list most used templates")
	}

	return templates, nil
}

func (r *smsTemplateRepository) ListRecentlyUsed(ctx context.Context, orgID *xid.ID, limit int) ([]*ent.SMSTemplate, error) {
	query := r.client.SMSTemplate.Query().
		Where(smstemplate.LastUsedAtNotNil()).
		Order(smstemplate.ByLastUsedAt(sql.OrderDesc())).
		Limit(limit)

	if orgID != nil {
		query = query.Where(smstemplate.OrganizationID(*orgID))
	}

	templates, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list recently used templates")
	}

	return templates, nil
}

func (r *smsTemplateRepository) ListUnused(ctx context.Context, orgID *xid.ID, since time.Time) ([]*ent.SMSTemplate, error) {
	query := r.client.SMSTemplate.Query().
		Where(
			smstemplate.Or(
				smstemplate.LastUsedAtIsNil(),
				smstemplate.LastUsedAtLT(since),
			),
		)

	if orgID != nil {
		query = query.Where(smstemplate.OrganizationID(*orgID))
	}

	templates, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list unused templates")
	}

	return templates, nil
}

// Template validation operations

func (r *smsTemplateRepository) ValidateTemplate(ctx context.Context, content string, maxLength int) error {
	if len(content) == 0 {
		return errors.New(errors.CodeBadRequest, "Template content cannot be empty")
	}

	if len(content) > maxLength {
		return errors.New(errors.CodeBadRequest, fmt.Sprintf("Template content exceeds maximum length of %d characters", maxLength))
	}

	return nil
}

func (r *smsTemplateRepository) ValidateVariables(ctx context.Context, content string, variables []string) error {
	for _, variable := range variables {
		placeholder := fmt.Sprintf("{{%s}}", variable)
		if !strings.Contains(content, placeholder) {
			return errors.New(errors.CodeBadRequest, fmt.Sprintf("Variable %s is not used in template content", variable))
		}
	}

	return nil
}

func (r *smsTemplateRepository) GetTemplateVariables(ctx context.Context, templateType string) ([]string, error) {
	// This would typically return common variables for each template type
	commonVariables := map[string][]string{
		"verification":   {"code", "user_name", "app_name"},
		"mfa_code":       {"code", "user_name", "expires_in"},
		"password_reset": {"reset_link", "user_name", "expires_in"},
		"welcome":        {"user_name", "app_name", "login_url"},
		"invitation":     {"inviter_name", "organization_name", "invite_link"},
	}

	if variables, exists := commonVariables[templateType]; exists {
		return variables, nil
	}

	return []string{}, nil
}

func (r *smsTemplateRepository) EstimateCost(ctx context.Context, content string, recipientCount int) (*SMSCostEstimate, error) {
	segments := r.calculateSegments(content)
	costPerSegment := 0.05 // Default cost per segment in USD

	estimate := &SMSCostEstimate{
		EstimatedSegments: segments,
		EstimatedCost:     float64(segments) * costPerSegment,
		Currency:          "USD",
		CostPerSegment:    costPerSegment,
		TotalRecipients:   recipientCount,
		TotalCost:         float64(segments) * costPerSegment * float64(recipientCount),
	}

	return estimate, nil
}

func (r *smsTemplateRepository) EstimateSegments(ctx context.Context, content string) (int, error) {
	return r.calculateSegments(content), nil
}

func (r *smsTemplateRepository) calculateSegments(content string) int {
	// GSM 7-bit encoding: 160 characters per segment
	// Unicode encoding: 70 characters per segment
	const gsmSegmentLength = 160
	const unicodeSegmentLength = 70

	// Simple heuristic: if content contains non-ASCII characters, use Unicode
	isUnicode := false
	for _, r := range content {
		if r > 127 {
			isUnicode = true
			break
		}
	}

	segmentLength := gsmSegmentLength
	if isUnicode {
		segmentLength = unicodeSegmentLength
	}

	segments := len(content) / segmentLength
	if len(content)%segmentLength != 0 {
		segments++
	}

	return segments
}

// Bulk operations

func (r *smsTemplateRepository) BulkCreate(ctx context.Context, inputs []CreateSMSTemplateInput) ([]*ent.SMSTemplate, error) {
	var builders []*ent.SMSTemplateCreate

	for _, input := range inputs {
		builder := r.client.SMSTemplate.Create().
			SetName(input.Name).
			SetContent(input.Content).
			SetType(input.Type).
			SetActive(input.Active).
			SetSystem(input.System).
			SetLocale(input.Locale).
			SetMaxLength(input.MaxLength).
			SetMessageType(input.MessageType)

		if input.OrganizationID != nil {
			builder = builder.SetOrganizationID(*input.OrganizationID)
		}

		if input.EstimatedSegments > 0 {
			builder = builder.SetEstimatedSegments(input.EstimatedSegments)
		}

		if input.EstimatedCost > 0 {
			builder = builder.SetEstimatedCost(input.EstimatedCost)
		}

		if input.Currency != "" {
			builder = builder.SetCurrency(input.Currency)
		}

		if len(input.Variables) > 0 {
			builder = builder.SetVariables(input.Variables)
		}

		if input.Metadata != nil {
			builder = builder.SetMetadata(input.Metadata)
		}

		builders = append(builders, builder)
	}

	templates, err := r.client.SMSTemplate.CreateBulk(builders...).Save(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to bulk create SMS templates")
	}

	return templates, nil
}

func (r *smsTemplateRepository) BulkUpdate(ctx context.Context, updates []BulkSMSTemplateUpdate) ([]*ent.SMSTemplate, error) {
	var templates []*ent.SMSTemplate

	for _, update := range updates {
		template, err := r.Update(ctx, update.ID, update.Input)
		if err != nil {
			return nil, err
		}
		templates = append(templates, template)
	}

	return templates, nil
}

func (r *smsTemplateRepository) BulkDelete(ctx context.Context, ids []xid.ID) error {
	count, err := r.client.SMSTemplate.Delete().
		Where(smstemplate.IDIn(ids...)).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to bulk delete SMS templates")
	}

	if count != len(ids) {
		return errors.New(errors.CodeNotFound, "Some SMS templates were not found")
	}

	return nil
}

func (r *smsTemplateRepository) BulkActivate(ctx context.Context, ids []xid.ID) error {
	_, err := r.client.SMSTemplate.Update().
		Where(smstemplate.IDIn(ids...)).
		SetActive(true).
		Save(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to bulk activate SMS templates")
	}

	return nil
}

func (r *smsTemplateRepository) BulkDeactivate(ctx context.Context, ids []xid.ID) error {
	_, err := r.client.SMSTemplate.Update().
		Where(smstemplate.IDIn(ids...)).
		SetActive(false).
		Save(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to bulk deactivate SMS templates")
	}

	return nil
}

// Import/Export operations

func (r *smsTemplateRepository) ImportTemplates(ctx context.Context, templates []ImportSMSTemplate, overwrite bool) (*ImportResult, error) {
	result := &ImportResult{
		Total: len(templates),
	}

	for _, tmpl := range templates {
		// Check if template already exists
		existing, err := r.client.SMSTemplate.Query().
			Where(
				smstemplate.Type(tmpl.Type),
				smstemplate.Locale(tmpl.Locale),
			).
			First(ctx)

		if err != nil && !ent.IsNotFound(err) {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to check existing template: %v", err))
			continue
		}

		if existing != nil {
			if !overwrite {
				result.Skipped++
				continue
			}

			// Update existing template
			_, err = r.client.SMSTemplate.UpdateOne(existing).
				SetName(tmpl.Name).
				SetContent(tmpl.Content).
				SetMaxLength(tmpl.MaxLength).
				SetMessageType(tmpl.MessageType).
				SetVariables(tmpl.Variables).
				SetMetadata(tmpl.Metadata).
				Save(ctx)

			if err != nil {
				result.Failed++
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to update template: %v", err))
				continue
			}

			result.Updated++
			result.UpdatedIDs = append(result.UpdatedIDs, existing.ID)
		} else {
			// Create new template
			createInput := CreateSMSTemplateInput{
				Name:        tmpl.Name,
				Content:     tmpl.Content,
				Type:        tmpl.Type,
				Active:      true,
				System:      false,
				Locale:      tmpl.Locale,
				MaxLength:   tmpl.MaxLength,
				MessageType: tmpl.MessageType,
				Variables:   tmpl.Variables,
				Metadata:    tmpl.Metadata,
			}

			template, err := r.Create(ctx, createInput)
			if err != nil {
				result.Failed++
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to create template: %v", err))
				continue
			}

			result.Imported++
			result.ImportedIDs = append(result.ImportedIDs, template.ID)
		}
	}

	return result, nil
}

func (r *smsTemplateRepository) ExportTemplates(ctx context.Context, filters ExportFilters) ([]*ent.SMSTemplate, error) {
	query := r.client.SMSTemplate.Query()

	if filters.OrganizationID != nil {
		query = query.Where(smstemplate.OrganizationID(*filters.OrganizationID))
	}

	if len(filters.TemplateIDs) > 0 {
		query = query.Where(smstemplate.IDIn(filters.TemplateIDs...))
	}

	if filters.Type != "" {
		query = query.Where(smstemplate.Type(filters.Type))
	}

	if filters.MessageType != "" {
		query = query.Where(smstemplate.MessageType(filters.MessageType))
	}

	if filters.Locale != "" {
		query = query.Where(smstemplate.Locale(filters.Locale))
	}

	if filters.Active != nil {
		query = query.Where(smstemplate.Active(*filters.Active))
	}

	if filters.System != nil {
		query = query.Where(smstemplate.System(*filters.System))
	}

	if filters.CreatedAfter != nil {
		query = query.Where(smstemplate.CreatedAtGTE(*filters.CreatedAfter))
	}

	if filters.CreatedBefore != nil {
		query = query.Where(smstemplate.CreatedAtLTE(*filters.CreatedBefore))
	}

	templates, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to export SMS templates")
	}

	return templates, nil
}

// Analytics and reporting

func (r *smsTemplateRepository) GetTemplateStats(ctx context.Context, orgID *xid.ID) (*SMSTemplateStats, error) {
	query := r.client.SMSTemplate.Query()
	if orgID != nil {
		query = query.Where(smstemplate.OrganizationID(*orgID))
	}

	templates, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get template stats")
	}

	stats := &SMSTemplateStats{
		TotalTemplates:         len(templates),
		TemplatesByType:        make(map[string]int),
		TemplatesByMessageType: make(map[string]int),
		TemplatesByLocale:      make(map[string]int),
		Currency:               "USD",
	}

	var totalCost float64
	var totalSent int
	var topTemplates []TemplateUsageSummary

	for _, template := range templates {
		if template.Active {
			stats.ActiveTemplates++
		}
		if template.System {
			stats.SystemTemplates++
		} else {
			stats.CustomTemplates++
		}

		stats.TemplatesByType[template.Type]++
		stats.TemplatesByMessageType[template.MessageType]++
		stats.TemplatesByLocale[template.Locale]++

		totalSent += template.UsageCount
		templateCost := float64(template.UsageCount) * template.EstimatedCost
		totalCost += templateCost

		if template.UsageCount > 0 {
			topTemplates = append(topTemplates, TemplateUsageSummary{
				TemplateID:   template.ID,
				Name:         template.Name,
				Type:         template.Type,
				SentCount:    template.UsageCount,
				DeliveryRate: 0.95, // Would be calculated from actual delivery data
				AverageCost:  template.EstimatedCost,
			})
		}
	}

	// Sort top templates by usage
	sort.Slice(topTemplates, func(i, j int) bool {
		return topTemplates[i].SentCount > topTemplates[j].SentCount
	})

	// Keep only top 10
	if len(topTemplates) > 10 {
		topTemplates = topTemplates[:10]
	}

	stats.TotalSMSSent = totalSent
	stats.TotalCost = totalCost
	stats.TopTemplates = topTemplates
	stats.AverageDeliveryRate = 0.95 // Would be calculated from actual delivery data

	return stats, nil
}

func (r *smsTemplateRepository) GetUsageReport(ctx context.Context, orgID *xid.ID, period string) (*SMSUsageReport, error) {
	// This is a simplified implementation
	// In a real system, you'd query actual usage logs with time-based filtering

	templates, err := r.client.SMSTemplate.Query().
		Where(func(s *sql.Selector) {
			if orgID != nil {
				s.Where(sql.EQ(smstemplate.FieldOrganizationID, *orgID))
			}
		}).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get usage report")
	}

	report := &SMSUsageReport{
		Period:        period,
		Currency:      "USD",
		ByMessageType: make(map[string]UsageDetail),
	}

	var totalMessages, totalSegments int
	var totalCost float64
	var templateDetails []TemplateUsageDetail

	for _, template := range templates {
		messages := template.UsageCount
		segments := messages * template.EstimatedSegments
		cost := float64(messages) * template.EstimatedCost

		totalMessages += messages
		totalSegments += segments
		totalCost += cost

		if messages > 0 {
			templateDetails = append(templateDetails, TemplateUsageDetail{
				TemplateID:   template.ID,
				Name:         template.Name,
				Type:         template.Type,
				Messages:     messages,
				Segments:     segments,
				Cost:         cost,
				DeliveryRate: 0.95, // Would be from actual delivery data
			})

			// Aggregate by message type
			if detail, exists := report.ByMessageType[template.MessageType]; exists {
				detail.Messages += messages
				detail.Segments += segments
				detail.Cost += cost
				report.ByMessageType[template.MessageType] = detail
			} else {
				report.ByMessageType[template.MessageType] = UsageDetail{
					Messages: messages,
					Segments: segments,
					Cost:     cost,
				}
			}
		}
	}

	report.TotalMessages = totalMessages
	report.TotalSegments = totalSegments
	report.TotalCost = totalCost
	report.ByTemplate = templateDetails
	report.DeliveryStats = SMSDeliveryReport{
		TotalSent:      totalMessages,
		TotalDelivered: int(float64(totalMessages) * 0.95),
		TotalFailed:    int(float64(totalMessages) * 0.05),
		DeliveryRate:   0.95,
		FailureRate:    0.05,
		ByStatus: map[string]int{
			"delivered": int(float64(totalMessages) * 0.95),
			"failed":    int(float64(totalMessages) * 0.05),
		},
	}

	return report, nil
}

func (r *smsTemplateRepository) GetCostReport(ctx context.Context, orgID *xid.ID, period string) (*SMSCostReport, error) {
	// Simplified implementation
	usageReport, err := r.GetUsageReport(ctx, orgID, period)
	if err != nil {
		return nil, err
	}

	report := &SMSCostReport{
		Period:    period,
		TotalCost: usageReport.TotalCost,
		Currency:  usageReport.Currency,
	}

	if usageReport.TotalMessages > 0 {
		report.AverageCost = usageReport.TotalCost / float64(usageReport.TotalMessages)
	}

	// Convert template usage to cost details
	for _, template := range usageReport.ByTemplate {
		costDetail := TemplateCostDetail{
			TemplateID: template.TemplateID,
			Name:       template.Name,
			Messages:   template.Messages,
			Cost:       template.Cost,
		}

		if usageReport.TotalCost > 0 {
			costDetail.Percentage = (template.Cost / usageReport.TotalCost) * 100
		}

		report.CostByTemplate = append(report.CostByTemplate, costDetail)
	}

	return report, nil
}

func (r *smsTemplateRepository) GetPerformanceMetrics(ctx context.Context, orgID *xid.ID, templateIDs []xid.ID) ([]*SMSTemplateMetrics, error) {
	query := r.client.SMSTemplate.Query()

	if orgID != nil {
		query = query.Where(smstemplate.OrganizationID(*orgID))
	}

	if len(templateIDs) > 0 {
		query = query.Where(smstemplate.IDIn(templateIDs...))
	}

	templates, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get performance metrics")
	}

	var metrics []*SMSTemplateMetrics
	for _, template := range templates {
		metric := &SMSTemplateMetrics{
			TemplateID:      template.ID,
			Name:            template.Name,
			TotalSent:       template.UsageCount,
			DeliveryRate:    0.95, // Would be from actual delivery data
			FailureRate:     0.05,
			AverageSegments: float64(template.EstimatedSegments),
			AverageCost:     template.EstimatedCost,
			LastUsed:        &template.LastUsedAt,
			TrendDirection:  "stable", // Would be calculated from historical data
		}

		metrics = append(metrics, metric)
	}

	return metrics, nil
}

// Compliance and audit operations - simplified implementations

func (r *smsTemplateRepository) GetAuditLog(ctx context.Context, templateID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*SMSTemplateAuditEntry], error) {
	// In a real implementation, you'd have a separate audit_logs table
	// For now, return empty results
	return &model.PaginatedOutput[*SMSTemplateAuditEntry]{
		Data:       []*SMSTemplateAuditEntry{},
		Pagination: &model.Pagination{},
	}, nil
}

func (r *smsTemplateRepository) LogTemplateUsage(ctx context.Context, templateID xid.ID, usage SMSTemplateUsageLog) error {
	// In a real implementation, you'd log to a separate usage_logs table
	// For now, just increment the usage count
	return r.IncrementUsage(ctx, templateID)
}

func (r *smsTemplateRepository) GetComplianceReport(ctx context.Context, orgID xid.ID, from, to time.Time) (*SMSComplianceReport, error) {
	// Simplified compliance report
	templates, err := r.client.SMSTemplate.Query().
		Where(smstemplate.OrganizationID(orgID)).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get compliance report")
	}

	report := &SMSComplianceReport{
		Period: fmt.Sprintf("%s to %s", from.Format("2006-01-02"), to.Format("2006-01-02")),
	}

	for _, template := range templates {
		report.TotalMessages += template.UsageCount

		switch template.MessageType {
		case "transactional":
			report.TransactionalCount += template.UsageCount
		case "promotional":
			report.PromotionalCount += template.UsageCount
		case "marketing":
			report.MarketingCount += template.UsageCount
		}
	}

	return report, nil
}

// Template optimization operations

func (r *smsTemplateRepository) AnalyzeTemplate(ctx context.Context, id xid.ID) (*SMSTemplateAnalysis, error) {
	template, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	analysis := &SMSTemplateAnalysis{
		TemplateID:        id,
		ContentLength:     len(template.Content),
		SegmentCount:      r.calculateSegments(template.Content),
		CharacterType:     r.getCharacterType(template.Content),
		VariableCount:     len(template.Variables),
		OptimizationScore: r.calculateOptimizationScore(template),
		ReadabilityScore:  r.calculateReadabilityScore(template.Content),
	}

	// Analyze for issues
	if analysis.ContentLength > template.MaxLength {
		analysis.Issues = append(analysis.Issues, TemplateIssue{
			Type:        "length",
			Severity:    "high",
			Description: "Template content exceeds maximum length",
		})
	}

	if analysis.SegmentCount > 1 {
		analysis.Suggestions = append(analysis.Suggestions, "Consider shortening the message to fit in a single SMS segment")
	}

	return analysis, nil
}

func (r *smsTemplateRepository) GetOptimizationSuggestions(ctx context.Context, id xid.ID) ([]*SMSOptimizationSuggestion, error) {
	analysis, err := r.AnalyzeTemplate(ctx, id)
	if err != nil {
		return nil, err
	}

	var suggestions []*SMSOptimizationSuggestion

	if analysis.SegmentCount > 1 {
		suggestions = append(suggestions, &SMSOptimizationSuggestion{
			Type:             "length",
			Title:            "Reduce Message Length",
			Description:      "Your message uses multiple SMS segments which increases cost",
			Impact:           "high",
			Effort:           "medium",
			EstimatedSavings: 0.05, // Cost per segment
			Implementation:   "Shorten the message content to fit within a single SMS segment",
		})
	}

	if analysis.OptimizationScore < 0.7 {
		suggestions = append(suggestions, &SMSOptimizationSuggestion{
			Type:        "readability",
			Title:       "Improve Readability",
			Description: "The message could be more readable",
			Impact:      "medium",
			Effort:      "low",
		})
	}

	return suggestions, nil
}

func (r *smsTemplateRepository) OptimizeTemplate(ctx context.Context, id xid.ID, optimizations []string) (*ent.SMSTemplate, error) {
	template, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply optimizations (simplified)
	content := template.Content
	for _, optimization := range optimizations {
		switch optimization {
		case "shorten":
			// Simple shortening by removing unnecessary words
			content = strings.ReplaceAll(content, " please ", " ")
			content = strings.ReplaceAll(content, " kindly ", " ")
		case "remove_punctuation":
			content = strings.ReplaceAll(content, ".", "")
			content = strings.ReplaceAll(content, "!", "")
		}
	}

	// Update the template with optimized content
	return r.Update(ctx, id, UpdateSMSTemplateInput{
		Content: &content,
	})
}

// Helper methods

func (r *smsTemplateRepository) getCharacterType(content string) string {
	for _, r := range content {
		if r > 127 {
			return "unicode"
		}
	}
	return "gsm7"
}

func (r *smsTemplateRepository) calculateOptimizationScore(template *ent.SMSTemplate) float64 {
	score := 1.0

	// Penalize for multiple segments
	if template.EstimatedSegments > 1 {
		score -= 0.2
	}

	// Penalize for very long content
	if len(template.Content) > template.MaxLength*80/100 {
		score -= 0.1
	}

	// Reward for having variables (personalization)
	if len(template.Variables) > 0 {
		score += 0.1
	}

	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score
}

func (r *smsTemplateRepository) calculateReadabilityScore(content string) float64 {
	// Simple readability score based on average word length and sentence count
	words := strings.Fields(content)
	if len(words) == 0 {
		return 0
	}

	totalChars := 0
	for _, word := range words {
		totalChars += len(word)
	}

	avgWordLength := float64(totalChars) / float64(len(words))
	sentences := strings.Split(content, ".")

	// Higher score for shorter average word length and more sentences
	score := 1.0 - (avgWordLength-3)/10   // Penalize long words
	score += float64(len(sentences)) / 10 // Reward more sentences

	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score
}
