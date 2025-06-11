package repository

import (
	"context"
	"time"

	"github.com/juicycleff/frank/internal/model"
	"github.com/rs/xid"
)

// ProviderCatalogRepository manages SSO provider templates
type ProviderCatalogRepository interface {
	// Template management
	UpsertTemplate(ctx context.Context, template model.ProviderTemplate) error
	GetTemplateByKey(ctx context.Context, key string) (*model.ProviderTemplate, error)
	GetTemplateByID(ctx context.Context, id xid.ID) (*model.ProviderTemplate, error)
	ListTemplates(ctx context.Context, params ListTemplatesParams) ([]model.ProviderTemplate, error)
	UpdateTemplate(ctx context.Context, key string, template model.ProviderTemplate) error
	DeleteTemplate(ctx context.Context, key string) error

	// Template queries
	ListTemplatesByCategory(ctx context.Context, category string) ([]model.ProviderTemplate, error)
	ListPopularTemplates(ctx context.Context) ([]model.ProviderTemplate, error)
	SearchTemplates(ctx context.Context, query string) ([]model.ProviderTemplate, error)

	// Template analytics
	GetTemplateUsageStats(ctx context.Context, key string) (*TemplateUsageStats, error)
	GetMostUsedTemplates(ctx context.Context, limit int) ([]TemplateUsageStats, error)
}

// OrganizationProviderRepository manages organization-provider relationships
type OrganizationProviderRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateOrganizationProviderInput) (*model.OrganizationProvider, error)
	GetByID(ctx context.Context, id xid.ID) (*model.OrganizationProvider, error)
	GetByOrganizationAndProvider(ctx context.Context, orgID, providerID xid.ID) (*model.OrganizationProvider, error)
	Update(ctx context.Context, id xid.ID, input UpdateOrganizationProviderInput) (*model.OrganizationProvider, error)
	Delete(ctx context.Context, id xid.ID) error

	// List operations
	ListByOrganization(ctx context.Context, orgID xid.ID) ([]model.OrganizationProvider, error)
	ListByProvider(ctx context.Context, providerID xid.ID) ([]model.OrganizationProvider, error)
	ListByTemplate(ctx context.Context, templateKey string) ([]model.OrganizationProvider, error)

	// Analytics
	UpdateUsageStats(ctx context.Context, id xid.ID) error
	GetUsageStats(ctx context.Context, orgID xid.ID) (*OrganizationProviderStats, error)

	// Bulk operations
	EnableMultipleProviders(ctx context.Context, orgID xid.ID, providerConfigs []EnableProviderConfig) error
	DisableAllProviders(ctx context.Context, orgID xid.ID) error
}

// Input types for repository operations

type ListTemplatesParams struct {
	Category        string
	Popular         *bool
	Type            string
	IncludeInactive bool
	Search          string
	Limit           int
	Offset          int
}

type CreateOrganizationProviderInput struct {
	OrganizationID xid.ID                       `json:"organizationId"`
	ProviderID     xid.ID                       `json:"providerId"`
	TemplateKey    string                       `json:"templateKey"`
	CustomConfig   model.IdentityProviderConfig `json:"customConfig"`
	EnabledAt      time.Time                    `json:"enabledAt"`
}

type UpdateOrganizationProviderInput struct {
	CustomConfig model.IdentityProviderConfig `json:"customConfig,omitempty"`
	LastUsed     *time.Time                   `json:"lastUsed,omitempty"`
	UsageCount   *int                         `json:"usageCount,omitempty"`
	Enabled      *bool                        `json:"enabled,omitempty"`
}

type EnableProviderConfig struct {
	TemplateKey      string                 `json:"templateKey"`
	CustomName       string                 `json:"customName,omitempty"`
	Config           map[string]interface{} `json:"config"`
	AutoProvision    bool                   `json:"autoProvision"`
	DefaultRole      string                 `json:"defaultRole,omitempty"`
	AttributeMapping map[string]string      `json:"attributeMapping,omitempty"`
}

// Analytics types

type TemplateUsageStats struct {
	TemplateKey       string    `json:"templateKey"`
	TemplateName      string    `json:"templateName"`
	OrganizationCount int       `json:"organizationCount"`
	TotalLogins       int       `json:"totalLogins"`
	LastUsed          time.Time `json:"lastUsed"`
	AverageSetupTime  float64   `json:"averageSetupTime"` // in minutes
	SuccessRate       float64   `json:"successRate"`      // percentage
	PopularityRank    int       `json:"popularityRank"`
}

type OrganizationProviderStats struct {
	OrganizationID    xid.ID                    `json:"organizationId"`
	TotalProviders    int                       `json:"totalProviders"`
	EnabledProviders  int                       `json:"enabledProviders"`
	ProvidersByType   map[string]int            `json:"providersByType"`
	MostUsedProvider  string                    `json:"mostUsedProvider"`
	LastProviderAdded time.Time                 `json:"lastProviderAdded"`
	ProviderStats     []IndividualProviderStats `json:"providerStats"`
}

type IndividualProviderStats struct {
	ProviderID   xid.ID    `json:"providerId"`
	ProviderName string    `json:"providerName"`
	TemplateKey  string    `json:"templateKey"`
	LoginCount   int       `json:"loginCount"`
	LastUsed     time.Time `json:"lastUsed"`
	SuccessRate  float64   `json:"successRate"`
	UniqueUsers  int       `json:"uniqueUsers"`
	SetupDate    time.Time `json:"setupDate"`
	ConfigErrors int       `json:"configErrors"`
}

// Extended model types that should be added to the model package

// These types extend the existing model package for the catalog system

func init() {
	// This ensures the new model types are properly integrated
}

// ProviderMarketplace represents a curated list of providers
type ProviderMarketplace struct {
	FeaturedProviders []model.ProviderTemplate `json:"featuredProviders"`
	PopularProviders  []model.ProviderTemplate `json:"popularProviders"`
	Categories        []ProviderCategory       `json:"categories"`
	RecentlyAdded     []model.ProviderTemplate `json:"recentlyAdded"`
	RecommendedForOrg []model.ProviderTemplate `json:"recommendedForOrg"`
}

type ProviderCategory struct {
	Key         string                   `json:"key"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	IconURL     string                   `json:"iconUrl"`
	Providers   []model.ProviderTemplate `json:"providers"`
	Count       int                      `json:"count"`
}

// Marketplace service for advanced provider discovery
type MarketplaceService interface {
	GetMarketplace(ctx context.Context, orgID xid.ID) (*ProviderMarketplace, error)
	GetProvidersByCategory(ctx context.Context, category string) ([]model.ProviderTemplate, error)
	GetRecommendedProviders(ctx context.Context, orgID xid.ID) ([]model.ProviderTemplate, error)
	SearchProviders(ctx context.Context, query string, filters ProviderFilters) ([]model.ProviderTemplate, error)
}

type ProviderFilters struct {
	Category        []string `json:"category"`
	Type            []string `json:"type"`
	Popular         bool     `json:"popular"`
	Enterprise      bool     `json:"enterprise"`
	Features        []string `json:"features"`
	ComplexityLevel string   `json:"complexityLevel"` // "simple", "intermediate", "advanced"
}

// Provider setup wizard support
type ProviderSetupWizard struct {
	TemplateKey string                 `json:"templateKey"`
	Steps       []SetupWizardStep      `json:"steps"`
	Validation  SetupValidation        `json:"validation"`
	TestResults *ConnectionTestResults `json:"testResults,omitempty"`
}

type SetupWizardStep struct {
	StepNumber  int                `json:"stepNumber"`
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Fields      []SetupWizardField `json:"fields"`
	Optional    bool               `json:"optional"`
	HelpText    string             `json:"helpText,omitempty"`
	DocsURL     string             `json:"docsUrl,omitempty"`
}

type SetupWizardField struct {
	Key          string      `json:"key"`
	Label        string      `json:"label"`
	Type         string      `json:"type"` // "text", "password", "url", "select", "textarea", "file"
	Required     bool        `json:"required"`
	Placeholder  string      `json:"placeholder,omitempty"`
	HelpText     string      `json:"helpText,omitempty"`
	Validation   string      `json:"validation,omitempty"` // regex pattern
	Options      []string    `json:"options,omitempty"`    // for select fields
	DefaultValue interface{} `json:"defaultValue,omitempty"`
	Sensitive    bool        `json:"sensitive"` // for password/secret fields
}

type SetupValidation struct {
	ConfigValid     bool     `json:"configValid"`
	MissingFields   []string `json:"missingFields,omitempty"`
	InvalidFields   []string `json:"invalidFields,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`
}

type ConnectionTestResults struct {
	Success         bool              `json:"success"`
	TestsPerformed  []ConnectionTest  `json:"testsPerformed"`
	OverallLatency  int               `json:"overallLatency"` // milliseconds
	Recommendations []string          `json:"recommendations,omitempty"`
	Issues          []ConnectionIssue `json:"issues,omitempty"`
}

type ConnectionTest struct {
	TestName     string                 `json:"testName"`
	Success      bool                   `json:"success"`
	Latency      int                    `json:"latency"` // milliseconds
	ErrorMessage string                 `json:"errorMessage,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

type ConnectionIssue struct {
	Severity   string `json:"severity"` // "error", "warning", "info"
	Message    string `json:"message"`
	Resolution string `json:"resolution,omitempty"`
	DocsURL    string `json:"docsUrl,omitempty"`
}

// Usage example for the enhanced catalog system:
/*
// 1. Seed the catalog on application startup
catalogService.SeedProviderCatalog(ctx)

// 2. Organization admin sees available providers
availableProviders, _ := catalogService.GetAvailableProviders(ctx)

// 3. Organization enables Google SSO
enableReq := model.EnableProviderRequest{
    OrganizationID: orgID,
    TemplateKey:    "google",
    Config: map[string]interface{}{
        "client_id":     "your-google-client-id",
        "client_secret": "your-google-client-secret",
    },
    AutoProvision: true,
    Domain: "company.com",
}

provider, _ := catalogService.EnableProviderForOrganization(ctx, enableReq)

// 4. Users can now login with Google SSO
// The provider is automatically configured with Google's endpoints
*/
