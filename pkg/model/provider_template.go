package model

import (
	"time"

	"github.com/rs/xid"
)

// ProviderTemplate represents a provider template in the catalog
type ProviderTemplate struct {
	Base
	Key               string                 `json:"key" example:"google" doc:"Unique template key"`
	Name              string                 `json:"name" example:"Google" doc:"Provider name"`
	DisplayName       string                 `json:"displayName" example:"Sign in with Google" doc:"Display name for UI"`
	Type              string                 `json:"type" example:"oidc" doc:"Provider type (oidc, oauth2, saml)"`
	Protocol          string                 `json:"protocol" example:"openid_connect" doc:"Authentication protocol"`
	IconURL           string                 `json:"iconUrl,omitempty" example:"https://developers.google.com/identity/images/g-logo.png" doc:"Provider icon URL"`
	Category          string                 `json:"category" example:"social" doc:"Provider category"`
	Popular           bool                   `json:"popular" example:"true" doc:"Whether this is a popular provider"`
	Active            bool                   `json:"active" example:"true" doc:"Whether template is active"`
	Description       string                 `json:"description,omitempty" example:"Sign in with your Google account" doc:"Provider description"`
	ConfigTemplate    map[string]interface{} `json:"configTemplate" doc:"Default configuration template"`
	RequiredFields    []string               `json:"requiredFields,omitempty" example:"[\"client_id\", \"client_secret\"]" doc:"Required configuration fields"`
	SupportedFeatures []string               `json:"supportedFeatures,omitempty" example:"[\"auto_discovery\", \"pkce\"]" doc:"Supported features"`
	DocumentationURL  *string                `json:"documentationUrl,omitempty" example:"https://developers.google.com/identity/protocols/oauth2" doc:"Documentation URL"`
	SetupGuideURL     *string                `json:"setupGuideUrl,omitempty" example:"https://docs.example.com/setup/google" doc:"Setup guide URL"`
	Documentation     string                 `json:"documentation,omitempty" doc:"Setup documentation"`

	// Usage statistics
	UsageCount       int                    `json:"usageCount" example:"1250" doc:"Number of organizations using this template"`
	AverageSetupTime *float64               `json:"averageSetupTime,omitempty" example:"5.5" doc:"Average setup time in minutes"`
	SuccessRate      float64                `json:"successRate" example:"95.5" doc:"Setup success rate percentage"`
	PopularityRank   int                    `json:"popularityRank" example:"1" doc:"Popularity ranking"`
	Metadata         map[string]interface{} `json:"metadata,omitempty" doc:"Additional template metadata"`
	LastUsed         time.Time              `json:"lastUsed" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
}

// ProviderTemplateSummary represents a simplified provider template for listings
type ProviderTemplateSummary struct {
	ID          xid.ID  `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Template ID"`
	Key         string  `json:"key" example:"google" doc:"Template key"`
	Name        string  `json:"name" example:"Google" doc:"Provider name"`
	DisplayName string  `json:"displayName" example:"Sign in with Google" doc:"Display name"`
	Type        string  `json:"type" example:"oidc" doc:"Provider type"`
	IconURL     *string `json:"iconUrl,omitempty" doc:"Provider icon URL"`
	Category    string  `json:"category" example:"social" doc:"Provider category"`
	Popular     bool    `json:"popular" example:"true" doc:"Whether this is popular"`
	Active      bool    `json:"active" example:"true" doc:"Whether template is active"`
	UsageCount  int     `json:"usageCount" example:"1250" doc:"Usage count"`
}

// OrganizationProvider represents the relationship between an organization and an enabled provider
type OrganizationProvider struct {
	Base
	OrganizationID      xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	ProviderID          xid.ID                 `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Identity Provider ID"`
	TemplateKey         string                 `json:"templateKey" example:"google" doc:"Template key used"`
	CustomConfig        map[string]interface{} `json:"customConfig,omitempty" doc:"Custom configuration overrides"`
	EnabledAt           time.Time              `json:"enabledAt" example:"2023-01-01T12:00:00Z" doc:"When provider was enabled"`
	LastUsed            *time.Time             `json:"lastUsed,omitempty" example:"2023-01-15T12:00:00Z" doc:"Last authentication time"`
	UsageCount          int                    `json:"usageCount" example:"45" doc:"Number of times used"`
	Enabled             bool                   `json:"enabled" example:"true" doc:"Whether provider is enabled"`
	SuccessRate         float64                `json:"successRate" example:"98.5" doc:"Authentication success rate"`
	TotalLogins         int                    `json:"totalLogins" example:"150" doc:"Total login attempts"`
	SuccessfulLogins    int                    `json:"successfulLogins" example:"148" doc:"Successful logins"`
	FailedLogins        int                    `json:"failedLogins" example:"2" doc:"Failed logins"`
	LastSuccess         *time.Time             `json:"lastSuccess,omitempty" example:"2023-01-15T12:00:00Z" doc:"Last successful authentication"`
	LastFailure         *time.Time             `json:"lastFailure,omitempty" example:"2023-01-10T08:30:00Z" doc:"Last failed authentication"`
	ConfigErrors        int                    `json:"configErrors" example:"0" doc:"Number of configuration errors"`
	AverageResponseTime float64                `json:"averageResponseTime" example:"250.5" doc:"Average response time in milliseconds"`
	AnalyticsData       map[string]interface{} `json:"analyticsData,omitempty" doc:"Additional analytics data"`
	Metadata            map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`

	// Relationships
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
	Provider     *IdentityProvider    `json:"provider,omitempty" doc:"Identity provider information"`
	Template     *ProviderTemplate    `json:"template,omitempty" doc:"Provider template information"`
}

// OrganizationProviderSummary represents a simplified organization provider for listings
type OrganizationProviderSummary struct {
	ID               xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization provider ID"`
	OrganizationID   xid.ID     `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	ProviderID       xid.ID     `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
	TemplateKey      string     `json:"templateKey" example:"google" doc:"Template key"`
	ProviderName     string     `json:"providerName" example:"Google SSO" doc:"Provider name"`
	TemplateName     string     `json:"templateName" example:"Google" doc:"Template name"`
	Enabled          bool       `json:"enabled" example:"true" doc:"Whether enabled"`
	EnabledAt        time.Time  `json:"enabledAt" example:"2023-01-01T12:00:00Z" doc:"When enabled"`
	LastUsed         *time.Time `json:"lastUsed,omitempty" example:"2023-01-15T12:00:00Z" doc:"Last used"`
	UsageCount       int        `json:"usageCount" example:"45" doc:"Usage count"`
	SuccessRate      float64    `json:"successRate" example:"98.5" doc:"Success rate"`
	TotalLogins      int        `json:"totalLogins" example:"150" doc:"Total logins"`
	ConfigErrors     int        `json:"configErrors" example:"0" doc:"Config errors"`
	OrganizationName string     `json:"organizationName" example:"Acme Corp" doc:"Organization name"`
}

// EnableProviderBody represents a request to enable a provider for an organization
type EnableProviderBody struct {
	OrganizationID   xid.ID                 `json:"-" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	TemplateKey      string                 `json:"templateKey" example:"google" doc:"Template key to use" validate:"required"`
	CustomName       string                 `json:"customName,omitempty" example:"Company Google SSO" doc:"Custom provider name"`
	CustomButtonText string                 `json:"customButtonText,omitempty" example:"Continue with Company Google" doc:"Custom button text"`
	Config           map[string]interface{} `json:"config" doc:"Provider configuration" validate:"required"`
	Domain           string                 `json:"domain,omitempty" example:"company.com" doc:"Domain restriction"`
	AutoProvision    bool                   `json:"autoProvision" example:"true" doc:"Whether to auto-provision users"`
	DefaultRole      string                 `json:"defaultRole,omitempty" example:"member" doc:"Default role for new users"`
	AttributeMapping map[string]string      `json:"attributeMapping,omitempty" doc:"Attribute mapping configuration"`
}

// ProviderConfiguration represents provider configuration update
type ProviderConfiguration struct {
	Config           map[string]interface{} `json:"config" doc:"Provider configuration"`
	Domain           string                 `json:"domain,omitempty" doc:"Domain restriction"`
	AutoProvision    bool                   `json:"autoProvision,omitempty" doc:"Auto-provision setting"`
	DefaultRole      string                 `json:"defaultRole,omitempty" doc:"Default role"`
	AttributeMapping map[string]string      `json:"attributeMapping,omitempty" doc:"Attribute mapping"`
	Enabled          bool                   `json:"enabled,omitempty" doc:"Whether provider is enabled"`
}

// ProviderMarketplace represents the provider marketplace view
type ProviderMarketplace struct {
	FeaturedProviders []ProviderTemplate `json:"featuredProviders" doc:"Featured provider templates"`
	PopularProviders  []ProviderTemplate `json:"popularProviders" doc:"Popular provider templates"`
	Categories        []ProviderCategory `json:"categories" doc:"Provider categories"`
	RecentlyAdded     []ProviderTemplate `json:"recentlyAdded" doc:"Recently added templates"`
	RecommendedForOrg []ProviderTemplate `json:"recommendedForOrg" doc:"Recommended for organization"`
}

// ProviderCategory represents a provider category
type ProviderCategory struct {
	Key         string             `json:"key" example:"social" doc:"Category key"`
	Name        string             `json:"name" example:"Social" doc:"Category name"`
	Description string             `json:"description" example:"Social media authentication providers" doc:"Category description"`
	IconURL     string             `json:"iconUrl" example:"https://example.com/social-icon.svg" doc:"Category icon URL"`
	Providers   []ProviderTemplate `json:"providers" doc:"Providers in this category"`
	Count       int                `json:"count" example:"8" doc:"Number of providers in category"`
}

// ProviderFilters represents filters for provider search
type ProviderFilters struct {
	Category        []string `json:"category,omitempty" example:"[\"social\", \"enterprise\"]" doc:"Filter by categories"`
	Type            []string `json:"type,omitempty" example:"[\"oidc\", \"oauth2\"]" doc:"Filter by types"`
	Popular         bool     `json:"popular" example:"true" doc:"Show only popular providers"`
	Enterprise      bool     `json:"enterprise" example:"false" doc:"Show only enterprise providers"`
	Features        []string `json:"features,omitempty" example:"[\"auto_discovery\", \"pkce\"]" doc:"Required features"`
	ComplexityLevel string   `json:"complexityLevel,omitempty" example:"simple" doc:"Complexity level (simple, intermediate, advanced)"`
}

// ProviderSetupWizard represents setup wizard data
type ProviderSetupWizard struct {
	TemplateKey string                 `json:"templateKey" example:"google" doc:"Template key"`
	Steps       []SetupWizardStep      `json:"steps" doc:"Setup wizard steps"`
	Validation  SetupValidation        `json:"validation" doc:"Validation results"`
	TestResults *ConnectionTestResults `json:"testResults,omitempty" doc:"Connection test results"`
}

// SetupWizardStep represents a step in the setup wizard
type SetupWizardStep struct {
	StepNumber  int                `json:"stepNumber" example:"1" doc:"Step number"`
	Title       string             `json:"title" example:"Configure OAuth Client" doc:"Step title"`
	Description string             `json:"description" example:"Enter your OAuth client credentials" doc:"Step description"`
	Fields      []SetupWizardField `json:"fields" doc:"Step fields"`
	Optional    bool               `json:"optional" example:"false" doc:"Whether step is optional"`
	HelpText    string             `json:"helpText,omitempty" doc:"Additional help text"`
	DocsURL     string             `json:"docsUrl,omitempty" example:"https://developers.google.com/identity/protocols/oauth2" doc:"Documentation URL"`
}

// SetupWizardField represents a field in the setup wizard
type SetupWizardField struct {
	Key         string `json:"key" example:"client_id" doc:"Field key"`
	Label       string `json:"label" example:"Client ID" doc:"Field label"`
	Type        string `json:"type" example:"text" doc:"Field type (text, password, url, select, textarea, file)"`
	Required    bool   `json:"required" example:"true" doc:"Whether field is required"`
	Placeholder string `json:"placeholder,omitempty" example:"Enter your client ID" doc:"Field placeholder"`
	HelpText    string `json:"help

Text,omitempty" example:"Found in your Google Cloud Console" doc:"Help text"`
	Validation   string      `json:"validation,omitempty" doc:"Validation regex pattern"`
	Options      []string    `json:"options,omitempty" doc:"Options for select fields"`
	DefaultValue interface{} `json:"defaultValue,omitempty" doc:"Default field value"`
	Sensitive    bool        `json:"sensitive" example:"false" doc:"Whether field contains sensitive data"`
}

// SetupValidation represents configuration validation results
type SetupValidation struct {
	ConfigValid     bool     `json:"configValid" example:"true" doc:"Whether configuration is valid"`
	MissingFields   []string `json:"missingFields,omitempty" example:"[\"client_secret\"]" doc:"Missing required fields"`
	InvalidFields   []string `json:"invalidFields,omitempty" example:"[\"redirect_uri\"]" doc:"Invalid field values"`
	Warnings        []string `json:"warnings,omitempty" doc:"Configuration warnings"`
	Recommendations []string `json:"recommendations,omitempty" doc:"Configuration recommendations"`
}

// ConnectionTestResults represents provider connection test results
type ConnectionTestResults struct {
	Success         bool              `json:"success" example:"true" doc:"Whether connection test was successful"`
	TestsPerformed  []ConnectionTest  `json:"testsPerformed" doc:"Individual tests performed"`
	OverallLatency  int               `json:"overallLatency" example:"250" doc:"Overall latency in milliseconds"`
	Recommendations []string          `json:"recommendations,omitempty" doc:"Connection recommendations"`
	Issues          []ConnectionIssue `json:"issues,omitempty" doc:"Connection issues found"`
}

// ConnectionTest represents an individual connection test
type ConnectionTest struct {
	TestName     string                 `json:"testName" example:"Authorization Endpoint" doc:"Test name"`
	Success      bool                   `json:"success" example:"true" doc:"Whether test was successful"`
	Latency      int                    `json:"latency" example:"120" doc:"Test latency in milliseconds"`
	ErrorMessage string                 `json:"errorMessage,omitempty" doc:"Error message if test failed"`
	Details      map[string]interface{} `json:"details,omitempty" doc:"Additional test details"`
}

// ConnectionIssue represents a connection issue
type ConnectionIssue struct {
	Severity   string `json:"severity" example:"error" doc:"Issue severity (error, warning, info)"`
	Message    string `json:"message" example:"Invalid client credentials" doc:"Issue message"`
	Resolution string `json:"resolution,omitempty" doc:"Suggested resolution"`
	DocsURL    string `json:"docsUrl,omitempty" example:"https://docs.example.com/troubleshooting" doc:"Documentation URL"`
}

// Analytics and reporting types

// ProviderTemplateUsageStats represents usage statistics for a template
type ProviderTemplateUsageStats struct {
	TemplateKey       string    `json:"templateKey" example:"google" doc:"Template key"`
	TemplateName      string    `json:"templateName" example:"Google" doc:"Template name"`
	OrganizationCount int       `json:"organizationCount" example:"125" doc:"Number of organizations using this template"`
	TotalLogins       int       `json:"totalLogins" example:"15420" doc:"Total logins across all organizations"`
	LastUsed          time.Time `json:"lastUsed" example:"2023-01-15T12:00:00Z" doc:"Last time template was used"`
	AverageSetupTime  float64   `json:"averageSetupTime" example:"5.5" doc:"Average setup time in minutes"`
	SuccessRate       float64   `json:"successRate" example:"95.8" doc:"Average success rate percentage"`
	PopularityRank    int       `json:"popularityRank" example:"1" doc:"Popularity ranking"`
}

// OrganizationProviderStats represents statistics for an organization's providers
type OrganizationProviderStats struct {
	OrganizationID    xid.ID                    `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	TotalProviders    int                       `json:"totalProviders" example:"5" doc:"Total number of configured providers"`
	EnabledProviders  int                       `json:"enabledProviders" example:"4" doc:"Number of enabled providers"`
	ProvidersByType   map[string]int            `json:"providersByType" example:"{\"oidc\":3,\"oauth2\":1,\"saml\":1}" doc:"Providers grouped by type"`
	MostUsedProvider  string                    `json:"mostUsedProvider" example:"Google" doc:"Most used provider name"`
	LastProviderAdded time.Time                 `json:"lastProviderAdded" example:"2023-01-10T12:00:00Z" doc:"When last provider was added"`
	ProviderStats     []IndividualProviderStats `json:"providerStats" doc:"Individual provider statistics"`
}

// IndividualProviderStats represents statistics for a single provider
type IndividualProviderStats struct {
	ProviderID   xid.ID    `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
	ProviderName string    `json:"providerName" example:"Google SSO" doc:"Provider name"`
	TemplateKey  string    `json:"templateKey" example:"google" doc:"Template key"`
	LoginCount   int       `json:"loginCount" example:"150" doc:"Total login attempts"`
	LastUsed     time.Time `json:"lastUsed" example:"2023-01-15T12:00:00Z" doc:"Last usage time"`
	SuccessRate  float64   `json:"successRate" example:"98.5" doc:"Success rate percentage"`
	UniqueUsers  int       `json:"uniqueUsers" example:"45" doc:"Number of unique users"`
	SetupDate    time.Time `json:"setupDate" example:"2023-01-01T12:00:00Z" doc:"When provider was set up"`
	ConfigErrors int       `json:"configErrors" example:"0" doc:"Number of configuration errors"`
}

// Request/Response types for API endpoints

// ListProviderTemplatesRequest represents parameters for listing templates
type ListProviderTemplatesParams struct {
	PaginationParams
	Category        string              `json:"category,omitempty" query:"category" example:"social" doc:"Filter by category"`
	Type            string              `json:"type,omitempty" query:"type" example:"oidc" doc:"Filter by type"`
	Popular         OptionalParam[bool] `json:"popular,omitempty" query:"popular" example:"true" doc:"Filter by popularity"`
	Search          string              `json:"search,omitempty" query:"search" example:"google" doc:"Search query"`
	IncludeInactive bool                `json:"includeInactive" query:"includeInactive" example:"false" doc:"Include inactive templates"`
}

// ListProviderTemplatesResponse represents the response for listing templates
type ListProviderTemplatesResponse = PaginatedOutput[ProviderTemplateSummary]

// GetProviderTemplateResponse represents the response for getting a single template
type GetProviderTemplateResponse = Output[ProviderTemplate]

// ListOrganizationProvidersParams represents parameters for listing organization providers
type ListOrganizationProvidersParams struct {
	PaginationParams
	Enabled     OptionalParam[bool] `json:"enabled,omitempty" query:"enabled" example:"true" doc:"Filter by enabled status"`
	TemplateKey string              `json:"templateKey,omitempty" query:"templateKey" example:"google" doc:"Filter by template key"`
	Type        string              `json:"type,omitempty" query:"type" example:"oidc" doc:"Filter by provider type"`
}

// ListOrganizationProvidersResponse represents the response for listing organization providers
type ListOrganizationProvidersResponse = PaginatedOutput[OrganizationProviderSummary]

// GetOrganizationProviderResponse represents the response for getting a single organization provider
type GetOrganizationProviderResponse = Output[OrganizationProvider]

// EnableProviderResponse represents the response for enabling a provider
type EnableProviderResponse = Output[OrganizationProvider]

// ProviderMarketplaceResponse represents the response for getting the provider marketplace
type ProviderMarketplaceResponse = Output[ProviderMarketplace]

// ProviderAnalyticsParams represents parameters for provider analytics
type ProviderAnalyticsParams struct {
	StartDate OptionalParam[time.Time] `json:"startDate,omitempty" query:"startDate" doc:"OnStart date for analytics"`
	EndDate   OptionalParam[time.Time] `json:"endDate,omitempty" query:"endDate" doc:"End date for analytics"`
	Interval  string                   `json:"interval,omitempty" query:"interval" example:"day" doc:"Analytics interval (hour, day, week, month)"`
}

// OrganizationProviderStatsResponse represents the response for organization provider statistics
type OrganizationProviderStatsResponse = Output[OrganizationProviderStats]

// TemplateUsageStatsResponse represents the response for template usage statistics
type TemplateUsageStatsResponse = Output[TemplateUsageStats]
