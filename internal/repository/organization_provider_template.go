package repository

import (
	"context"
	"encoding/json"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/organizationprovider"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

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
	model.PaginationParams
	Category        string
	Popular         *bool
	Type            string
	IncludeInactive bool
	Search          string
}

type CreateOrganizationProviderInput struct {
	OrganizationID xid.ID         `json:"organizationId"`
	ProviderID     xid.ID         `json:"providerId"`
	TemplateKey    string         `json:"templateKey"`
	CustomConfig   map[string]any `json:"customConfig"`
	EnabledAt      time.Time      `json:"enabledAt"`
}

type UpdateOrganizationProviderInput struct {
	CustomConfig map[string]any `json:"customConfig,omitempty"`
	LastUsed     *time.Time     `json:"lastUsed,omitempty"`
	UsageCount   *int           `json:"usageCount,omitempty"`
	Enabled      *bool          `json:"enabled,omitempty"`
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

// organizationProviderRepository implements OrganizationProviderRepository
type organizationProviderRepository struct {
	client *ent.Client
	logger logging.Logger
}

// NewOrganizationProviderRepository creates a new organization provider repository
func NewOrganizationProviderRepository(client *ent.Client, logger logging.Logger) OrganizationProviderRepository {
	return &organizationProviderRepository{
		client: client,
		logger: logger,
	}
}

// Basic CRUD operations

// Create creates a new organization provider relationship
func (r *organizationProviderRepository) Create(ctx context.Context, input CreateOrganizationProviderInput) (*model.OrganizationProvider, error) {
	var customConfig map[string]interface{}
	marshal, err := json.Marshal(input.CustomConfig)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(marshal, &customConfig)
	if err != nil {
		return nil, err
	}
	orgProvider, err := r.client.OrganizationProvider.Create().
		SetOrganizationID(input.OrganizationID).
		SetProviderID(input.ProviderID).
		SetTemplateKey(input.TemplateKey).
		SetCustomConfig(customConfig).
		SetEnabledAt(input.EnabledAt).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "organization provider relationship already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create organization provider")
	}

	return r.entToModelOrganizationProvider(orgProvider), nil
}

// GetByID retrieves an organization provider by ID
func (r *organizationProviderRepository) GetByID(ctx context.Context, id xid.ID) (*model.OrganizationProvider, error) {
	orgProvider, err := r.client.OrganizationProvider.Query().
		Where(organizationprovider.ID(id)).
		WithOrganization().
		WithProvider().
		WithTemplate().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization provider by ID")
	}

	return r.entToModelOrganizationProviderWithEdges(orgProvider), nil
}

// GetByOrganizationAndProvider retrieves an organization provider by organization and provider IDs
func (r *organizationProviderRepository) GetByOrganizationAndProvider(ctx context.Context, orgID, providerID xid.ID) (*model.OrganizationProvider, error) {
	orgProvider, err := r.client.OrganizationProvider.Query().
		Where(
			organizationprovider.OrganizationID(orgID),
			organizationprovider.ProviderID(providerID),
		).
		WithOrganization().
		WithProvider().
		WithTemplate().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization provider")
	}

	return r.entToModelOrganizationProviderWithEdges(orgProvider), nil
}

// Update updates an organization provider
func (r *organizationProviderRepository) Update(ctx context.Context, id xid.ID, input UpdateOrganizationProviderInput) (*model.OrganizationProvider, error) {
	update := r.client.OrganizationProvider.UpdateOneID(id)

	if input.CustomConfig != nil {
		var customConfig map[string]interface{}
		marshal, err := json.Marshal(input.CustomConfig)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(marshal, &customConfig)
		if err != nil {
			return nil, err
		}
		update.SetCustomConfig(customConfig)
	}
	if input.LastUsed != nil {
		update.SetLastUsed(*input.LastUsed)
	}
	if input.UsageCount != nil {
		update.SetUsageCount(*input.UsageCount)
	}
	if input.Enabled != nil {
		update.SetEnabled(*input.Enabled)
	}

	orgProvider, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update organization provider")
	}

	return r.entToModelOrganizationProvider(orgProvider), nil
}

// Delete deletes an organization provider
func (r *organizationProviderRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.OrganizationProvider.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization provider not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete organization provider")
	}
	return nil
}

// List operations

// ListByOrganization retrieves all providers for an organization
func (r *organizationProviderRepository) ListByOrganization(ctx context.Context, orgID xid.ID) ([]model.OrganizationProvider, error) {
	orgProviders, err := r.client.OrganizationProvider.Query().
		Where(organizationprovider.OrganizationID(orgID)).
		WithOrganization().
		WithProvider().
		WithTemplate().
		Order(organizationprovider.ByEnabledAt(sql.OrderDesc())).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list organization providers")
	}

	result := make([]model.OrganizationProvider, len(orgProviders))
	for i, op := range orgProviders {
		result[i] = *r.entToModelOrganizationProviderWithEdges(op)
	}

	return result, nil
}

// ListByProvider retrieves all organizations using a provider
func (r *organizationProviderRepository) ListByProvider(ctx context.Context, providerID xid.ID) ([]model.OrganizationProvider, error) {
	orgProviders, err := r.client.OrganizationProvider.Query().
		Where(organizationprovider.ProviderID(providerID)).
		WithOrganization().
		WithProvider().
		WithTemplate().
		Order(organizationprovider.ByEnabledAt(sql.OrderDesc())).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list organization providers by provider")
	}

	result := make([]model.OrganizationProvider, len(orgProviders))
	for i, op := range orgProviders {
		result[i] = *r.entToModelOrganizationProviderWithEdges(op)
	}

	return result, nil
}

// ListByTemplate retrieves all organization providers using a template
func (r *organizationProviderRepository) ListByTemplate(ctx context.Context, templateKey string) ([]model.OrganizationProvider, error) {
	orgProviders, err := r.client.OrganizationProvider.Query().
		Where(organizationprovider.TemplateKey(templateKey)).
		WithOrganization().
		WithProvider().
		WithTemplate().
		Order(organizationprovider.ByEnabledAt(sql.OrderDesc())).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list organization providers by template")
	}

	result := make([]model.OrganizationProvider, len(orgProviders))
	for i, op := range orgProviders {
		result[i] = *r.entToModelOrganizationProviderWithEdges(op)
	}

	return result, nil
}

// Analytics methods

// UpdateUsageStats updates usage statistics for an organization provider
func (r *organizationProviderRepository) UpdateUsageStats(ctx context.Context, id xid.ID) error {
	now := time.Now()

	_, err := r.client.OrganizationProvider.UpdateOneID(id).
		SetLastUsed(now).
		AddUsageCount(1).
		AddTotalLogins(1).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization provider not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update usage stats")
	}

	return nil
}

// GetUsageStats retrieves usage statistics for an organization
func (r *organizationProviderRepository) GetUsageStats(ctx context.Context, orgID xid.ID) (*OrganizationProviderStats, error) {
	// Get all providers for the organization
	orgProviders, err := r.client.OrganizationProvider.Query().
		Where(organizationprovider.OrganizationID(orgID)).
		WithProvider().
		WithTemplate().
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization providers")
	}

	if len(orgProviders) == 0 {
		return &OrganizationProviderStats{
			OrganizationID:   orgID,
			TotalProviders:   0,
			EnabledProviders: 0,
			ProvidersByType:  make(map[string]int),
			ProviderStats:    []IndividualProviderStats{},
		}, nil
	}

	stats := &OrganizationProviderStats{
		OrganizationID:  orgID,
		TotalProviders:  len(orgProviders),
		ProvidersByType: make(map[string]int),
		ProviderStats:   make([]IndividualProviderStats, 0),
	}

	var mostUsedProvider string
	var mostUsedCount int
	var latestAddedTime time.Time

	for _, op := range orgProviders {
		// Count enabled providers
		if op.Enabled {
			stats.EnabledProviders++
		}

		// Count providers by type
		if op.Edges.Provider != nil {
			providerType := op.Edges.Provider.ProviderType
			stats.ProvidersByType[providerType]++
		}

		// Track most used provider
		if op.TotalLogins > mostUsedCount {
			mostUsedCount = op.TotalLogins
			if op.Edges.Template != nil {
				mostUsedProvider = op.Edges.Template.Name
			}
		}

		// Track latest added provider
		if op.EnabledAt.After(latestAddedTime) {
			latestAddedTime = op.EnabledAt
		}

		// Calculate success rate
		successRate := 0.0
		if op.TotalLogins > 0 {
			successRate = (float64(op.SuccessfulLogins) / float64(op.TotalLogins)) * 100
		}

		// Individual provider stats
		providerStats := IndividualProviderStats{
			ProviderID:   op.ProviderID,
			TemplateKey:  op.TemplateKey,
			LoginCount:   op.TotalLogins,
			SuccessRate:  successRate,
			SetupDate:    op.EnabledAt,
			ConfigErrors: op.ConfigErrors,
		}

		if op.LastUsed != nil {
			providerStats.LastUsed = *op.LastUsed
		}

		if op.Edges.Provider != nil {
			providerStats.ProviderName = op.Edges.Provider.Name
		}

		// Count unique users would require additional query to sessions/authentications
		// For now, we'll estimate based on successful logins
		providerStats.UniqueUsers = op.SuccessfulLogins / 5 // Rough estimate

		stats.ProviderStats = append(stats.ProviderStats, providerStats)
	}

	stats.MostUsedProvider = mostUsedProvider
	stats.LastProviderAdded = latestAddedTime

	return stats, nil
}

// Bulk operations

// EnableMultipleProviders enables multiple providers for an organization
func (r *organizationProviderRepository) EnableMultipleProviders(ctx context.Context, orgID xid.ID, providerConfigs []EnableProviderConfig) error {
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to start transaction")
	}
	defer tx.Rollback()

	for _, config := range providerConfigs {
		// This would need to be integrated with the actual IdentityProvider creation
		// For now, we'll create a placeholder entry
		_, err = tx.OrganizationProvider.Create().
			SetOrganizationID(orgID).
			SetTemplateKey(config.TemplateKey).
			SetCustomConfig(config.Config).
			SetEnabledAt(time.Now()).
			Save(ctx)
		if err != nil {
			return errors.Wrap(err, errors.CodeDatabaseError, "failed to enable provider")
		}
	}

	if err = tx.Commit(); err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to commit transaction")
	}

	return nil
}

// DisableAllProviders disables all providers for an organization
func (r *organizationProviderRepository) DisableAllProviders(ctx context.Context, orgID xid.ID) error {
	_, err := r.client.OrganizationProvider.Update().
		Where(organizationprovider.OrganizationID(orgID)).
		SetEnabled(false).
		Save(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to disable all providers")
	}

	return nil
}

// Helper methods

// entToModelOrganizationProvider converts ent.OrganizationProvider to model.OrganizationProvider
func (r *organizationProviderRepository) entToModelOrganizationProvider(entOrgProvider *ent.OrganizationProvider) *model.OrganizationProvider {
	return &model.OrganizationProvider{
		Base: model.Base{
			ID:        entOrgProvider.ID,
			CreatedAt: entOrgProvider.CreatedAt,
			UpdatedAt: entOrgProvider.UpdatedAt,
		},
		OrganizationID:      entOrgProvider.OrganizationID,
		ProviderID:          entOrgProvider.ProviderID,
		TemplateKey:         entOrgProvider.TemplateKey,
		CustomConfig:        entOrgProvider.CustomConfig,
		EnabledAt:           entOrgProvider.EnabledAt,
		LastUsed:            entOrgProvider.LastUsed,
		UsageCount:          entOrgProvider.UsageCount,
		Enabled:             entOrgProvider.Enabled,
		SuccessRate:         entOrgProvider.SuccessRate,
		TotalLogins:         entOrgProvider.TotalLogins,
		SuccessfulLogins:    entOrgProvider.SuccessfulLogins,
		FailedLogins:        entOrgProvider.FailedLogins,
		LastSuccess:         entOrgProvider.LastSuccess,
		LastFailure:         entOrgProvider.LastFailure,
		ConfigErrors:        entOrgProvider.ConfigErrors,
		AverageResponseTime: entOrgProvider.AverageResponseTime,
		AnalyticsData:       entOrgProvider.AnalyticsData,
		Metadata:            entOrgProvider.Metadata,
	}
}

// entToModelOrganizationProviderWithEdges converts with relationship data
func (r *organizationProviderRepository) entToModelOrganizationProviderWithEdges(entOrgProvider *ent.OrganizationProvider) *model.OrganizationProvider {
	orgProvider := r.entToModelOrganizationProvider(entOrgProvider)

	// Add relationship data if available
	if entOrgProvider.Edges.Organization != nil {
		orgProvider.Organization = &model.OrganizationSummary{
			ID:   entOrgProvider.Edges.Organization.ID,
			Name: entOrgProvider.Edges.Organization.Name,
			Slug: entOrgProvider.Edges.Organization.Slug,
		}
	}

	if entOrgProvider.Edges.Provider != nil {
		orgProvider.Provider = &model.IdentityProvider{
			Base: model.Base{
				ID:        entOrgProvider.Edges.Provider.ID,
				CreatedAt: entOrgProvider.Edges.Provider.CreatedAt,
				UpdatedAt: entOrgProvider.Edges.Provider.UpdatedAt,
			},
			Name:     entOrgProvider.Edges.Provider.Name,
			Type:     entOrgProvider.Edges.Provider.ProviderType,
			Protocol: entOrgProvider.Edges.Provider.Protocol,
			Enabled:  entOrgProvider.Edges.Provider.Enabled,
			// Add other fields as needed
		}
	}

	if entOrgProvider.Edges.Template != nil {
		template := entOrgProvider.Edges.Template
		orgProvider.Template = entToModelTemplate(template)
	}

	return orgProvider
}

// Record authentication success
func (r *organizationProviderRepository) RecordSuccess(ctx context.Context, id xid.ID, responseTime float64) error {
	now := time.Now()

	orgProvider, err := r.client.OrganizationProvider.Get(ctx, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization provider")
	}

	// Calculate new success rate
	newTotalLogins := orgProvider.TotalLogins + 1
	newSuccessfulLogins := orgProvider.SuccessfulLogins + 1
	newSuccessRate := (float64(newSuccessfulLogins) / float64(newTotalLogins)) * 100

	// Calculate new average response time
	newAvgResponseTime := ((orgProvider.AverageResponseTime * float64(orgProvider.SuccessfulLogins)) + responseTime) / float64(newSuccessfulLogins)

	_, err = r.client.OrganizationProvider.UpdateOneID(id).
		SetLastUsed(now).
		SetLastSuccess(now).
		SetTotalLogins(newTotalLogins).
		SetSuccessfulLogins(newSuccessfulLogins).
		SetSuccessRate(newSuccessRate).
		SetAverageResponseTime(newAvgResponseTime).
		AddUsageCount(1).
		Save(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to record success")
	}

	return nil
}

// Record authentication failure
func (r *organizationProviderRepository) RecordFailure(ctx context.Context, id xid.ID, errorType string) error {
	now := time.Now()

	orgProvider, err := r.client.OrganizationProvider.Get(ctx, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization provider")
	}

	// Calculate new success rate
	newTotalLogins := orgProvider.TotalLogins + 1
	newFailedLogins := orgProvider.FailedLogins + 1
	var newSuccessRate float64
	if newTotalLogins > 0 {
		newSuccessRate = (float64(orgProvider.SuccessfulLogins) / float64(newTotalLogins)) * 100
	}

	update := r.client.OrganizationProvider.UpdateOneID(id).
		SetLastUsed(now).
		SetLastFailure(now).
		SetTotalLogins(newTotalLogins).
		SetFailedLogins(newFailedLogins).
		SetSuccessRate(newSuccessRate)

	// Increment config errors if it's a configuration-related error
	if errorType == "config_error" {
		update = update.AddConfigErrors(1)
	}

	_, err = update.Save(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to record failure")
	}

	return nil
}
