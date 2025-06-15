package repository

import (
	"context"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/organizationprovider"
	"github.com/juicycleff/frank/ent/providertemplate"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// ProviderCatalogRepository manages SSO provider templates
type ProviderCatalogRepository interface {
	// Template management
	UpsertTemplate(ctx context.Context, template model.ProviderTemplate) error
	GetTemplateByKey(ctx context.Context, key string) (*model.ProviderTemplate, error)
	GetTemplateByID(ctx context.Context, id xid.ID) (*model.ProviderTemplate, error)
	ListTemplates(ctx context.Context, params ListTemplatesParams) (*model.PaginatedOutput[model.ProviderTemplate], error)
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

// Input types for repository operations
// providerCatalogRepository implements ProviderCatalogRepository
type providerCatalogRepository struct {
	client *ent.Client
	logger logging.Logger
}

// NewProviderCatalogRepository creates a new provider catalog repository
func NewProviderCatalogRepository(client *ent.Client, logger logging.Logger) ProviderCatalogRepository {
	return &providerCatalogRepository{
		client: client,
		logger: logger,
	}
}

// Template management methods

// UpsertTemplate creates or updates a provider template
func (r *providerCatalogRepository) UpsertTemplate(ctx context.Context, template model.ProviderTemplate) error {
	// Try to get existing template by key
	existing, err := r.client.ProviderTemplate.Query().
		Where(providertemplate.Key(template.Key)).
		Only(ctx)

	if ent.IsNotFound(err) {
		// Create new template
		_, err = r.client.ProviderTemplate.Create().
			SetKey(template.Key).
			SetName(template.Name).
			SetDisplayName(template.DisplayName).
			SetType(template.Type).
			SetProtocol(template.Protocol).
			SetIconURL(template.IconURL).
			SetCategory(template.Category).
			SetPopular(template.Popular).
			SetActive(template.Active).
			SetDescription(template.Description).
			SetConfigTemplate(template.ConfigTemplate).
			SetRequiredFields(template.RequiredFields).
			SetSupportedFeatures(template.SupportedFeatures).
			SetNillableDocumentationURL(template.DocumentationURL).
			SetNillableSetupGuideURL(template.SetupGuideURL).
			SetUsageCount(template.UsageCount).
			SetNillableAverageSetupTime(template.AverageSetupTime).
			SetSuccessRate(template.SuccessRate).
			SetPopularityRank(template.PopularityRank).
			SetMetadata(template.Metadata).
			Save(ctx)
		if err != nil {
			return errors.Wrap(err, errors.CodeDatabaseError, "failed to create provider template")
		}
		return nil
	}

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to query existing template")
	}

	// Update existing template
	_, err = existing.Update().
		SetName(template.Name).
		SetDisplayName(template.DisplayName).
		SetType(template.Type).
		SetProtocol(template.Protocol).
		SetIconURL(template.IconURL).
		SetCategory(template.Category).
		SetPopular(template.Popular).
		SetActive(template.Active).
		SetDescription(template.Description).
		SetConfigTemplate(template.ConfigTemplate).
		SetRequiredFields(template.RequiredFields).
		SetSupportedFeatures(template.SupportedFeatures).
		SetNillableDocumentationURL(template.DocumentationURL).
		SetNillableSetupGuideURL(template.SetupGuideURL).
		SetNillableAverageSetupTime(template.AverageSetupTime).
		SetSuccessRate(template.SuccessRate).
		SetPopularityRank(template.PopularityRank).
		SetMetadata(template.Metadata).
		Save(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update provider template")
	}

	return nil
}

// GetTemplateByKey retrieves a template by its key
func (r *providerCatalogRepository) GetTemplateByKey(ctx context.Context, key string) (*model.ProviderTemplate, error) {
	template, err := r.client.ProviderTemplate.Query().
		Where(providertemplate.Key(key)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "provider template not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get provider template by key")
	}

	return entToModelTemplate(template), nil
}

// GetTemplateByID retrieves a template by its ID
func (r *providerCatalogRepository) GetTemplateByID(ctx context.Context, id xid.ID) (*model.ProviderTemplate, error) {
	template, err := r.client.ProviderTemplate.Query().
		Where(providertemplate.ID(id)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "provider template not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get provider template by ID")
	}

	return entToModelTemplate(template), nil
}

// ListTemplates retrieves templates with filtering
func (r *providerCatalogRepository) ListTemplates(ctx context.Context, params ListTemplatesParams) (*model.PaginatedOutput[model.ProviderTemplate], error) {
	query := r.client.ProviderTemplate.Query()

	// Apply filters
	if params.Category != "" {
		query = query.Where(providertemplate.Category(params.Category))
	}
	if params.Popular != nil {
		query = query.Where(providertemplate.Popular(*params.Popular))
	}
	if params.Type != "" {
		query = query.Where(providertemplate.Type(params.Type))
	}
	if !params.IncludeInactive {
		query = query.Where(providertemplate.Active(true))
	}
	if params.Search != "" {
		query = query.Where(providertemplate.Or(
			providertemplate.NameContains(params.Search),
			providertemplate.DisplayNameContains(params.Search),
			providertemplate.DescriptionContains(params.Search),
		))
	}

	// Apply ordering
	if params.OrderBy == nil {
		query = query.Order(providertemplate.ByPopularityRank(), providertemplate.ByName())
	}

	templates, err := model.WithPaginationAndOptions[*ent.ProviderTemplate, *ent.ProviderTemplateQuery](ctx, query, params.PaginationParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list provider templates")
	}

	result := make([]model.ProviderTemplate, len(templates.Data))
	for i, template := range templates.Data {
		result[i] = *entToModelTemplate(template)
	}

	return &model.PaginatedOutput[model.ProviderTemplate]{
		Pagination: templates.Pagination,
		Data:       result,
	}, nil
}

// UpdateTemplate updates a template by key
func (r *providerCatalogRepository) UpdateTemplate(ctx context.Context, key string, template model.ProviderTemplate) error {
	_, err := r.client.ProviderTemplate.Update().
		Where(providertemplate.Key(key)).
		SetName(template.Name).
		SetDisplayName(template.DisplayName).
		SetType(template.Type).
		SetProtocol(template.Protocol).
		SetIconURL(template.IconURL).
		SetCategory(template.Category).
		SetPopular(template.Popular).
		SetActive(template.Active).
		SetDescription(template.Description).
		SetConfigTemplate(template.ConfigTemplate).
		SetRequiredFields(template.RequiredFields).
		SetSupportedFeatures(template.SupportedFeatures).
		SetNillableDocumentationURL(template.DocumentationURL).
		SetNillableSetupGuideURL(template.SetupGuideURL).
		SetUsageCount(template.UsageCount).
		SetNillableAverageSetupTime(template.AverageSetupTime).
		SetSuccessRate(template.SuccessRate).
		SetPopularityRank(template.PopularityRank).
		SetMetadata(template.Metadata).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "provider template not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update provider template")
	}

	return nil
}

// DeleteTemplate deletes a template by key
func (r *providerCatalogRepository) DeleteTemplate(ctx context.Context, key string) error {
	_, err := r.client.ProviderTemplate.Delete().
		Where(providertemplate.Key(key)).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete provider template")
	}

	return nil
}

// Template query methods

// ListTemplatesByCategory retrieves templates by category
func (r *providerCatalogRepository) ListTemplatesByCategory(ctx context.Context, category string) ([]model.ProviderTemplate, error) {
	templates, err := r.client.ProviderTemplate.Query().
		Where(
			providertemplate.Category(category),
			providertemplate.Active(true),
		).
		Order(providertemplate.ByPopularityRank(), providertemplate.ByName()).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list templates by category")
	}

	result := make([]model.ProviderTemplate, len(templates))
	for i, template := range templates {
		result[i] = *entToModelTemplate(template)
	}

	return result, nil
}

// ListPopularTemplates retrieves popular templates
func (r *providerCatalogRepository) ListPopularTemplates(ctx context.Context) ([]model.ProviderTemplate, error) {
	templates, err := r.client.ProviderTemplate.Query().
		Where(
			providertemplate.Popular(true),
			providertemplate.Active(true),
		).
		Order(providertemplate.ByPopularityRank(), providertemplate.ByUsageCount(sql.OrderDesc())).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list popular templates")
	}

	result := make([]model.ProviderTemplate, len(templates))
	for i, template := range templates {
		result[i] = *entToModelTemplate(template)
	}

	return result, nil
}

// SearchTemplates searches templates by query
func (r *providerCatalogRepository) SearchTemplates(ctx context.Context, query string) ([]model.ProviderTemplate, error) {
	templates, err := r.client.ProviderTemplate.Query().
		Where(
			providertemplate.Active(true),
			providertemplate.Or(
				providertemplate.NameContains(query),
				providertemplate.DisplayNameContains(query),
				providertemplate.DescriptionContains(query),
				providertemplate.Key(query),
			),
		).
		Order(providertemplate.ByPopularityRank(), providertemplate.ByName()).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to search templates")
	}

	result := make([]model.ProviderTemplate, len(templates))
	for i, template := range templates {
		result[i] = *entToModelTemplate(template)
	}

	return result, nil
}

// Template analytics methods

// GetTemplateUsageStats retrieves usage statistics for a template
func (r *providerCatalogRepository) GetTemplateUsageStats(ctx context.Context, key string) (*TemplateUsageStats, error) {
	// Get template
	template, err := r.client.ProviderTemplate.Query().
		Where(providertemplate.Key(key)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "provider template not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get template")
	}

	// Get organization count using this template
	orgCount, err := r.client.OrganizationProvider.Query().
		Where(organizationprovider.TemplateKey(key)).
		Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to count organizations")
	}

	// Calculate total logins
	var totalLogins int
	err = r.client.OrganizationProvider.Query().
		Where(organizationprovider.TemplateKey(key)).
		Aggregate(ent.Sum(organizationprovider.FieldTotalLogins)).
		Scan(ctx, &totalLogins)
	if err != nil {
		r.logger.Warn("Failed to calculate total logins", logging.Error(err))
		totalLogins = 0
	}

	// Get last used time
	lastUsedTime := time.Time{}
	orgProvider, err := r.client.OrganizationProvider.Query().
		Where(
			organizationprovider.TemplateKey(key),
			organizationprovider.LastUsedNotNil(),
		).
		Order(organizationprovider.ByLastUsed(sql.OrderDesc())).
		First(ctx)
	if err == nil && orgProvider.LastUsed != nil {
		lastUsedTime = *orgProvider.LastUsed
	}

	// Calculate average success rate
	var avgSuccessRate float64
	if orgCount > 0 {
		err = r.client.OrganizationProvider.Query().
			Where(organizationprovider.TemplateKey(key)).
			Aggregate(func(s *sql.Selector) string {
				return sql.As(sql.Avg(organizationprovider.FieldSuccessRate), "success_rate")
			}).
			Scan(ctx, &avgSuccessRate)
		if err != nil {
			r.logger.Warn("Failed to calculate average success rate", logging.Error(err))
			avgSuccessRate = 0.0
		}
	}

	stats := &TemplateUsageStats{
		TemplateKey:       template.Key,
		TemplateName:      template.Name,
		OrganizationCount: orgCount,
		TotalLogins:       totalLogins,
		LastUsed:          lastUsedTime,
		AverageSetupTime:  template.AverageSetupTime,
		SuccessRate:       avgSuccessRate,
		PopularityRank:    template.PopularityRank,
	}

	return stats, nil
}

// GetMostUsedTemplates retrieves most used templates
func (r *providerCatalogRepository) GetMostUsedTemplates(ctx context.Context, limit int) ([]TemplateUsageStats, error) {
	templates, err := r.client.ProviderTemplate.Query().
		Where(providertemplate.Active(true)).
		Order(providertemplate.ByUsageCount(sql.OrderDesc())).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get most used templates")
	}

	var result []TemplateUsageStats
	for _, template := range templates {
		stats, err := r.GetTemplateUsageStats(ctx, template.Key)
		if err != nil {
			r.logger.Warn("Failed to get usage stats for template",
				logging.String("template", template.Key),
				logging.Error(err))
			continue
		}
		result = append(result, *stats)
	}

	return result, nil
}

// Helper methods

// entToModelTemplate converts ent.ProviderTemplate to model.ProviderTemplate
func entToModelTemplate(entTemplate *ent.ProviderTemplate) *model.ProviderTemplate {
	template := &model.ProviderTemplate{
		Base: model.Base{
			ID:        entTemplate.ID,
			CreatedAt: entTemplate.CreatedAt,
			UpdatedAt: entTemplate.UpdatedAt,
		},
		Key:               entTemplate.Key,
		Name:              entTemplate.Name,
		DisplayName:       entTemplate.DisplayName,
		Type:              entTemplate.Type,
		Protocol:          entTemplate.Protocol,
		IconURL:           entTemplate.IconURL,
		Category:          entTemplate.Category,
		Popular:           entTemplate.Popular,
		Active:            entTemplate.Active,
		Description:       entTemplate.Description,
		ConfigTemplate:    entTemplate.ConfigTemplate,
		RequiredFields:    entTemplate.RequiredFields,
		SupportedFeatures: entTemplate.SupportedFeatures,
		DocumentationURL:  &entTemplate.DocumentationURL,
		SetupGuideURL:     &entTemplate.SetupGuideURL,
		UsageCount:        entTemplate.UsageCount,
		AverageSetupTime:  &entTemplate.AverageSetupTime,
		SuccessRate:       entTemplate.SuccessRate,
		PopularityRank:    entTemplate.PopularityRank,
		Metadata:          entTemplate.Metadata,
	}

	return template
}

// Helper function to set optional string pointer
func (r *providerCatalogRepository) setOptionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// Helper function to set optional float pointer
func (r *providerCatalogRepository) setOptionalFloat(value *float64) float64 {
	if value == nil {
		return 0.0
	}
	return *value
}

// Helper function to convert string to pointer if not empty
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Helper function to convert float to pointer if not zero
func floatPtr(f float64) *float64 {
	if f == 0.0 {
		return nil
	}
	return &f
}
