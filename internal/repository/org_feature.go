package repository

import (
	"context"
	"fmt"

	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/featureflag"
	"github.com/xraph/frank/ent/organizationfeature"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/model"
)

// OrganizationFeatureRepository defines the interface for organization feature data operations
type OrganizationFeatureRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateOrganizationFeatureInput) (*ent.OrganizationFeature, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.OrganizationFeature, error)
	GetByOrganizationAndFeature(ctx context.Context, orgID, featureID xid.ID) (*ent.OrganizationFeature, error)
	Update(ctx context.Context, id xid.ID, input UpdateOrganizationFeatureInput) (*ent.OrganizationFeature, error)
	Delete(ctx context.Context, id xid.ID) error
	DeleteByOrganizationAndFeature(ctx context.Context, orgID, featureID xid.ID) error

	// Query operations
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.OrganizationFeature], error)
	ListByFeatureID(ctx context.Context, featureID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.OrganizationFeature], error)
	ListEnabledByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.OrganizationFeature, error)
	ListDisabledByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.OrganizationFeature, error)

	// Feature checking operations
	IsFeatureEnabled(ctx context.Context, orgID, featureID xid.ID) (bool, error)
	IsFeatureEnabledByKey(ctx context.Context, orgID xid.ID, featureKey string) (bool, error)
	GetFeatureSettings(ctx context.Context, orgID, featureID xid.ID) (map[string]any, error)
	GetFeatureSettingsByKey(ctx context.Context, orgID xid.ID, featureKey string) (map[string]any, error)

	// Bulk operations
	EnableFeature(ctx context.Context, orgID, featureID xid.ID, settings map[string]any) (*ent.OrganizationFeature, error)
	DisableFeature(ctx context.Context, orgID, featureID xid.ID) error
	EnableMultipleFeatures(ctx context.Context, orgID xid.ID, featureIDs []xid.ID) error
	DisableMultipleFeatures(ctx context.Context, orgID xid.ID, featureIDs []xid.ID) error

	// Utility operations
	CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)
	CountEnabledByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)
	CountByFeatureID(ctx context.Context, featureID xid.ID) (int, error)

	// Advanced queries
	ListOrganizationsWithFeature(ctx context.Context, featureID xid.ID, enabled bool) ([]*ent.OrganizationFeature, error)
	GetOrganizationFeatureMatrix(ctx context.Context, orgID xid.ID) (map[string]OrganizationFeatureStatus, error)
	ListFeatureUsageStats(ctx context.Context) ([]FeatureUsageStats, error)
}

// organizationFeatureRepository implements OrganizationFeatureRepository interface
type organizationFeatureRepository struct {
	client *ent.Client
}

// NewOrganizationFeatureRepository creates a new organization feature repository
func NewOrganizationFeatureRepository(client *ent.Client) OrganizationFeatureRepository {
	return &organizationFeatureRepository{
		client: client,
	}
}

// CreateOrganizationFeatureInput defines the input for creating an organization feature
type CreateOrganizationFeatureInput struct {
	OrganizationID xid.ID         `json:"organization_id"`
	FeatureID      xid.ID         `json:"feature_id"`
	Enabled        bool           `json:"enabled"`
	Settings       map[string]any `json:"settings,omitempty"`
}

// UpdateOrganizationFeatureInput defines the input for updating an organization feature
type UpdateOrganizationFeatureInput struct {
	Enabled  *bool          `json:"enabled,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
}

// OrganizationFeatureStatus represents the status of a feature for an organization
type OrganizationFeatureStatus struct {
	FeatureID   xid.ID         `json:"feature_id"`
	FeatureKey  string         `json:"feature_key"`
	FeatureName string         `json:"feature_name"`
	Enabled     bool           `json:"enabled"`
	Settings    map[string]any `json:"settings"`
}

// FeatureUsageStats represents usage statistics for a feature
type FeatureUsageStats struct {
	FeatureID    xid.ID  `json:"feature_id"`
	FeatureKey   string  `json:"feature_key"`
	FeatureName  string  `json:"feature_name"`
	TotalOrgs    int     `json:"total_orgs"`
	EnabledOrgs  int     `json:"enabled_orgs"`
	DisabledOrgs int     `json:"disabled_orgs"`
	AdoptionRate float64 `json:"adoption_rate"`
}

// Create creates a new organization feature
func (r *organizationFeatureRepository) Create(ctx context.Context, input CreateOrganizationFeatureInput) (*ent.OrganizationFeature, error) {
	builder := r.client.OrganizationFeature.Create().
		SetOrganizationID(input.OrganizationID).
		SetFeatureID(input.FeatureID).
		SetEnabled(input.Enabled)

	if input.Settings != nil {
		builder.SetSettings(input.Settings)
	}

	orgFeature, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "Organization feature mapping already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to create organization feature")
	}

	return orgFeature, nil
}

// GetByID retrieves an organization feature by its ID
func (r *organizationFeatureRepository) GetByID(ctx context.Context, id xid.ID) (*ent.OrganizationFeature, error) {
	orgFeature, err := r.client.OrganizationFeature.
		Query().
		Where(organizationfeature.ID(id)).
		WithOrganization().
		WithFeature().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Organization feature not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get organization feature")
	}

	return orgFeature, nil
}

// GetByOrganizationAndFeature retrieves an organization feature by organization and feature IDs
func (r *organizationFeatureRepository) GetByOrganizationAndFeature(ctx context.Context, orgID, featureID xid.ID) (*ent.OrganizationFeature, error) {
	orgFeature, err := r.client.OrganizationFeature.
		Query().
		Where(
			organizationfeature.OrganizationID(orgID),
			organizationfeature.FeatureID(featureID),
		).
		WithOrganization().
		WithFeature().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Organization feature mapping not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get organization feature by organization and feature")
	}

	return orgFeature, nil
}

// Update updates an organization feature
func (r *organizationFeatureRepository) Update(ctx context.Context, id xid.ID, input UpdateOrganizationFeatureInput) (*ent.OrganizationFeature, error) {
	builder := r.client.OrganizationFeature.UpdateOneID(id)

	if input.Enabled != nil {
		builder.SetEnabled(*input.Enabled)
	}

	if input.Settings != nil {
		builder.SetSettings(input.Settings)
	}

	orgFeature, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Organization feature not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to update organization feature")
	}

	return orgFeature, nil
}

// Delete deletes an organization feature
func (r *organizationFeatureRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.OrganizationFeature.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Organization feature not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete organization feature")
	}

	return nil
}

// DeleteByOrganizationAndFeature deletes an organization feature by organization and feature IDs
func (r *organizationFeatureRepository) DeleteByOrganizationAndFeature(ctx context.Context, orgID, featureID xid.ID) error {
	_, err := r.client.OrganizationFeature.
		Delete().
		Where(
			organizationfeature.OrganizationID(orgID),
			organizationfeature.FeatureID(featureID),
		).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete organization feature by organization and feature")
	}

	return nil
}

// ListByOrganizationID retrieves paginated organization features for an organization
func (r *organizationFeatureRepository) ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.OrganizationFeature], error) {
	query := r.client.OrganizationFeature.
		Query().
		Where(organizationfeature.OrganizationID(orgID)).
		WithOrganization().
		WithFeature()

	// Apply ordering
	query.Order(ent.Desc(organizationfeature.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.OrganizationFeature, *ent.OrganizationFeatureQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list organization features by organization ID")
	}

	return result, nil
}

// ListByFeatureID retrieves paginated organization features for a feature
func (r *organizationFeatureRepository) ListByFeatureID(ctx context.Context, featureID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.OrganizationFeature], error) {
	query := r.client.OrganizationFeature.
		Query().
		Where(organizationfeature.FeatureID(featureID)).
		WithOrganization().
		WithFeature()

	// Apply ordering
	query.Order(ent.Desc(organizationfeature.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.OrganizationFeature, *ent.OrganizationFeatureQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list organization features by feature ID")
	}

	return result, nil
}

// ListEnabledByOrganizationID retrieves all enabled features for an organization
func (r *organizationFeatureRepository) ListEnabledByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.OrganizationFeature, error) {
	orgFeatures, err := r.client.OrganizationFeature.
		Query().
		Where(
			organizationfeature.OrganizationID(orgID),
			organizationfeature.Enabled(true),
		).
		WithOrganization().
		WithFeature().
		Order(ent.Desc(organizationfeature.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list enabled organization features")
	}

	return orgFeatures, nil
}

// ListDisabledByOrganizationID retrieves all disabled features for an organization
func (r *organizationFeatureRepository) ListDisabledByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.OrganizationFeature, error) {
	orgFeatures, err := r.client.OrganizationFeature.
		Query().
		Where(
			organizationfeature.OrganizationID(orgID),
			organizationfeature.Enabled(false),
		).
		WithOrganization().
		WithFeature().
		Order(ent.Desc(organizationfeature.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list disabled organization features")
	}

	return orgFeatures, nil
}

// IsFeatureEnabled checks if a feature is enabled for an organization
func (r *organizationFeatureRepository) IsFeatureEnabled(ctx context.Context, orgID, featureID xid.ID) (bool, error) {
	count, err := r.client.OrganizationFeature.
		Query().
		Where(
			organizationfeature.OrganizationID(orgID),
			organizationfeature.FeatureID(featureID),
			organizationfeature.Enabled(true),
		).
		Count(ctx)

	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "Failed to check if feature is enabled")
	}

	return count > 0, nil
}

// IsFeatureEnabledByKey checks if a feature is enabled for an organization by feature key
func (r *organizationFeatureRepository) IsFeatureEnabledByKey(ctx context.Context, orgID xid.ID, featureKey string) (bool, error) {
	count, err := r.client.OrganizationFeature.
		Query().
		Where(
			organizationfeature.OrganizationID(orgID),
			organizationfeature.Enabled(true),
			organizationfeature.HasFeatureWith(featureflag.KeyEQ(featureKey), featureflag.Enabled(true)),
		).
		Count(ctx)

	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "Failed to check if feature is enabled by key")
	}

	return count > 0, nil
}

// GetFeatureSettings retrieves the settings for a feature in an organization
func (r *organizationFeatureRepository) GetFeatureSettings(ctx context.Context, orgID, featureID xid.ID) (map[string]any, error) {
	orgFeature, err := r.GetByOrganizationAndFeature(ctx, orgID, featureID)
	if err != nil {
		return nil, err
	}

	if !orgFeature.Enabled {
		return nil, errors.New(errors.CodeNotFound, "Feature is not enabled for this organization")
	}

	return orgFeature.Settings, nil
}

// GetFeatureSettingsByKey retrieves the settings for a feature in an organization by feature key
func (r *organizationFeatureRepository) GetFeatureSettingsByKey(ctx context.Context, orgID xid.ID, featureKey string) (map[string]any, error) {
	orgFeature, err := r.client.OrganizationFeature.
		Query().
		Where(
			organizationfeature.OrganizationID(orgID),
			organizationfeature.Enabled(true),
			organizationfeature.HasFeatureWith(featureflag.KeyEQ(featureKey)),
		).
		WithFeature().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Feature not found or not enabled")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get feature settings by key")
	}

	return orgFeature.Settings, nil
}

// EnableFeature enables a feature for an organization with optional settings
func (r *organizationFeatureRepository) EnableFeature(ctx context.Context, orgID, featureID xid.ID, settings map[string]any) (*ent.OrganizationFeature, error) {
	// Try to get existing feature mapping
	orgFeature, err := r.GetByOrganizationAndFeature(ctx, orgID, featureID)

	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}

	if orgFeature != nil {
		// Update existing mapping
		updateInput := UpdateOrganizationFeatureInput{
			Enabled:  &[]bool{true}[0],
			Settings: settings,
		}
		return r.Update(ctx, orgFeature.ID, updateInput)
	}

	// Create new mapping
	createInput := CreateOrganizationFeatureInput{
		OrganizationID: orgID,
		FeatureID:      featureID,
		Enabled:        true,
		Settings:       settings,
	}
	return r.Create(ctx, createInput)
}

// DisableFeature disables a feature for an organization
func (r *organizationFeatureRepository) DisableFeature(ctx context.Context, orgID, featureID xid.ID) error {
	orgFeature, err := r.GetByOrganizationAndFeature(ctx, orgID, featureID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil // Already disabled/not exists
		}
		return err
	}

	updateInput := UpdateOrganizationFeatureInput{
		Enabled: &[]bool{false}[0],
	}
	_, err = r.Update(ctx, orgFeature.ID, updateInput)
	return err
}

// EnableMultipleFeatures enables multiple features for an organization
func (r *organizationFeatureRepository) EnableMultipleFeatures(ctx context.Context, orgID xid.ID, featureIDs []xid.ID) error {
	for _, featureID := range featureIDs {
		_, err := r.EnableFeature(ctx, orgID, featureID, nil)
		if err != nil {
			return errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to enable feature %s", featureID))
		}
	}
	return nil
}

// DisableMultipleFeatures disables multiple features for an organization
func (r *organizationFeatureRepository) DisableMultipleFeatures(ctx context.Context, orgID xid.ID, featureIDs []xid.ID) error {
	for _, featureID := range featureIDs {
		err := r.DisableFeature(ctx, orgID, featureID)
		if err != nil {
			return errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to disable feature %s", featureID))
		}
	}
	return nil
}

// CountByOrganizationID counts the number of feature mappings for an organization
func (r *organizationFeatureRepository) CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error) {
	count, err := r.client.OrganizationFeature.
		Query().
		Where(organizationfeature.OrganizationID(orgID)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count organization features")
	}

	return count, nil
}

// CountEnabledByOrganizationID counts the number of enabled features for an organization
func (r *organizationFeatureRepository) CountEnabledByOrganizationID(ctx context.Context, orgID xid.ID) (int, error) {
	count, err := r.client.OrganizationFeature.
		Query().
		Where(
			organizationfeature.OrganizationID(orgID),
			organizationfeature.Enabled(true),
		).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count enabled organization features")
	}

	return count, nil
}

// CountByFeatureID counts the number of organizations using a feature
func (r *organizationFeatureRepository) CountByFeatureID(ctx context.Context, featureID xid.ID) (int, error) {
	count, err := r.client.OrganizationFeature.
		Query().
		Where(organizationfeature.FeatureID(featureID)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count organizations using feature")
	}

	return count, nil
}

// ListOrganizationsWithFeature retrieves organizations that have a feature enabled or disabled
func (r *organizationFeatureRepository) ListOrganizationsWithFeature(ctx context.Context, featureID xid.ID, enabled bool) ([]*ent.OrganizationFeature, error) {
	orgFeatures, err := r.client.OrganizationFeature.
		Query().
		Where(
			organizationfeature.FeatureID(featureID),
			organizationfeature.Enabled(enabled),
		).
		WithOrganization().
		WithFeature().
		Order(ent.Desc(organizationfeature.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list organizations with feature")
	}

	return orgFeatures, nil
}

// GetOrganizationFeatureMatrix retrieves all features for an organization as a map
func (r *organizationFeatureRepository) GetOrganizationFeatureMatrix(ctx context.Context, orgID xid.ID) (map[string]OrganizationFeatureStatus, error) {
	orgFeatures, err := r.client.OrganizationFeature.
		Query().
		Where(organizationfeature.OrganizationID(orgID)).
		WithFeature().
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get organization feature matrix")
	}

	matrix := make(map[string]OrganizationFeatureStatus)
	for _, orgFeature := range orgFeatures {
		if orgFeature.Edges.Feature != nil {
			// Note: Adjust based on your actual FeatureFlag schema
			featureKey := "feature_key" // Replace with actual field access
			matrix[featureKey] = OrganizationFeatureStatus{
				FeatureID:   orgFeature.FeatureID,
				FeatureKey:  featureKey,
				FeatureName: orgFeature.Edges.Feature.Name,
				Enabled:     orgFeature.Enabled,
				Settings:    orgFeature.Settings,
			}
		}
	}

	return matrix, nil
}

// ListFeatureUsageStats retrieves usage statistics for all features
func (r *organizationFeatureRepository) ListFeatureUsageStats(ctx context.Context) ([]FeatureUsageStats, error) {
	// This would require a more complex query with aggregations
	// Implementation depends on your specific requirements and database capabilities

	// For now, return empty slice - implement based on your needs
	return []FeatureUsageStats{}, nil
}
