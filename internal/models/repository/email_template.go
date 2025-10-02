package repository

import (
	"context"
	"database/sql"
	errors2 "errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/uptrace/bun"
	"github.com/xraph/frank/internal/models"
	"github.com/xraph/frank/pkg/errors"
)

// EmailTemplateRepository defines the interface for email template data operations
type EmailTemplateRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateEmailTemplateInput) (*models.EmailTemplate, error)
	GetByID(ctx context.Context, id string) (*models.EmailTemplate, error)
	Update(ctx context.Context, id string, input UpdateEmailTemplateInput) (*models.EmailTemplate, error)
	Delete(ctx context.Context, id string) error

	// Query operations
	List(ctx context.Context, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error)
	ListByOrganizationID(ctx context.Context, orgID string, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error)
	ListByType(ctx context.Context, templateType string, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error)
	ListByLocale(ctx context.Context, locale string, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error)
	ListActive(ctx context.Context, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error)
	ListSystem(ctx context.Context, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error)

	// Template retrieval operations
	GetByTypeAndOrganization(ctx context.Context, templateType string, orgID *string, locale string) (*models.EmailTemplate, error)
	GetByTypeAndLocale(ctx context.Context, templateType, locale string) (*models.EmailTemplate, error)
	GetSystemTemplate(ctx context.Context, templateType, locale string) (*models.EmailTemplate, error)
	GetOrganizationTemplate(ctx context.Context, templateType string, orgID string, locale string) (*models.EmailTemplate, error)

	// Template management operations
	ActivateTemplate(ctx context.Context, id string) error
	DeactivateTemplate(ctx context.Context, id string) error
	CloneTemplate(ctx context.Context, id string, newName string, orgID *string) (*models.EmailTemplate, error)

	// Utility operations
	CountByOrganizationID(ctx context.Context, orgID string) (int, error)
	CountByType(ctx context.Context, templateType string) (int, error)
	ListTemplateTypes(ctx context.Context) ([]string, error)
	ListLocales(ctx context.Context) ([]string, error)

	// Advanced queries
	ListByOrganizationAndType(ctx context.Context, orgID string, templateType string) ([]*models.EmailTemplate, error)
	GetTemplateHierarchy(ctx context.Context, templateType string, orgID *string, locale string) ([]*models.EmailTemplate, error)
	SearchTemplates(ctx context.Context, query string, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error)

	// Template validation operations
	ValidateTemplate(ctx context.Context, htmlContent, textContent string) error
	GetTemplateVariables(ctx context.Context, templateType string) ([]string, error)
}

// emailTemplateRepository implements EmailTemplateRepository interface
type emailTemplateRepository struct {
	db *bun.DB
}

// NewEmailTemplateRepository creates a new email template repository
func NewEmailTemplateRepository(db *bun.DB) EmailTemplateRepository {
	return &emailTemplateRepository{
		db: db,
	}
}

// CreateEmailTemplateInput defines the input for creating an email template
type CreateEmailTemplateInput struct {
	Name           string         `json:"name"`
	Subject        string         `json:"subject"`
	Type           string         `json:"type"`
	HTMLContent    string         `json:"html_content"`
	TextContent    *string        `json:"text_content,omitempty"`
	OrganizationID *string        `json:"organization_id,omitempty"`
	Active         bool           `json:"active"`
	System         bool           `json:"system"`
	Locale         string         `json:"locale"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// UpdateEmailTemplateInput defines the input for updating an email template
type UpdateEmailTemplateInput struct {
	Name        *string        `json:"name,omitempty"`
	Subject     *string        `json:"subject,omitempty"`
	HTMLContent *string        `json:"html_content,omitempty"`
	TextContent *string        `json:"text_content,omitempty"`
	Active      *bool          `json:"active,omitempty"`
	Locale      *string        `json:"locale,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Create creates a new email template
func (r *emailTemplateRepository) Create(ctx context.Context, input CreateEmailTemplateInput) (*models.EmailTemplate, error) {
	template := &models.EmailTemplate{
		Name:        input.Name,
		Subject:     input.Subject,
		Type:        input.Type,
		HTMLContent: input.HTMLContent,
		Active:      input.Active,
		System:      input.System,
		Locale:      input.Locale,
	}

	if input.TextContent != nil {
		template.TextContent = input.TextContent
	}

	if input.OrganizationID != nil {
		template.OrganizationID = input.OrganizationID
	}

	if input.Metadata != nil {
		template.Metadata = input.Metadata
	}

	_, err := r.db.NewInsert().
		Model(template).
		Exec(ctx)

	if err != nil {
		if errors2.Is(err, &pq.Error{Code: "23505"}) {
			return nil, errors.New(errors.CodeConflict, "Email template with this organization, type, and locale already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to create email template")
	}

	return template, nil
}

// GetByID retrieves an email template by its ID
func (r *emailTemplateRepository) GetByID(ctx context.Context, id string) (*models.EmailTemplate, error) {
	template := &models.EmailTemplate{}

	err := r.db.NewSelect().
		Model(template).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "Email template not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get email template")
	}

	return template, nil
}

// Update updates an email template
func (r *emailTemplateRepository) Update(ctx context.Context, id string, input UpdateEmailTemplateInput) (*models.EmailTemplate, error) {
	template := &models.EmailTemplate{
		CommonModel: models.CommonModel{ID: id},
	}

	query := r.db.NewUpdate().
		Model(template).
		WherePK()

	if input.Name != nil {
		query = query.Set("name = ?", *input.Name)
	}

	if input.Subject != nil {
		query = query.Set("subject = ?", *input.Subject)
	}

	if input.HTMLContent != nil {
		query = query.Set("html_content = ?", *input.HTMLContent)
	}

	if input.TextContent != nil {
		query = query.Set("text_content = ?", *input.TextContent)
	}

	if input.Active != nil {
		query = query.Set("active = ?", *input.Active)
	}

	if input.Locale != nil {
		query = query.Set("locale = ?", *input.Locale)
	}

	if input.Metadata != nil {
		query = query.Set("metadata = ?", input.Metadata)
	}

	_, err := query.Exec(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to update email template")
	}

	// Fetch updated template
	return r.GetByID(ctx, id)
}

// Delete deletes an email template (soft delete)
func (r *emailTemplateRepository) Delete(ctx context.Context, id string) error {
	// Check if it's a system template
	template, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if template.System {
		return errors.New(errors.CodeForbidden, "Cannot delete system templates")
	}

	_, err = r.db.NewUpdate().
		Model(&models.EmailTemplate{}).
		Set("deleted_at = ?", time.Now()).
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete email template")
	}

	return nil
}

// List retrieves paginated email templates
func (r *emailTemplateRepository) List(ctx context.Context, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error) {
	query := r.db.NewSelect().
		Model((*models.EmailTemplate)(nil)).
		Where("deleted_at IS NULL").
		Order("created_at DESC")

	result, err := models.WithPaginationAndOptions[*models.EmailTemplate](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list email templates")
	}

	return result, nil
}

// ListByOrganizationID retrieves paginated email templates for an organization
func (r *emailTemplateRepository) ListByOrganizationID(ctx context.Context, orgID string, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error) {
	query := r.db.NewSelect().
		Model((*models.EmailTemplate)(nil)).
		Where("organization_id = ?", orgID).
		Where("deleted_at IS NULL").
		Order("created_at DESC")

	result, err := models.WithPaginationAndOptions[*models.EmailTemplate](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list email templates by organization ID")
	}

	return result, nil
}

// ListByType retrieves paginated email templates by type
func (r *emailTemplateRepository) ListByType(ctx context.Context, templateType string, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error) {
	query := r.db.NewSelect().
		Model((*models.EmailTemplate)(nil)).
		Where("type = ?", templateType).
		Where("deleted_at IS NULL").
		Order("created_at DESC")

	result, err := models.WithPaginationAndOptions[*models.EmailTemplate](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list email templates by type %s", templateType))
	}

	return result, nil
}

// ListByLocale retrieves paginated email templates by locale
func (r *emailTemplateRepository) ListByLocale(ctx context.Context, locale string, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error) {
	query := r.db.NewSelect().
		Model((*models.EmailTemplate)(nil)).
		Where("locale = ?", locale).
		Where("deleted_at IS NULL").
		Order("created_at DESC")

	result, err := models.WithPaginationAndOptions[*models.EmailTemplate](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list email templates by locale %s", locale))
	}

	return result, nil
}

// ListActive retrieves paginated active email templates
func (r *emailTemplateRepository) ListActive(ctx context.Context, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error) {
	query := r.db.NewSelect().
		Model((*models.EmailTemplate)(nil)).
		Where("active = ?", true).
		Where("deleted_at IS NULL").
		Order("created_at DESC")

	result, err := models.WithPaginationAndOptions[*models.EmailTemplate](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list active email templates")
	}

	return result, nil
}

// ListSystem retrieves paginated system email templates
func (r *emailTemplateRepository) ListSystem(ctx context.Context, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error) {
	query := r.db.NewSelect().
		Model((*models.EmailTemplate)(nil)).
		Where("system = ?", true).
		Where("deleted_at IS NULL").
		Order("created_at DESC")

	result, err := models.WithPaginationAndOptions[*models.EmailTemplate](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list system email templates")
	}

	return result, nil
}

// GetByTypeAndOrganization retrieves an email template by type and organization (with fallback to system)
func (r *emailTemplateRepository) GetByTypeAndOrganization(ctx context.Context, templateType string, orgID *string, locale string) (*models.EmailTemplate, error) {
	// First try to get organization-specific template
	if orgID != nil {
		template, err := r.GetOrganizationTemplate(ctx, templateType, *orgID, locale)
		if err == nil {
			return template, nil
		}
		if !errors.IsNotFound(err) {
			return nil, err
		}
	}

	// Fallback to system template
	return r.GetSystemTemplate(ctx, templateType, locale)
}

// GetByTypeAndLocale retrieves an email template by type and locale (system only)
func (r *emailTemplateRepository) GetByTypeAndLocale(ctx context.Context, templateType, locale string) (*models.EmailTemplate, error) {
	template := &models.EmailTemplate{}

	err := r.db.NewSelect().
		Model(template).
		Where("type = ?", templateType).
		Where("locale = ?", locale).
		Where("active = ?", true).
		Where("deleted_at IS NULL").
		Order("system DESC"). // Prefer system templates
		Limit(1).
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("Email template not found for type %s and locale %s", templateType, locale))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get email template by type and locale")
	}

	return template, nil
}

// GetSystemTemplate retrieves a system email template
func (r *emailTemplateRepository) GetSystemTemplate(ctx context.Context, templateType, locale string) (*models.EmailTemplate, error) {
	template := &models.EmailTemplate{}

	err := r.db.NewSelect().
		Model(template).
		Where("type = ?", templateType).
		Where("locale = ?", locale).
		Where("system = ?", true).
		Where("active = ?", true).
		Where("deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("System email template not found for type %s and locale %s", templateType, locale))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get system email template")
	}

	return template, nil
}

// GetOrganizationTemplate retrieves an organization-specific email template
func (r *emailTemplateRepository) GetOrganizationTemplate(ctx context.Context, templateType string, orgID string, locale string) (*models.EmailTemplate, error) {
	template := &models.EmailTemplate{}

	err := r.db.NewSelect().
		Model(template).
		Where("type = ?", templateType).
		Where("organization_id = ?", orgID).
		Where("locale = ?", locale).
		Where("active = ?", true).
		Where("deleted_at IS NULL").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("Organization email template not found for type %s and locale %s", templateType, locale))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get organization email template")
	}

	return template, nil
}

// ActivateTemplate activates an email template
func (r *emailTemplateRepository) ActivateTemplate(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model(&models.EmailTemplate{}).
		Set("active = ?", true).
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to activate email template")
	}

	return nil
}

// DeactivateTemplate deactivates an email template
func (r *emailTemplateRepository) DeactivateTemplate(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model(&models.EmailTemplate{}).
		Set("active = ?", false).
		Where("id = ?", id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to deactivate email template")
	}

	return nil
}

// CloneTemplate clones an existing email template
func (r *emailTemplateRepository) CloneTemplate(ctx context.Context, id string, newName string, orgID *string) (*models.EmailTemplate, error) {
	// Get the original template
	original, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Create the clone
	input := CreateEmailTemplateInput{
		Name:           newName,
		Subject:        original.Subject,
		Type:           original.Type,
		HTMLContent:    original.HTMLContent,
		TextContent:    original.TextContent,
		OrganizationID: orgID,
		Active:         true,
		System:         false, // Clones are never system templates
		Locale:         original.Locale,
		Metadata:       original.Metadata,
	}

	return r.Create(ctx, input)
}

// CountByOrganizationID counts email templates for an organization
func (r *emailTemplateRepository) CountByOrganizationID(ctx context.Context, orgID string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.EmailTemplate)(nil)).
		Where("organization_id = ?", orgID).
		Where("deleted_at IS NULL").
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count email templates by organization ID")
	}

	return count, nil
}

// CountByType counts email templates by type
func (r *emailTemplateRepository) CountByType(ctx context.Context, templateType string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.EmailTemplate)(nil)).
		Where("type = ?", templateType).
		Where("deleted_at IS NULL").
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count email templates by type")
	}

	return count, nil
}

// ListTemplateTypes retrieves all unique template types
func (r *emailTemplateRepository) ListTemplateTypes(ctx context.Context) ([]string, error) {
	var types []string

	err := r.db.NewSelect().
		Model((*models.EmailTemplate)(nil)).
		Column("type").
		Where("deleted_at IS NULL").
		Group("type").
		Scan(ctx, &types)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list template types")
	}

	return types, nil
}

// ListLocales retrieves all unique locales
func (r *emailTemplateRepository) ListLocales(ctx context.Context) ([]string, error) {
	var locales []string

	err := r.db.NewSelect().
		Model((*models.EmailTemplate)(nil)).
		Column("locale").
		Where("deleted_at IS NULL").
		Group("locale").
		Scan(ctx, &locales)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list locales")
	}

	return locales, nil
}

// ListByOrganizationAndType retrieves email templates by organization and type
func (r *emailTemplateRepository) ListByOrganizationAndType(ctx context.Context, orgID string, templateType string) ([]*models.EmailTemplate, error) {
	var templates []*models.EmailTemplate

	err := r.db.NewSelect().
		Model(&templates).
		Where("organization_id = ?", orgID).
		Where("type = ?", templateType).
		Where("deleted_at IS NULL").
		Order("created_at DESC").
		Scan(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list email templates by organization and type")
	}

	return templates, nil
}

// GetTemplateHierarchy retrieves template hierarchy (organization -> system fallback)
func (r *emailTemplateRepository) GetTemplateHierarchy(ctx context.Context, templateType string, orgID *string, locale string) ([]*models.EmailTemplate, error) {
	var templates []*models.EmailTemplate

	// First, get organization template if orgID is provided
	if orgID != nil {
		orgTemplate, err := r.GetOrganizationTemplate(ctx, templateType, *orgID, locale)
		if err == nil {
			templates = append(templates, orgTemplate)
		} else if !errors.IsNotFound(err) {
			return nil, err
		}
	}

	// Then, get system template
	systemTemplate, err := r.GetSystemTemplate(ctx, templateType, locale)
	if err == nil {
		templates = append(templates, systemTemplate)
	} else if !errors.IsNotFound(err) {
		return nil, err
	}

	if len(templates) == 0 {
		return nil, errors.New(errors.CodeNotFound, "No templates found in hierarchy")
	}

	return templates, nil
}

// SearchTemplates searches email templates by name or content
func (r *emailTemplateRepository) SearchTemplates(ctx context.Context, query string, opts models.PaginationParams) (*models.PaginatedOutput[*models.EmailTemplate], error) {
	searchQuery := r.db.NewSelect().
		Model((*models.EmailTemplate)(nil)).
		Where("deleted_at IS NULL").
		Where("name ILIKE ? OR subject ILIKE ? OR html_content ILIKE ?",
			"%"+query+"%", "%"+query+"%", "%"+query+"%").
		Order("created_at DESC")

	result, err := models.WithPaginationAndOptions[*models.EmailTemplate](ctx, searchQuery, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to search email templates")
	}

	return result, nil
}

// ValidateTemplate validates email template content
func (r *emailTemplateRepository) ValidateTemplate(ctx context.Context, htmlContent, textContent string) error {
	// Basic validation - can be extended with HTML parsing, template variable validation, etc.
	if htmlContent == "" {
		return errors.New(errors.CodeBadRequest, "HTML content cannot be empty")
	}

	// Additional validation logic can be added here
	return nil
}

// GetTemplateVariables retrieves available variables for a template type
func (r *emailTemplateRepository) GetTemplateVariables(ctx context.Context, templateType string) ([]string, error) {
	var variables []string

	switch templateType {
	case "verification":
		variables = []string{"user_name", "user_email", "verification_link", "verification_code", "company_name"}
	case "password_reset":
		variables = []string{"user_name", "user_email", "reset_link", "reset_code", "company_name"}
	case "invitation":
		variables = []string{"inviter_name", "invitee_email", "organization_name", "invitation_link", "company_name"}
	case "welcome":
		variables = []string{"user_name", "user_email", "organization_name", "login_link", "company_name"}
	default:
		variables = []string{"user_name", "user_email", "company_name"}
	}

	return variables, nil
}
