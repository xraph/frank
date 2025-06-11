package repository

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/emailtemplate"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

// EmailTemplateRepository defines the interface for email template data operations
type EmailTemplateRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateEmailTemplateInput) (*ent.EmailTemplate, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.EmailTemplate, error)
	Update(ctx context.Context, id xid.ID, input UpdateEmailTemplateInput) (*ent.EmailTemplate, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	List(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)
	ListByType(ctx context.Context, templateType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)
	ListByLocale(ctx context.Context, locale string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)
	ListActive(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)
	ListSystem(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)

	// Template retrieval operations
	GetByTypeAndOrganization(ctx context.Context, templateType string, orgID *xid.ID, locale string) (*ent.EmailTemplate, error)
	GetByTypeAndLocale(ctx context.Context, templateType, locale string) (*ent.EmailTemplate, error)
	GetSystemTemplate(ctx context.Context, templateType, locale string) (*ent.EmailTemplate, error)
	GetOrganizationTemplate(ctx context.Context, templateType string, orgID xid.ID, locale string) (*ent.EmailTemplate, error)

	// Template management operations
	ActivateTemplate(ctx context.Context, id xid.ID) error
	DeactivateTemplate(ctx context.Context, id xid.ID) error
	CloneTemplate(ctx context.Context, id xid.ID, newName string, orgID *xid.ID) (*ent.EmailTemplate, error)

	// Utility operations
	CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)
	CountByType(ctx context.Context, templateType string) (int, error)
	ListTemplateTypes(ctx context.Context) ([]string, error)
	ListLocales(ctx context.Context) ([]string, error)

	// Advanced queries
	ListByOrganizationAndType(ctx context.Context, orgID xid.ID, templateType string) ([]*ent.EmailTemplate, error)
	GetTemplateHierarchy(ctx context.Context, templateType string, orgID *xid.ID, locale string) ([]*ent.EmailTemplate, error)
	SearchTemplates(ctx context.Context, query string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)

	// Template validation operations
	ValidateTemplate(ctx context.Context, htmlContent, textContent string) error
	GetTemplateVariables(ctx context.Context, templateType string) ([]string, error)
}

// emailTemplateRepository implements EmailTemplateRepository interface
type emailTemplateRepository struct {
	client *ent.Client
}

// NewEmailTemplateRepository creates a new email template repository
func NewEmailTemplateRepository(client *ent.Client) EmailTemplateRepository {
	return &emailTemplateRepository{
		client: client,
	}
}

// CreateEmailTemplateInput defines the input for creating an email template
type CreateEmailTemplateInput struct {
	Name           string         `json:"name"`
	Subject        string         `json:"subject"`
	Type           string         `json:"type"`
	HTMLContent    string         `json:"html_content"`
	TextContent    *string        `json:"text_content,omitempty"`
	OrganizationID *xid.ID        `json:"organization_id,omitempty"`
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
func (r *emailTemplateRepository) Create(ctx context.Context, input CreateEmailTemplateInput) (*ent.EmailTemplate, error) {
	builder := r.client.EmailTemplate.Create().
		SetName(input.Name).
		SetSubject(input.Subject).
		SetType(input.Type).
		SetHTMLContent(input.HTMLContent).
		SetActive(input.Active).
		SetSystem(input.System).
		SetLocale(input.Locale)

	if input.TextContent != nil {
		builder.SetTextContent(*input.TextContent)
	}

	if input.OrganizationID != nil {
		builder.SetOrganizationID(*input.OrganizationID)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	template, err := builder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "Email template with this organization, type, and locale already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to create email template")
	}

	return template, nil
}

// GetByID retrieves an email template by its ID
func (r *emailTemplateRepository) GetByID(ctx context.Context, id xid.ID) (*ent.EmailTemplate, error) {
	template, err := r.client.EmailTemplate.
		Query().
		Where(emailtemplate.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Email template not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get email template")
	}

	return template, nil
}

// Update updates an email template
func (r *emailTemplateRepository) Update(ctx context.Context, id xid.ID, input UpdateEmailTemplateInput) (*ent.EmailTemplate, error) {
	builder := r.client.EmailTemplate.UpdateOneID(id)

	if input.Name != nil {
		builder.SetName(*input.Name)
	}

	if input.Subject != nil {
		builder.SetSubject(*input.Subject)
	}

	if input.HTMLContent != nil {
		builder.SetHTMLContent(*input.HTMLContent)
	}

	if input.TextContent != nil {
		builder.SetTextContent(*input.TextContent)
	}

	if input.Active != nil {
		builder.SetActive(*input.Active)
	}

	if input.Locale != nil {
		builder.SetLocale(*input.Locale)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	template, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Email template not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to update email template")
	}

	return template, nil
}

// Delete deletes an email template
func (r *emailTemplateRepository) Delete(ctx context.Context, id xid.ID) error {
	// Check if it's a system template
	template, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if template.System {
		return errors.New(errors.CodeForbidden, "Cannot delete system templates")
	}

	err = r.client.EmailTemplate.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Email template not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete email template")
	}

	return nil
}

// List retrieves paginated email templates
func (r *emailTemplateRepository) List(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error) {
	query := r.client.EmailTemplate.Query()

	// Apply ordering
	query.Order(ent.Desc(emailtemplate.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.EmailTemplate, *ent.EmailTemplateQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list email templates")
	}

	return result, nil
}

// ListByOrganizationID retrieves paginated email templates for an organization
func (r *emailTemplateRepository) ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error) {
	query := r.client.EmailTemplate.
		Query().
		Where(emailtemplate.OrganizationID(orgID))

	// Apply ordering
	query.Order(ent.Desc(emailtemplate.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.EmailTemplate, *ent.EmailTemplateQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list email templates by organization ID")
	}

	return result, nil
}

// ListByType retrieves paginated email templates by type
func (r *emailTemplateRepository) ListByType(ctx context.Context, templateType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error) {
	query := r.client.EmailTemplate.
		Query().
		Where(emailtemplate.Type(templateType))

	// Apply ordering
	query.Order(ent.Desc(emailtemplate.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.EmailTemplate, *ent.EmailTemplateQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list email templates by type %s", templateType))
	}

	return result, nil
}

// ListByLocale retrieves paginated email templates by locale
func (r *emailTemplateRepository) ListByLocale(ctx context.Context, locale string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error) {
	query := r.client.EmailTemplate.
		Query().
		Where(emailtemplate.Locale(locale))

	// Apply ordering
	query.Order(ent.Desc(emailtemplate.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.EmailTemplate, *ent.EmailTemplateQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list email templates by locale %s", locale))
	}

	return result, nil
}

// ListActive retrieves paginated active email templates
func (r *emailTemplateRepository) ListActive(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error) {
	query := r.client.EmailTemplate.
		Query().
		Where(emailtemplate.Active(true))

	// Apply ordering
	query.Order(ent.Desc(emailtemplate.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.EmailTemplate, *ent.EmailTemplateQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list active email templates")
	}

	return result, nil
}

// ListSystem retrieves paginated system email templates
func (r *emailTemplateRepository) ListSystem(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error) {
	query := r.client.EmailTemplate.
		Query().
		Where(emailtemplate.System(true))

	// Apply ordering
	query.Order(ent.Desc(emailtemplate.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.EmailTemplate, *ent.EmailTemplateQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list system email templates")
	}

	return result, nil
}

// GetByTypeAndOrganization retrieves an email template by type and organization (with fallback to system)
func (r *emailTemplateRepository) GetByTypeAndOrganization(ctx context.Context, templateType string, orgID *xid.ID, locale string) (*ent.EmailTemplate, error) {
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
func (r *emailTemplateRepository) GetByTypeAndLocale(ctx context.Context, templateType, locale string) (*ent.EmailTemplate, error) {
	template, err := r.client.EmailTemplate.
		Query().
		Where(
			emailtemplate.Type(templateType),
			emailtemplate.Locale(locale),
			emailtemplate.Active(true),
		).
		Order(ent.Desc(emailtemplate.FieldSystem)). // Prefer system templates
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("Email template not found for type %s and locale %s", templateType, locale))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get email template by type and locale")
	}

	return template, nil
}

// GetSystemTemplate retrieves a system email template
func (r *emailTemplateRepository) GetSystemTemplate(ctx context.Context, templateType, locale string) (*ent.EmailTemplate, error) {
	template, err := r.client.EmailTemplate.
		Query().
		Where(
			emailtemplate.Type(templateType),
			emailtemplate.Locale(locale),
			emailtemplate.System(true),
			emailtemplate.Active(true),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("System email template not found for type %s and locale %s", templateType, locale))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get system email template")
	}

	return template, nil
}

// GetOrganizationTemplate retrieves an organization-specific email template
func (r *emailTemplateRepository) GetOrganizationTemplate(ctx context.Context, templateType string, orgID xid.ID, locale string) (*ent.EmailTemplate, error) {
	template, err := r.client.EmailTemplate.
		Query().
		Where(
			emailtemplate.Type(templateType),
			emailtemplate.OrganizationID(orgID),
			emailtemplate.Locale(locale),
			emailtemplate.Active(true),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("Organization email template not found for type %s and locale %s", templateType, locale))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get organization email template")
	}

	return template, nil
}

// ActivateTemplate activates an email template
func (r *emailTemplateRepository) ActivateTemplate(ctx context.Context, id xid.ID) error {
	err := r.client.EmailTemplate.
		UpdateOneID(id).
		SetActive(true).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Email template not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to activate email template")
	}

	return nil
}

// DeactivateTemplate deactivates an email template
func (r *emailTemplateRepository) DeactivateTemplate(ctx context.Context, id xid.ID) error {
	err := r.client.EmailTemplate.
		UpdateOneID(id).
		SetActive(false).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Email template not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to deactivate email template")
	}

	return nil
}

// CloneTemplate clones an existing email template
func (r *emailTemplateRepository) CloneTemplate(ctx context.Context, id xid.ID, newName string, orgID *xid.ID) (*ent.EmailTemplate, error) {
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
		TextContent:    &original.TextContent,
		OrganizationID: orgID,
		Active:         true,
		System:         false, // Clones are never system templates
		Locale:         original.Locale,
		Metadata:       original.Metadata,
	}

	return r.Create(ctx, input)
}

// CountByOrganizationID counts email templates for an organization
func (r *emailTemplateRepository) CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error) {
	count, err := r.client.EmailTemplate.
		Query().
		Where(emailtemplate.OrganizationID(orgID)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count email templates by organization ID")
	}

	return count, nil
}

// CountByType counts email templates by type
func (r *emailTemplateRepository) CountByType(ctx context.Context, templateType string) (int, error) {
	count, err := r.client.EmailTemplate.
		Query().
		Where(emailtemplate.Type(templateType)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count email templates by type")
	}

	return count, nil
}

// ListTemplateTypes retrieves all unique template types
func (r *emailTemplateRepository) ListTemplateTypes(ctx context.Context) ([]string, error) {
	var types []string

	err := r.client.EmailTemplate.
		Query().
		Select(emailtemplate.FieldType).
		GroupBy(emailtemplate.FieldType).
		Scan(ctx, &types)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list template types")
	}

	return types, nil
}

// ListLocales retrieves all unique locales
func (r *emailTemplateRepository) ListLocales(ctx context.Context) ([]string, error) {
	var locales []string

	err := r.client.EmailTemplate.
		Query().
		Select(emailtemplate.FieldLocale).
		GroupBy(emailtemplate.FieldLocale).
		Scan(ctx, &locales)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list locales")
	}

	return locales, nil
}

// ListByOrganizationAndType retrieves email templates by organization and type
func (r *emailTemplateRepository) ListByOrganizationAndType(ctx context.Context, orgID xid.ID, templateType string) ([]*ent.EmailTemplate, error) {
	templates, err := r.client.EmailTemplate.
		Query().
		Where(
			emailtemplate.OrganizationID(orgID),
			emailtemplate.Type(templateType),
		).
		Order(ent.Desc(emailtemplate.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list email templates by organization and type")
	}

	return templates, nil
}

// GetTemplateHierarchy retrieves template hierarchy (organization -> system fallback)
func (r *emailTemplateRepository) GetTemplateHierarchy(ctx context.Context, templateType string, orgID *xid.ID, locale string) ([]*ent.EmailTemplate, error) {
	var templates []*ent.EmailTemplate

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
func (r *emailTemplateRepository) SearchTemplates(ctx context.Context, query string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.EmailTemplate], error) {
	searchQuery := r.client.EmailTemplate.
		Query().
		Where(
			emailtemplate.Or(
				emailtemplate.NameContains(query),
				emailtemplate.SubjectContains(query),
				emailtemplate.HTMLContentContains(query),
			),
		)

	// Apply ordering
	searchQuery.Order(ent.Desc(emailtemplate.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.EmailTemplate, *ent.EmailTemplateQuery](ctx, searchQuery, opts)
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
	// - Check for required template variables
	// - Validate HTML structure
	// - Check for security issues

	return nil
}

// GetTemplateVariables retrieves available variables for a template type
func (r *emailTemplateRepository) GetTemplateVariables(ctx context.Context, templateType string) ([]string, error) {
	// This would typically return a predefined list of variables based on template type
	// Implementation depends on your template variable system

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
