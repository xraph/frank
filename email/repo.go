package email

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/emailtemplate"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/utils"
)

// templateRepository implements TemplateRepository
type templateRepository struct {
	client *ent.Client
}

// NewTemplateRepository creates a new template repository
func NewTemplateRepository(client *ent.Client) TemplateRepository {
	return &templateRepository{
		client: client,
	}
}

// Create creates a new email template
func (r *templateRepository) Create(ctx context.Context, input TemplateRepositoryCreateInput) (*ent.EmailTemplate, error) {
	// Generate UUID
	id := utils.NewID()

	// Check if a template with the same type, organization and locale already exists
	if input.OrganizationID != "" {
		exists, err := r.client.EmailTemplate.
			Query().
			Where(
				emailtemplate.Type(input.Type),
				emailtemplate.OrganizationID(input.OrganizationID),
				emailtemplate.Locale(input.Locale),
			).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check template existence")
		}

		if exists {
			return nil, errors.New(errors.CodeConflict, "template already exists for this type, organization and locale")
		}
	}

	// Create template
	template, err := r.client.EmailTemplate.
		Create().
		SetID(id.String()).
		SetName(input.Name).
		SetSubject(input.Subject).
		SetType(input.Type).
		SetHTMLContent(input.HTMLContent).
		SetNillableTextContent(nilIfEmpty(input.TextContent)).
		SetNillableOrganizationID(nilIfEmpty(input.OrganizationID)).
		SetActive(input.Active).
		SetSystem(input.System).
		SetLocale(input.Locale).
		SetMetadata(input.Metadata).
		Save(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create email template")
	}

	return template, nil
}

// GetByID retrieves an email template by ID
func (r *templateRepository) GetByID(ctx context.Context, id string) (*ent.EmailTemplate, error) {
	template, err := r.client.EmailTemplate.
		Query().
		Where(emailtemplate.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "email template not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get email template")
	}

	return template, nil
}

// GetByTypeAndOrganization retrieves an email template by type and organization
func (r *templateRepository) GetByTypeAndOrganization(ctx context.Context, templateType, organizationID, locale string) (*ent.EmailTemplate, error) {
	query := r.client.EmailTemplate.
		Query().
		Where(
			emailtemplate.Type(templateType),
			emailtemplate.Locale(locale),
			emailtemplate.Active(true),
		)

	if organizationID != "" {
		query = query.Where(emailtemplate.OrganizationID(organizationID))
	} else {
		query = query.Where(emailtemplate.OrganizationIDIsNil())
	}

	temp, err := query.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("email template not found for type '%s'", templateType))
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get email template")
	}

	return temp, nil
}

// List retrieves email templates with pagination
func (r *templateRepository) List(ctx context.Context, input TemplateRepositoryListInput) ([]*ent.EmailTemplate, int, error) {
	// Build query
	query := r.client.EmailTemplate.Query()

	// Apply filters
	if input.Type != "" {
		query = query.Where(emailtemplate.Type(input.Type))
	}

	if input.OrganizationID != "" {
		query = query.Where(emailtemplate.OrganizationID(input.OrganizationID))
	}

	if input.Locale != "" {
		query = query.Where(emailtemplate.Locale(input.Locale))
	}

	// Count total results
	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to count email templates")
	}

	// Apply pagination
	templates, err := query.
		Limit(input.Limit).
		Offset(input.Offset).
		Order(ent.Desc(emailtemplate.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to list email templates")
	}

	return templates, total, nil
}

// GetRepository returns the template repository if it has been set
func (m *TemplateManager) GetRepository() TemplateRepository {
	// This method should be implemented to provide access to the repository
	if repo, ok := m.repo.(TemplateRepository); ok {
		return repo
	}
	return nil
}

// Update updates an email template
func (r *templateRepository) Update(ctx context.Context, id string, input TemplateRepositoryUpdateInput) (*ent.EmailTemplate, error) {
	// Check if template exists
	template, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Check if it's a system template and prevent certain changes
	if template.System {
		// Can't change locale for system templates
		if input.Locale != nil && *input.Locale != template.Locale {
			return nil, errors.New(errors.CodeForbidden, "cannot change locale for system templates")
		}
	}

	// Build update query
	update := r.client.EmailTemplate.
		UpdateOneID(id)

	// Apply updates
	if input.Name != nil {
		update = update.SetName(*input.Name)
	}

	if input.Subject != nil {
		update = update.SetSubject(*input.Subject)
	}

	if input.HTMLContent != nil {
		update = update.SetHTMLContent(*input.HTMLContent)
	}

	if input.TextContent != nil {
		if *input.TextContent == "" {
			update = update.ClearTextContent()
		} else {
			update = update.SetTextContent(*input.TextContent)
		}
	}

	if input.Active != nil {
		update = update.SetActive(*input.Active)
	}

	if input.Locale != nil {
		update = update.SetLocale(*input.Locale)
	}

	if input.Metadata != nil {
		update = update.SetMetadata(input.Metadata)
	}

	// Execute update
	updatedTemplate, err := update.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to update email template")
	}

	return updatedTemplate, nil
}

// Delete deletes an email template
func (r *templateRepository) Delete(ctx context.Context, id string) error {
	// Check if template exists and is not a system template
	template, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if template.System {
		return errors.New(errors.CodeForbidden, "cannot delete system templates")
	}

	// Delete template
	err = r.client.EmailTemplate.
		DeleteOneID(id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete email template")
	}

	return nil
}

// Helper function to handle empty strings
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
