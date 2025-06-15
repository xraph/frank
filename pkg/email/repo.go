package email

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/emailtemplate"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

var (
	ErrTemplateNotFound      = errors.New(errors.CodeNotFound, "email template not found")
	ErrTemplateAlreadyExists = errors.New(errors.CodeConflict, "template already exists for this type, organization and locale")
	ErrSystemTemplateDelete  = errors.New(errors.CodeForbidden, "cannot delete system templates")
	ErrSystemTemplateLocale  = errors.New(errors.CodeForbidden, "cannot change locale for system templates")
)

// ListTemplatesParams defines the parameters for listing email templates
type ListTemplatesParams struct {
	model.PaginationParams
	Type   string                      `query:"type"`
	OrgID  model.OptionalParam[xid.ID] `query:"orgID"`
	Locale string                      `query:"locale"`
	Active *bool                       `query:"active"`
}

// TemplateRepository provides access to email template storage
type TemplateRepository interface {
	// Create creates a new email template
	Create(ctx context.Context, templateCreate *ent.EmailTemplateCreate) (*ent.EmailTemplate, error)

	// GetByID retrieves an email template by ID
	GetByID(ctx context.Context, id xid.ID) (*ent.EmailTemplate, error)

	// GetByTypeAndOrganization retrieves an email template by type and organization
	GetByTypeAndOrganization(ctx context.Context, templateType string, organizationID xid.ID, locale string) (*ent.EmailTemplate, error)

	// List retrieves email templates with pagination
	List(ctx context.Context, params ListTemplatesParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)

	// Update updates an email template
	Update(ctx context.Context, templateUpdate *ent.EmailTemplateUpdateOne) (*ent.EmailTemplate, error)

	// Delete deletes an email template
	Delete(ctx context.Context, id xid.ID) error

	// BulkCreate creates multiple email templates in a single operation
	BulkCreate(ctx context.Context, templates []*ent.EmailTemplateCreate) ([]*ent.EmailTemplate, error)

	// BulkUpdate updates multiple email templates in a single operation
	BulkUpdate(ctx context.Context, updates []*ent.EmailTemplateUpdateOne) ([]*ent.EmailTemplate, error)

	// ExportAll exports all email templates
	ExportAll(ctx context.Context) ([]*ent.EmailTemplate, error)

	// Client returns the database client
	Client() *ent.Client
}

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
func (r *templateRepository) Create(ctx context.Context, templateCreate *ent.EmailTemplateCreate) (*ent.EmailTemplate, error) {
	// Check if a template with the same type, organization and locale already exists
	templateType, _ := templateCreate.Mutation().GetType()
	organizationID, _ := templateCreate.Mutation().OrganizationID()
	locale, _ := templateCreate.Mutation().Locale()

	if !organizationID.IsNil() {
		exists, err := r.client.EmailTemplate.
			Query().
			Where(
				emailtemplate.Type(templateType),
				emailtemplate.OrganizationID(organizationID),
				emailtemplate.Locale(locale),
			).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to check template existence")
		}

		if exists {
			return nil, ErrTemplateAlreadyExists
		}
	}

	// Create template
	template, err := templateCreate.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrTemplateAlreadyExists
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create email template")
	}

	return template, nil
}

// GetByID retrieves an email template by ID
func (r *templateRepository) GetByID(ctx context.Context, id xid.ID) (*ent.EmailTemplate, error) {
	template, err := r.client.EmailTemplate.
		Query().
		Where(emailtemplate.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrTemplateNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get email template")
	}

	return template, nil
}

// GetByTypeAndOrganization retrieves an email template by type and organization
func (r *templateRepository) GetByTypeAndOrganization(ctx context.Context, templateType string, organizationID xid.ID, locale string) (*ent.EmailTemplate, error) {
	query := r.client.EmailTemplate.
		Query().
		Where(
			emailtemplate.Type(templateType),
			emailtemplate.Locale(locale),
			emailtemplate.Active(true),
		)

	if !organizationID.IsNil() {
		query = query.Where(emailtemplate.OrganizationID(organizationID))
	} else {
		query = query.Where(emailtemplate.OrganizationIDIsNil())
	}

	template, err := query.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("email template not found for type '%s'", templateType))
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get email template")
	}

	return template, nil
}

// List retrieves email templates with pagination
func (r *templateRepository) List(ctx context.Context, params ListTemplatesParams) (*model.PaginatedOutput[*ent.EmailTemplate], error) {
	// Build query
	query := r.client.EmailTemplate.Query()

	// Apply filters
	if params.Type != "" {
		query = query.Where(emailtemplate.Type(params.Type))
	}

	if params.OrgID.IsSet {
		query = query.Where(emailtemplate.OrganizationID(params.OrgID.Value))
	}

	if params.Locale != "" {
		query = query.Where(emailtemplate.Locale(params.Locale))
	}

	if params.Active != nil {
		query = query.Where(emailtemplate.Active(*params.Active))
	}

	// Apply ordering
	for _, o := range model.GetOrdering(params.PaginationParams) {
		if o.Desc {
			query = query.Order(ent.Desc(o.Field))
			continue
		}
		query = query.Order(ent.Asc(o.Field))
	}

	return model.WithPaginationAndOptions[*ent.EmailTemplate, *ent.EmailTemplateQuery](ctx, query, params.PaginationParams)
}

// Update updates an email template
func (r *templateRepository) Update(ctx context.Context, templateUpdate *ent.EmailTemplateUpdateOne) (*ent.EmailTemplate, error) {
	// Get the template ID from the update mutation
	templateID, _ := templateUpdate.Mutation().ID()

	// Check if template exists
	template, err := r.GetByID(ctx, xid.ID(templateID))
	if err != nil {
		return nil, err
	}

	// Check if it's a system template and prevent certain changes
	if template.System {
		// Can't change locale for system templates
		if locale, localeUpdated := templateUpdate.Mutation().Locale(); localeUpdated && locale != template.Locale {
			return nil, ErrSystemTemplateLocale
		}
	}

	// Execute update
	updatedTemplate, err := templateUpdate.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrTemplateNotFound
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update email template")
	}

	return updatedTemplate, nil
}

// Delete deletes an email template
func (r *templateRepository) Delete(ctx context.Context, id xid.ID) error {
	// Check if template exists and is not a system template
	template, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if template.System {
		return ErrSystemTemplateDelete
	}

	// Delete template
	err = r.client.EmailTemplate.
		DeleteOneID(id).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return ErrTemplateNotFound
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete email template")
	}

	return nil
}

// BulkCreate creates multiple email templates in a single operation
func (r *templateRepository) BulkCreate(ctx context.Context, templates []*ent.EmailTemplateCreate) ([]*ent.EmailTemplate, error) {
	// Create templates in a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]*ent.EmailTemplate, 0, len(templates))

	for _, templateCreate := range templates {
		// Get fields from mutation
		name, _ := templateCreate.Mutation().Name()
		subject, _ := templateCreate.Mutation().Subject()
		templateType, _ := templateCreate.Mutation().GetType()
		htmlContent, _ := templateCreate.Mutation().HTMLContent()
		locale, _ := templateCreate.Mutation().Locale()

		// Clone the create action for transaction
		creator := tx.EmailTemplate.Create().
			SetName(name).
			SetSubject(subject).
			SetType(templateType).
			SetHTMLContent(htmlContent).
			SetLocale(locale)

		// Add optional fields
		if textContent, exists := templateCreate.Mutation().TextContent(); exists {
			creator.SetTextContent(textContent)
		}

		if orgID, exists := templateCreate.Mutation().OrganizationID(); exists {
			creator.SetOrganizationID(orgID)
		}

		if active, exists := templateCreate.Mutation().Active(); exists {
			creator.SetActive(active)
		} else {
			creator.SetActive(true) // Default to active
		}

		if system, exists := templateCreate.Mutation().System(); exists {
			creator.SetSystem(system)
		}

		if metadata, exists := templateCreate.Mutation().Metadata(); exists {
			creator.SetMetadata(metadata)
		}

		// Create template
		template, err := creator.Save(ctx)
		if err != nil {
			tx.Rollback()
			return nil, err
		}

		results = append(results, template)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return results, nil
}

// BulkUpdate updates multiple email templates in a single operation
func (r *templateRepository) BulkUpdate(ctx context.Context, updates []*ent.EmailTemplateUpdateOne) ([]*ent.EmailTemplate, error) {
	// Update templates in a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]*ent.EmailTemplate, 0, len(updates))

	for _, update := range updates {
		// Get ID for the update
		p := update.Mutation()
		templateID, _ := p.ID()

		// Create updater
		updater := tx.EmailTemplate.UpdateOneID(templateID)

		// Apply all updates from the original update
		if name, exists := p.Name(); exists {
			updater.SetName(name)
		}

		if subject, exists := p.Subject(); exists {
			updater.SetSubject(subject)
		}

		if htmlContent, exists := p.HTMLContent(); exists {
			updater.SetHTMLContent(htmlContent)
		}

		if textContent, exists := p.TextContent(); exists {
			updater.SetTextContent(textContent)
		}

		if active, exists := p.Active(); exists {
			updater.SetActive(active)
		}

		if locale, exists := p.Locale(); exists {
			updater.SetLocale(locale)
		}

		if metadata, exists := p.Metadata(); exists {
			updater.SetMetadata(metadata)
		}

		// Update template
		template, err := updater.Save(ctx)
		if err != nil {
			tx.Rollback()
			return nil, err
		}

		results = append(results, template)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return results, nil
}

// ExportAll exports all email templates
func (r *templateRepository) ExportAll(ctx context.Context) ([]*ent.EmailTemplate, error) {
	templates, err := r.client.EmailTemplate.Query().All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to export email templates")
	}
	return templates, nil
}

// Client returns the database client
func (r *templateRepository) Client() *ent.Client {
	return r.client
}
