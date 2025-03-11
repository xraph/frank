package email

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	texttemplate "text/template"

	"github.com/google/uuid"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/emailtemplate"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// TemplateManager manages email templates
type TemplateManager struct {
	config        *config.Config
	logger        logging.Logger
	htmlTemplates map[string]*template.Template
	textTemplates map[string]*texttemplate.Template
	mu            sync.RWMutex // For thread safety when accessing templates
}

// TemplateRepository provides access to email template storage
type TemplateRepository interface {
	// Create creates a new email template
	Create(ctx context.Context, input TemplateRepositoryCreateInput) (*ent.EmailTemplate, error)

	// GetByID retrieves an email template by ID
	GetByID(ctx context.Context, id string) (*ent.EmailTemplate, error)

	// GetByTypeAndOrganization retrieves an email template by type and organization
	GetByTypeAndOrganization(ctx context.Context, templateType, organizationID, locale string) (*ent.EmailTemplate, error)

	// List retrieves email templates with pagination
	List(ctx context.Context, input TemplateRepositoryListInput) ([]*ent.EmailTemplate, int, error)

	// Update updates an email template
	Update(ctx context.Context, id string, input TemplateRepositoryUpdateInput) (*ent.EmailTemplate, error)

	// Delete deletes an email template
	Delete(ctx context.Context, id string) error
}

// TemplateRepositoryCreateInput represents input for creating an email template
type TemplateRepositoryCreateInput struct {
	Name           string
	Subject        string
	Type           string
	HTMLContent    string
	TextContent    string
	OrganizationID string
	Active         bool
	System         bool
	Locale         string
	Metadata       map[string]interface{}
}

// TemplateRepositoryUpdateInput represents input for updating an email template
type TemplateRepositoryUpdateInput struct {
	Name        *string
	Subject     *string
	HTMLContent *string
	TextContent *string
	Active      *bool
	Locale      *string
	Metadata    map[string]interface{}
}

// TemplateRepositoryListInput represents input for listing email templates
type TemplateRepositoryListInput struct {
	Offset         int
	Limit          int
	Type           string
	OrganizationID string
	Locale         string
}

// NewTemplateManager creates a new template manager
func NewTemplateManager(cfg *config.Config, logger logging.Logger) *TemplateManager {
	manager := &TemplateManager{
		config:        cfg,
		logger:        logger,
		htmlTemplates: make(map[string]*template.Template),
		textTemplates: make(map[string]*texttemplate.Template),
	}

	// Load templates
	if err := manager.LoadTemplates(); err != nil {
		logger.Error("Failed to load email templates", logging.Error(err))
	}

	return manager
}

// LoadTemplates loads templates from the templates directory
func (m *TemplateManager) LoadTemplates() error {
	// Get template paths
	templatePath := m.config.Templates.EmailPath
	if templatePath == "" {
		templatePath = "./web/templates/email"
	}

	// Check if directory exists
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		m.logger.Warn("Email templates directory not found", logging.String("path", templatePath))
		return nil
	}

	// Lock for writing
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing templates
	m.htmlTemplates = make(map[string]*template.Template)
	m.textTemplates = make(map[string]*texttemplate.Template)

	// Walk template directory
	err := filepath.Walk(templatePath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Get file extension
		ext := strings.ToLower(filepath.Ext(path))

		// Only process .html and .txt files
		if ext != ".html" && ext != ".txt" {
			return nil
		}

		// Read file
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		// Get template name (file name without extension)
		name := strings.TrimSuffix(filepath.Base(path), ext)

		// Parse template
		if ext == ".html" {
			tmpl, err := template.New(name).Parse(string(content))
			if err != nil {
				m.logger.Warn("Failed to parse HTML template",
					logging.String("name", name),
					logging.Error(err),
				)
				return nil
			}
			m.htmlTemplates[name] = tmpl
		} else {
			tmpl, err := texttemplate.New(name).Parse(string(content))
			if err != nil {
				m.logger.Warn("Failed to parse text template",
					logging.String("name", name),
					logging.Error(err),
				)
				return nil
			}
			m.textTemplates[name] = tmpl
		}

		return nil
	})

	if err != nil {
		return err
	}

	m.logger.Info("Loaded email templates",
		logging.Int("html_count", len(m.htmlTemplates)),
		logging.Int("text_count", len(m.textTemplates)),
	)

	return nil
}

// RenderHTML renders an HTML template with data
func (m *TemplateManager) RenderHTML(content string, data map[string]interface{}) (string, error) {
	// Parse template
	tmpl, err := template.New("dynamic").Parse(content)
	if err != nil {
		return "", err
	}

	// Render template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// RenderText renders a text template with data
func (m *TemplateManager) RenderText(content string, data map[string]interface{}) (string, error) {
	// Parse template
	tmpl, err := texttemplate.New("dynamic").Parse(content)
	if err != nil {
		return "", err
	}

	// Render template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
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
func (r *templateRepository) Create(ctx context.Context, input TemplateRepositoryCreateInput) (*ent.EmailTemplate, error) {
	// Generate UUID
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(errors.CodeInternalServer, err, "failed to generate uuid")
	}

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

	template, err := query.Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, fmt.Sprintf("email template not found for type '%s'", templateType))
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get email template")
	}

	return template, nil
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
