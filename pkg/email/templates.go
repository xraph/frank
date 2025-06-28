package email

import (
	"bytes"
	"context"
	"html/template"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	texttemplate "text/template"

	"github.com/chanced/caps"
	"github.com/xraph/frank/internal/repository"

	"github.com/rs/xid"
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
)

// TemplateManager manages email templates
type TemplateManager struct {
	config        *config.EmailConfig
	logger        logging.Logger
	htmlTemplates map[string]*template.Template
	textTemplates map[string]*texttemplate.Template
	smsTemplates  map[string]*texttemplate.Template
	repo          TemplateRepository
	smsRepo       repository.SMSTemplateRepository
	mu            sync.RWMutex // For thread safety when accessing templates
}

// NewTemplateManager creates a new template manager
func NewTemplateManager(
	repo TemplateRepository,
	smsRepo repository.SMSTemplateRepository,
	cfg *config.EmailConfig,
	logger logging.Logger,
) *TemplateManager {
	manager := &TemplateManager{
		config:        cfg,
		logger:        logger,
		htmlTemplates: make(map[string]*template.Template),
		textTemplates: make(map[string]*texttemplate.Template),
		smsTemplates:  make(map[string]*texttemplate.Template),
		repo:          repo,
		smsRepo:       smsRepo,
	}

	// Load templates
	if err := manager.LoadTemplates(); err != nil {
		logger.Error("Failed to load email templates", logging.Error(err))
	}

	// Load templates
	if err := manager.LoadSMSTemplates(); err != nil {
		logger.Error("Failed to load sms templates", logging.Error(err))
	}

	return manager
}

type templatePersist struct {
	name        string
	subject     string
	htmlContent string
	textContent string
	locale      string
}

// LoadTemplates loads templates from the templates directory
func (m *TemplateManager) LoadTemplates() error {
	// Get template paths
	templatePath := m.config.TemplatesDir
	if templatePath == "" {
		templatePath = "./templates/email"
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

	// Keep track of templates to persist to database
	templatesToPersist := make(map[string]templatePersist)

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
		baseName := strings.TrimSuffix(filepath.Base(path), ext)

		// Check if this is a template in a locale directory
		relPath, err := filepath.Rel(templatePath, path)
		if err != nil {
			return err
		}

		// Extract template name and locale
		parts := strings.Split(relPath, string(filepath.Separator))
		locale := "en" // Default locale
		templateName := baseName

		if len(parts) > 1 {
			// Format: locale/templateName.ext
			locale = parts[0]
			templateName = strings.TrimSuffix(parts[1], ext)
		}

		// Parse template
		if ext == ".html" {
			tmpl, err := template.New(templateName).Parse(string(content))
			if err != nil {
				m.logger.Warn("Failed to parse HTML template",
					logging.String("name", templateName),
					logging.Error(err),
				)
				return nil
			}
			m.htmlTemplates[templateName] = tmpl

			// Store for database persistence
			if t, exists := templatesToPersist[templateName]; exists {
				t.htmlContent = string(content)
				templatesToPersist[templateName] = t
			} else {
				templatesToPersist[templateName] = templatePersist{
					name:        templateName,
					subject:     caps.ToTitle(templateName), // Default subject
					htmlContent: string(content),
					locale:      locale,
				}
			}
		} else {
			tmpl, err := texttemplate.New(templateName).Parse(string(content))
			if err != nil {
				m.logger.Warn("Failed to parse text template",
					logging.String("name", templateName),
					logging.Error(err),
				)
				return nil
			}
			m.textTemplates[templateName] = tmpl

			// Store for database persistence
			if t, exists := templatesToPersist[templateName]; exists {
				t.textContent = string(content)
				templatesToPersist[templateName] = t
			} else {
				templatesToPersist[templateName] = templatePersist{
					name:        templateName,
					subject:     caps.ToTitle(templateName), // Default subject
					textContent: string(content),
					locale:      locale,
				}
			}
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

	if m.config.EnableRemoteStore {
		return m.persistTemplates(templatesToPersist)
	}

	return nil
}

// persistTemplates persists templates to database
func (m *TemplateManager) persistTemplates(templatesToPersist map[string]templatePersist) error {
	// Persist templates to database if repository is available
	if m.repo != nil {
		// Create a background context for database operations
		ctx := context.Background()

		// Persist each template
		for templateName, template := range templatesToPersist {
			// Skip templates with missing HTML content
			if template.htmlContent == "" {
				continue
			}

			// Try to find existing template in database
			existingTemplate, err := m.repo.GetByTypeAndOrganization(ctx, templateName, xid.NilID(), template.locale)

			if err != nil {
				if errors.IsNotFound(err) {
					// Create new template using ent builder
					templateCreate := m.repo.Client().EmailTemplate.Create().
						SetName(template.name).
						SetSubject(template.subject).
						SetType(templateName).
						SetHTMLContent(template.htmlContent).
						SetLocale(template.locale).
						SetActive(true).
						SetSystem(true) // Mark as system template

					if template.textContent != "" {
						templateCreate = templateCreate.SetTextContent(template.textContent)
					}

					_, err = m.repo.Create(ctx, templateCreate)
					if err != nil {
						m.logger.Error("Failed to persist template to database",
							logging.String("name", templateName),
							logging.Error(err),
						)
					} else {
						m.logger.Info("Created new template in database",
							logging.String("name", templateName),
							logging.String("locale", template.locale),
						)
					}
				} else {
					m.logger.Error("Failed to check for existing template",
						logging.String("name", templateName),
						logging.Error(err),
					)
				}
				continue
			}

			// Update existing template if content has changed
			if existingTemplate.HTMLContent != template.htmlContent ||
				existingTemplate.TextContent != template.textContent {

				// Create update using ent builder
				templateUpdate := m.repo.Client().EmailTemplate.UpdateOneID(existingTemplate.ID).
					SetHTMLContent(template.htmlContent)

				if template.textContent != "" {
					templateUpdate = templateUpdate.SetTextContent(template.textContent)
				}

				_, err = m.repo.Update(ctx, templateUpdate)
				if err != nil {
					m.logger.Error("Failed to update template in database",
						logging.String("name", templateName),
						logging.Error(err),
					)
				} else {
					m.logger.Info("Updated template in database",
						logging.String("name", templateName),
						logging.String("locale", template.locale),
					)
				}
			}
		}
	}

	return nil
}

// LoadSMSTemplates loads templates from the templates directory
func (m *TemplateManager) LoadSMSTemplates() error {
	// Get template paths
	templatePath := m.config.TemplatesDir
	templatePath = "./templates/sms"
	// if templatePath == "" {
	// }

	// Check if directory exists
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		m.logger.Warn("Email templates directory not found", logging.String("path", templatePath))
		return nil
	}

	// Lock for writing
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing templates
	m.smsTemplates = make(map[string]*texttemplate.Template)

	// Keep track of templates to persist to database
	templatesToPersist := make(map[string]templatePersist)

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
		baseName := strings.TrimSuffix(filepath.Base(path), ext)

		// Check if this is a template in a locale directory
		relPath, err := filepath.Rel(templatePath, path)
		if err != nil {
			return err
		}

		// Extract template name and locale
		parts := strings.Split(relPath, string(filepath.Separator))
		locale := "en" // Default locale
		templateName := baseName

		if len(parts) > 1 {
			// Format: locale/templateName.ext
			locale = parts[0]
			templateName = strings.TrimSuffix(parts[1], ext)
		}

		// Parse template
		if ext == ".txt" {
			tmpl, err := texttemplate.New(templateName).Parse(string(content))
			if err != nil {
				m.logger.Warn("Failed to parse text template",
					logging.String("name", templateName),
					logging.Error(err),
				)
				return nil
			}
			m.smsTemplates[templateName] = tmpl

			// Store for database persistence
			if t, exists := templatesToPersist[templateName]; exists {
				t.textContent = string(content)
				templatesToPersist[templateName] = t
			} else {
				templatesToPersist[templateName] = templatePersist{
					name:        templateName,
					subject:     caps.ToTitle(templateName), // Default subject
					textContent: string(content),
					locale:      locale,
				}
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	m.logger.Info("Loaded sms templates",
		logging.Int("html_count", len(m.htmlTemplates)),
		logging.Int("text_count", len(m.textTemplates)),
	)

	if m.config.EnableRemoteStore {
		return m.persistSMSTemplates(templatesToPersist)
	}

	return nil
}

// persistTemplates persists templates to database
func (m *TemplateManager) persistSMSTemplates(templatesToPersist map[string]templatePersist) error {
	// Persist templates to database if repository is available
	if m.repo != nil {
		// Create a background context for database operations
		ctx := context.Background()

		// Persist each template
		for templateName, template := range templatesToPersist {
			// Skip templates with missing HTML content
			if template.htmlContent == "" {
				continue
			}

			// Try to find existing template in database
			existingTemplate, err := m.smsRepo.GetByTypeAndOrganization(ctx, templateName, nil, template.locale)

			if err != nil {
				if errors.IsNotFound(err) {
					templateCreate := repository.CreateSMSTemplateInput{
						Name:    template.name,
						Type:    templateName,
						Content: template.textContent,
						Locale:  template.locale,
						Active:  true,
						System:  true,
					}

					_, err = m.smsRepo.Create(ctx, templateCreate)
					if err != nil {
						m.logger.Error("Failed to persist template to database",
							logging.String("name", templateName),
							logging.Error(err),
						)
					} else {
						m.logger.Info("Created new template in database",
							logging.String("name", templateName),
							logging.String("locale", template.locale),
						)
					}
				} else {
					m.logger.Error("Failed to check for existing template",
						logging.String("name", templateName),
						logging.Error(err),
					)
				}
				continue
			}

			// Update existing template if content has changed
			if existingTemplate.Content != template.textContent {
				templateUpdate := repository.UpdateSMSTemplateInput{
					Content: &template.textContent,
				}

				_, err = m.smsRepo.Update(ctx, existingTemplate.ID, templateUpdate)
				if err != nil {
					m.logger.Error("Failed to update template in database",
						logging.String("name", templateName),
						logging.Error(err),
					)
				} else {
					m.logger.Info("Updated template in database",
						logging.String("name", templateName),
						logging.String("locale", template.locale),
					)
				}
			}
		}
	}

	return nil
}

// GetRepository returns the template repository
func (m *TemplateManager) GetRepository() TemplateRepository {
	return m.repo
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
