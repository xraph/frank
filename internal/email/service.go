package email

import (
	"context"
	"fmt"
	"html/template"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// Service provides email operations
type Service interface {
	// Send sends an email
	Send(ctx context.Context, input SendEmailInput) error

	// SendTemplate sends an email using a template
	SendTemplate(ctx context.Context, input SendTemplateInput) error

	// GetTemplate retrieves an email template
	GetTemplate(ctx context.Context, templateType, organizationID, locale string) (*ent.EmailTemplate, error)

	// CreateTemplate creates an email template
	CreateTemplate(ctx context.Context, input CreateTemplateInput) (*ent.EmailTemplate, error)

	// UpdateTemplate updates an email template
	UpdateTemplate(ctx context.Context, id string, input UpdateTemplateInput) (*ent.EmailTemplate, error)

	// ListTemplates lists email templates
	ListTemplates(ctx context.Context, input ListTemplatesInput) ([]*ent.EmailTemplate, int, error)

	// DeleteTemplate deletes an email template
	DeleteTemplate(ctx context.Context, id string) error

	// SendMagicLinkEmail sends an email containing a magic login link to the specified email address with additional metadata.
	SendMagicLinkEmail(ctx context.Context, email, firstName, magicLink string, expiresAt time.Time, ipAddress, userAgent string) error
}

// SendEmailInput represents input for sending an email
type SendEmailInput struct {
	To          []string               `json:"to" validate:"required,dive,email"`
	From        string                 `json:"from,omitempty"`
	Subject     string                 `json:"subject" validate:"required"`
	HTMLContent string                 `json:"html_content,omitempty"`
	TextContent string                 `json:"text_content,omitempty"`
	CC          []string               `json:"cc,omitempty"`
	BCC         []string               `json:"bcc,omitempty"`
	ReplyTo     string                 `json:"reply_to,omitempty"`
	Attachments []Attachment           `json:"attachments,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SendTemplateInput represents input for sending an email using a template
type SendTemplateInput struct {
	To             []string               `json:"to" validate:"required,dive,email"`
	From           string                 `json:"from,omitempty"`
	Subject        *string                `json:"subject,omitempty"`
	TemplateType   string                 `json:"template_type" validate:"required"`
	TemplateData   map[string]interface{} `json:"template_data" validate:"required"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	Locale         string                 `json:"locale,omitempty"`
	CC             []string               `json:"cc,omitempty"`
	BCC            []string               `json:"bcc,omitempty"`
	ReplyTo        string                 `json:"reply_to,omitempty"`
	Attachments    []Attachment           `json:"attachments,omitempty"`
	Headers        map[string]string      `json:"headers,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// CreateTemplateInput represents input for creating an email template
type CreateTemplateInput struct {
	Name           string                 `json:"name" validate:"required"`
	Subject        string                 `json:"subject" validate:"required"`
	Type           string                 `json:"type" validate:"required"`
	HTMLContent    string                 `json:"html_content" validate:"required"`
	TextContent    string                 `json:"text_content,omitempty"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	Active         bool                   `json:"active"`
	System         bool                   `json:"system,omitempty"`
	Locale         string                 `json:"locale,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateTemplateInput represents input for updating an email template
type UpdateTemplateInput struct {
	Name        *string                `json:"name,omitempty"`
	Subject     *string                `json:"subject,omitempty"`
	HTMLContent *string                `json:"html_content,omitempty"`
	TextContent *string                `json:"text_content,omitempty"`
	Active      *bool                  `json:"active,omitempty"`
	Locale      *string                `json:"locale,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ListTemplatesInput represents input for listing email templates
type ListTemplatesInput struct {
	Offset         int    `json:"offset" query:"offset"`
	Limit          int    `json:"limit" query:"limit"`
	Type           string `json:"type" query:"type"`
	OrganizationID string `json:"organization_id" query:"organization_id"`
	Locale         string `json:"locale" query:"locale"`
}

// Attachment represents an email attachment
type Attachment struct {
	Content []byte `json:"content"`

	// Filename is the name of the attachment
	Filename string

	// ContentType is the MIME type of the attachment
	ContentType string

	// Base64Content is the base64-encoded content of the attachment
	Base64Content string

	// Size is the size of the attachment in bytes (optional)
	Size int64
}

// NewAttachment creates a new email attachment
func NewAttachment(filename string, contentType string, base64Content string) Attachment {
	return Attachment{
		Filename:      filename,
		ContentType:   contentType,
		Base64Content: base64Content,
		Size:          int64(len(base64Content)),
	}
}

type service struct {
	config    *config.Config
	sender    Sender
	templates *TemplateManager
	logger    logging.Logger
	repo      TemplateRepository
}

// NewService creates a new email service
func NewService(
	cfg *config.Config,
	sender Sender,
	templates *TemplateManager,
	repo TemplateRepository,
	logger logging.Logger,
) Service {
	return &service{
		config:    cfg,
		sender:    sender,
		templates: templates,
		logger:    logger,
		repo:      repo,
	}
}

// Send sends an email
func (s *service) Send(ctx context.Context, input SendEmailInput) error {
	// Validate input
	if len(input.To) == 0 {
		return errors.New(errors.CodeInvalidInput, "no recipients specified")
	}

	if input.Subject == "" {
		return errors.New(errors.CodeInvalidInput, "subject is required")
	}

	if input.HTMLContent == "" && input.TextContent == "" {
		return errors.New(errors.CodeInvalidInput, "either HTML or text content is required")
	}

	// Use default from address if not provided
	if input.From == "" {
		input.From = s.config.Email.FromEmail
	}

	// Use custom headers from config if provided
	headers := make(map[string]string)
	for k, v := range s.config.Email.CustomHeaders {
		headers[k] = v
	}

	// Add custom headers from input
	for k, v := range input.Headers {
		headers[k] = v
	}

	// Create email
	email := Email{
		To:          input.To,
		From:        input.From,
		Subject:     input.Subject,
		HTMLContent: input.HTMLContent,
		TextContent: input.TextContent,
		CC:          input.CC,
		BCC:         input.BCC,
		ReplyTo:     input.ReplyTo,
		Attachments: input.Attachments,
		Headers:     headers,
	}

	// Send email
	err := s.sender.Send(ctx, email)
	if err != nil {
		s.logger.Error("Failed to send email",
			logging.Error(err),
			logging.String("to", fmt.Sprintf("%v", input.To)),
			logging.String("subject", input.Subject),
		)
		return errors.Wrap(errors.CodeEmailDeliveryFail, err, "failed to send email")
	}

	return nil
}

// SendTemplate sends an email using a template
func (s *service) SendTemplate(ctx context.Context, input SendTemplateInput) error {
	// Validate input
	if len(input.To) == 0 {
		return errors.New(errors.CodeInvalidInput, "no recipients specified")
	}

	if input.TemplateType == "" {
		return errors.New(errors.CodeInvalidInput, "template type is required")
	}

	// Set default locale if not provided
	locale := input.Locale
	if locale == "" {
		locale = "en"
	}

	// Get template from database or fallback to system template
	template, err := s.GetTemplate(ctx, input.TemplateType, input.OrganizationID, locale)
	if err != nil {
		// If organization-specific template not found, try to get system template
		if errors.IsNotFound(err) && input.OrganizationID != "" {
			template, err = s.GetTemplate(ctx, input.TemplateType, "", locale)
			if err != nil {
				s.logger.Error("Failed to find email template",
					logging.Error(err),
					logging.String("template_type", input.TemplateType),
					logging.String("locale", locale),
				)
				return errors.Wrap(errors.CodeTemplateNotFound, err, "email template not found")
			}
		} else {
			s.logger.Error("Failed to find email template",
				logging.Error(err),
				logging.String("template_type", input.TemplateType),
				logging.String("organization_id", input.OrganizationID),
				logging.String("locale", locale),
			)
			return errors.Wrap(errors.CodeTemplateNotFound, err, "email template not found")
		}
	}

	// Use default from address if not provided
	fromEmail := input.From
	if fromEmail == "" {
		fromEmail = s.config.Email.FromEmail
	}

	// Render HTML content
	htmlContent, err := s.templates.RenderHTML(template.HTMLContent, input.TemplateData)
	if err != nil {
		s.logger.Error("Failed to render HTML template",
			logging.Error(err),
			logging.String("template_id", template.ID),
		)
		return errors.Wrap(errors.CodeTemplateNotFound, err, "failed to render email template")
	}

	// Render text content if available
	var textContent string
	if template.TextContent != "" {
		textContent, err = s.templates.RenderText(template.TextContent, input.TemplateData)
		if err != nil {
			s.logger.Error("Failed to render text template",
				logging.Error(err),
				logging.String("template_id", template.ID),
			)
			// Continue with HTML only
		}
	}

	// Render subject
	subject, err := s.templates.RenderText(template.Subject, input.TemplateData)
	if err != nil {
		s.logger.Error("Failed to render subject template",
			logging.Error(err),
			logging.String("template_id", template.ID),
		)
		subject = template.Subject // Use unrendered subject as fallback
	}

	// Use custom headers from config if provided
	headers := make(map[string]string)
	for k, v := range s.config.Email.CustomHeaders {
		headers[k] = v
	}

	// Add custom headers from input
	for k, v := range input.Headers {
		headers[k] = v
	}

	// Create email
	email := Email{
		To:          input.To,
		From:        fromEmail,
		Subject:     subject,
		HTMLContent: htmlContent,
		TextContent: textContent,
		CC:          input.CC,
		BCC:         input.BCC,
		ReplyTo:     input.ReplyTo,
		Attachments: input.Attachments,
		Headers:     headers,
	}

	// Send email
	err = s.sender.Send(ctx, email)
	if err != nil {
		s.logger.Error("Failed to send template email",
			logging.Error(err),
			logging.String("to", fmt.Sprintf("%v", input.To)),
			logging.String("template_type", input.TemplateType),
		)
		return errors.Wrap(errors.CodeEmailDeliveryFail, err, "failed to send email")
	}

	return nil
}

// GetTemplate retrieves an email template
func (s *service) GetTemplate(ctx context.Context, templateType, organizationID, locale string) (*ent.EmailTemplate, error) {
	return s.repo.GetByTypeAndOrganization(ctx, templateType, organizationID, locale)
}

// SendMagicLinkEmail sends an email with a magic link for passwordless authentication
func (s *service) SendMagicLinkEmail(ctx context.Context, email, firstName, magicLink string, expiresAt time.Time, ipAddress, userAgent string) error {
	// Create template data
	data := map[string]interface{}{
		"FirstName":       firstName,
		"MagicLink":       magicLink,
		"ExpiresAt":       expiresAt.Format(time.RFC1123),
		"IPAddress":       ipAddress,
		"UserAgent":       userAgent,
		"ApplicationName": s.config.Server.Name,
		"SupportEmail":    s.config.Email.FromEmail,
	}

	sbj := "Your Magic Link for " + s.config.Server.Name
	err := s.SendTemplate(ctx, SendTemplateInput{
		To:           []string{email},
		From:         s.config.Email.FromEmail,
		Subject:      &sbj,
		TemplateType: "magic_link",
		TemplateData: data,
		Headers: map[string]string{
			"X-Priority":       "1",
			"X-Mailer":         "Frank Authentication Server",
			"X-Authentication": "Magic Link",
		},
	})
	if err != nil {
		return errors.Wrap(errors.CodeEmailDeliveryFail, err, "failed to render text template for magic link email")
	}

	// Log that the email was sent
	s.logger.Info("Magic link email sent",
		logging.String("email", email),
		logging.String("ip_address", ipAddress),
	)

	return nil
}

// CreateTemplate creates an email template
func (s *service) CreateTemplate(ctx context.Context, input CreateTemplateInput) (*ent.EmailTemplate, error) {
	// Set default locale if not provided
	locale := input.Locale
	if locale == "" {
		locale = "en"
	}

	// Check template validity by parsing it
	_, err := template.New("test").Parse(input.HTMLContent)
	if err != nil {
		return nil, errors.Wrap(errors.CodeInvalidInput, err, "invalid HTML template")
	}

	if input.TextContent != "" {
		_, err = template.New("test").Parse(input.TextContent)
		if err != nil {
			return nil, errors.Wrap(errors.CodeInvalidInput, err, "invalid text template")
		}
	}

	// Parse subject template
	_, err = template.New("test").Parse(input.Subject)
	if err != nil {
		return nil, errors.Wrap(errors.CodeInvalidInput, err, "invalid subject template")
	}

	// Create template
	return s.repo.Create(ctx, TemplateRepositoryCreateInput{
		Name:           input.Name,
		Subject:        input.Subject,
		Type:           input.Type,
		HTMLContent:    input.HTMLContent,
		TextContent:    input.TextContent,
		OrganizationID: input.OrganizationID,
		Active:         input.Active,
		System:         input.System,
		Locale:         locale,
		Metadata:       input.Metadata,
	})
}

// UpdateTemplate updates an email template
func (s *service) UpdateTemplate(ctx context.Context, id string, input UpdateTemplateInput) (*ent.EmailTemplate, error) {
	// Create repository input
	repoInput := TemplateRepositoryUpdateInput{
		Name:        input.Name,
		Subject:     input.Subject,
		HTMLContent: input.HTMLContent,
		TextContent: input.TextContent,
		Active:      input.Active,
		Locale:      input.Locale,
		Metadata:    input.Metadata,
	}

	// Validate HTML template if provided
	if input.HTMLContent != nil {
		_, err := template.New("test").Parse(*input.HTMLContent)
		if err != nil {
			return nil, errors.Wrap(errors.CodeInvalidInput, err, "invalid HTML template")
		}
	}

	// Validate text template if provided
	if input.TextContent != nil {
		_, err := template.New("test").Parse(*input.TextContent)
		if err != nil {
			return nil, errors.Wrap(errors.CodeInvalidInput, err, "invalid text template")
		}
	}

	// Validate subject template if provided
	if input.Subject != nil {
		_, err := template.New("test").Parse(*input.Subject)
		if err != nil {
			return nil, errors.Wrap(errors.CodeInvalidInput, err, "invalid subject template")
		}
	}

	return s.repo.Update(ctx, id, repoInput)
}

// ListTemplates lists email templates
func (s *service) ListTemplates(ctx context.Context, input ListTemplatesInput) ([]*ent.EmailTemplate, int, error) {
	// Set default limit if not provided
	if input.Limit <= 0 {
		input.Limit = 10
	}

	return s.repo.List(ctx, TemplateRepositoryListInput{
		Offset:         input.Offset,
		Limit:          input.Limit,
		Type:           input.Type,
		OrganizationID: input.OrganizationID,
		Locale:         input.Locale,
	})
}

// DeleteTemplate deletes an email template
func (s *service) DeleteTemplate(ctx context.Context, id string) error {
	// Check if template is a system template
	template, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if template.System {
		return errors.New(errors.CodeForbidden, "cannot delete system templates")
	}

	return s.repo.Delete(ctx, id)
}
