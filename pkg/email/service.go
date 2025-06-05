package email

import (
	"context"
	"fmt"
	"html/template"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// Service provides email operations
type Service interface {
	// Send sends an email
	Send(ctx context.Context, input SendEmailInput) error

	// SendTemplate sends an email using a template
	SendTemplate(ctx context.Context, input SendTemplateInput) error

	// GetTemplate retrieves an email template
	GetTemplate(ctx context.Context, templateType string, organizationID xid.ID, locale string) (*ent.EmailTemplate, error)

	// CreateTemplate creates an email template
	CreateTemplate(ctx context.Context, input CreateTemplateInput) (*ent.EmailTemplate, error)

	// UpdateTemplate updates an email template
	UpdateTemplate(ctx context.Context, id xid.ID, input UpdateTemplateInput) (*ent.EmailTemplate, error)

	// ListTemplates lists email templates
	ListTemplates(ctx context.Context, params ListTemplatesParams) (*model.PaginatedOutput[*ent.EmailTemplate], error)

	// DeleteTemplate deletes an email template
	DeleteTemplate(ctx context.Context, id xid.ID) error

	// SendMagicLinkEmail sends an email containing a magic login link to the specified email address with additional metadata.
	SendMagicLinkEmail(ctx context.Context, email, firstName, magicLink string, expiresAt time.Time, ipAddress, userAgent string) error
}

type service struct {
	config    *config.EmailConfig
	sender    Sender
	templates *TemplateManager
	logger    logging.Logger
	repo      TemplateRepository
}

// NewService creates a new email service
func NewService(
	cfg *config.EmailConfig,
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
		input.From = s.config.FromEmail
	}

	// Use custom headers from config if provided
	headers := make(map[string]string)
	for k, v := range s.config.CustomHeaders {
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
		if errors.IsNotFound(err) && !input.OrganizationID.IsNil() {
			template, err = s.GetTemplate(ctx, input.TemplateType, xid.NilID(), locale)
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
				logging.String("organization_id", input.OrganizationID.String()),
				logging.String("locale", locale),
			)
			return errors.Wrap(errors.CodeTemplateNotFound, err, "email template not found")
		}
	}

	// Use default from address if not provided
	fromEmail := input.From
	if fromEmail == "" {
		fromEmail = s.config.FromEmail
	}

	// Render HTML content
	htmlContent, err := s.templates.RenderHTML(template.HTMLContent, input.TemplateData)
	if err != nil {
		s.logger.Error("Failed to render HTML template",
			logging.Error(err),
			logging.String("template_id", template.ID.String()),
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
				logging.String("template_id", template.ID.String()),
			)
			// Continue with HTML only
		}
	}

	// Render subject
	subject, err := s.templates.RenderText(template.Subject, input.TemplateData)
	if err != nil {
		s.logger.Error("Failed to render subject template",
			logging.Error(err),
			logging.String("template_id", template.ID.String()),
		)
		subject = template.Subject // Use unrendered subject as fallback
	}

	// Use custom headers from config if provided
	headers := make(map[string]string)
	for k, v := range s.config.CustomHeaders {
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
func (s *service) GetTemplate(ctx context.Context, templateType string, organizationID xid.ID, locale string) (*ent.EmailTemplate, error) {
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
		"ApplicationName": s.config.FromName,
		"SupportEmail":    s.config.FromEmail,
	}

	sbj := "Your Magic Link for " + s.config.FromName
	err := s.SendTemplate(ctx, SendTemplateInput{
		To:           []string{email},
		From:         s.config.FromEmail,
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

	// Create ent.EmailTemplateCreate
	templateCreate := s.repo.Client().EmailTemplate.Create().
		SetName(input.Name).
		SetSubject(input.Subject).
		SetType(input.Type).
		SetHTMLContent(input.HTMLContent).
		SetLocale(locale).
		SetActive(input.Active).
		SetSystem(input.System)

	// Set optional fields
	if input.TextContent != "" {
		templateCreate = templateCreate.SetTextContent(input.TextContent)
	}

	if input.OrganizationID.IsNil() {
		templateCreate = templateCreate.SetOrganizationID(*input.OrganizationID)
	}

	if input.Metadata != nil {
		templateCreate = templateCreate.SetMetadata(input.Metadata)
	}

	// Create template
	return s.repo.Create(ctx, templateCreate)
}

// UpdateTemplate updates an email template
func (s *service) UpdateTemplate(ctx context.Context, id xid.ID, input UpdateTemplateInput) (*ent.EmailTemplate, error) {
	// Validate HTML template if provided
	if input.HTMLContent != nil {
		_, err := template.New("test").Parse(*input.HTMLContent)
		if err != nil {
			return nil, errors.Wrap(errors.CodeInvalidInput, err, "invalid HTML template")
		}
	}

	// Validate text template if provided
	if input.TextContent != nil && *input.TextContent != "" {
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

	// Create ent.EmailTemplateUpdateOne
	templateUpdate := s.repo.Client().EmailTemplate.UpdateOneID(id)

	// Apply updates conditionally
	if input.Name != nil {
		templateUpdate = templateUpdate.SetName(*input.Name)
	}

	if input.Subject != nil {
		templateUpdate = templateUpdate.SetSubject(*input.Subject)
	}

	if input.HTMLContent != nil {
		templateUpdate = templateUpdate.SetHTMLContent(*input.HTMLContent)
	}

	if input.TextContent != nil {
		if *input.TextContent == "" {
			templateUpdate = templateUpdate.ClearTextContent()
		} else {
			templateUpdate = templateUpdate.SetTextContent(*input.TextContent)
		}
	}

	if input.Active != nil {
		templateUpdate = templateUpdate.SetActive(*input.Active)
	}

	if input.Locale != nil {
		templateUpdate = templateUpdate.SetLocale(*input.Locale)
	}

	if input.Metadata != nil {
		templateUpdate = templateUpdate.SetMetadata(input.Metadata)
	}

	return s.repo.Update(ctx, templateUpdate)
}

// ListTemplates lists email templates
func (s *service) ListTemplates(ctx context.Context, params ListTemplatesParams) (*model.PaginatedOutput[*ent.EmailTemplate], error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	return s.repo.List(ctx, params)
}

// DeleteTemplate deletes an email template
func (s *service) DeleteTemplate(ctx context.Context, id xid.ID) error {
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
