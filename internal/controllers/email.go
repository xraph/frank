package controllers

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/gen/email"
	"goa.design/clue/log"
	"goa.design/goa/v3/security"
)

// email service example implementation.
// The example methods log the requests and return zero values.
type emailsrvc struct{}

// NewEmail returns the email service implementation.
func NewEmail() email.Service {
	return &emailsrvc{}
}

// JWTAuth implements the authorization logic for service "email" for the "jwt"
// security scheme.
func (s *emailsrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	//
	// TBD: add authorization logic.
	//
	// In case of authorization failure this function should return
	// one of the generated error structs, e.g.:
	//
	//    return ctx, myservice.MakeUnauthorizedError("invalid token")
	//
	// Alternatively this function may return an instance of
	// goa.ServiceError with a Name field value that matches one of
	// the design error names, e.g:
	//
	//    return ctx, goa.PermanentError("unauthorized", "invalid token")
	//
	return ctx, fmt.Errorf("not implemented")
}

// List email templates
func (s *emailsrvc) ListTemplates(ctx context.Context, p *email.ListTemplatesPayload) (res *email.ListTemplatesResult, err error) {
	res = &email.ListTemplatesResult{}
	log.Printf(ctx, "email.list_templates")
	return
}

// Create a new email template
func (s *emailsrvc) CreateTemplate(ctx context.Context, p *email.CreateTemplatePayload) (res *email.EmailTemplateResponse, err error) {
	res = &email.EmailTemplateResponse{}
	log.Printf(ctx, "email.create_template")
	return
}

// Get email template by ID
func (s *emailsrvc) GetTemplate(ctx context.Context, p *email.GetTemplatePayload) (res *email.EmailTemplateResponse, err error) {
	res = &email.EmailTemplateResponse{}
	log.Printf(ctx, "email.get_template")
	return
}

// Get email template by type
func (s *emailsrvc) GetTemplateByType(ctx context.Context, p *email.GetTemplateByTypePayload) (res *email.EmailTemplateResponse, err error) {
	res = &email.EmailTemplateResponse{}
	log.Printf(ctx, "email.get_template_by_type")
	return
}

// Update email template
func (s *emailsrvc) UpdateTemplate(ctx context.Context, p *email.UpdateTemplatePayload) (res *email.EmailTemplateResponse, err error) {
	res = &email.EmailTemplateResponse{}
	log.Printf(ctx, "email.update_template")
	return
}

// Delete email template
func (s *emailsrvc) DeleteTemplate(ctx context.Context, p *email.DeleteTemplatePayload) (err error) {
	log.Printf(ctx, "email.delete_template")
	return
}

// Send email
func (s *emailsrvc) Send(ctx context.Context, p *email.SendPayload) (res *email.SendResult, err error) {
	res = &email.SendResult{}
	log.Printf(ctx, "email.send")
	return
}

// Send email using a template
func (s *emailsrvc) SendTemplate(ctx context.Context, p *email.SendTemplatePayload) (res *email.SendTemplateResult, err error) {
	res = &email.SendTemplateResult{}
	log.Printf(ctx, "email.send_template")
	return
}
