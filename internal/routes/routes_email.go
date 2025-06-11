package routes

// import (
// 	"context"
// 	"net/http"
//
// 	"github.com/danielgtaylor/huma/v2"
// 	"github.com/juicycleff/frank/ent"
// 	"github.com/juicycleff/frank/internal/authz"
// 	"github.com/juicycleff/frank/internal/di"
// 	"github.com/juicycleff/frank/internal/model"
// 	"github.com/juicycleff/frank/pkg/email"
// 	"github.com/juicycleff/frank/pkg/errors"
// 	"github.com/rs/xid"
// )
//
// // RegisterEmailAPI registers all email-related endpoints
// func RegisterEmailAPI(api huma.API, di di.Container) {
// 	emailCtrl := &emailController{
// 		api: api,
// 		di:  di,
// 	}
//
// 	// Register email template endpoints
// 	registerListEmailTemplates(api, emailCtrl)
// 	registerGetEmailTemplate(api, emailCtrl)
// 	registerCreateEmailTemplate(api, emailCtrl)
// 	registerUpdateEmailTemplate(api, emailCtrl)
// 	registerDeleteEmailTemplate(api, emailCtrl)
// }
//
// func registerListEmailTemplates(api huma.API, emailCtrl *emailController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "listEmailTemplates",
// 		Method:      http.MethodGet,
// 		Path:        "/email-templates",
// 		Summary:     "List email templates",
// 		Description: "List all email templates with pagination and filtering options",
// 		Tags:        []string{"Email Templates"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 	}, emailCtrl.listEmailTemplatesHandler)
// }
//
// func registerGetEmailTemplate(api huma.API, emailCtrl *emailController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "getEmailTemplate",
// 		Method:      http.MethodGet,
// 		Path:        "/email-templates/{id}",
// 		Summary:     "Get an email template",
// 		Description: "Get an email template by ID with organization and template type filters",
// 		Tags:        []string{"Email Templates"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Template not found")),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 	}, emailCtrl.getEmailTemplateHandler)
// }
//
// func registerCreateEmailTemplate(api huma.API, emailCtrl *emailController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "createEmailTemplate",
// 		Method:      http.MethodPost,
// 		Path:        "/email-templates",
// 		Summary:     "Create a new email template",
// 		Description: "Create a new email template with the specified content and metadata",
// 		Tags:        []string{"Email Templates"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, emailCtrl.di.AuthZ().Checker(), emailCtrl.di.Logger())(
// 			authz.PermissionManageEmailTemplates, authz.ResourceOrganization, "organizationId",
// 		)},
// 	}, emailCtrl.createEmailTemplateHandler)
// }
//
// func registerUpdateEmailTemplate(api huma.API, emailCtrl *emailController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID: "updateEmailTemplate",
// 		Method:      http.MethodPut,
// 		Path:        "/email-templates/{id}",
// 		Summary:     "Update an email template",
// 		Description: "Update an existing email template by ID",
// 		Tags:        []string{"Email Templates"},
// 		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Template not found")),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, emailCtrl.di.AuthZ().Checker(), emailCtrl.di.Logger())(
// 			authz.PermissionManageEmailTemplates, authz.ResourceOrganization, "organizationId",
// 		)},
// 	}, emailCtrl.updateEmailTemplateHandler)
// }
//
// func registerDeleteEmailTemplate(api huma.API, emailCtrl *emailController) {
// 	huma.Register(api, huma.Operation{
// 		OperationID:   "deleteEmailTemplate",
// 		Method:        http.MethodDelete,
// 		Path:          "/email-templates/{id}",
// 		Summary:       "Delete an email template",
// 		Description:   "Delete an email template by ID",
// 		Tags:          []string{"Email Templates"},
// 		DefaultStatus: 204,
// 		Responses: model.MergeErrorResponses(map[string]*huma.Response{
// 			"204": {
// 				Description: "Template successfully deleted",
// 			},
// 		}, true, model.NotFoundError("Template not found")),
// 		Security: []map[string][]string{
// 			{"jwt": {}},
// 		},
// 		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, emailCtrl.di.AuthZ().Checker(), emailCtrl.di.Logger())(
// 			authz.PermissionManageEmailTemplates, authz.ResourceOrganization, "organizationId",
// 		)},
// 	}, emailCtrl.deleteEmailTemplateHandler)
// }
//
// // emailController handles email-related API requests
// type emailController struct {
// 	api huma.API
// 	di  di.Container
// }
//
// // Input/Output type definitions for email template handlers
//
// type ListEmailTemplatesOutput = model.Output[model.PaginatedOutput[*ent.EmailTemplate]]
//
// // GetEmailTemplateInput represents input for getting a specific email template
// type GetEmailTemplateInput struct {
// 	ID           xid.ID `path:"id" doc:"Template ID"`
// 	OrgID        xid.ID `query:"orgId" validate:"required" doc:"OrgID"`
// 	TemplateType string `query:"templateType" validate:"required" doc:"Template type"`
// }
//
// type GetEmailTemplateOutput = model.Output[*ent.EmailTemplate]
//
// // CreateEmailTemplateInput represents input for creating an email template
// type CreateEmailTemplateInput struct {
// 	Body email.CreateTemplateInput
// }
//
// type CreateEmailTemplateOutput = model.Output[*ent.EmailTemplate]
//
// // UpdateEmailTemplateInput represents input for updating an email template
// type UpdateEmailTemplateInput struct {
// 	ID   string `path:"id" doc:"Template ID"`
// 	Body email.UpdateTemplateInput
// }
//
// type UpdateEmailTemplateOutput = model.Output[*ent.EmailTemplate]
//
// // DeleteEmailTemplateInput represents input for deleting an email template
// type DeleteEmailTemplateInput struct {
// 	ID string `path:"id" doc:"Template ID"`
// }
//
// // Handler implementations
//
// func (c *emailController) listEmailTemplatesHandler(ctx context.Context, input *email.ListTemplatesParams) (*ListEmailTemplatesOutput, error) {
// 	result, err := c.di.EmailService().ListTemplates(ctx, *input)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &ListEmailTemplatesOutput{
// 		Body: *result,
// 	}, nil
// }
//
// func (c *emailController) getEmailTemplateHandler(ctx context.Context, input *GetEmailTemplateInput) (*GetEmailTemplateOutput, error) {
// 	template, err := c.di.EmailService().GetTemplate(ctx, input.TemplateType, input.OrgID, "en")
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &GetEmailTemplateOutput{
// 		Body: template,
// 	}, nil
// }
//
// func (c *emailController) createEmailTemplateHandler(ctx context.Context, input *CreateEmailTemplateInput) (*CreateEmailTemplateOutput, error) {
// 	template, err := c.di.EmailService().CreateTemplate(ctx, input.Body)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &CreateEmailTemplateOutput{
// 		Body: template,
// 	}, nil
// }
//
// func (c *emailController) updateEmailTemplateHandler(ctx context.Context, input *UpdateEmailTemplateInput) (*UpdateEmailTemplateOutput, error) {
// 	// Convert string ID to xid.ID
// 	id, err := xid.FromString(input.ID)
// 	if err != nil {
// 		return nil, errors.New(errors.CodeInvalidInput, "invalid template ID")
// 	}
//
// 	template, err := c.di.EmailService().UpdateTemplate(ctx, id, input.Body)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &UpdateEmailTemplateOutput{
// 		Body: template,
// 	}, nil
// }
//
// func (c *emailController) deleteEmailTemplateHandler(ctx context.Context, input *DeleteEmailTemplateInput) (*model.EmptyOutput, error) {
// 	// Convert string ID to xid.ID
// 	id, err := xid.FromString(input.ID)
// 	if err != nil {
// 		return nil, errors.New(errors.CodeInvalidInput, "invalid template ID")
// 	}
//
// 	err = c.di.EmailService().DeleteTemplate(ctx, id)
// 	return nil, err
// }
