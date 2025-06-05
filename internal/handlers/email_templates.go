package handlers

import (
	"net/http"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/email"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// EmailHandler handles Single Sign-On operations
type EmailHandler struct {
	emailService email.Service
	config       *config.Config
	logger       logging.Logger
}

// NewEmailHandler creates a new RBAC handler
func NewEmailHandler(
	emailService email.Service,
	config *config.Config,
	logger logging.Logger,
) *EmailHandler {
	return &EmailHandler{
		emailService: emailService,
		config:       config,
		logger:       logger,
	}
}

// ListTemplates handles the HTTP request to list email templates with pagination and filtering options.
func (h *EmailHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	params := email.ListTemplatesInput{
		Offset:         0,
		Limit:          0,
		Type:           "",
		OrganizationID: "",
		Locale:         "",
	}

	// Get providers
	templates, totalCount, err := h.emailService.ListTemplates(r.Context(), params)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return providers
	utils.RespondPagedJSON(w, http.StatusOK, utils.PagedResponse{
		Items: templates,
		PageInfo: utils.PageInfo{
			TotalCount: totalCount,
		},
	})
}

// GetTemplate retrieves email templates based on input parameters and sends a paginated JSON response or error if failed.
func (h *EmailHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	id := utils.GetPathVar(r, "id")
	if id == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "template id is required"))
		return
	}

	organizationID := utils.GetQueryParam(r, "organizationId")
	if organizationID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "organizationID is required"))
		return
	}

	templateType := utils.GetQueryParam(r, "templateType")
	if templateType == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "templateType is required"))
		return
	}

	// Get providers
	template, err := h.emailService.GetTemplate(r.Context(), id, templateType, organizationID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return providers
	utils.RespondJSON(w, http.StatusOK, template)
}

// CreateTemplate handles the creation of an email template by decoding input, invoking the service, and responding with JSON.
func (h *EmailHandler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input email.CreateTemplateInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	template, err := h.emailService.CreateTemplate(r.Context(), input)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondJSON(w, http.StatusOK, template)
}

// DeleteTemplate handles the HTTP request to delete an email template by decoding input, invoking the service, and responding with JSON.
func (h *EmailHandler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	id := utils.GetPathVar(r, "id")
	if id == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "template id is required"))
		return
	}

	err := h.emailService.DeleteTemplate(r.Context(), id)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondJSON(w, http.StatusOK, nil)
}

// UpdateTemplate handles updating an email template by ID, parses the input, interacts with the service, and responds with JSON.
func (h *EmailHandler) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	id := utils.GetPathVar(r, "id")
	if id == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "template id is required"))
		return
	}

	// Parse input
	var input email.UpdateTemplateInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	template, err := h.emailService.UpdateTemplate(r.Context(), id, input)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	utils.RespondJSON(w, http.StatusOK, template)
}

// Static handler functions for direct router registration

// EmailListTemplates handles HTTP requests to list available email templates based on user permissions.
func EmailListTemplates(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Email.ListTemplates(w, r)
}

// EmailGetTemplate handles HTTP requests to retrieve an email template by forwarding the request to the Email handler.
func EmailGetTemplate(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Email.GetTemplate(w, r)
}

// EmailCreateTemplate handles the HTTP request to create a new email template via the EmailHandler's CreateTemplate method.
func EmailCreateTemplate(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Email.CreateTemplate(w, r)
}

// EmailDeleteTemplate is an HTTP handler that invokes the Email service to delete an email template using its ID.
func EmailDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Email.DeleteTemplate(w, r)
}

// EmailUpdateTemplate is an HTTP handler that updates an email template by delegating the request to the Email handler.
func EmailUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Email.UpdateTemplate(w, r)
}
