package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/webhook"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// WebhookHandler handles webhook operations
type WebhookHandler struct {
	webhookService webhook.Service
	config         *config.Config
	logger         logging.Logger
}

// NewWebhookHandler creates a new webhook handler
func NewWebhookHandler(
	webhookService webhook.Service,
	config *config.Config,
	logger logging.Logger,
) *WebhookHandler {
	return &WebhookHandler{
		webhookService: webhookService,
		config:         config,
		logger:         logger,
	}
}

// CreateWebhookRequest represents the input for creating a webhook
type CreateWebhookRequest struct {
	Name       string                 `json:"name" validate:"required"`
	URL        string                 `json:"url" validate:"required,url"`
	EventTypes []string               `json:"event_types" validate:"required"`
	RetryCount *int                   `json:"retry_count,omitempty"`
	TimeoutMs  *int                   `json:"timeout_ms,omitempty"`
	Format     string                 `json:"format,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateWebhookRequest represents the input for updating a webhook
type UpdateWebhookRequest struct {
	Name       *string                `json:"name,omitempty"`
	URL        *string                `json:"url,omitempty"`
	Active     *bool                  `json:"active,omitempty"`
	EventTypes []string               `json:"event_types,omitempty"`
	RetryCount *int                   `json:"retry_count,omitempty"`
	TimeoutMs  *int                   `json:"timeout_ms,omitempty"`
	Format     *string                `json:"format,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ListWebhooks handles listing webhooks with pagination
func (h *WebhookHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	// Get organization ID from context
	orgID, ok := middleware.GetOrganizationIDReq(r)
	if !ok || orgID == "" {
		utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "organization ID is required"))
		return
	}

	// Parse query parameters
	offset := utils.ParseQueryInt(r, "offset", 0)
	limit := utils.ParseQueryInt(r, "limit", 20)
	eventTypes := r.URL.Query()["event_types"]

	// Create list params
	params := webhook.ListParams{
		Offset:         offset,
		Limit:          limit,
		OrganizationID: orgID,
		EventTypes:     eventTypes,
	}

	// List webhooks
	webhooks, total, err := h.webhookService.List(r.Context(), params)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return response with pagination
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"data":  webhooks,
		"total": total,
		"pagination": map[string]interface{}{
			"offset": offset,
			"limit":  limit,
			"total":  total,
		},
	})
}

// CreateWebhook handles creating a new webhook
func (h *WebhookHandler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	// Get organization ID from context
	orgID, ok := middleware.GetOrganizationIDReq(r)
	if !ok || orgID == "" {
		utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "organization ID is required"))
		return
	}

	// Parse input
	var input CreateWebhookRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Validate URL format
	if !utils.IsValidURL(input.URL) {
		utils.RespondError(w, errors.New(errors.CodeInvalidWebhookURL, "invalid webhook URL"))
		return
	}

	// Map to service input
	createInput := webhook.CreateWebhookInput{
		Name:           input.Name,
		URL:            input.URL,
		OrganizationID: orgID,
		EventTypes:     input.EventTypes,
		RetryCount:     input.RetryCount,
		TimeoutMs:      input.TimeoutMs,
		Format:         input.Format,
		Metadata:       input.Metadata,
	}

	// Create webhook
	newWebhook, err := h.webhookService.Create(r.Context(), createInput)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return created webhook
	utils.RespondJSON(w, http.StatusCreated, newWebhook)
}

// GetWebhook handles retrieving a webhook
func (h *WebhookHandler) GetWebhook(w http.ResponseWriter, r *http.Request) {
	// Get webhook ID from path
	webhookID := utils.GetPathVar(r, "id")
	if webhookID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "webhook ID is required"))
		return
	}

	// Get webhook
	webhook, err := h.webhookService.Get(r.Context(), webhookID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return webhook
	utils.RespondJSON(w, http.StatusOK, webhook)
}

// UpdateWebhook handles updating a webhook
func (h *WebhookHandler) UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	// Get webhook ID from path
	webhookID := utils.GetPathVar(r, "id")
	if webhookID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "webhook ID is required"))
		return
	}

	// Parse input
	var input UpdateWebhookRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Validate URL format if provided
	if input.URL != nil && !utils.IsValidURL(*input.URL) {
		utils.RespondError(w, errors.New(errors.CodeInvalidWebhookURL, "invalid webhook URL"))
		return
	}

	// Map to service input
	updateInput := webhook.UpdateWebhookInput{
		Name:       input.Name,
		URL:        input.URL,
		Active:     input.Active,
		EventTypes: input.EventTypes,
		RetryCount: input.RetryCount,
		TimeoutMs:  input.TimeoutMs,
		Format:     input.Format,
		Metadata:   input.Metadata,
	}

	// Update webhook
	updatedWebhook, err := h.webhookService.Update(r.Context(), webhookID, updateInput)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return updated webhook
	utils.RespondJSON(w, http.StatusOK, updatedWebhook)
}

// DeleteWebhook handles deleting a webhook
func (h *WebhookHandler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	// Get webhook ID from path
	webhookID := utils.GetPathVar(r, "id")
	if webhookID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "webhook ID is required"))
		return
	}

	// Delete webhook
	err := h.webhookService.Delete(r.Context(), webhookID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return success
	utils.RespondJSON(w, http.StatusNoContent, nil)
}

// ListWebhookEvents handles listing webhook events
func (h *WebhookHandler) ListWebhookEvents(w http.ResponseWriter, r *http.Request) {
	// Get webhook ID from path
	webhookID := utils.GetPathVar(r, "id")
	if webhookID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "webhook ID is required"))
		return
	}

	// Parse query parameters
	offset := utils.ParseQueryInt(r, "offset", 0)
	limit := utils.ParseQueryInt(r, "limit", 20)
	eventType := r.URL.Query().Get("event_type")

	deliveredStr := r.URL.Query().Get("delivered")
	var delivered *bool
	if deliveredStr != "" {
		deliveredBool := deliveredStr == "true"
		delivered = &deliveredBool
	}

	// Create list params
	params := webhook.EventListParams{
		Offset:    offset,
		Limit:     limit,
		EventType: eventType,
		Delivered: delivered,
	}

	// List webhook events
	events, total, err := h.webhookService.GetEvents(r.Context(), webhookID, params)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return response with pagination
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"data":  events,
		"total": total,
		"pagination": map[string]interface{}{
			"offset": offset,
			"limit":  limit,
			"total":  total,
		},
	})
}

// ReplayWebhookEvent handles replaying a webhook event
func (h *WebhookHandler) ReplayWebhookEvent(w http.ResponseWriter, r *http.Request) {
	// Get webhook ID and event ID from path
	webhookID := utils.GetPathVar(r, "id")
	if webhookID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "webhook ID is required"))
		return
	}

	eventID := utils.GetPathVar(r, "eventId")
	if eventID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "event ID is required"))
		return
	}

	// Replay event
	event, err := h.webhookService.ReplayEvent(r.Context(), eventID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return replayed event
	utils.RespondJSON(w, http.StatusOK, event)
}

// TriggerEventRequest represents the input for triggering a webhook event
type TriggerEventRequest struct {
	EventType string                 `json:"event_type" validate:"required"`
	Payload   map[string]interface{} `json:"payload" validate:"required"`
	Headers   map[string]string      `json:"headers,omitempty"`
}

// TriggerWebhookEvent handles manually triggering a webhook event
func (h *WebhookHandler) TriggerWebhookEvent(w http.ResponseWriter, r *http.Request) {
	// Get organization ID from context
	orgID, ok := middleware.GetOrganizationIDReq(r)
	if !ok || orgID == "" {
		utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "organization ID is required"))
		return
	}

	// Parse input
	var input TriggerEventRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Map to service input
	triggerInput := webhook.TriggerEventInput{
		EventType:      input.EventType,
		OrganizationID: orgID,
		Payload:        input.Payload,
		Headers:        input.Headers,
	}

	// Trigger event
	event, err := h.webhookService.TriggerEvent(r.Context(), triggerInput)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return triggered event
	utils.RespondJSON(w, http.StatusOK, event)
}

// ReceiveWebhook handles incoming webhook requests
func (h *WebhookHandler) ReceiveWebhook(w http.ResponseWriter, r *http.Request) {
	// Get webhook ID from path
	webhookID := utils.GetPathVar(r, "id")
	if webhookID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "webhook ID is required"))
		return
	}

	// Read request body
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInvalidInput, err, "failed to read request body"))
		return
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	// Validate signature if provided
	signature := r.Header.Get("X-Signature")
	if signature != "" {
		webhook, err := h.webhookService.Get(r.Context(), webhookID)
		if err != nil {
			utils.RespondError(w, err)
			return
		}

		// Calculate expected signature
		mac := hmac.New(sha256.New, []byte(webhook.Secret))
		mac.Write(bodyBytes)
		expectedSignature := hex.EncodeToString(mac.Sum(nil))

		// Compare signatures
		if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
			utils.RespondError(w, errors.New(errors.CodeInvalidInput, "invalid webhook signature"))
			return
		}
	}

	// Process webhook (implementation depends on requirements)
	// For now, just return success
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Webhook received successfully",
	})
}

// SetupRoutes sets up the webhook routes
func (h *WebhookHandler) SetupRoutes(router chi.Router) {
	router.HandleFunc("/api/v1/webhooks", h.ListWebhooks)
	router.HandleFunc("/api/v1/webhooks", h.CreateWebhook)
	router.HandleFunc("/api/v1/webhooks/{id}", h.GetWebhook)
	router.HandleFunc("/api/v1/webhooks/{id}", h.UpdateWebhook)
	router.HandleFunc("/api/v1/webhooks/{id}", h.DeleteWebhook)
	router.HandleFunc("/api/v1/webhooks/{id}/events", h.ListWebhookEvents)
	router.HandleFunc("/api/v1/webhooks/{id}/events/{eventId}/replay", h.ReplayWebhookEvent)
	router.HandleFunc("/api/v1/webhooks/trigger", h.TriggerWebhookEvent)
	router.HandleFunc("/webhooks/{id}", h.ReceiveWebhook)
}

// RegisterOrganizationRoutes registers organization-specific webhook routes
func (h *WebhookHandler) RegisterOrganizationRoutes(router chi.Router) {
	router.Route("/api/v1/webhooks", func(router chi.Router) {
		router.Post("/", h.CreateWebhook)
		router.Get("/", h.ListWebhooks)
		router.Post("/trigger", h.TriggerWebhookEvent)

		router.Route("/{id}", func(router chi.Router) {
			router.Get("/", h.GetWebhook)
			router.Put("/", h.UpdateWebhook)
			router.Delete("/", h.DeleteWebhook)

			router.Get("/events", h.ListWebhookEvents)
			router.Post("/events/{eventId}/replay", h.ReplayWebhookEvent)
		})
	})
}

// Static handler functions for direct router registration

// ListWebhooks handles listing webhooks API endpoint
func ListWebhooks(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Webhook.ListWebhooks(w, r)
}

// CreateWebhook handles creating a webhook API endpoint
func CreateWebhook(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Webhook.CreateWebhook(w, r)
}

// GetWebhook handles retrieving a webhook API endpoint
func GetWebhook(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Webhook.GetWebhook(w, r)
}

// UpdateWebhook handles updating a webhook API endpoint
func UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Webhook.UpdateWebhook(w, r)
}

// DeleteWebhook handles deleting a webhook API endpoint
func DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Webhook.DeleteWebhook(w, r)
}

// ListWebhookEvents handles listing webhook events API endpoint
func ListWebhookEvents(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Webhook.ListWebhookEvents(w, r)
}

// ReplayWebhookEvent handles replaying a webhook event API endpoint
func ReplayWebhookEvent(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Webhook.ReplayWebhookEvent(w, r)
}

// TriggerWebhookEvent handles triggering a webhook event API endpoint
func TriggerWebhookEvent(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Webhook.TriggerWebhookEvent(w, r)
}

// ReceiveWebhook handles receiving a webhook API endpoint
func ReceiveWebhook(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Webhook.ReceiveWebhook(w, r)
}
