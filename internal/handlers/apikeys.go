package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/apikeys"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/swaggergen"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// APIKeyHandler handles API key operations
type APIKeyHandler struct {
	apiKeyService apikeys.Service
	config        *config.Config
	logger        logging.Logger
}

// NewAPIKeyHandler creates a new API key handler
func NewAPIKeyHandler(
	apiKeyService apikeys.Service,
	config *config.Config,
	logger logging.Logger,
) *APIKeyHandler {
	return &APIKeyHandler{
		apiKeyService: apiKeyService,
		config:        config,
		logger:        logger,
	}
}

// CreateAPIKeyRequest represents the input for creating an API key
type CreateAPIKeyRequest struct {
	Name        string                 `json:"name" validate:"required"`
	Type        string                 `json:"type,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Scopes      []string               `json:"scopes,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	ExpiresIn   *int                   `json:"expires_in,omitempty"` // In seconds
}

// UpdateAPIKeyRequest represents the input for updating an API key
type UpdateAPIKeyRequest struct {
	Name        *string                `json:"name,omitempty"`
	Active      *bool                  `json:"active,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Scopes      []string               `json:"scopes,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
}

// ListAPIKeys handles listing API keys with pagination
func (h *APIKeyHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	// Get user and organization IDs from context
	userID, _ := middleware.GetUserIDReq(r)
	orgID, _ := middleware.GetOrganizationID(r)

	if userID == "" && orgID == "" {
		utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "either user ID or organization ID is required"))
		return
	}

	// Parse query parameters
	offset := utils.ParseQueryInt(r, "offset", 0)
	limit := utils.ParseQueryInt(r, "limit", 20)
	keyType := r.URL.Query().Get("type")

	// Create list params
	params := apikeys.ListParams{
		Offset:         offset,
		Limit:          limit,
		UserID:         userID,
		OrganizationID: orgID,
		Type:           keyType,
	}

	// List API keys
	apiKeys, total, err := h.apiKeyService.List(r.Context(), params)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return response with pagination
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"data":  apiKeys,
		"total": total,
		"pagination": map[string]interface{}{
			"offset": offset,
			"limit":  limit,
			"total":  total,
		},
	})
}

// CreateAPIKey handles creating a new API key
func (h *APIKeyHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	// Get user and organization IDs from context
	userID, _ := middleware.GetUserIDReq(r)
	orgID, _ := middleware.GetOrganizationID(r)

	if userID == "" && orgID == "" {
		utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "either user ID or organization ID is required"))
		return
	}

	// Parse input
	var input CreateAPIKeyRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Set default type if not provided
	if input.Type == "" {
		input.Type = "client"
	}

	// Convert expires_in to duration if provided
	var expiresIn *time.Duration
	if input.ExpiresIn != nil {
		duration := time.Duration(*input.ExpiresIn) * time.Second
		expiresIn = &duration
	}

	// Map to service input
	createInput := apikeys.CreateAPIKeyRequest{
		Name:           input.Name,
		Type:           input.Type,
		UserID:         userID,
		OrganizationID: orgID,
		Permissions:    input.Permissions,
		Scopes:         input.Scopes,
		Metadata:       input.Metadata,
		ExpiresIn:      expiresIn,
	}

	// Create API key
	apiKeyWithKey, err := h.apiKeyService.Create(r.Context(), createInput)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return created API key with plaintext key
	utils.RespondJSON(w, http.StatusCreated, apiKeyWithKey)
}

// GetAPIKey handles retrieving an API key
func (h *APIKeyHandler) GetAPIKey(w http.ResponseWriter, r *http.Request) {
	// Get API key ID from path
	apiKeyID := utils.GetPathVar(r, "id")
	if apiKeyID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "API key ID is required"))
		return
	}

	// Get API key
	apiKey, err := h.apiKeyService.Get(r.Context(), apiKeyID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return API key
	utils.RespondJSON(w, http.StatusOK, apiKey)
}

// UpdateAPIKey handles updating an API key
func (h *APIKeyHandler) UpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	// Get API key ID from path
	apiKeyID := utils.GetPathVar(r, "id")
	if apiKeyID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "API key ID is required"))
		return
	}

	// Parse input
	var input UpdateAPIKeyRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Map to service input
	updateInput := apikeys.UpdateAPIKeyRequest{
		Name:        input.Name,
		Active:      input.Active,
		Permissions: input.Permissions,
		Scopes:      input.Scopes,
		Metadata:    input.Metadata,
		ExpiresAt:   input.ExpiresAt,
	}

	// Update API key
	updatedAPIKey, err := h.apiKeyService.Update(r.Context(), apiKeyID, updateInput)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return updated API key
	utils.RespondJSON(w, http.StatusOK, updatedAPIKey)
}

// DeleteAPIKey handles deleting an API key
func (h *APIKeyHandler) DeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	// Get API key ID from path
	apiKeyID := utils.GetPathVar(r, "id")
	if apiKeyID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "API key ID is required"))
		return
	}

	// Delete API key
	err := h.apiKeyService.Delete(r.Context(), apiKeyID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return success
	utils.RespondJSON(w, http.StatusNoContent, nil)
}

// ValidateAPIKey handles API key validation
func (h *APIKeyHandler) ValidateAPIKey(w http.ResponseWriter, r *http.Request) {
	// Get API key from header
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		// Try to get from query parameter
		apiKey = r.URL.Query().Get("api_key")
		if apiKey == "" {
			utils.RespondError(w, errors.New(errors.CodeInvalidAPIKey, "API key is required"))
			return
		}
	}

	// Validate API key
	validatedKey, err := h.apiKeyService.Validate(r.Context(), apiKey)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return validated API key
	utils.RespondJSON(w, http.StatusOK, validatedKey)
}

// SetupRoutes sets up the API key routes
func (h *APIKeyHandler) SetupRoutes(router chi.Router, gen *swaggergen.SwaggerGen) {
	routes := []routeConfig{
		{
			h: h.ListAPIKeys,
			methods: []string{
				"GET",
			},
			pattern: "/api/v1/api-keys",
			desc:    "List API Keys",
		},
		{
			h: h.CreateAPIKey,
			methods: []string{
				"POST",
			},
			pattern: "/api/v1/api-keys",
			desc:    "Create API Key",
		},
		{
			h: h.GetAPIKey,
			methods: []string{
				"GET",
			},
			pattern: "/api/v1/api-keys/{id}",
			desc:    "Get API key",
		},
		{
			h: h.UpdateAPIKey,
			methods: []string{
				"PATCH",
			},
			pattern: "/api/v1/api-keys/{id}",
			desc:    "Update API key",
		},
		{
			h: h.DeleteAPIKey,
			methods: []string{
				"DELETE",
			},
			pattern: "/api/v1/api-keys/{id}",
			desc:    "Delete API key",
		},
		{
			h: h.ValidateAPIKey,
			methods: []string{
				"GET",
			},
			pattern: "/api/v1/api-keys/validate",
			desc:    "Validate API key",
		},
	}
	schemas := []any{
		apikeys.CreateAPIKeyRequest{},
		apikeys.UpdateAPIKeyRequest{},
		apikeys.APIKeyWithKeyResponse{},
	}

	if gen != nil {
		for _, schema := range schemas {
			registerAPISchema(schema, gen)
		}
	}

	for _, route := range routes {
		for _, method := range route.methods {
			router.Method(method, route.pattern, route.h)
			if gen != nil {
				_ = gen.AddPathDescription(method, route.pattern, route.desc)
			}
		}
	}
}

// Static handler functions for direct router registration

// ListAPIKeys handles listing API keys API endpoint
func ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).APIKey.ListAPIKeys(w, r)
}

// CreateAPIKey handles creating an API key API endpoint
func CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).APIKey.CreateAPIKey(w, r)
}

// GetAPIKey handles retrieving an API key API endpoint
func GetAPIKey(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).APIKey.GetAPIKey(w, r)
}

// UpdateAPIKey handles updating an API key API endpoint
func UpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).APIKey.UpdateAPIKey(w, r)
}

// DeleteAPIKey handles deleting an API key API endpoint
func DeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).APIKey.DeleteAPIKey(w, r)
}

// ValidateAPIKey handles validating an API key API endpoint
func ValidateAPIKey(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).APIKey.ValidateAPIKey(w, r)
}
