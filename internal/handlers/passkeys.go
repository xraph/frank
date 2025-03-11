package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/passkeys"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// PasskeyHandler handles passkey operations
type PasskeyHandler struct {
	passkeyService *passkeys.Service
	config         *config.Config
	logger         logging.Logger
}

// NewPasskeyHandler creates a new passkey handler
func NewPasskeyHandler(
	passkeyService *passkeys.Service,
	config *config.Config,
	logger logging.Logger,
) *PasskeyHandler {
	return &PasskeyHandler{
		passkeyService: passkeyService,
		config:         config,
		logger:         logger,
	}
}

// PasskeyRegisterBeginRequest represents the input for beginning passkey registration
type PasskeyRegisterBeginRequest struct {
	DeviceName string `json:"device_name,omitempty"`
	DeviceType string `json:"device_type,omitempty"`
}

// PasskeyRegisterCompleteRequest represents the input for completing passkey registration
type PasskeyRegisterCompleteRequest struct {
	SessionID  string          `json:"session_id" validate:"required"`
	Response   json.RawMessage `json:"response" validate:"required"`
	DeviceName string          `json:"device_name,omitempty"`
	DeviceType string          `json:"device_type,omitempty"`
}

// PasskeyLoginBeginRequest represents the input for beginning passkey login
type PasskeyLoginBeginRequest struct {
}

// PasskeyLoginCompleteRequest represents the input for completing passkey login
type PasskeyLoginCompleteRequest struct {
	SessionID string          `json:"session_id" validate:"required"`
	Response  json.RawMessage `json:"response" validate:"required"`
}

// PasskeyRegisterBegin handles beginning passkey registration
func (h *PasskeyHandler) PasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Parse input
	var input PasskeyRegisterBeginRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Begin registration
	options := passkeys.RegistrationOptions{
		UserID:     userID,
		DeviceName: input.DeviceName,
		DeviceType: input.DeviceType,
	}

	credentialOptions, err := h.passkeyService.BeginRegistration(r.Context(), options)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodePasskeyRegistration, err, "failed to begin passkey registration"))
		return
	}

	// Return options to the client
	utils.RespondJSON(w, http.StatusOK, credentialOptions)
}

// PasskeyRegisterComplete handles completing passkey registration
func (h *PasskeyHandler) PasskeyRegisterComplete(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Parse input
	var input PasskeyRegisterCompleteRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Complete registration
	options := passkeys.RegistrationOptions{
		UserID:     userID,
		DeviceName: input.DeviceName,
		DeviceType: input.DeviceType,
	}

	registeredPasskey, err := h.passkeyService.FinishRegistration(r.Context(), input.SessionID, r, options)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodePasskeyRegistration, err, "failed to complete passkey registration"))
		return
	}

	// Return registered passkey
	utils.RespondJSON(w, http.StatusOK, registeredPasskey)
}

// PasskeyLoginBegin handles beginning passkey login
func (h *PasskeyHandler) PasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input PasskeyLoginBeginRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Get user ID from request if available
	userID, _ := middleware.GetUserID(r)

	// Begin authentication
	options := passkeys.AuthenticationOptions{
		UserID: userID,
	}

	assertionOptions, err := h.passkeyService.BeginAuthentication(r.Context(), options)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodePasskeyAuthentication, err, "failed to begin passkey authentication"))
		return
	}

	// Return options to the client
	utils.RespondJSON(w, http.StatusOK, assertionOptions)
}

// PasskeyLoginComplete handles completing passkey login
func (h *PasskeyHandler) PasskeyLoginComplete(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input PasskeyLoginCompleteRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Complete authentication
	userID, err := h.passkeyService.FinishAuthentication(r.Context(), input.SessionID, r)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodePasskeyAuthentication, err, "failed to complete passkey authentication"))
		return
	}

	// Create session
	session, err := utils.GetSession(r, h.config)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to get session"))
		return
	}

	// Set session values
	session.Values["user_id"] = userID
	session.Values["authenticated"] = true
	if err := session.Save(r, w); err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to save session"))
		return
	}

	// Return success with user ID
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"user_id":       userID,
	})
}

// GetUserPasskeys handles retrieving a user's passkeys
func (h *PasskeyHandler) GetUserPasskeys(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Get passkeys
	passkeys, err := h.passkeyService.GetUserPasskeys(r.Context(), userID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return passkeys
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"passkeys": passkeys,
	})
}

// UpdatePasskey handles updating a passkey
func (h *PasskeyHandler) UpdatePasskey(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Get passkey ID from path
	passkeyID := utils.GetPathVar(r, "id")
	if passkeyID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "passkey ID is required"))
		return
	}

	// Parse input
	var input struct {
		Name string `json:"name" validate:"required"`
	}
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Update passkey
	err := h.passkeyService.UpdatePasskey(r.Context(), passkeyID, userID, input.Name)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return success
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Passkey updated successfully",
	})
}

// DeletePasskey handles deleting a passkey
func (h *PasskeyHandler) DeletePasskey(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Get passkey ID from path
	passkeyID := utils.GetPathVar(r, "id")
	if passkeyID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "passkey ID is required"))
		return
	}

	// Delete passkey
	err := h.passkeyService.DeletePasskey(r.Context(), passkeyID, userID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return success
	utils.RespondJSON(w, http.StatusNoContent, nil)
}

// SetupRoutes sets up the passkey routes
func (h *PasskeyHandler) SetupRoutes(router *http.ServeMux) {
	router.HandleFunc("/api/v1/auth/passkeys/register/begin", h.PasskeyRegisterBegin)
	router.HandleFunc("/api/v1/auth/passkeys/register/complete", h.PasskeyRegisterComplete)
	router.HandleFunc("/api/v1/auth/passkeys/login/begin", h.PasskeyLoginBegin)
	router.HandleFunc("/api/v1/auth/passkeys/login/complete", h.PasskeyLoginComplete)
	router.HandleFunc("/api/v1/auth/passkeys", h.GetUserPasskeys)
	router.HandleFunc("/api/v1/auth/passkeys/{id}", h.UpdatePasskey)
	router.HandleFunc("/api/v1/auth/passkeys/{id}", h.DeletePasskey)
}

// Static handler functions for direct router registration

// PasskeyRegisterBegin handles passkey registration begin API endpoint
func PasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passkey.PasskeyRegisterBegin(w, r)
}

// PasskeyRegisterComplete handles passkey registration complete API endpoint
func PasskeyRegisterComplete(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passkey.PasskeyRegisterComplete(w, r)
}

// PasskeyLoginBegin handles passkey login begin API endpoint
func PasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passkey.PasskeyLoginBegin(w, r)
}

// PasskeyLoginComplete handles passkey login complete API endpoint
func PasskeyLoginComplete(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passkey.PasskeyLoginComplete(w, r)
}

// GetUserPasskeys handles getting user passkeys API endpoint
func GetUserPasskeys(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passkey.GetUserPasskeys(w, r)
}

// UpdatePasskey handles updating a passkey API endpoint
func UpdatePasskey(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passkey.UpdatePasskey(w, r)
}

// DeletePasskey handles deleting a passkey API endpoint
func DeletePasskey(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passkey.DeletePasskey(w, r)
}
