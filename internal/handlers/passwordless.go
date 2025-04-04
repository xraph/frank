package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/passwordless"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
	"github.com/juicycleff/frank/user"
)

// PasswordlessHandler handles passwordless authentication operations
type PasswordlessHandler struct {
	passwordlessService passwordless.Service
	userService         user.Service
	config              *config.Config
	logger              logging.Logger
}

// NewPasswordlessHandler creates a new passwordless handler
func NewPasswordlessHandler(
	passwordlessService passwordless.Service,
	userService user.Service,
	config *config.Config,
	logger logging.Logger,
) *PasswordlessHandler {
	return &PasswordlessHandler{
		passwordlessService: passwordlessService,
		userService:         userService,
		config:              config,
		logger:              logger,
	}
}

// PasswordlessEmailRequest represents the input for passwordless email login
type PasswordlessEmailRequest struct {
	Email       string `json:"email" validate:"required,email"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

// PasswordlessSMSRequest represents the input for passwordless SMS login
type PasswordlessSMSRequest struct {
	PhoneNumber string `json:"phone_number" validate:"required"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

// PasswordlessVerifyRequest represents the input for verifying a passwordless login
type PasswordlessVerifyRequest struct {
	Token       string `json:"token,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Code        string `json:"code,omitempty"`
	AuthType    string `json:"auth_type" validate:"required"`
}

// PasswordlessEmail handles passwordless email login
func (h *PasswordlessHandler) PasswordlessEmail(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input PasswordlessEmailRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Create login request
	loginReq := passwordless.LoginRequest{
		Email:       input.Email,
		RedirectURL: input.RedirectURL,
		AuthType:    passwordless.AuthTypeEmail,
		IPAddress:   utils.GetRealIP(r),
		UserAgent:   r.UserAgent(),
	}

	// Send login link/code
	verificationID, err := h.passwordlessService.Login(r.Context(), loginReq)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return success
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message":         "Passwordless login email sent",
		"verification_id": verificationID,
	})
}

// PasswordlessSMS handles passwordless SMS login
func (h *PasswordlessHandler) PasswordlessSMS(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input PasswordlessSMSRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Create login request
	loginReq := passwordless.LoginRequest{
		PhoneNumber: input.PhoneNumber,
		RedirectURL: input.RedirectURL,
		AuthType:    passwordless.AuthTypeSMS,
		IPAddress:   utils.GetRealIP(r),
		UserAgent:   r.UserAgent(),
	}

	// Send verification code
	verificationID, err := h.passwordlessService.Login(r.Context(), loginReq)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return success
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message":         "Passwordless login SMS sent",
		"verification_id": verificationID,
	})
}

// PasswordlessVerify handles verifying a passwordless login
func (h *PasswordlessHandler) PasswordlessVerify(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input PasswordlessVerifyRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Validate input based on auth type
	switch input.AuthType {
	case string(passwordless.AuthTypeEmail):
		if input.Token == "" {
			utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "token is required for email verification"))
			return
		}
	case string(passwordless.AuthTypeSMS):
		if input.PhoneNumber == "" || input.Code == "" {
			utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "phone number and code are required for SMS verification"))
			return
		}
	default:
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "invalid authentication type"))
		return
	}

	// Create verify request
	verifyReq := passwordless.VerifyRequest{
		Token:       input.Token,
		PhoneNumber: input.PhoneNumber,
		Code:        input.Code,
		AuthType:    passwordless.AuthType(input.AuthType),
		IPAddress:   utils.GetRealIP(r),
	}

	// Verify login
	userID, userEmail, err := h.passwordlessService.VerifyLogin(r.Context(), verifyReq)
	if err != nil {
		utils.RespondError(w, err)
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

	// Get user entity
	userEntity, err := h.userService.Get(r.Context(), userID)
	if err != nil {
		// Log error but continue
		h.logger.Error("Failed to get user after passwordless authentication",
			logging.String("user_id", userID),
			logging.Error(err),
		)
	}

	// Return success with user info
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"user_id":       userID,
		"email":         userEmail,
		"user":          userEntity,
	})
}

// GetPasswordlessMethods retrieves available passwordless methods
func (h *PasswordlessHandler) GetPasswordlessMethods(w http.ResponseWriter, r *http.Request) {
	// Check if passwordless is configured
	if !h.passwordlessService.IsConfigured() {
		utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
			"methods": []string{},
		})
		return
	}

	// Get supported methods
	methods := h.passwordlessService.GetSupportedMethods()

	// Return methods
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"enabled": true,
		"methods": methods,
	})
}

// GenerateMagicLinkRequest represents the input for generating a magic link
type GenerateMagicLinkRequest struct {
	Email       string `json:"email" validate:"required,email"`
	UserID      string `json:"user_id" validate:"required"`
	RedirectURL string `json:"redirect_url" validate:"required"`
	ExpiresIn   int    `json:"expires_in,omitempty"` // In seconds
}

// GenerateMagicLink handles generating a magic link for a user
func (h *PasswordlessHandler) GenerateMagicLink(w http.ResponseWriter, r *http.Request) {
	// Parse input
	var input GenerateMagicLinkRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Set default expiry if not provided
	expiresIn := time.Hour * 24 // 24 hours
	if input.ExpiresIn > 0 {
		expiresIn = time.Duration(input.ExpiresIn) * time.Second
	}

	// Generate magic link
	link, err := h.passwordlessService.GenerateMagicLink(
		r.Context(),
		input.UserID,
		input.Email,
		input.RedirectURL,
		expiresIn,
	)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return magic link
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"magic_link": link,
		"expires_in": int(expiresIn.Seconds()),
	})
}

// SetupRoutes sets up the passwordless routes
func (h *PasswordlessHandler) SetupRoutes(router chi.Router) {
	router.HandleFunc("/api/v1/auth/passwordless/email", h.PasswordlessEmail)
	router.HandleFunc("/api/v1/auth/passwordless/sms", h.PasswordlessSMS)
	router.HandleFunc("/api/v1/auth/passwordless/verify", h.PasswordlessVerify)
	router.HandleFunc("/api/v1/auth/passwordless/methods", h.GetPasswordlessMethods)
	router.HandleFunc("/api/v1/auth/passwordless/magic-link", h.GenerateMagicLink)
}

// Static handler functions for direct router registration

// PasswordlessEmail handles passwordless email login API endpoint
func PasswordlessEmail(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passwordless.PasswordlessEmail(w, r)
}

// PasswordlessSMS handles passwordless SMS login API endpoint
func PasswordlessSMS(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passwordless.PasswordlessSMS(w, r)
}

// PasswordlessVerify handles passwordless verification API endpoint
func PasswordlessVerify(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passwordless.PasswordlessVerify(w, r)
}

// GetPasswordlessMethods handles getting passwordless methods API endpoint
func GetPasswordlessMethods(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passwordless.GetPasswordlessMethods(w, r)
}

// GenerateMagicLink handles generating a magic link API endpoint
func GenerateMagicLink(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Passwordless.GenerateMagicLink(w, r)
}
