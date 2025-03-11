package handlers

import (
	"net/http"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/mfa"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/user"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// MFAHandler handles multi-factor authentication operations
type MFAHandler struct {
	mfaService  *mfa.Service
	userService user.Service
	config      *config.Config
	logger      logging.Logger
}

// NewMFAHandler creates a new MFA handler
func NewMFAHandler(
	mfaService *mfa.Service,
	userService user.Service,
	config *config.Config,
	logger logging.Logger,
) *MFAHandler {
	return &MFAHandler{
		mfaService:  mfaService,
		userService: userService,
		config:      config,
		logger:      logger,
	}
}

// EnableTOTPRequest represents the input for enabling TOTP
type EnableTOTPRequest struct {
	Email string `json:"email,omitempty"`
}

// EnableTOTPResponse represents the response for enabling TOTP
type EnableTOTPResponse struct {
	Secret     string `json:"secret"`
	URI        string `json:"uri"`
	QRCodeData string `json:"qr_code_data"`
}

// VerifyTOTPRequest represents the input for verifying TOTP
type VerifyTOTPRequest struct {
	Code string `json:"code" validate:"required"`
}

// EnableSMSRequest represents the input for enabling SMS-based MFA
type EnableSMSRequest struct {
	PhoneNumber string `json:"phone_number" validate:"required"`
}

// VerifySMSRequest represents the input for verifying SMS code
type VerifySMSRequest struct {
	Code string `json:"code" validate:"required"`
}

// EnableEmailRequest represents the input for enabling email-based MFA
type EnableEmailRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// VerifyEmailRequest represents the input for verifying email code
type VerifyEmailRequest struct {
	Code string `json:"code" validate:"required"`
}

// MFAEnrollRequest represents the input for enrolling in MFA
type MFAEnrollRequest struct {
	Method      string `json:"method" validate:"required"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Email       string `json:"email,omitempty"`
}

// MFAVerifyRequest represents the input for verifying MFA
type MFAVerifyRequest struct {
	Method      string `json:"method" validate:"required"`
	Code        string `json:"code" validate:"required"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

// MFAEnroll handles enrolling in MFA
func (h *MFAHandler) MFAEnroll(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Parse input
	var input MFAEnrollRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Process based on method
	switch input.Method {
	case "totp":
		// Get user email if not provided
		email := input.Email
		if email == "" {
			user, err := h.userService.Get(r.Context(), userID)
			if err != nil {
				utils.RespondError(w, err)
				return
			}
			email = user.Email
		}

		// Enable TOTP
		secret, err := h.mfaService.EnableTOTP(r.Context(), userID, email)
		if err != nil {
			utils.RespondError(w, err)
			return
		}

		// Return TOTP data
		utils.RespondJSON(w, http.StatusOK, &EnableTOTPResponse{
			Secret:     secret.Secret,
			URI:        secret.URL,
			QRCodeData: string(secret.QRCodePNG),
		})

	case "sms":
		// Validate phone number
		if input.PhoneNumber == "" {
			utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "phone number is required for SMS MFA"))
			return
		}

		// Enable SMS MFA
		err := h.mfaService.EnableSMS(r.Context(), userID, input.PhoneNumber)
		if err != nil {
			utils.RespondError(w, err)
			return
		}

		// Return success
		utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"message": "SMS MFA enabled, verification code sent",
		})

	case "email":
		// Validate email
		if input.Email == "" {
			utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "email is required for email MFA"))
			return
		}

		// Enable email MFA
		err := h.mfaService.EnableEmail(r.Context(), userID, input.Email)
		if err != nil {
			utils.RespondError(w, err)
			return
		}

		// Return success
		utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"message": "Email MFA enabled, verification code sent",
		})

	case "backup_codes":
		// Enable backup codes
		codes, err := h.mfaService.EnableBackupCodes(r.Context(), userID)
		if err != nil {
			utils.RespondError(w, err)
			return
		}

		// Return backup codes
		utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"backup_codes": codes,
		})

	default:
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "unsupported MFA method"))
	}
}

// MFAVerify handles verifying MFA
func (h *MFAHandler) MFAVerify(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Parse input
	var input MFAVerifyRequest
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Process based on method
	var verified bool
	var err error

	switch input.Method {
	case "totp":
		verified, err = h.mfaService.VerifyTOTP(r.Context(), userID, input.Code)

	case "sms":
		verified, err = h.mfaService.VerifySMSCode(r.Context(), userID, input.Code)

	case "email":
		verified, err = h.mfaService.VerifyEmailCode(r.Context(), userID, input.Code)

	case "backup_codes":
		verified, err = h.mfaService.VerifyBackupCode(r.Context(), userID, input.Code)

	default:
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "unsupported MFA method"))
		return
	}

	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return verification result
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"verified": verified,
	})
}

// MFAUnenroll handles unenrolling from MFA
func (h *MFAHandler) MFAUnenroll(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Parse input
	var input struct {
		Method string `json:"method" validate:"required"`
	}
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Process based on method
	var err error

	switch input.Method {
	case "totp":
		err = h.mfaService.DisableTOTP(r.Context(), userID)

	case "sms":
		err = h.mfaService.DisableSMS(r.Context(), userID)

	case "email":
		err = h.mfaService.DisableEmail(r.Context(), userID)

	case "backup_codes":
		err = h.mfaService.DisableBackupCodes(r.Context(), userID)

	case "all":
		err = h.mfaService.DisableAllMethods(r.Context(), userID)

	default:
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "unsupported MFA method"))
		return
	}

	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return success
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "MFA method disabled successfully",
	})
}

// GetMFAMethods handles retrieving enabled MFA methods
func (h *MFAHandler) GetMFAMethods(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Get enabled methods
	methods, err := h.mfaService.GetEnabledMethods(r.Context(), userID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return enabled methods
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"methods": methods,
	})
}

// SendMFACode handles sending MFA verification code
func (h *MFAHandler) SendMFACode(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(r)
	if !ok {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Parse input
	var input struct {
		Method string `json:"method" validate:"required"`
	}
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Process based on method
	var expiresAt time.Time
	var err error

	switch input.Method {
	case "sms":
		expiresAt, err = h.mfaService.SendSMSCode(r.Context(), userID)

	case "email":
		expiresAt, err = h.mfaService.SendEmailCode(r.Context(), userID)

	default:
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "unsupported MFA method"))
		return
	}

	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return success with expiration time
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "Verification code sent successfully",
		"expires_at": expiresAt.Unix(),
	})
}

// SetupRoutes sets up the MFA routes
func (h *MFAHandler) SetupRoutes(router *http.ServeMux) {
	router.HandleFunc("/api/v1/auth/mfa/enroll", h.MFAEnroll)
	router.HandleFunc("/api/v1/auth/mfa/verify", h.MFAVerify)
	router.HandleFunc("/api/v1/auth/mfa/unenroll", h.MFAUnenroll)
	router.HandleFunc("/api/v1/auth/mfa/methods", h.GetMFAMethods)
	router.HandleFunc("/api/v1/auth/mfa/send-code", h.SendMFACode)
}

// Static handler functions for direct router registration

// MFAEnroll handles MFA enrollment API endpoint
func MFAEnroll(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).MFA.MFAEnroll(w, r)
}

// MFAVerify handles MFA verification API endpoint
func MFAVerify(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).MFA.MFAVerify(w, r)
}

// MFAUnenroll handles MFA unenrollment API endpoint
func MFAUnenroll(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).MFA.MFAUnenroll(w, r)
}

// GetMFAMethods handles getting MFA methods API endpoint
func GetMFAMethods(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).MFA.GetMFAMethods(w, r)
}

// SendMFACode handles sending MFA code API endpoint
func SendMFACode(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).MFA.SendMFACode(w, r)
}
