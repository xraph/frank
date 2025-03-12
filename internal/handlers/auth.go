package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/internal/user"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// AuthHandler handles authentication operations
type AuthHandler struct {
	userService    user.Service
	config         *config.Config
	logger         logging.Logger
	sessionManager *session.Manager
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(
	userService user.Service,
	config *config.Config,
	logger logging.Logger,
	sessionManager *session.Manager,
) *AuthHandler {
	return &AuthHandler{
		userService:    userService,
		config:         config,
		logger:         logger,
		sessionManager: sessionManager,
	}
}

// LoginInput represents the input for login requests
type LoginInput struct {
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required"`
	OrganizationID  string `json:"organization_id,omitempty"`
	RememberMe      bool   `json:"remember_me,omitempty"`
	CaptchaResponse string `json:"captcha_response,omitempty"`
}

// LoginResponse represents the response for login requests
type LoginResponse struct {
	User         *ent.User `json:"user"`
	Token        string    `json:"token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    int64     `json:"expires_at,omitempty"`
	MFARequired  bool      `json:"mfa_required,omitempty"`
	MFATypes     []string  `json:"mfa_types,omitempty"`
}

// RegisterInput represents the input for registration requests
type RegisterInput struct {
	Email          string                 `json:"email" validate:"required,email"`
	Password       string                 `json:"password" validate:"required,min=8"`
	FirstName      string                 `json:"first_name,omitempty"`
	LastName       string                 `json:"last_name,omitempty"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// Login handles user login
// @Summary Authenticate a user
// @Description Logs in a user with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param input body LoginInput true "Login credentials"
// @Success 200 {object} LoginResponse "Login successful"
// @Failure 400 {object} errors.ErrorResponse "Invalid input"
// @Failure 401 {object} errors.ErrorResponse "Authentication failed"
// @Failure 403 {object} errors.ErrorResponse "Email not verified"
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var input LoginInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Authenticate user
	authenticatedUser, err := h.userService.Authenticate(r.Context(), input.Email, input.Password)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Check if email verification is required
	if h.config.Auth.RequireEmailVerification && !authenticatedUser.EmailVerified {
		utils.RespondError(w, errors.New(errors.CodeEmailNotVerified, "email verification required"))
		return
	}

	// Check if MFA is required
	mfaRequired, mfaTypes, err := h.checkMFA(r.Context(), authenticatedUser.ID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Create tokens
	token, refreshToken, expiresAt, err := h.createTokens(authenticatedUser, input.OrganizationID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Create session if session manager is available
	if h.sessionManager != nil {
		session, err := h.createSession(r, w, authenticatedUser, input.OrganizationID, input.RememberMe)
		if err != nil {
			h.logger.Error("Failed to create session",
				logging.String("user_id", authenticatedUser.ID),
				logging.Error(err),
			)
			// Continue without session
		}

		// If session was created, don't include token in response
		if session != nil {
			token = ""
			refreshToken = ""
		}
	}

	// Return response
	utils.RespondJSON(w, http.StatusOK, &LoginResponse{
		User:         authenticatedUser,
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		MFARequired:  mfaRequired,
		MFATypes:     mfaTypes,
	})
}

// Register handles user registration
// @Summary Register a new user
// @Description Creates a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param input body RegisterInput true "Registration information"
// @Success 201 {object} LoginResponse "Registration successful"
// @Failure 400 {object} errors.ErrorResponse "Invalid input"
// @Failure 409 {object} errors.ErrorResponse "Email already exists"
// @Router /api/v1/auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var input RegisterInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Create user
	createInput := user.CreateUserInput{
		Email:          input.Email,
		Password:       input.Password,
		FirstName:      input.FirstName,
		LastName:       input.LastName,
		OrganizationID: input.OrganizationID,
		Metadata:       input.Metadata,
	}

	newUser, err := h.userService.Create(r.Context(), createInput)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Create tokens if email verification is not required
	var token, refreshToken string
	var expiresAt int64

	if !h.config.Auth.RequireEmailVerification {
		token, refreshToken, expiresAt, err = h.createTokens(newUser, input.OrganizationID)
		if err != nil {
			utils.RespondError(w, err)
			return
		}

		// Create session if session manager is available
		if h.sessionManager != nil {
			session, err := h.createSession(r, w, newUser, input.OrganizationID, false)
			if err != nil {
				h.logger.Error("Failed to create session",
					logging.String("user_id", newUser.ID),
					logging.Error(err),
				)
				// Continue without session
			}

			// If session was created, don't include token in response
			if session != nil {
				token = ""
				refreshToken = ""
			}
		}
	}

	// Return response
	utils.RespondJSON(w, http.StatusCreated, &LoginResponse{
		User:         newUser,
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	})
}

// Logout handles user logout
// @Summary Log out a user
// @Description Logs out the current user and invalidates their session
// @Tags auth
// @Produce json
// @Success 200 {object} map[string]interface{} "Logout successful"
// @Router /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Clear session if using sessions
	if h.sessionManager != nil {
		session, err := utils.GetSession(r, h.config)
		if err == nil {
			// Get user ID from session
			userID, ok := session.Values["user_id"].(string)
			if ok && userID != "" {
				// Get token from session
				token, ok := session.Values["token"].(string)
				if ok && token != "" {
					// Try to revoke the token in the session
					err := h.sessionManager.RevokeSession(r.Context(), token)
					if err != nil {
						h.logger.Error("Failed to revoke session",
							logging.String("user_id", userID),
							logging.Error(err),
						)
						// Continue with logout anyway
					}
				}
			}

			// Clear all session values
			for key := range session.Values {
				delete(session.Values, key)
			}

			// Save the session to clear it
			err = session.Save(r, w)
			if err != nil {
				h.logger.Error("Failed to save cleared session",
					logging.Error(err),
				)
				// Continue with logout anyway
			}
		}
	}

	// Respond with success
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Successfully logged out",
	})
}

// RefreshTokenInput handles token refresh
type RefreshTokenInput struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// RefreshToken refreshes an access token
// @Summary Refresh access token
// @Description Generates a new access token using a refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param input body RefreshTokenInput true "Refresh token"
// @Success 200 {object} map[string]interface{} "Token refresh successful"
// @Failure 400 {object} errors.ErrorResponse "Invalid input"
// @Failure 401 {object} errors.ErrorResponse "Invalid refresh token"
// @Router /api/v1/auth/refresh [post]
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var input RefreshTokenInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Create JWT config
	jwtConfig := &crypto.JWTConfig{
		SigningMethod: h.config.Auth.TokenSigningMethod,
		SignatureKey:  []byte(h.config.Auth.TokenSecretKey),
		ValidationKey: []byte(h.config.Auth.TokenSecretKey),
		Issuer:        h.config.Auth.TokenIssuer,
		Audience:      h.config.Auth.TokenAudience,
	}

	// Extract claims from refresh token
	claims, err := jwtConfig.ValidateToken(input.RefreshToken)
	if err != nil {
		utils.RespondError(w, errors.New(errors.CodeInvalidRefreshToken, "invalid refresh token"))
		return
	}

	// Check token type
	tokenType, ok := claims["token_type"].(string)
	if !ok || tokenType != "refresh" {
		utils.RespondError(w, errors.New(errors.CodeInvalidRefreshToken, "invalid token type"))
		return
	}

	// Extract user ID
	subject, err := jwtConfig.GetSubjectFromToken(input.RefreshToken)
	if err != nil {
		utils.RespondError(w, errors.New(errors.CodeInvalidRefreshToken, "invalid token subject"))
		return
	}

	// Get user from database
	userEntity, err := h.userService.Get(r.Context(), subject)
	if err != nil {
		utils.RespondError(w, errors.New(errors.CodeInvalidRefreshToken, "user not found"))
		return
	}

	// Extract organization ID if present
	var organizationID string
	if orgID, ok := claims["organization_id"].(string); ok {
		organizationID = orgID
	}

	// Generate new tokens
	token, refreshToken, expiresAt, err := h.createTokens(userEntity, organizationID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return new tokens
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"token":         token,
		"refresh_token": refreshToken,
		"expires_at":    expiresAt,
	})
}

// ForgotPasswordInput handles password reset requests
type ForgotPasswordInput struct {
	Email string `json:"email" validate:"required,email"`
}

// ForgotPassword initiates the password reset process
// @Summary Request password reset
// @Description Initiates the password reset process for a user
// @Tags auth
// @Accept json
// @Produce json
// @Param input body ForgotPasswordInput true "User email"
// @Param redirect_url query string false "URL to redirect to after password reset"
// @Success 202 {object} map[string]interface{} "Password reset initiated"
// @Failure 400 {object} errors.ErrorResponse "Invalid input"
// @Router /api/v1/auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var input ForgotPasswordInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Find user by email
	userEntity, err := h.userService.GetByEmail(r.Context(), input.Email)
	if err != nil {
		// Return success even if user not found for security
		utils.RespondJSON(w, http.StatusAccepted, map[string]interface{}{
			"message": "If your email is registered, you will receive a password reset link",
		})
		return
	}

	// Generate verification
	expiresAt := time.Now().Add(time.Hour * 24) // 24 hour expiry
	_, err = h.userService.CreateVerification(r.Context(), user.CreateVerificationInput{
		UserID:      userEntity.ID,
		Type:        "password_reset",
		Email:       userEntity.Email,
		ExpiresAt:   expiresAt,
		RedirectURL: r.URL.Query().Get("redirect_url"),
		IPAddress:   utils.GetRealIP(r),
		UserAgent:   r.UserAgent(),
	})

	if err != nil {
		h.logger.Error("Failed to create password reset verification",
			logging.String("user_id", userEntity.ID),
			logging.Error(err),
		)
		// Return success anyway for security
	}

	// Respond with success
	utils.RespondJSON(w, http.StatusAccepted, map[string]interface{}{
		"message": "If your email is registered, you will receive a password reset link",
	})
}

// ResetPasswordInput represents the input for password reset
type ResetPasswordInput struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

// ResetPassword resets a user's password using a token
// @Summary Reset password
// @Description Resets a user's password using a token received by email
// @Tags auth
// @Accept json
// @Produce json
// @Param input body ResetPasswordInput true "Reset password information"
// @Success 200 {object} map[string]interface{} "Password reset successful"
// @Failure 400 {object} errors.ErrorResponse "Invalid input"
// @Failure 401 {object} errors.ErrorResponse "Invalid token"
// @Router /api/v1/auth/reset-password [post]
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var input ResetPasswordInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Verify the token
	verification, err := h.userService.VerifyToken(r.Context(), input.Token)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Check if this is a password reset token
	if verification.Type != "password_reset" {
		utils.RespondError(w, errors.New(errors.CodeInvalidToken, "invalid token type"))
		return
	}

	// Update user password
	err = h.userService.UpdatePassword(r.Context(), verification.UserID, "", input.NewPassword)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Respond with success
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Password has been reset successfully",
	})
}

// VerifyEmailInput represents the input for email verification
type VerifyEmailInput struct {
	Token string `json:"token" validate:"required"`
}

// VerifyEmail verifies a user's email address
// @Summary Verify email
// @Description Verifies a user's email address using a token
// @Tags auth
// @Accept json
// @Produce json
// @Param input body VerifyEmailInput true "Email verification token"
// @Success 200 {object} map[string]interface{} "Email verification successful"
// @Failure 400 {object} errors.ErrorResponse "Invalid input"
// @Failure 401 {object} errors.ErrorResponse "Invalid token"
// @Router /api/v1/auth/verify-email [post]
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var input VerifyEmailInput
	if err := utils.DecodeJSON(r, &input); err != nil {
		utils.RespondError(w, err)
		return
	}

	// Verify the token
	verification, err := h.userService.VerifyToken(r.Context(), input.Token)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Check if this is an email verification token
	if verification.Type != "email" {
		utils.RespondError(w, errors.New(errors.CodeInvalidToken, "invalid token type"))
		return
	}

	// Update user's email verification status
	err = h.userService.VerifyEmail(r.Context(), verification.UserID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Respond with success
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Email verification successful",
	})
}

// createTokens generates JWT tokens for a user
func (h *AuthHandler) createTokens(user *ent.User, organizationID string) (string, string, int64, error) {
	// Create JWT config
	jwtConfig := &crypto.JWTConfig{
		SigningMethod: h.config.Auth.TokenSigningMethod,
		SignatureKey:  []byte(h.config.Auth.TokenSecretKey),
		ValidationKey: []byte(h.config.Auth.TokenSecretKey),
		Issuer:        h.config.Auth.TokenIssuer,
		Audience:      h.config.Auth.TokenAudience,
		DefaultExpiry: h.config.Auth.AccessTokenDuration,
	}

	// Create claims for access token
	accessClaims := map[string]interface{}{
		"user_id":    user.ID,
		"email":      user.Email,
		"token_type": "access",
	}

	if organizationID != "" {
		accessClaims["organization_id"] = organizationID
	}

	// Generate access token
	accessToken, err := jwtConfig.GenerateToken(user.ID, accessClaims, h.config.Auth.AccessTokenDuration)
	if err != nil {
		return "", "", 0, errors.Wrap(errors.CodeCryptoError, err, "failed to generate access token")
	}

	// Create claims for refresh token
	refreshClaims := map[string]interface{}{
		"user_id":    user.ID,
		"email":      user.Email,
		"token_type": "refresh",
	}

	if organizationID != "" {
		refreshClaims["organization_id"] = organizationID
	}

	// Generate refresh token
	refreshToken, err := jwtConfig.GenerateToken(user.ID, refreshClaims, h.config.Auth.RefreshTokenDuration)
	if err != nil {
		return "", "", 0, errors.Wrap(errors.CodeCryptoError, err, "failed to generate refresh token")
	}

	// Calculate expiration time
	expiresAt := time.Now().Add(h.config.Auth.AccessTokenDuration).Unix()

	return accessToken, refreshToken, expiresAt, nil
}

// createSession creates a new session for the user
func (h *AuthHandler) createSession(r *http.Request, w http.ResponseWriter, user *ent.User, organizationID string, rememberMe bool) (*session.SessionInfo, error) {
	// Skip if session manager not initialized
	if h.sessionManager == nil {
		return nil, nil
	}

	// Create options for session
	options := []session.SessionOption{
		session.WithIPAddress(utils.GetRealIP(r)),
		session.WithUserAgent(r.UserAgent()),
	}

	if organizationID != "" {
		options = append(options, session.WithOrganizationID(organizationID))
	}

	// Create session
	sessionInfo, err := h.sessionManager.CreateSession(r.Context(), user.ID, options...)
	if err != nil {
		return nil, err
	}

	// Store session info in cookie session
	session, err := utils.GetSession(r, h.config)
	if err != nil {
		return nil, err
	}

	// Set session values
	session.Values["user_id"] = user.ID
	session.Values["authenticated"] = true
	session.Values["token"] = sessionInfo.Token
	session.Values["session_id"] = sessionInfo.ID

	if organizationID != "" {
		session.Values["organization_id"] = organizationID
	}

	// Set session expiration based on remember me option
	if rememberMe {
		session.Options.MaxAge = int(h.config.Auth.RememberMeDuration.Seconds())
	} else {
		session.Options.MaxAge = int(h.config.Auth.SessionDuration.Seconds())
	}

	// Save session
	if err := session.Save(r, w); err != nil {
		return nil, err
	}

	return sessionInfo, nil
}

// checkMFA checks if MFA is required for the user
func (h *AuthHandler) checkMFA(ctx context.Context, userID string) (bool, []string, error) {
	// Implement MFA check logic here
	// For now returning false (no MFA required)
	return false, nil, nil
}

// GetCurrentUser returns the current authenticated user
func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID from request context
	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "not authenticated"))
		return
	}

	// Get user from database
	userEntity, err := h.userService.Get(r.Context(), userID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return user data
	utils.RespondJSON(w, http.StatusOK, userEntity)
}

// SetupRoutes sets up the auth routes
func (h *AuthHandler) SetupRoutes(router chi.Router) {
	router.HandleFunc("/api/v1/auth/login", h.Login)
	router.HandleFunc("/api/v1/auth/register", h.Register)
	router.HandleFunc("/api/v1/auth/logout", h.Logout)
	router.HandleFunc("/api/v1/auth/refresh", h.RefreshToken)
	router.HandleFunc("/api/v1/auth/forgot-password", h.ForgotPassword)
	router.HandleFunc("/api/v1/auth/reset-password", h.ResetPassword)
	router.HandleFunc("/api/v1/auth/verify-email", h.VerifyEmail)
}

// Login handles user login API endpoint
func Login(w http.ResponseWriter, r *http.Request) {
	// This function is used to register with the router directly
	// The implementation is delegated to the handler instance
	HandlerFromContext(r.Context()).Auth.Login(w, r)
}

// Register handles user registration API endpoint
func Register(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Auth.Register(w, r)
}

// Logout handles user logout API endpoint
func Logout(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Auth.Logout(w, r)
}

// RefreshToken handles token refresh API endpoint
func RefreshToken(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Auth.RefreshToken(w, r)
}

// ForgotPassword handles forgot password API endpoint
func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Auth.ForgotPassword(w, r)
}

// ResetPassword handles password reset API endpoint
func ResetPassword(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Auth.ResetPassword(w, r)
}

// VerifyEmail handles email verification API endpoint
func VerifyEmail(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Auth.VerifyEmail(w, r)
}

// GetCurrentUser handles current user API endpoint
func GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Auth.GetCurrentUser(w, r)
}
