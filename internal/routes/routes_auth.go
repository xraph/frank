package routes

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/ent/userpermission"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/internal/services/audit"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// RegisterPublicAuthAPI registers all authentication-related endpoints
func RegisterPublicAuthAPI(group huma.API, di di.Container) {
	authCtrl := &authController{
		group: group,
		di:    di,
	}

	// Register authentication endpoints
	registerLogin(group, authCtrl)
	registerRegister(group, authCtrl)
	registerLogout(group, authCtrl)
	registerRefreshToken(group, authCtrl)
	registerForgotPassword(group, authCtrl)
	registerResetPassword(group, authCtrl)
	registerVerifyEmail(group, authCtrl)
	registerVerifyPhone(group, authCtrl)
	registerResendVerification(group, authCtrl)
	registerMagicLink(group, authCtrl)
	registerVerifyMagicLink(group, authCtrl)
	registerAuthStatus(group, authCtrl)

	// MFA endpoints
	registerMFARecovery(group, authCtrl)

	// Passkey endpoints
	registerPasskeyAuthenticationBegin(group, authCtrl)
	registerPasskeyAuthenticationFinish(group, authCtrl)

	// OAuth endpoints
	registerOAuthAuthorize(group, authCtrl)
	registerOAuthCallback(group, authCtrl)
	registerOAuthToken(group, authCtrl)
	registerOAuthUserInfo(group, authCtrl)
	registerListOAuthProviders(group, authCtrl)
}

// RegisterAuthAPI registers all authentication-related endpoints
func RegisterAuthAPI(group huma.API, di di.Container) {
	authCtrl := &authController{
		group: group,
		di:    di,
	}

	// MFA endpoints
	registerMFASetup(group, authCtrl)
	registerMFAVerify(group, authCtrl)
	registerMFADisable(group, authCtrl)
	registerMFABackupCodes(group, authCtrl)

	// Passkey endpoints
	registerPasskeyRegistrationBegin(group, authCtrl)
	registerPasskeyRegistrationFinish(group, authCtrl)
	registerListPasskeys(group, authCtrl)
	registerDeletePasskey(group, authCtrl)

	// Session management
	registerListSessions(group, authCtrl)
	registerRevokeSession(group, authCtrl)
	registerRevokeAllSessions(group, authCtrl)
}

// authController handles authentication-related API requests
type authController struct {
	group huma.API
	di    di.Container
}

// Basic Authentication Endpoints

func registerLogin(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "login",
		Method:      http.MethodPost,
		Path:        "/auth/login",
		Summary:     "User login",
		Description: "Authenticate user with email/password, OAuth, or passwordless",
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.loginHandler)
}

func registerRegister(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "register",
		Method:      http.MethodPost,
		Path:        "/auth/register",
		Summary:     "User registration",
		Description: "Register a new user account",
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.registerHandler)
}

func registerLogout(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "logout",
		Method:      http.MethodPost,
		Path:        "/auth/logout",
		Summary:     "User logout",
		Description: "Log out user and invalidate session/tokens",
		Tags:        []string{"Authentication"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.logoutHandler)
}

func registerRefreshToken(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "refreshToken",
		Method:      http.MethodPost,
		Path:        "/auth/refresh",
		Summary:     "Refresh access token",
		Description: "Refresh access token using refresh token",
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.refreshTokenHandler)
}

func registerForgotPassword(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "forgotPassword",
		Method:      http.MethodPost,
		Path:        "/auth/forgot-password",
		Summary:     "Forgot password",
		Description: "Request password reset email",
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.forgotPasswordHandler)
}

func registerResetPassword(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "resetPassword",
		Method:      http.MethodPost,
		Path:        "/auth/reset-password",
		Summary:     "Reset password",
		Description: "Reset password with token from email",
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.resetPasswordHandler)
}

func registerVerifyEmail(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "verifyEmail",
		Method:      http.MethodPost,
		Path:        "/auth/verify-email",
		Summary:     "Verify email address",
		Description: "Verify email address with token from email",
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.verifyEmailHandler)
}

func registerVerifyPhone(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "verifyPhone",
		Method:      http.MethodPost,
		Path:        "/auth/verify-phone",
		Summary:     "Verify phone number",
		Description: "Verify phone number with SMS code",
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.verifyPhoneHandler)
}

func registerResendVerification(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "resendVerification",
		Method:      http.MethodPost,
		Path:        "/auth/resend-verification",
		Summary:     "Resend verification",
		Description: "Resend email or SMS verification",
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.resendVerificationHandler)
}

func registerMagicLink(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "magicLink",
		Method:      http.MethodPost,
		Path:        "/auth/magic-link",
		Summary:     "Send magic link",
		Description: "Send passwordless magic link for authentication",
		Tags:        []string{"Authentication", "Passwordless"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.magicLinkHandler)
}

func registerVerifyMagicLink(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "verifyMagicLink",
		Method:      http.MethodGet,
		Path:        "/auth/magic-link/verify/{token}",
		Summary:     "Verify magic link token via GET",
		Description: "Verify magic link token and authenticate user (typically called from email link)",
		Tags:        []string{"Authentication", "Passwordless"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.verifyMagicLinkHandler)
}

func registerAuthStatus(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "authStatus",
		Method:      http.MethodGet,
		Path:        "/auth/status",
		Summary:     "Get authentication status",
		Description: "Get current user authentication status and context",
		Tags:        []string{"Authentication"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.authStatusHandler)
}

// MFA Endpoints

func registerMFASetup(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "setupMFA",
		Method:      http.MethodPost,
		Path:        "/auth/mfa/setup",
		Summary:     "Setup MFA",
		Description: "Setup multi-factor authentication",
		Tags:        []string{"Authentication", "MFA"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.mfaSetupHandler)
}

func registerMFAVerify(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "verifyMFA",
		Method:      http.MethodPost,
		Path:        "/auth/mfa/verify",
		Summary:     "Verify MFA",
		Description: "Verify multi-factor authentication code",
		Tags:        []string{"Authentication", "MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.mfaVerifyHandler)
}

func registerMFADisable(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "disableMFA",
		Method:      http.MethodDelete,
		Path:        "/auth/mfa",
		Summary:     "Disable MFA",
		Description: "Disable multi-factor authentication",
		Tags:        []string{"Authentication", "MFA"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "MFA successfully disabled"},
		}, false),
	}, authCtrl.mfaDisableHandler)
}

func registerMFABackupCodes(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "getMFABackupCodes",
		Method:      http.MethodGet,
		Path:        "/auth/mfa/backup-codes",
		Summary:     "Get MFA backup codes",
		Description: "Get or regenerate MFA backup codes",
		Tags:        []string{"Authentication", "MFA"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.mfaBackupCodesHandler)
}

func registerMFARecovery(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "mfaRecovery",
		Method:      http.MethodPost,
		Path:        "/auth/mfa/recovery",
		Summary:     "MFA recovery",
		Description: "Use backup code for MFA recovery",
		Tags:        []string{"Authentication", "MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.mfaRecoveryHandler)
}

// Passkey Endpoints

func registerPasskeyRegistrationBegin(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "beginPasskeyRegistration",
		Method:      http.MethodPost,
		Path:        "/auth/passkeys/register/begin",
		Summary:     "Begin passkey registration",
		Description: "Begin WebAuthn passkey registration process",
		Tags:        []string{"Authentication", "Passkeys"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.passkeyRegistrationBeginHandler)
}

func registerPasskeyRegistrationFinish(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "finishPasskeyRegistration",
		Method:      http.MethodPost,
		Path:        "/auth/passkeys/register/finish",
		Summary:     "Finish passkey registration",
		Description: "Complete WebAuthn passkey registration process",
		Tags:        []string{"Authentication", "Passkeys"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.passkeyRegistrationFinishHandler)
}

func registerPasskeyAuthenticationBegin(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "beginPasskeyAuthentication",
		Method:      http.MethodPost,
		Path:        "/auth/passkeys/authenticate/begin",
		Summary:     "Begin passkey authentication",
		Description: "Begin WebAuthn passkey authentication process",
		Tags:        []string{"Authentication", "Passkeys"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.passkeyAuthenticationBeginHandler)
}

func registerPasskeyAuthenticationFinish(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "finishPasskeyAuthentication",
		Method:      http.MethodPost,
		Path:        "/auth/passkeys/authenticate/finish",
		Summary:     "Finish passkey authentication",
		Description: "Complete WebAuthn passkey authentication process",
		Tags:        []string{"Authentication", "Passkeys"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.passkeyAuthenticationFinishHandler)
}

func registerListPasskeys(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "listPasskeys",
		Method:      http.MethodGet,
		Path:        "/auth/passkeys",
		Summary:     "List user passkeys",
		Description: "List all passkeys registered for the current user",
		Tags:        []string{"Authentication", "Passkeys"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.listPasskeysHandler)
}

func registerDeletePasskey(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "deletePasskey",
		Method:      http.MethodDelete,
		Path:        "/auth/passkeys/{id}",
		Summary:     "Delete passkey",
		Description: "Delete a specific passkey",
		Tags:        []string{"Authentication", "Passkeys"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Passkey successfully deleted"},
		}, false, model.NotFoundError("Passkey not found")),
	}, authCtrl.deletePasskeyHandler)
}

// OAuth Endpoints

func registerOAuthAuthorize(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "oauthAuthorize",
		Method:      http.MethodGet,
		Path:        "/auth/oauth/{provider}/authorize",
		Summary:     "OAuth authorization",
		Description: "Redirect to OAuth provider for authorization",
		Tags:        []string{"Authentication", "OAuth"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.oauthAuthorizeHandler)
}

func registerOAuthCallback(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "oauthCallback",
		Method:      http.MethodGet,
		Path:        "/auth/oauth/{provider}/callback",
		Summary:     "OAuth callback",
		Description: "Handle OAuth provider callback",
		Tags:        []string{"Authentication", "OAuth"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.oauthCallbackHandler)
}

func registerOAuthToken(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "oauthToken",
		Method:      http.MethodPost,
		Path:        "/auth/oauth/token",
		Summary:     "OAuth token exchange",
		Description: "Exchange OAuth authorization code for tokens",
		Tags:        []string{"Authentication", "OAuth"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.oauthTokenHandler)
}

func registerOAuthUserInfo(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "oauthUserInfo",
		Method:      http.MethodGet,
		Path:        "/auth/oauth/userinfo",
		Summary:     "OAuth user info",
		Description: "Get user information from OAuth token",
		Tags:        []string{"Authentication", "OAuth"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.oauthUserInfoHandler)
}

func registerListOAuthProviders(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "listOAuthProviders",
		Method:      http.MethodGet,
		Path:        "/auth/oauth/providers",
		Summary:     "List OAuth providers",
		Description: "List available OAuth providers",
		Tags:        []string{"Authentication", "OAuth"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.listOAuthProvidersHandler)
}

// Session Management Endpoints

func registerListSessions(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "listSessions",
		Method:      http.MethodGet,
		Path:        "/auth/sessions",
		Summary:     "List user sessions",
		Description: "List all active sessions for the current user",
		Tags:        []string{"Authentication", "Sessions"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.listSessionsHandler)
}

func registerRevokeSession(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "revokeSession",
		Method:      http.MethodDelete,
		Path:        "/auth/sessions/{id}",
		Summary:     "Revoke session",
		Description: "Revoke a specific session",
		Tags:        []string{"Authentication", "Sessions"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Session successfully revoked"},
		}, false, model.NotFoundError("Session not found")),
	}, authCtrl.revokeSessionHandler)
}

func registerRevokeAllSessions(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "revokeAllSessions",
		Method:      http.MethodDelete,
		Path:        "/auth/sessions",
		Summary:     "Revoke all sessions",
		Description: "Revoke all sessions for the current user",
		Tags:        []string{"Authentication", "Sessions"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "All sessions successfully revoked"},
		}, false),
	}, authCtrl.revokeAllSessionsHandler)
}

// Input/Output type definitions

type LoginInput struct {
	Body model.LoginRequest
}

type LoginOutput = model.Output[model.LoginResponse]

type RegisterInput struct {
	Body model.RegisterRequest
}

type RegisterOutput = model.Output[model.RegisterResponse]

type LogoutInput struct {
	Body model.LogoutRequest
}

type LogoutOutput = model.Output[model.LogoutResponse]

type RefreshTokenInput struct {
	Body model.RefreshTokenRequest
}

type RefreshTokenOutput = model.Output[model.RefreshTokenResponse]

type ForgotPasswordInput struct {
	Body model.PasswordResetRequest
}

type ForgotPasswordOutput = model.Output[model.PasswordResetResponse]

type ResetPasswordInput struct {
	Body model.PasswordResetConfirmRequest
}

type ResetPasswordOutput = model.Output[model.PasswordResetConfirmResponse]

type VerifyEmailInput struct {
	Body model.VerificationRequest
}

type VerifyEmailOutput = model.Output[model.VerificationResponse]

type VerifyPhoneInput struct {
	Body model.VerificationRequest
}

type VerifyPhoneOutput = model.Output[model.VerificationResponse]

type ResendVerificationInput struct {
	Body model.ResendVerificationRequest
}

type ResendVerificationOutput = model.Output[model.ResendVerificationResponse]

type MagicLinkInput struct {
	Body model.MagicLinkRequest
}

type MagicLinkOutput = model.Output[model.MagicLinkResponse]

type AuthStatusOutput = model.Output[model.AuthStatus]

type DeletePasskeyInput struct {
	ID xid.ID `path:"id" doc:"Passkey ID"`
}

type RevokeSessionInput struct {
	ID xid.ID `path:"id" doc:"Session ID"`
}

type OAuthProviderPathInput struct {
	Provider string `json:"provider" path:"provider" doc:"OAuth provider name"`
	State    string `json:"state" query:"state" doc:"OAuth provider state"`
	Code     string `json:"code" query:"code" doc:"OAuth provider code"`
}

// Input/Output type definitions for passkey handlers
type PasskeyRegistrationBeginInput struct {
	Body model.PasskeyRegistrationBeginRequest
}

type PasskeyRegistrationBeginOutput = model.Output[model.PasskeyRegistrationBeginResponse]

type PasskeyRegistrationFinishInput struct {
	Body model.PasskeyRegistrationFinishRequest
}

type PasskeyRegistrationFinishOutput = model.Output[model.PasskeyRegistrationFinishResponse]

type PasskeyAuthenticationBeginInput struct {
	Body model.PasskeyAuthenticationBeginRequest
}

type PasskeyAuthenticationBeginOutput = model.Output[model.PasskeyAuthenticationBeginResponse]

type PasskeyAuthenticationFinishInput struct {
	Body model.PasskeyAuthenticationFinishRequest
}

type PasskeyAuthenticationFinishOutput = model.Output[model.PasskeyAuthenticationFinishResponse]

type ListPasskeysInput struct {
	model.PaginationParams
	UserID     model.OptionalParam[xid.ID] `query:"userId" doc:"Filter by user ID"`
	Active     model.OptionalParam[bool]   `query:"active" doc:"Filter by active status"`
	DeviceType string                      `query:"deviceType" doc:"Filter by device type"`
	Search     string                      `query:"search" doc:"Search in passkey name"`
}

type ListPasskeysOutput = model.Output[model.PasskeyListResponse]

// Input/Output type definitions for OAuth and session handlers

type OAuthTokenInput struct {
	Body model.TokenRequest
}

type OAuthTokenOutput = model.Output[model.TokenResponse]

type OAuthUserInfoInput struct {
	Authorization string `header:"Authorization" doc:"Bearer access token"`
}

type OAuthUserInfoOutput = model.Output[map[string]interface{}]

type ListOAuthProvidersOutput = model.Output[[]model.AuthProvider]

type ListSessionsInput struct {
	model.ListSessionsParams
}

type ListSessionsOutput = model.Output[model.PaginatedOutput[model.SessionInfo]]

type RevokeAllSessionsInput struct {
	ExceptCurrent bool `json:"exceptCurrent" query:"exceptCurrent" doc:"Keep current session active"`
}

// Handler implementations

func (c *authController) loginHandler(ctx context.Context, input *LoginInput) (*LoginOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	// Validate required fields
	if input.Body.Email == "" && input.Body.Username == "" && input.Body.PhoneNumber == "" {
		return nil, errors.New(errors.CodeBadRequest, "email, username, or phone number is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionUserLogin,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"email":    input.Body.Email,
			"provider": input.Body.Provider,
			"method":   c.getLoginMethod(input.Body),
		},
		Source: audit.SourceWeb,
	}

	// Log authentication attempt
	defer c.logAuditEvent(ctx, auditEvent)

	response, err := authSvc.Login(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	if !response.VerificationRequired && !response.MFARequired {
		auditEvent.Status = audit.StatusSuccess
	}

	logResp := &LoginOutput{
		Body: *response,
	}

	if response.Session != nil && c.di.Config().Auth.AllowSession && response.Session.Token != "" {
		logResp.SetCookie = c.createCookie(response.Session.Token)
	}

	return logResp, nil
}

func (c *authController) registerHandler(ctx context.Context, input *RegisterInput) (*RegisterOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	// Validate required fields
	if input.Body.Email == "" {
		return nil, errors.New(errors.CodeBadRequest, "email is required")
	}

	if input.Body.UserType == "" {
		input.Body.UserType = "external" // Default user type
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionUserRegister,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"email":     input.Body.Email,
			"user_type": input.Body.UserType,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := authSvc.Register(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &RegisterOutput{
		Body: *response,
	}, nil
}

func (c *authController) logoutHandler(ctx context.Context, input *LogoutInput) (*LogoutOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionUserLogout,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"logout_all": input.Body.LogoutAll,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := authSvc.Logout(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &LogoutOutput{
		SetCookie: c.deleteCookie(),
		Body:      *response,
	}, nil
}

func (c *authController) refreshTokenHandler(ctx context.Context, input *RefreshTokenInput) (*RefreshTokenOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	if input.Body.RefreshToken == "" {
		return nil, errors.New(errors.CodeBadRequest, "refresh token is required")
	}

	response, err := authSvc.RefreshToken(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &RefreshTokenOutput{
		Body: *response,
	}, nil
}

func (c *authController) forgotPasswordHandler(ctx context.Context, input *ForgotPasswordInput) (*ForgotPasswordOutput, error) {
	pwdSvc := c.di.PasswordService()
	if pwdSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "password service not available")
	}

	if input.Body.Email == "" {
		return nil, errors.New(errors.CodeBadRequest, "email is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionPasswordReset,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"email": input.Body.Email,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	// Generate password reset token
	rsp, err := pwdSvc.InitiatePasswordReset(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	if !config.IsDevelopment() {
		rsp.Token = "" // Remove token for non dev
	}

	return &ForgotPasswordOutput{
		Body: *rsp,
	}, err
}

func (c *authController) resetPasswordHandler(ctx context.Context, input *ResetPasswordInput) (*ResetPasswordOutput, error) {
	pwdSvc := c.di.PasswordService()
	if pwdSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "password service not available")
	}

	if input.Body.Token == "" {
		return nil, errors.New(errors.CodeBadRequest, "reset token is required")
	}

	if input.Body.NewPassword == "" {
		return nil, errors.New(errors.CodeBadRequest, "new password is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionPasswordChange,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"token": input.Body.Token,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	// Confirm password reset token
	rsp, err := pwdSvc.ConfirmPasswordReset(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &ResetPasswordOutput{
		Body: *rsp,
	}, err
}

func (c *authController) verifyEmailHandler(ctx context.Context, input *VerifyEmailInput) (*VerifyEmailOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	if input.Body.Token == "" {
		return nil, errors.New(errors.CodeBadRequest, "verification token is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionEmailVerify,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"token": input.Body.Token,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := authSvc.VerifyEmail(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &VerifyEmailOutput{
		Body: *response,
	}, nil
}

func (c *authController) verifyPhoneHandler(ctx context.Context, input *VerifyPhoneInput) (*VerifyPhoneOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	if input.Body.Token == "" {
		return nil, errors.New(errors.CodeBadRequest, "verification token is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionPhoneVerify,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"token": input.Body.Token,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := authSvc.VerifyPhone(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &VerifyPhoneOutput{
		Body: *response,
	}, nil
}

func (c *authController) resendVerificationHandler(ctx context.Context, input *ResendVerificationInput) (*ResendVerificationOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	if input.Body.Email == "" && input.Body.PhoneNumber == "" {
		return nil, errors.New(errors.CodeBadRequest, "email or phone number is required")
	}

	if input.Body.Type == "" {
		return nil, errors.New(errors.CodeBadRequest, "verification type is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionResendVerification,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"email":        input.Body.Email,
			"type":         input.Body.Type,
			"phone_number": input.Body.PhoneNumber,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := authSvc.ResendVerification(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &ResendVerificationOutput{
		Body: *response,
	}, nil
}

func (c *authController) magicLinkHandler(ctx context.Context, input *MagicLinkInput) (*MagicLinkOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	if input.Body.Email == "" {
		return nil, errors.New(errors.CodeBadRequest, "email is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionGenerateMagicLink,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"email":        input.Body.Email,
			"redirect_url": input.Body.RedirectURL,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := authSvc.SendMagicLink(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &MagicLinkOutput{
		Body: *response,
	}, nil
}

// VerifyMagicLinkInput represents a magic link verification request
type VerifyMagicLinkInput struct {
	Token string `path:"token" doc:"Magic link token"`
}

func (c *authController) verifyMagicLinkHandler(ctx context.Context, input *VerifyMagicLinkInput) (*LoginOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	if input.Token == "" {
		return nil, errors.New(errors.CodeBadRequest, "magic link token is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionUserLogin,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"token":  input.Token,
			"method": "magic_link",
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	// Verify magic link token
	response, err := authSvc.VerifyMagicLink(ctx, input.Token)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	logResp := &LoginOutput{
		Body: *response,
	}

	// Set session cookie if configured
	if response.Session != nil && c.di.Config().Auth.AllowSession && response.Session.Token != "" {
		logResp.SetCookie = c.createCookie(response.Session.Token)
	}

	return logResp, nil
}

func (c *authController) authStatusHandler(ctx context.Context, input *struct{}) (*AuthStatusOutput, error) { // Get current user from context
	currentUser := middleware.GetUserFromContext(ctx)
	currentSession := middleware.GetSessionFromContext(ctx)

	if currentUser == nil {
		// Return unauthenticated status instead of error
		response := &model.AuthStatus{
			IsAuthenticated: false,
		}
		return &AuthStatusOutput{
			Body: *response,
		}, nil
	}

	var sessId *xid.ID
	if currentSession != nil {
		sessId = &currentSession.ID
	}

	ctxType := userpermission.ContextTypeApplication

	if currentUser.UserType == user.UserTypeInternal {
		ctxType = userpermission.ContextTypeSystem
	} else if currentUser.UserType == user.UserTypeEndUser {
		ctxType = userpermission.ContextTypeOrganization
	}

	response, err := c.di.Auth().GetAuthStatus(
		ctx,
		currentUser.ID,
		ctxType,
		sessId,
		nil,
	)
	if err != nil {
		response := &model.AuthStatus{
			IsAuthenticated: false,
		}
		return &AuthStatusOutput{Body: *response}, nil
	}

	return &AuthStatusOutput{
		Body: *response,
	}, nil
}

type SetupTOTPInput struct {
	Body model.SetupTOTPRequest
}

type SetupTOTPOutput = model.Output[model.TOTPSetupResponse]

func (c *authController) mfaSetupHandler(ctx context.Context, input *SetupTOTPInput) (*SetupTOTPOutput, error) {
	mfaSvc := c.di.MFAService()
	if mfaSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "MFA service not available")
	}

	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionMFASetup,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"name": input.Body.Name,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := mfaSvc.SetupTOTP(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &SetupTOTPOutput{
		Body: *response,
	}, nil
}

type VerifyMFAInput struct {
	Body model.MFAVerifyRequest
}

type VerifyMFAOutput = model.Output[model.MFAVerifyResponse]

func (c *authController) mfaVerifyHandler(ctx context.Context, input *VerifyMFAInput) (*VerifyMFAOutput, error) {
	mfaSvc := c.di.MFAService()
	if mfaSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "MFA service not available")
	}

	if input.Body.Code == "" {
		return nil, errors.New(errors.CodeBadRequest, "MFA code is required")
	}

	if input.Body.Method == "" {
		input.Body.Method = "totp" // Default to TOTP
	}

	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionMFAEnable,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"method": input.Body.Method,
			"code":   input.Body.Code,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := mfaSvc.VerifyMFA(ctx, user.ID, input.Body.Method, input.Body.Code)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &VerifyMFAOutput{
		Body: *response,
	}, nil
}

func (c *authController) mfaDisableHandler(ctx context.Context, input *struct{}) (*model.EmptyOutput, error) {
	mfaSvc := c.di.MFAService()
	if mfaSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "MFA service not available")
	}

	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	auditEvent := audit.AuditEvent{
		Action:  audit.ActionMFADisable,
		Status:  audit.StatusFailure,
		Details: map[string]interface{}{},
		Source:  audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	err = mfaSvc.DisableAllMFA(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &model.EmptyOutput{}, nil
}

type GenerateBackupCodesInput struct {
	Body model.GenerateBackupCodesRequest
}

type GenerateBackupCodesOutput = model.Output[model.MFABackCodes]

func (c *authController) mfaBackupCodesHandler(ctx context.Context, input *GenerateBackupCodesInput) (*GenerateBackupCodesOutput, error) {
	mfaSvc := c.di.MFAService()
	if mfaSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "MFA service not available")
	}

	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionMFAGenerateBackup,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"count": input.Body.Count,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := mfaSvc.GenerateBackupCodes(ctx, user.ID, &input.Body)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &GenerateBackupCodesOutput{
		Body: *response,
	}, nil
}

func (c *authController) mfaRecoveryHandler(ctx context.Context, input *struct{}) (*model.EmptyOutput, error) {
	// TODO: Implement MFA recovery logic
	// 1. Validate backup code
	// 2. Mark backup code as used
	// 3. Authenticate user
	// 4. Return authentication tokens
	return nil, nil
}

func (c *authController) passkeyRegistrationBeginHandler(ctx context.Context, input *PasskeyRegistrationBeginInput) (*PasskeyRegistrationBeginOutput, error) {
	logger := c.di.Logger().Named("passkey-registration-begin")

	// Get current user from context (must be authenticated to register passkey)
	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	logger.Debug("Beginning passkey registration",
		logging.String("userId", user.ID.String()),
		logging.String("username", input.Body.Username))

	passkeyService := c.di.PasskeyService()
	if passkeyService == nil {
		return nil, errors.New(errors.CodeInternalServer, "passkey service not available")
	}

	// Set username from user if not provided
	if input.Body.Username == "" {
		input.Body.Username = user.Email
	}
	if input.Body.DisplayName == "" {
		displayName := user.FirstName + " " + user.LastName
		if displayName == " " {
			displayName = user.Email
		}
		input.Body.DisplayName = displayName
	}

	// Begin passkey registration
	response, err := passkeyService.BeginRegistration(ctx, input.Body)
	if err != nil {
		logger.Error("Failed to begin passkey registration", logging.Error(err))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to begin passkey registration")
	}

	// Log audit event
	auditEvent := audit.AuditEvent{
		Action: audit.ActionPasskeyRegisterBegin,
		Status: audit.StatusSuccess,
		Details: map[string]interface{}{
			"username":           input.Body.Username,
			"session_id":         response.SessionID,
			"authenticator_type": input.Body.AuthenticatorType,
		},
		Source: audit.SourceWeb,
	}
	c.logAuditEvent(ctx, auditEvent)

	logger.Info("Passkey registration begun successfully",
		logging.String("userId", user.ID.String()),
		logging.String("sessionId", response.SessionID))

	return &PasskeyRegistrationBeginOutput{
		Body: *response,
	}, nil
}

func (c *authController) passkeyRegistrationFinishHandler(ctx context.Context, input *PasskeyRegistrationFinishInput) (*PasskeyRegistrationFinishOutput, error) {
	logger := c.di.Logger().Named("passkey-registration-finish")

	// Get current user from context
	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	logger.Debug("Finishing passkey registration",
		logging.String("userId", user.ID.String()),
		logging.String("sessionId", input.Body.SessionID))

	passkeyService := c.di.PasskeyService()
	if passkeyService == nil {
		return nil, errors.New(errors.CodeInternalServer, "passkey service not available")
	}

	// Validate required fields
	if input.Body.SessionID == "" {
		return nil, errors.New(errors.CodeBadRequest, "session ID is required")
	}
	if input.Body.Response == nil {
		return nil, errors.New(errors.CodeBadRequest, "WebAuthn response is required")
	}
	if input.Body.Name == "" {
		input.Body.Name = "Passkey" // Default name
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionPasskeyRegisterFinish,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"session_id": input.Body.SessionID,
			"name":       input.Body.Name,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	// Finish passkey registration
	response, err := passkeyService.FinishRegistration(ctx, input.Body)
	if err != nil {
		logger.Error("Failed to finish passkey registration",
			logging.Error(err),
			logging.String("sessionId", input.Body.SessionID))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to finish passkey registration")
	}

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Details["passkey_id"] = response.Passkey.ID.String()
	auditEvent.Details["device_type"] = response.Passkey.DeviceType

	logger.Info("Passkey registration completed successfully",
		logging.String("userId", user.ID.String()),
		logging.String("passkeyId", response.Passkey.ID.String()),
		logging.String("name", response.Passkey.Name))

	return &PasskeyRegistrationFinishOutput{
		Body: *response,
	}, nil
}

func (c *authController) passkeyAuthenticationBeginHandler(ctx context.Context, input *PasskeyAuthenticationBeginInput) (*PasskeyAuthenticationBeginOutput, error) {
	logger := c.di.Logger().Named("passkey-auth-begin")

	logger.Debug("Beginning passkey authentication",
		logging.String("username", input.Body.Username))

	passkeyService := c.di.PasskeyService()
	if passkeyService == nil {
		return nil, errors.New(errors.CodeInternalServer, "passkey service not available")
	}

	// Validate username if provided
	if input.Body.Username == "" {
		return nil, errors.New(errors.CodeBadRequest, "username is required for passkey authentication")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionPasskeyAuthBegin,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"username": input.Body.Username,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	// Begin passkey authentication
	response, err := passkeyService.BeginAuthentication(ctx, input.Body)
	if err != nil {
		logger.Error("Failed to begin passkey authentication",
			logging.Error(err),
			logging.String("username", input.Body.Username))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to begin passkey authentication")
	}

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Details["session_id"] = response.SessionID

	logger.Info("Passkey authentication begun successfully",
		logging.String("username", input.Body.Username),
		logging.String("sessionId", response.SessionID))

	return &PasskeyAuthenticationBeginOutput{
		Body: *response,
	}, nil
}

func (c *authController) passkeyAuthenticationFinishHandler(ctx context.Context, input *PasskeyAuthenticationFinishInput) (*PasskeyAuthenticationFinishOutput, error) {
	logger := c.di.Logger().Named("passkey-auth-finish")

	logger.Debug("Finishing passkey authentication",
		logging.String("sessionId", input.Body.SessionID))

	passkeyService := c.di.PasskeyService()
	if passkeyService == nil {
		return nil, errors.New(errors.CodeInternalServer, "passkey service not available")
	}

	// Validate required fields
	if input.Body.SessionID == "" {
		return nil, errors.New(errors.CodeBadRequest, "session ID is required")
	}
	if input.Body.Response == nil {
		return nil, errors.New(errors.CodeBadRequest, "WebAuthn response is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionUserLogin,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"session_id": input.Body.SessionID,
			"method":     "passkey",
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	// Finish passkey authentication
	response, err := passkeyService.FinishAuthentication(ctx, input.Body)
	if err != nil {
		logger.Error("Failed to finish passkey authentication",
			logging.Error(err),
			logging.String("sessionId", input.Body.SessionID))
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "passkey authentication failed")
	}

	// Generate authentication tokens for successful authentication
	sessionInput := repository.CreateSessionInput{
		UserID:         response.User.ID,
		OrganizationID: response.User.OrganizationID,
		ExpiresAt:      time.Now().Add(24 * time.Hour),
		Metadata: map[string]interface{}{
			"login_method": "passkey",
		},
	}

	// Get client info from context if available
	if ipAddress, ok := middleware.GetIPAddressFromContext(ctx); ok {
		sessionInput.IPAddress = &ipAddress
	}
	if userAgent, ok := middleware.GetUserAgentFromContext(ctx); ok {
		sessionInput.UserAgent = &userAgent
	}

	session, err := c.di.SessionService().CreateSession(ctx, sessionInput)
	if err != nil {
		logger.Error("Failed to create session after passkey auth", logging.Error(err))
		// Don't fail the authentication, just log the error
	}

	// Generate tokens
	var accessToken, refreshToken string
	var expiresIn int

	if session != nil {
		tokenService := c.di.TokenService()
		if tokenService != nil {
			at, err := tokenService.CreateAccessToken(ctx, response.User.ID, response.User.OrganizationID, session.ID)
			if err == nil {
				accessToken = at.Token
				expiresIn = int(time.Until(at.ExpiresAt).Seconds())
			}

			rt, err := tokenService.CreateRefreshToken(ctx, response.User.ID, session.ID)
			if err == nil {
				refreshToken = rt.Token
			}
		}
	}

	// Update response with tokens
	response.AccessToken = accessToken
	response.RefreshToken = refreshToken
	response.ExpiresIn = expiresIn

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Details["user_id"] = response.User.ID.String()

	logger.Info("Passkey authentication completed successfully",
		logging.String("userId", response.User.ID.String()),
		logging.String("email", response.User.Email))

	logResp := &PasskeyAuthenticationFinishOutput{
		Body: *response,
	}

	// Set session cookie if configured
	if session != nil && c.di.Config().Auth.AllowSession && session.Token != "" {
		logResp.SetCookie = c.createCookie(session.Token)
	}

	return logResp, nil
}

func (c *authController) listPasskeysHandler(ctx context.Context, input *ListPasskeysInput) (*ListPasskeysOutput, error) {
	logger := c.di.Logger().Named("list-passkeys")

	// Get current user from context
	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	logger.Debug("Listing user passkeys",
		logging.String("userId", user.ID.String()))

	passkeyService := c.di.PasskeyService()
	if passkeyService == nil {
		return nil, errors.New(errors.CodeInternalServer, "passkey service not available")
	}

	// Build request parameters - limit to current user's passkeys
	listRequest := model.PasskeyListRequest{
		PaginationParams: input.PaginationParams,
		UserID:           model.OptionalParam[xid.ID]{Value: user.ID, IsSet: true},
		Active:           input.Active,
		DeviceType:       input.DeviceType,
		Search:           input.Search,
	}

	// List user's passkeys
	response, err := passkeyService.ListPasskeys(ctx, listRequest)
	if err != nil {
		logger.Error("Failed to list user passkeys",
			logging.Error(err),
			logging.String("userId", user.ID.String()))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to list passkeys")
	}

	logger.Debug("Listed user passkeys successfully",
		logging.String("userId", user.ID.String()),
		logging.Int("count", len(response.Data)))

	return &ListPasskeysOutput{
		Body: *response,
	}, nil
}

func (c *authController) deletePasskeyHandler(ctx context.Context, input *DeletePasskeyInput) (*model.EmptyOutput, error) {
	logger := c.di.Logger().Named("delete-passkey")

	// Get current user from context
	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	logger.Debug("Deleting user passkey",
		logging.String("userId", user.ID.String()),
		logging.String("passkeyId", input.ID.String()))

	passkeyService := c.di.PasskeyService()
	if passkeyService == nil {
		return nil, errors.New(errors.CodeInternalServer, "passkey service not available")
	}

	// First, verify the passkey belongs to the current user
	passkey, err := passkeyService.GetPasskey(ctx, input.ID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "passkey not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to retrieve passkey")
	}

	// Check ownership
	if passkey.UserID != user.ID {
		return nil, errors.New(errors.CodeForbidden, "you can only delete your own passkeys")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionPasskeyDelete,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"passkey_id":   input.ID.String(),
			"passkey_name": passkey.Name,
			"device_type":  passkey.DeviceType,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	// Delete the passkey
	err = passkeyService.DeletePasskey(ctx, input.ID)
	if err != nil {
		logger.Error("Failed to delete passkey",
			logging.Error(err),
			logging.String("passkeyId", input.ID.String()))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to delete passkey")
	}

	auditEvent.Status = audit.StatusSuccess

	logger.Info("Passkey deleted successfully",
		logging.String("userId", user.ID.String()),
		logging.String("passkeyId", input.ID.String()),
		logging.String("name", passkey.Name))

	return &model.EmptyOutput{}, nil
}

type OAuthAuthorizeOutput struct {
	model.RedirectOutput
}

func (c *authController) oauthAuthorizeHandler(ctx context.Context, input *OAuthProviderPathInput) (*OAuthAuthorizeOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	// Get OAuth URL for the provider
	redirectURL := "http://localhost:8080/auth/oauth/" + input.Provider + "/callback" // This should come from config

	auditEvent := audit.AuditEvent{
		Action: audit.ActionOAUTHAuthorize,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"provider":     input.Provider,
			"redirect_uri": redirectURL,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	oauthURL, err := authSvc.GetOAuthURL(ctx, input.Provider, redirectURL)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &OAuthAuthorizeOutput{
		RedirectOutput: model.RedirectOutput{
			Status:   http.StatusFound,
			Location: oauthURL,
		},
	}, nil
}

func (c *authController) oauthCallbackHandler(ctx context.Context, input *OAuthProviderPathInput) (*LoginOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionUserLogin,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"code":     input.Code,
			"provider": input.Provider,
			"method":   "oauth_" + input.Provider,
		},
		Source: audit.SourceWeb,
	}

	// Log authentication attempt
	defer c.logAuditEvent(ctx, auditEvent)

	response, err := authSvc.HandleOAuthCallback(ctx, input.Provider, input.Code, input.State)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &LoginOutput{
		Body: *response,
	}, nil
}

func (c *authController) oauthTokenHandler(ctx context.Context, input *OAuthTokenInput) (*OAuthTokenOutput, error) {
	logger := c.di.Logger().Named("oauth-token")

	logger.Debug("Processing OAuth token exchange",
		logging.String("grant_type", input.Body.GrantType),
		logging.String("client_id", input.Body.ClientID))

	oauthService := c.di.OAuthService()
	if oauthService == nil {
		return nil, errors.New(errors.CodeInternalServer, "OAuth service not available")
	}

	// Validate required fields
	if input.Body.GrantType == "" {
		return nil, errors.New(errors.CodeBadRequest, "grant_type is required")
	}

	if input.Body.ClientID == "" {
		return nil, errors.New(errors.CodeBadRequest, "client_id is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionOAuthTokenExchange,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"grant_type": input.Body.GrantType,
			"client_id":  input.Body.ClientID,
		},
		Source: audit.SourceAPI,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	var response *model.TokenResponse
	var err error

	// Handle different grant types
	switch input.Body.GrantType {
	case "authorization_code":
		// Validate authorization code grant
		if input.Body.Code == "" {
			return nil, errors.New(errors.CodeBadRequest, "code is required for authorization_code grant")
		}
		if input.Body.RedirectURI == "" {
			return nil, errors.New(errors.CodeBadRequest, "redirect_uri is required for authorization_code grant")
		}

		// Exchange authorization code for tokens
		response, err = oauthService.OAuth().ExchangeCodeForToken(ctx, input.Body)
		if err != nil {
			logger.Error("Failed to exchange authorization code", logging.Error(err))
			return nil, errors.Wrap(err, errors.CodeBadRequest, "invalid authorization code")
		}

	case "refresh_token":
		// Validate refresh token grant
		if input.Body.RefreshToken == "" {
			return nil, errors.New(errors.CodeBadRequest, "refresh_token is required for refresh_token grant")
		}

		// Refresh access token
		response, err = oauthService.OAuth().RefreshToken(ctx, input.Body)
		if err != nil {
			logger.Error("Failed to refresh token", logging.Error(err))
			return nil, errors.Wrap(err, errors.CodeBadRequest, "invalid refresh token")
		}

	case "client_credentials":
		// Validate client credentials
		if input.Body.ClientSecret == "" {
			return nil, errors.New(errors.CodeBadRequest, "client_secret is required for client_credentials grant")
		}

		// Handle client credentials flow
		clientCredsReq := model.OAuthClientCredentials{
			ClientID:     input.Body.ClientID,
			ClientSecret: input.Body.ClientSecret,
			GrantType:    input.Body.GrantType,
			Scope:        input.Body.Scope,
		}

		clientResponse, err := oauthService.OAuth().ClientCredentials(ctx, clientCredsReq)
		if err != nil {
			logger.Error("Failed client credentials flow", logging.Error(err))
			return nil, errors.Wrap(err, errors.CodeUnauthorized, "invalid client credentials")
		}

		// Convert to standard token response
		response = &model.TokenResponse{
			AccessToken: clientResponse.AccessToken,
			TokenType:   clientResponse.TokenType,
			ExpiresIn:   clientResponse.ExpiresIn,
			Scope:       clientResponse.Scope,
		}

	default:
		return nil, errors.Newf(errors.CodeBadRequest, "unsupported grant type: %s", input.Body.GrantType)
	}

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Details["token_type"] = response.TokenType
	auditEvent.Details["expires_in"] = response.ExpiresIn

	logger.Info("OAuth token exchange successful",
		logging.String("grant_type", input.Body.GrantType),
		logging.String("client_id", input.Body.ClientID),
		logging.Int("expires_in", response.ExpiresIn))

	return &OAuthTokenOutput{
		Body: *response,
	}, nil
}

func (c *authController) oauthUserInfoHandler(ctx context.Context, input *OAuthUserInfoInput) (*OAuthUserInfoOutput, error) {
	logger := c.di.Logger().Named("oauth-userinfo")

	logger.Debug("Processing OAuth user info request")

	oauthService := c.di.OAuthService()
	if oauthService == nil {
		return nil, errors.New(errors.CodeInternalServer, "OAuth service not available")
	}

	// Extract access token from Authorization header
	accessToken := input.Authorization
	if accessToken == "" {
		return nil, errors.New(errors.CodeUnauthorized, "access token is required")
	}

	// Remove "Bearer " prefix if present
	if len(accessToken) > 7 && accessToken[:7] == "Bearer " {
		accessToken = accessToken[7:]
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionOAuthUserInfo,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"token_prefix": c.getTokenPrefix(accessToken),
		},
		Source: audit.SourceAPI,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	// Get user info using the access token
	userInfo, err := oauthService.OAuth().GetUserInfo(ctx, accessToken)
	if err != nil {
		logger.Error("Failed to get user info", logging.Error(err))
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "invalid access token")
	}

	auditEvent.Status = audit.StatusSuccess
	if userID, ok := userInfo["sub"].(string); ok {
		auditEvent.Details["user_id"] = userID
	}

	logger.Info("OAuth user info retrieved successfully")

	return &OAuthUserInfoOutput{
		Body: userInfo,
	}, nil
}

func (c *authController) listOAuthProvidersHandler(ctx context.Context, input *struct{}) (*ListOAuthProvidersOutput, error) {
	logger := c.di.Logger().Named("list-oauth-providers")

	logger.Debug("Listing OAuth providers")

	// Build list of available OAuth providers
	providers := []model.AuthProvider{}
	return &ListOAuthProvidersOutput{
		Body: providers,
	}, nil
}

func (c *authController) listSessionsHandler(ctx context.Context, input *ListSessionsInput) (*ListSessionsOutput, error) {
	logger := c.di.Logger().Named("list-sessions")

	// Get current user from context
	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	logger.Debug("Listing user sessions",
		logging.String("userId", user.ID.String()))

	sessionService := c.di.SessionService()
	if sessionService == nil {
		return nil, errors.New(errors.CodeInternalServer, "session service not available")
	}

	// Get user's sessions
	result, err := sessionService.ListUserSessions(ctx, user.ID, input.ListSessionsParams)
	if err != nil {
		logger.Error("Failed to list user sessions",
			logging.Error(err),
			logging.String("userId", user.ID.String()))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to list sessions")
	}

	// Convert to SessionInfo objects
	sessions := make([]model.SessionInfo, len(result.Data))
	for i, session := range result.Data {
		sessions[i] = model.SessionInfo{
			ID:           session.ID,
			UserID:       session.UserID,
			IPAddress:    session.IPAddress,
			UserAgent:    session.UserAgent,
			DeviceID:     session.DeviceID,
			Location:     session.Location,
			Active:       session.Active,
			ExpiresAt:    session.ExpiresAt,
			LastActiveAt: session.LastActiveAt,
			CreatedAt:    session.CreatedAt,
		}
	}

	response := model.PaginatedOutput[model.SessionInfo]{
		Data:       sessions,
		Pagination: result.Pagination,
	}

	logger.Debug("User sessions listed successfully",
		logging.String("userId", user.ID.String()),
		logging.Int("count", len(sessions)))

	return &ListSessionsOutput{
		Body: response,
	}, nil
}

func (c *authController) revokeSessionHandler(ctx context.Context, input *RevokeSessionInput) (*model.EmptyOutput, error) {
	logger := c.di.Logger().Named("revoke-session")

	// Get current user from context
	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	logger.Debug("Revoking user session",
		logging.String("userId", user.ID.String()),
		logging.String("sessionId", input.ID.String()))

	sessionService := c.di.SessionService()
	if sessionService == nil {
		return nil, errors.New(errors.CodeInternalServer, "session service not available")
	}

	// First, verify the session belongs to the current user
	session, err := sessionService.GetSession(ctx, input.ID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "session not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to retrieve session")
	}

	// Check ownership
	if session.UserID != user.ID {
		return nil, errors.New(errors.CodeForbidden, "you can only revoke your own sessions")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionSessionRevoke,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"session_id": input.ID.String(),
			"ip_address": session.IPAddress,
			"user_agent": session.UserAgent,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	// Revoke the session
	err = sessionService.InvalidateSession(ctx, input.ID)
	if err != nil {
		logger.Error("Failed to revoke session",
			logging.Error(err),
			logging.String("sessionId", input.ID.String()))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to revoke session")
	}

	auditEvent.Status = audit.StatusSuccess

	logger.Info("Session revoked successfully",
		logging.String("userId", user.ID.String()),
		logging.String("sessionId", input.ID.String()))

	return &model.EmptyOutput{}, nil
}

func (c *authController) revokeAllSessionsHandler(ctx context.Context, input *RevokeAllSessionsInput) (*model.EmptyOutput, error) {
	logger := c.di.Logger().Named("revoke-all-sessions")

	// Get current user from context
	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	logger.Debug("Revoking all user sessions",
		logging.String("userId", user.ID.String()),
		logging.Bool("exceptCurrent", input.ExceptCurrent))

	sessionService := c.di.SessionService()
	if sessionService == nil {
		return nil, errors.New(errors.CodeInternalServer, "session service not available")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionSessionRevokeAll,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"except_current": input.ExceptCurrent,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	var sessionsRevoked int

	if input.ExceptCurrent {
		// Get current session from context
		currentSession := middleware.GetSessionFromContext(ctx)
		var currentSessionID *xid.ID
		if currentSession != nil {
			currentSessionID = &currentSession.ID
		}

		if currentSessionID == nil {
			return nil, errors.New(errors.CodeNotFound, "current session not found")
		}

		// Revoke all sessions except current
		count, err := sessionService.InvalidateOtherUserSessions(ctx, user.ID, *currentSessionID)
		if err != nil {
			logger.Error("Failed to revoke all user sessions except current",
				logging.Error(err),
				logging.String("userId", user.ID.String()))
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to revoke sessions")
		}
		sessionsRevoked = count
	} else {
		// Revoke all sessions
		count, err := sessionService.InvalidateAllUserSessions(ctx, user.ID)
		if err != nil {
			logger.Error("Failed to revoke all user sessions",
				logging.Error(err),
				logging.String("userId", user.ID.String()))
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to revoke sessions")
		}
		sessionsRevoked = count
	}

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Details["sessions_revoked"] = sessionsRevoked

	logger.Info("All user sessions revoked successfully",
		logging.String("userId", user.ID.String()),
		logging.Int("sessionsRevoked", sessionsRevoked),
		logging.Bool("exceptCurrent", input.ExceptCurrent))

	return &model.EmptyOutput{}, nil
}

// Helper methods

func (c *authController) getTokenPrefix(token string) string {
	if len(token) > 8 {
		return token[:8] + "..."
	}
	return token
}

func (c *authController) logAuditEvent(ctx context.Context, event audit.AuditEvent) {
	if event.Resource == "" {
		event.Resource = "auth"
	}
	logAuditEvent(ctx, event, c.di.AuditService(), c.di.Logger())
}

func (c *authController) getLoginMethod(req model.LoginRequest) string {
	if req.Provider != "" {
		return "oauth_" + req.Provider
	}
	if req.Password != "" {
		return "password"
	}
	if req.PhoneNumber != "" {
		return "sms"
	}
	return "unknown"
}

func (c *authController) deleteCookie() http.Cookie {
	return http.Cookie{
		Name:     c.di.Config().Auth.SessionName,
		Value:    "",
		Domain:   c.di.Config().Auth.CookieDomain,
		Path:     "/",
		Secure:   c.di.Config().Auth.CookieSecure,
		HttpOnly: c.di.Config().Auth.CookieHTTPOnly,
		MaxAge:   -1,
	}
}

func (c *authController) createCookie(token string) http.Cookie {
	return http.Cookie{
		Name:     c.di.Config().Auth.SessionName,
		Value:    token,
		Domain:   c.di.Config().Auth.CookieDomain,
		Path:     "/",
		Secure:   c.di.Config().Auth.CookieSecure,
		HttpOnly: c.di.Config().Auth.CookieHTTPOnly,
		MaxAge:   int(c.di.Config().Auth.CookieMaxAge.Seconds()),
	}
}

func logAuditEvent(ctx context.Context, event audit.AuditEvent, auditService audit.Service, logg logging.Logger) {
	logger := logg.Named("audit")

	// Get IP address and user agent from context
	ipAddress, _ := middleware.GetIPAddressFromContext(ctx)
	userAgent, _ := middleware.GetUserAgentFromContext(ctx)
	event.UserAgent = userAgent
	event.IPAddress = ipAddress

	user := middleware.GetUserFromContext(ctx)
	if user != nil {
		event.UserID = &user.ID
	}

	orgId := middleware.GetOrganizationIDFromContext(ctx)
	if orgId != nil {
		event.OrganizationID = orgId
	}

	session := middleware.GetSessionFromContext(ctx)
	if session != nil {
		event.SessionID = &session.ID
	}

	auditService.LogEvent(ctx, event)

	logger.Info("Audit event",
		logging.String("action", event.Action),
		logging.String("status", event.Status),
		logging.String("ip", event.IPAddress),
		logging.String("source", event.Source),
		logging.Any("details", event.Details))
}
