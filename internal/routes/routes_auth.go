package routes

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/xid"
	"github.com/samber/lo"
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/internal/di"
	"github.com/xraph/frank/internal/middleware"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/contexts"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"github.com/xraph/frank/pkg/services/audit"
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
	registerForgotPassword(group, authCtrl)
	registerResetPassword(group, authCtrl)
	registerValidateToken(group, authCtrl)
	registerVerifyEmail(group, authCtrl)
	registerVerifyPhone(group, authCtrl)
	registerResendVerification(group, authCtrl)
	registerMagicLink(group, authCtrl)
	registerVerifyMagicLink(group, authCtrl)
	// registerAuthStatus(group, authCtrl)

	// MFA endpoints
	registerMFARecovery(group, authCtrl)
	registerMFAVerify(group, authCtrl)

	// Passkey endpoints
	registerPasskeyAuthenticationBegin(group, authCtrl)
	registerPasskeyAuthenticationFinish(group, authCtrl)

	// OAuth endpoints
	registerOAuthAuthorizeByAuth(group, authCtrl)
	registerOAuthCallback(group, authCtrl)
	registerOAuthTokenByAuth(group, authCtrl)
	registerOAuthUserInfoByAuth(group, authCtrl)
	registerListOAuthProviders(group, authCtrl)
}

// RegisterAuthAPI registers all authentication-related endpoints
func RegisterAuthAPI(group huma.API, di di.Container) {
	// authCtrl := &authController{
	// 	group: group,
	// 	di:    di,
	// }
	//
	// // MFA endpoints
	// registerMFASetup(group, authCtrl)
	// registerMFASetupVerify(group, authCtrl)
	// registerMFADisable(group, authCtrl)
	// registerMFABackupCodes(group, authCtrl)
}

// RegisterPersonalAuthAPI New function to register personal auth endpoints
func RegisterPersonalAuthAPI(group huma.API, di di.Container) {
	authCtrl := &authController{
		group: group,
		di:    di,
	}

	// Personal auth operations that don't need organization context
	registerLogout(group, authCtrl)
	registerRefreshToken(group, authCtrl)
	registerAuthStatus(group, authCtrl)

	// Personal MFA endpoints
	registerMFASetup(group, authCtrl)
	registerMFASetupVerify(group, authCtrl)
	registerMFADisable(group, authCtrl)
	registerMFABackupCodes(group, authCtrl)

	// Personal passkey endpoints
	registerPasskeyRegistrationBegin(group, authCtrl)
	registerPasskeyRegistrationFinish(group, authCtrl)
	registerListPasskeys(group, authCtrl)
	registerDeletePasskey(group, authCtrl)

	// Personal session management
	registerRefreshSession(group, authCtrl)
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
	}, authCtrl.unifiedRegistrationHandler)
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

func registerValidateToken(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "validateToken",
		Method:      http.MethodPost,
		Path:        "/auth/validate-token",
		Summary:     "Validate token",
		Description: "Validate token token from email",
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.verifyTokenHandler)
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
		Tags:        []string{"Authentication"},
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
		Tags:        []string{"Authentication"},
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
		Tags:        []string{"Authentication"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.mfaSetupHandler)
}

// Register the new setup verification endpoint
func registerMFASetupVerify(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "verifyMFASetup",
		Method:      http.MethodPost,
		Path:        "/auth/mfa/setup/verify",
		Summary:     "Verify MFA setup",
		Description: "Verify MFA method setup with code to complete configuration",
		Tags:        []string{"Authentication"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.mfaSetupVerifyHandler)
}
func registerMFAVerify(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "verifyMFAAuth",
		Method:      http.MethodPost,
		Path:        "/auth/mfa/verify",
		Summary:     "Verify MFA",
		Description: "Verify multi-factor authentication code",
		Tags:        []string{"Authentication"},
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
		Tags:        []string{"Authentication"},
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
		Tags:        []string{"Authentication"},
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
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.mfaRecoveryHandler)
}

// Passkey Endpoints

func registerPasskeyRegistrationBegin(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "beginPasskeyRegistrationAuth",
		Method:      http.MethodPost,
		Path:        "/auth/passkeys/register/begin",
		Summary:     "Begin passkey registration",
		Description: "Begin WebAuthn passkey registration process",
		Tags:        []string{"Authentication"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.passkeyRegistrationBeginHandler)
}

func registerPasskeyRegistrationFinish(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "finishPasskeyRegistrationAuth",
		Method:      http.MethodPost,
		Path:        "/auth/passkeys/register/finish",
		Summary:     "Finish passkey registration",
		Description: "Complete WebAuthn passkey registration process",
		Tags:        []string{"Authentication"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.passkeyRegistrationFinishHandler)
}

func registerPasskeyAuthenticationBegin(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "beginPasskeyAuthenticationAuth",
		Method:      http.MethodPost,
		Path:        "/auth/passkeys/authenticate/begin",
		Summary:     "Begin passkey authentication",
		Description: "Begin WebAuthn passkey authentication process",
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.passkeyAuthenticationBeginHandler)
}

func registerPasskeyAuthenticationFinish(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "finishPasskeyAuthenticationAuth",
		Method:      http.MethodPost,
		Path:        "/auth/passkeys/authenticate/finish",
		Summary:     "Finish passkey authentication",
		Description: "Complete WebAuthn passkey authentication process",
		Tags:        []string{"Authentication"},
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
		Tags:        []string{"Authentication"},
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
		Tags:        []string{"Authentication"},
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

func registerOAuthAuthorizeByAuth(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "oauthAuthorizeByAuth",
		Method:      http.MethodGet,
		Path:        "/auth/oauth/{provider}/authorize",
		Summary:     "OAuth authorization",
		Description: "Redirect to OAuth provider for authorization",
		Tags:        []string{"Authentication"},
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
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.oauthCallbackHandler)
}

func registerOAuthTokenByAuth(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "oauthTokenByAuth",
		Method:      http.MethodPost,
		Path:        "/auth/oauth/token",
		Summary:     "OAuth token exchange",
		Description: "Exchange OAuth authorization code for tokens",
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.oauthTokenHandler)
}

func registerOAuthUserInfoByAuth(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "oauthUserInfoByAuth",
		Method:      http.MethodGet,
		Path:        "/auth/oauth/userinfo",
		Summary:     "OAuth user info",
		Description: "Get user information from OAuth token",
		Tags:        []string{"Authentication"},
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
		Tags:        []string{"Authentication"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, authCtrl.listOAuthProvidersHandler)
}

// Session Management Endpoints
func registerRefreshSession(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "refreshSession",
		Method:      http.MethodPost,
		Path:        "/auth/sessions/{id}/refresh",
		Summary:     "Refresh session",
		Description: "Extend a session's expiration time",
		Tags:        []string{"Authentication"},
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Responses: model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Session not found")),
	}, authCtrl.refreshSessionHandler)
}

func registerListSessions(group huma.API, authCtrl *authController) {
	huma.Register(group, huma.Operation{
		OperationID: "listSessions",
		Method:      http.MethodGet,
		Path:        "/auth/sessions",
		Summary:     "List user sessions",
		Description: "List all active sessions for the current user",
		Tags:        []string{"Authentication"},
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
		Tags:        []string{"Authentication"},
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
		Tags:        []string{"Authentication"},
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

// ListOAuthProvidersOutput Input/Output type definitions for OAuth and session handlers
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
	// Check if user is already authenticated (but allow client API keys through)
	currentUser := middleware.GetUserFromContext(ctx)
	requestedOrgID := c.getRequestedOrganizationID(ctx)

	// Check if we need to handle organization context switching
	if currentUser != nil && !middleware.IsClientAPIKey(ctx) {
		needsOrgSwitch, err := c.needsOrganizationSwitch(ctx, currentUser, requestedOrgID)
		if err != nil {
			return nil, err
		}

		if !needsOrgSwitch {
			return nil, errors.New(errors.CodeBadRequest, "user is already authenticated in the same organization context")
		}

		// Handle organization switching by invalidating current session
		if err := c.handleOrganizationSwitch(ctx, currentUser, requestedOrgID); err != nil {
			c.di.Logger().Warn("Failed to handle organization switch", logging.Error(err))
			// Continue with login instead of failing
		}
	}

	// Get organization context from API key or header with enhanced detection
	var orgID *xid.ID
	if apiOrgID := c.getOrganizationFromAPIKey(ctx); apiOrgID != nil {
		orgID = apiOrgID
	} else {
		// Enhanced organization context detection
		orgID = c.detectOrganizationContext(ctx, input.Body)
		if orgID != nil {
			c.di.Logger().Debug("Detected organization context for login",
				logging.String("orgId", orgID.String()),
				logging.String("email", input.Body.Email))
		}
	}

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
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"email":               input.Body.Email,
			"provider":            input.Body.Provider,
			"method":              c.getLoginMethod(input.Body),
			"organization_id":     orgIDToString(orgID),
			"organization_switch": currentUser != nil,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := authSvc.Login(ctx, input.Body, orgID)
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
		logResp.SetCookie = c.createCookie(ctx, response.Session.Token)
	}

	return logResp, nil
}

func (c *authController) registerHandler(ctx context.Context, input *RegisterInput) (*RegisterOutput, error) {
	// Check if user is already authenticated (but allow client API keys through)
	currentUser := middleware.GetUserFromContext(ctx)
	if currentUser != nil && !middleware.IsClientAPIKey(ctx) {
		return nil, errors.New(errors.CodeBadRequest, "user is already authenticated")
	}

	// Get organization context from API key or header
	var orgID *xid.ID
	if apiOrgID := c.getOrganizationFromAPIKey(ctx); apiOrgID != nil {
		orgID = apiOrgID
		input.Body.OrganizationID = orgID
	} else {
		userType := c.getDetectedUserType(ctx)
		if err := c.validateOrganizationContext(ctx, userType, true); err != nil {
			return nil, err
		}
		orgContext := c.getOrganizationContext(ctx)
		if orgContext != nil {
			input.Body.OrganizationID = &orgContext.ID
		}
	}

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
		Status: audit.StatusFailure,
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

func (c *authController) unifiedRegistrationHandler(ctx context.Context, input *RegisterInput) (*RegisterOutput, error) {
	// Check if user is already authenticated (but allow client API keys through)
	currentUser := middleware.GetUserFromContext(ctx)
	requestedOrgID := c.getRequestedOrganizationID(ctx)

	// Allow registration even if authenticated, but handle organization context switching
	if currentUser != nil && !middleware.IsClientAPIKey(ctx) {
		needsOrgSwitch, err := c.needsOrganizationSwitch(ctx, currentUser, requestedOrgID)
		if err != nil {
			return nil, err
		}

		if !needsOrgSwitch {
			// User is authenticated in the same organization context
			// This might be valid for certain scenarios (e.g., creating additional accounts)
			c.di.Logger().Debug("User attempting registration while authenticated in same org context",
				logging.String("userId", currentUser.ID.String()),
				logging.String("email", input.Body.Email))
		} else {
			// Handle organization switching
			if err := c.handleOrganizationSwitch(ctx, currentUser, requestedOrgID); err != nil {
				c.di.Logger().Warn("Failed to handle organization switch during registration", logging.Error(err))
			}
		}
	}

	// Get organization context from API key first, then fallback to other sources
	var orgID *xid.ID
	if apiOrgID := c.getOrganizationFromAPIKey(ctx); apiOrgID != nil {
		orgID = apiOrgID
		// Set organization context in flow data for consistency
		flowData := contexts.GetRegistrationFlowDataFromContext(ctx)
		if flowData == nil {
			flowData = make(map[string]interface{})
		}
		flowData["organization_id"] = apiOrgID.String()
		ctx = context.WithValue(ctx, contexts.RegistrationFlowDataKey, flowData)
	} else {
		phoneNumber := ""
		if input.Body.PhoneNumber != nil {
			phoneNumber = *input.Body.PhoneNumber
		}
		// Enhanced organization context detection for registration
		orgID = c.detectOrganizationContext(ctx, model.LoginRequest{
			Email:       input.Body.Email,
			PhoneNumber: phoneNumber,
		})
		if orgID != nil {
			c.di.Logger().Debug("Detected organization context for registration",
				logging.String("orgId", orgID.String()),
				logging.String("email", input.Body.Email))
		}
	}

	// Get detected flow from middleware
	flow := contexts.GetRegistrationFlowFromContext(ctx)
	flowData := contexts.GetRegistrationFlowDataFromContext(ctx)

	c.di.Logger().Info("Processing unified registration",
		logging.String("email", input.Body.Email),
		logging.String("userType", input.Body.UserType),
		logging.String("flow", string(flow)),
		logging.Bool("hasClientAPIKey", middleware.IsClientAPIKey(ctx)),
		logging.String("orgFromAPIKey", orgIDToString(orgID)),
		logging.Bool("organizationSwitch", currentUser != nil))

	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	// Validate required fields
	if input.Body.Email == "" {
		return nil, errors.New(errors.CodeBadRequest, "email is required")
	}

	// Set default user type if not provided
	if input.Body.UserType == "" {
		if detectedType, ok := flowData["user_type"].(string); ok && detectedType != "" {
			input.Body.UserType = detectedType
		} else {
			// Default based on API key context or fallback
			if middleware.IsClientAPIKey(ctx) {
				input.Body.UserType = string(model.UserTypeEndUser) // Client API keys typically for end users
			} else {
				input.Body.UserType = string(model.UserTypeExternal) // Default
			}
		}
	}

	// Set organization ID from enhanced detection if available
	if orgID != nil {
		input.Body.OrganizationID = orgID
	}

	// Process registration based on detected flow
	switch flow {
	case contexts.RegistrationFlowOrganization:
		return c.handleOrganizationCreationRegistration(ctx, input, flowData)
	case contexts.RegistrationFlowInvitation:
		return c.handleInvitationBasedRegistration(ctx, input, flowData)
	case contexts.RegistrationFlowInternalUser:
		return c.handleInternalUserRegistration(ctx, input, flowData)
	case contexts.RegistrationFlowExternalUser:
		return c.handleExternalUserRegistration(ctx, input, flowData)
	case contexts.RegistrationFlowEndUser:
		return c.handleEndUserRegistration(ctx, input, flowData)
	default:
		// Default flow based on API key context
		if middleware.IsClientAPIKey(ctx) && orgID != nil {
			// Client API key with organization context - likely end user registration
			return c.handleEndUserRegistration(ctx, input, flowData)
		} else {
			// Default to external user registration
			return c.handleExternalUserRegistration(ctx, input, flowData)
		}
	}
}

// needsOrganizationSwitch determines if the current user needs to switch organization context
func (c *authController) needsOrganizationSwitch(ctx context.Context, currentUser *middleware.UserContext, requestedOrgID *xid.ID) (bool, error) {
	// Internal users don't need organization switching
	if currentUser.UserType == model.UserTypeInternal {
		return false, nil
	}

	// If no organization is requested, no switch needed
	if requestedOrgID == nil {
		return false, nil
	}

	// If user has no organization context, switch is needed
	if currentUser.OrganizationID == nil {
		return true, nil
	}

	// If user is in a different organization, switch is needed
	if *currentUser.OrganizationID != *requestedOrgID {
		return true, nil
	}

	// No switch needed - same organization context
	return false, nil
}

// handleOrganizationSwitch handles switching between organization contexts
func (c *authController) handleOrganizationSwitch(ctx context.Context, currentUser *middleware.UserContext, newOrgID *xid.ID) error {
	c.di.Logger().Info("Handling organization context switch",
		logging.String("userId", currentUser.ID.String()),
		logging.String("currentOrgId", orgIDToString(currentUser.OrganizationID)),
		logging.String("newOrgId", orgIDToString(newOrgID)))

	// Invalidate current session if it exists
	if currentSession := middleware.GetSessionFromContext(ctx); currentSession != nil {
		sessionService := c.di.SessionService()
		if sessionService != nil {
			err := sessionService.InvalidateSession(ctx, currentSession.ID)
			if err != nil {
				c.di.Logger().Error("Failed to invalidate session during organization switch",
					logging.Error(err),
					logging.String("sessionId", currentSession.ID.String()))
				return errors.Wrap(err, errors.CodeInternalServer, "failed to invalidate current session")
			}

			c.di.Logger().Debug("Invalidated session for organization switch",
				logging.String("sessionId", currentSession.ID.String()))
		}
	}

	// Log audit event for organization switch
	auditEvent := audit.AuditEvent{
		Action: audit.ActionOrganizationSwitch,
		Status: audit.StatusSuccess,
		Details: map[string]interface{}{
			"previous_organization_id": orgIDToString(currentUser.OrganizationID),
			"new_organization_id":      orgIDToString(newOrgID),
			"user_type":                currentUser.UserType,
		},
		Source: audit.SourceWeb,
	}
	c.logAuditEvent(ctx, auditEvent)

	return nil
}

// detectOrganizationContext attempts to detect organization context from various sources
func (c *authController) detectOrganizationContext(ctx context.Context, req model.LoginRequest) *xid.ID {
	// 1. Check API key organization context
	if apiOrgID := c.getOrganizationFromAPIKey(ctx); apiOrgID != nil {
		return apiOrgID
	}

	// 2. Check detected organization ID from middleware
	if detectedOrgID := c.getDetectedOrganizationID(ctx); detectedOrgID != nil {
		return detectedOrgID
	}

	// 3. Check organization context from headers/request
	if orgContext := c.getOrganizationContext(ctx); orgContext != nil {
		return &orgContext.ID
	}

	// 4. For end users, try to find organization from user's email domain (if configured)
	userType := c.getDetectedUserType(ctx)
	if userType == string(model.UserTypeEndUser) && req.Email != "" {
		if orgID := c.findOrganizationByEmailDomain(ctx, req.Email); orgID != nil {
			c.di.Logger().Debug("Found organization by email domain",
				logging.String("email", req.Email),
				logging.String("orgId", orgID.String()))
			return orgID
		}
	}

	return nil
}

// findOrganizationByEmailDomain attempts to find an organization by email domain
func (c *authController) findOrganizationByEmailDomain(ctx context.Context, email string) *xid.ID {
	if email == "" {
		return nil
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil
	}

	domain := parts[1]

	// Try to find organization by domain
	org, err := c.di.Repo().Organization().GetByDomain(ctx, domain)
	if err != nil {
		// Domain not found or error - this is normal
		return nil
	}

	if !org.Active {
		return nil
	}

	return &org.ID
}

// getRequestedOrganizationID gets the organization ID being requested in the current context
func (c *authController) getRequestedOrganizationID(ctx context.Context) *xid.ID {
	// Try various sources in priority order

	// 1. From API key context
	if apiOrgID := c.getOrganizationFromAPIKey(ctx); apiOrgID != nil {
		return apiOrgID
	}

	// 2. From detected organization context
	if detectedOrgID := c.getDetectedOrganizationID(ctx); detectedOrgID != nil {
		return detectedOrgID
	}

	// 3. From organization context
	if orgContext := c.getOrganizationContext(ctx); orgContext != nil {
		return &orgContext.ID
	}

	// 4. From middleware context
	if orgID := middleware.GetOrganizationIDFromContext(ctx); orgID != nil {
		return orgID
	}

	return nil
}

func (c *authController) handleOrganizationCreationRegistration(ctx context.Context, input *RegisterInput, flowData map[string]interface{}) (*RegisterOutput, error) {
	// Organization creation flow - typically not used with client API keys
	// but we'll handle it gracefully
	auditEvent := audit.AuditEvent{
		Action: audit.ActionOrganizationRegister,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"email":          input.Body.Email,
			"user_type":      input.Body.UserType,
			"flow":           "organization_creation",
			"via_client_api": middleware.IsClientAPIKey(ctx),
		},
		Source: audit.SourceWeb,
	}
	defer c.logAuditEvent(ctx, auditEvent)

	// Convert to organization registration request
	orgRegRequest := model.OrganizationRegistrationRequest{
		OrganizationName:     c.getOrganizationNameFromRequest(input.Body),
		OrganizationSlug:     c.getOrganizationSlugFromRequest(input.Body),
		Domain:               c.getDomainFromRequest(input.Body),
		Plan:                 c.getPlanFromRequest(input.Body),
		UserEmail:            input.Body.Email,
		UserPassword:         input.Body.Password,
		UserFirstName:        *input.Body.FirstName,
		UserLastName:         *input.Body.LastName,
		UserPhone:            *input.Body.PhoneNumber,
		UserCustomAttributes: input.Body.CustomAttributes,
		Metadata:             input.Body.Metadata,
	}

	authSvc := c.di.Auth()
	orgResponse, err := authSvc.RegisterOrganization(ctx, orgRegRequest)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Details["organization_id"] = orgResponse.Organization.ID.String()

	// Convert to standard register response
	response := &model.RegisterResponse{
		Success:      true,
		User:         orgResponse.User,
		AccessToken:  orgResponse.AccessToken,
		RefreshToken: orgResponse.RefreshToken,
		ExpiresIn:    orgResponse.ExpiresIn,
		Message:      "Organization and user created successfully",
	}

	return &RegisterOutput{Body: *response}, nil
}

func (c *authController) handleInvitationBasedRegistration(ctx context.Context, input *RegisterInput, flowData map[string]interface{}) (*RegisterOutput, error) {
	// Invitation-based registration
	invitationToken := flowData["invitation_token"].(string)

	auditEvent := audit.AuditEvent{
		Action: audit.ActionUserRegisterInvitation,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"email":            input.Body.Email,
			"invitation_token": invitationToken[:8] + "...",
			"flow":             "invitation_based",
			"via_client_api":   middleware.IsClientAPIKey(ctx),
		},
		Source: audit.SourceWeb,
	}
	defer c.logAuditEvent(ctx, auditEvent)

	// Convert to invitation registration request
	inviteRegRequest := model.InvitationRegistrationRequest{
		InvitationToken: invitationToken,
		Email:           input.Body.Email,
		Password:        input.Body.Password,
		FirstName:       *input.Body.FirstName,
		LastName:        *input.Body.LastName,
		Phone:           *input.Body.PhoneNumber,
		AcceptTerms:     input.Body.AcceptTerms,
		AcceptPrivacy:   input.Body.AcceptPrivacy,
	}

	authSvc := c.di.Auth()
	inviteResponse, err := authSvc.RegisterViaInvitation(ctx, inviteRegRequest)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Details["organization_id"] = inviteResponse.Organization.ID.String()

	// Convert to standard register response
	response := &model.RegisterResponse{
		Success:      true,
		User:         inviteResponse.User,
		AccessToken:  inviteResponse.AccessToken,
		RefreshToken: inviteResponse.RefreshToken,
		ExpiresIn:    inviteResponse.ExpiresIn,
		Message:      "User registered via invitation successfully",
	}

	return &RegisterOutput{Body: *response}, nil
}

func (c *authController) handleInternalUserRegistration(ctx context.Context, input *RegisterInput, flowData map[string]interface{}) (*RegisterOutput, error) {
	// Internal user registration (no org context needed)
	auditEvent := audit.AuditEvent{
		Action: audit.ActionUserRegister,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"email":     input.Body.Email,
			"user_type": model.UserTypeInternal,
			"flow":      "internal_user",
		},
		Source: audit.SourceWeb,
	}
	defer c.logAuditEvent(ctx, auditEvent)

	// Set user type to internal
	input.Body.UserType = string(model.UserTypeInternal)
	input.Body.OrganizationID = nil // Internal users don't belong to specific org

	authSvc := c.di.Auth()
	response, err := authSvc.Register(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &RegisterOutput{Body: *response}, nil
}

func (c *authController) handleExternalUserRegistration(ctx context.Context, input *RegisterInput, flowData map[string]interface{}) (*RegisterOutput, error) {
	// External user registration (may have org context from API key)
	auditEvent := audit.AuditEvent{
		Action: audit.ActionUserRegister,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"email":          input.Body.Email,
			"user_type":      model.UserTypeExternal,
			"flow":           "external_user",
			"via_client_api": middleware.IsClientAPIKey(ctx),
		},
		Source: audit.SourceWeb,
	}
	defer c.logAuditEvent(ctx, auditEvent)

	// Set user type to external
	input.Body.UserType = string(model.UserTypeExternal)

	// Get organization context from API key if available
	if apiOrgID := c.getOrganizationFromAPIKey(ctx); apiOrgID != nil {
		input.Body.OrganizationID = apiOrgID
		auditEvent.Details["organization_id"] = apiOrgID.String()
	} else {
		// External users can register without organization context
		// They'll join organizations later via invitations
		input.Body.OrganizationID = nil
	}

	authSvc := c.di.Auth()
	response, err := authSvc.Register(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	// Add helpful message about joining organizations
	if input.Body.OrganizationID == nil {
		response.Message = "Registration successful. You can join organizations via invitations."
	} else {
		response.Message = "Registration successful."
	}

	auditEvent.Status = audit.StatusSuccess

	return &RegisterOutput{Body: *response}, nil
}

func (c *authController) handleEndUserRegistration(ctx context.Context, input *RegisterInput, flowData map[string]interface{}) (*RegisterOutput, error) {
	// Get organization context from API key or other sources
	var orgContext *contexts.OrganizationContext
	var orgID *xid.ID

	if apiOrgID := c.getOrganizationFromAPIKey(ctx); apiOrgID != nil {
		orgID = apiOrgID
		// Create organization context from API key
		orgContext = &contexts.OrganizationContext{
			ID: *orgID,
			// Other fields would be populated by looking up the organization
		}
	} else {
		orgContext = c.getOrganizationContext(ctx)
		if orgContext != nil {
			orgID = &orgContext.ID
		}
	}

	if orgID == nil {
		return nil, errors.New(errors.CodeBadRequest, "organization context is required for end user registration 3")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionUserRegister,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"email":           input.Body.Email,
			"user_type":       model.UserTypeEndUser,
			"organization_id": orgID.String(),
			"flow":            "end_user",
			"via_client_api":  middleware.IsClientAPIKey(ctx),
		},
		Source: audit.SourceWeb,
	}
	defer c.logAuditEvent(ctx, auditEvent)

	// Set user type and organization
	input.Body.UserType = string(model.UserTypeEndUser)
	input.Body.OrganizationID = orgID

	authSvc := c.di.Auth()
	response, err := authSvc.Register(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &RegisterOutput{Body: *response}, nil
}

func (c *authController) logoutHandler(ctx context.Context, input *LogoutInput) (*LogoutOutput, error) {
	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	currentUser := middleware.GetUserFromContext(ctx)
	currentSession := middleware.GetSessionFromContext(ctx)

	auditEvent := audit.AuditEvent{
		Action: audit.ActionUserLogout,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"logout_all":      input.Body.LogoutAll,
			"organization_id": orgIDToString(currentUser.OrganizationID),
			"session_id":      sessionIDToString(currentSession),
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := authSvc.Logout(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	// Create response with cookie deletion
	logoutResp := &LogoutOutput{
		SetCookie: c.deleteCookie(ctx),
		Body:      *response,
	}

	// Add additional cookies to clear if needed
	if input.Body.LogoutAll {
		// Clear any additional session-related cookies
		logoutResp.Body.Message = "Logged out from all sessions successfully"
	}

	return logoutResp, nil
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

type VerifyTokenInput struct {
	Body model.ValidateTokenInputBody
}

type VerifyTokenOutput = model.Output[model.ValidateTokenResponse]

func (c *authController) verifyTokenHandler(ctx context.Context, input *VerifyTokenInput) (*VerifyTokenOutput, error) {
	pwdSvc := c.di.PasswordService()
	if pwdSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "password service not available")
	}

	if input.Body.Token == "" {
		return nil, errors.New(errors.CodeBadRequest, "reset token is required")
	}

	if input.Body.Token == "" {
		return nil, errors.New(errors.CodeBadRequest, "token type is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionPasswordChange,
		Status: audit.StatusFailure, // Will be updated if login fails
		Details: map[string]interface{}{
			"token": input.Body.Token,
			"type":  input.Body.Type,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	var rsp *model.ValidateTokenResponse
	var err error

	switch input.Body.Type {
	case "password_reset":
		// Confirm password reset token
		rsp, err = pwdSvc.ValidatePasswordResetToken(ctx, input.Body.Token)
		if err != nil {
			return nil, err
		}
		break
	default:
		return nil, errors.New(errors.CodeBadRequest, "invalid token type")
	}

	auditEvent.Status = audit.StatusSuccess

	return &VerifyTokenOutput{
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
	// Check if user is already authenticated (but allow client API keys through)
	currentUser := middleware.GetUserFromContext(ctx)
	requestedOrgID := c.getRequestedOrganizationID(ctx)

	// Allow magic link generation even if authenticated, but handle organization context switching
	if currentUser != nil && !middleware.IsClientAPIKey(ctx) {
		needsOrgSwitch, err := c.needsOrganizationSwitch(ctx, currentUser, requestedOrgID)
		if err != nil {
			return nil, err
		}

		if needsOrgSwitch {
			c.di.Logger().Debug("User requesting magic link for different organization context",
				logging.String("userId", currentUser.ID.String()),
				logging.String("currentOrgId", orgIDToString(currentUser.OrganizationID)),
				logging.String("requestedOrgId", orgIDToString(requestedOrgID)))
		}
	}

	// Get organization context from API key or header with enhanced detection
	var orgID *xid.ID
	if apiOrgID := c.getOrganizationFromAPIKey(ctx); apiOrgID != nil {
		orgID = apiOrgID
	} else {
		// Enhanced organization context detection for magic link
		orgID = c.detectOrganizationContext(ctx, model.LoginRequest{
			Email: input.Body.Email,
		})
	}

	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	if input.Body.Email == "" {
		return nil, errors.New(errors.CodeBadRequest, "email is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionGenerateMagicLink,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"email":               input.Body.Email,
			"redirect_url":        input.Body.RedirectURL,
			"organization_id":     orgIDToString(orgID),
			"organization_switch": currentUser != nil,
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	response, err := authSvc.SendMagicLink(ctx, input.Body, orgID)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

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
		logResp.SetCookie = c.createCookie(ctx, response.Session.Token)
	}

	return logResp, nil
}

func (c *authController) authStatusHandler(ctx context.Context, input *struct{}) (*AuthStatusOutput, error) {
	// Get current user from context
	currentUser := middleware.GetUserFromContext(ctx)
	currentSession := middleware.GetSessionFromContext(ctx)
	apiKey := middleware.GetAPIKeyFromContext(ctx)

	// For client API keys, always return unauthenticated status
	// This allows frontend SDKs to check auth status without appearing logged in
	if middleware.IsClientAPIKey(ctx) {
		response := &model.AuthStatus{
			IsAuthenticated: false,
			HasAPIAccess:    true, // Indicate API access is available
			APIKeyType:      string(model.APIKeyTypeClient),
			OrganizationID:  apiKey.OrganizationID,
			Permissions:     apiKey.Permissions,
			Scopes:          apiKey.Scopes,
		}
		return &AuthStatusOutput{
			Body: *response,
		}, nil
	}

	// For unauthenticated requests (no user, no API key, or client API key)
	if currentUser == nil {
		response := &model.AuthStatus{
			IsAuthenticated: false,
			HasAPIAccess:    apiKey != nil, // True if any API key is present
		}

		// Include API key info if present
		if apiKey != nil {
			response.APIKeyType = string(apiKey.Type)
			response.OrganizationID = apiKey.OrganizationID
			response.Permissions = apiKey.Permissions
			response.Scopes = apiKey.Scopes
		}

		return &AuthStatusOutput{
			Body: *response,
		}, nil
	}

	// For authenticated users (JWT, session, or server/admin API keys)
	var sessId *xid.ID
	if currentSession != nil {
		sessId = &currentSession.ID
	}

	ctxType := model.ContextApplication

	if currentUser.UserType == model.UserTypeInternal {
		ctxType = model.ContextPlatform
	} else if currentUser.UserType == model.UserTypeEndUser {
		ctxType = model.ContextOrganization
	}

	response, err := c.di.Auth().GetAuthStatus(
		ctx,
		currentUser.ID,
		ctxType,
		sessId,
		nil,
	)
	if err != nil {
		// Return unauthenticated status on error instead of failing
		response := &model.AuthStatus{
			IsAuthenticated: false,
			HasAPIAccess:    apiKey != nil,
		}
		return &AuthStatusOutput{Body: *response}, nil
	}

	// Add API key information to the response if present
	if apiKey != nil {
		response.HasAPIAccess = true
		response.APIKeyType = string(apiKey.Type)
		response.APIKeyID = &apiKey.ID
	}

	return &AuthStatusOutput{
		Body: *response,
	}, nil
}

type SetupTOTPInput struct {
	Body model.SetupMFARequest
}

type SetupMFAOutput = model.Output[model.MFASetupResponse]

func (c *authController) mfaSetupHandler(ctx context.Context, input *SetupTOTPInput) (*SetupMFAOutput, error) {
	mfaSvc := c.di.MFAService()
	if mfaSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "MFA service not available")
	}

	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	// Validate method type
	if input.Body.Method == "" {
		return nil, errors.New(errors.CodeBadRequest, "MFA method is required")
	}

	// Check if method is already set up
	existing, err := mfaSvc.GetMFAMethodByUserAndType(ctx, user.ID, input.Body.Method)
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}
	if existing != nil && existing.Verified {
		return nil, errors.New(errors.CodeConflict, "MFA method already set up and verified")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionMFASetup,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"method": input.Body.Method,
			"name":   input.Body.Name,
		},
		Source: audit.SourceWeb,
	}
	defer c.logAuditEvent(ctx, auditEvent)

	var response *model.MFASetupResponse

	// Handle different MFA method setups
	switch input.Body.Method {
	case "totp":
		totpResponse, err := mfaSvc.SetupTOTP(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		response = &model.MFASetupResponse{
			Method:                   "totp",
			MethodID:                 totpResponse.MethodID,
			Secret:                   totpResponse.Secret,
			QRCode:                   totpResponse.QRCode,
			BackupURL:                totpResponse.BackupURL,
			RequiresVerification:     true,
			VerificationInstructions: "Scan the QR code with your authenticator app and enter the 6-digit code to complete setup",
		}

	case "sms":
		if input.Body.PhoneNumber == "" {
			return nil, errors.New(errors.CodeBadRequest, "phone number is required for SMS MFA")
		}
		smsRequest := model.SetupSMSRequest{
			PhoneNumber: input.Body.PhoneNumber,
			Name:        input.Body.Name,
		}
		smsResponse, err := mfaSvc.SetupSMS(ctx, user.ID, smsRequest)
		if err != nil {
			return nil, err
		}
		response = &model.MFASetupResponse{
			Method:                   "sms",
			MethodID:                 smsResponse.MethodID,
			PhoneNumber:              smsResponse.PhoneNumber,
			RequiresVerification:     true,
			VerificationInstructions: "Enter the 6-digit code sent to your phone to complete setup",
			Message:                  smsResponse.Message,
		}

	case "email":
		if input.Body.Email == "" {
			input.Body.Email = user.Email // Use user's primary email
		}
		emailResponse, err := mfaSvc.SetupEmail(ctx, user.ID, input.Body.Email)
		if err != nil {
			return nil, err
		}
		// Send email code immediately
		_, err = mfaSvc.SendEmailCode(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		response = &model.MFASetupResponse{
			Method:                   "email",
			MethodID:                 emailResponse.MethodID,
			Email:                    emailResponse.Email,
			RequiresVerification:     true,
			VerificationInstructions: "Enter the 6-digit code sent to your email to complete setup",
			Message:                  "Verification code sent to your email",
		}

	default:
		return nil, errors.New(errors.CodeBadRequest, "unsupported MFA method")
	}

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Details["method_id"] = response.MethodID.String()

	return &SetupMFAOutput{
		Body: *response,
	}, nil
}

type VerifyMFASetupInput struct {
	Body model.VerifyMFASetupRequest
}

type VerifyMFASetupOutput = model.Output[model.MFASetupVerifyResponse]

func (c *authController) mfaSetupVerifyHandler(ctx context.Context, input *VerifyMFASetupInput) (*VerifyMFASetupOutput, error) {
	mfaSvc := c.di.MFAService()
	if mfaSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "MFA service not available")
	}

	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	if input.Body.Code == "" {
		return nil, errors.New(errors.CodeBadRequest, "verification code is required")
	}

	if input.Body.MethodID == nil && input.Body.Method == "" {
		return nil, errors.New(errors.CodeBadRequest, "method ID or method type is required")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionMFASetupVerify,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"method":    input.Body.Method,
			"method_id": input.Body.MethodID,
		},
		Source: audit.SourceWeb,
	}
	defer c.logAuditEvent(ctx, auditEvent)

	// Get MFA method to verify
	var mfaMethod *model.MFA
	if input.Body.MethodID != nil {
		mfaMethod, err = mfaSvc.GetMFAMethod(ctx, *input.Body.MethodID)
		if err != nil {
			return nil, err
		}
	} else {
		// Find by method type (get most recent unverified)
		methods, err := mfaSvc.ListUserMFAMethods(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		for _, method := range methods {
			if method.Method == input.Body.Method && !method.Verified {
				mfaMethod = method
				break
			}
		}
	}

	if mfaMethod == nil {
		return nil, errors.New(errors.CodeNotFound, "MFA method not found or already verified")
	}

	// Verify the method belongs to the current user
	if mfaMethod.UserID != user.ID {
		return nil, errors.New(errors.CodeForbidden, "you can only verify your own MFA methods")
	}

	// Check if already verified
	if mfaMethod.Verified {
		return &VerifyMFASetupOutput{
			Body: model.MFASetupVerifyResponse{
				Success:    true,
				Method:     mfaMethod.Method,
				MethodID:   mfaMethod.ID,
				Message:    "MFA method is already verified and active",
				IsVerified: true,
			},
		}, nil
	}

	// Verify the code
	verifyResponse, err := mfaSvc.VerifyMFA(ctx, user.ID, mfaMethod.Method, input.Body.Code)
	if err != nil {
		return nil, err
	}

	if !verifyResponse.Success {
		return &VerifyMFASetupOutput{
			Body: model.MFASetupVerifyResponse{
				Success:  false,
				Method:   mfaMethod.Method,
				MethodID: mfaMethod.ID,
				Message:  verifyResponse.Message,
			},
		}, nil
	}

	// Generate backup codes for verified TOTP methods
	var backupCodes []string
	if mfaMethod.Method == "totp" && input.Body.GenerateBackupCodes {
		backupRequest := &model.GenerateBackupCodesRequest{Count: 10}
		backupResponse, err := mfaSvc.GenerateBackupCodes(ctx, user.ID, backupRequest)
		if err != nil {
			c.di.Logger().Error("Failed to generate backup codes", logging.Error(err))
		} else {
			backupCodes = backupResponse.Codes
		}
	}

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Details["method_id"] = mfaMethod.ID.String()
	auditEvent.Details["backup_codes_generated"] = len(backupCodes) > 0

	return &VerifyMFASetupOutput{
		Body: model.MFASetupVerifyResponse{
			Success:     true,
			Method:      mfaMethod.Method,
			MethodID:    mfaMethod.ID,
			Message:     "MFA method verified and activated successfully",
			IsVerified:  true,
			BackupCodes: backupCodes,
		},
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

	auditEvent := audit.AuditEvent{
		Action: audit.ActionMFAVerify,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"method": input.Body.Method,
		},
		Source: audit.SourceWeb,
	}
	defer c.logAuditEvent(ctx, auditEvent)

	// Determine if this is MFA management or login completion
	currentUser := middleware.GetUserFromContext(ctx)

	if currentUser != nil {
		// Scenario 1: MFA Management (user already logged in)
		return c.handleMFAManagement(ctx, currentUser, input, auditEvent)
	} else {
		// Scenario 2: MFA Login Completion (complete authentication flow)
		return c.handleMFALoginCompletion(ctx, input, auditEvent)
	}
}

// handleMFAManagement handles MFA verification for already authenticated users
func (c *authController) handleMFAManagement(ctx context.Context, user *middleware.UserContext, input *VerifyMFAInput, auditEvent audit.AuditEvent) (*VerifyMFAOutput, error) {
	mfaSvc := c.di.MFAService()

	// Verify MFA code
	response, err := mfaSvc.VerifyMFA(ctx, user.ID, input.Body.Method, input.Body.Code)
	if err != nil {
		return nil, err
	}

	if response.Success {
		auditEvent.Status = audit.StatusSuccess
	}

	auditEvent.Details["user_id"] = user.ID.String()

	return &VerifyMFAOutput{
		Body: *response,
	}, nil
}

// handleMFALoginCompletion handles MFA verification during login flow
func (c *authController) handleMFALoginCompletion(ctx context.Context, input *VerifyMFAInput, auditEvent audit.AuditEvent) (*VerifyMFAOutput, error) {
	// Extract MFA session token from request (could be from header, body, or cookie)
	mfaToken := c.extractMFAToken(ctx, input)
	if mfaToken == "" {
		return nil, errors.New(errors.CodeUnauthorized, "MFA session token required for login completion")
	}

	// Validate MFA session token and get pending login info
	authSvc := c.di.Auth()
	pendingLogin, err := authSvc.ValidateMFASession(ctx, mfaToken)
	if err != nil {
		return nil, errors.New(errors.CodeUnauthorized, "invalid or expired MFA session")
	}

	mfaSvc := c.di.MFAService()

	// Verify MFA code for the user from pending login
	mfaResponse, err := mfaSvc.VerifyMFA(ctx, pendingLogin.UserID, input.Body.Method, input.Body.Code)
	if err != nil {
		return nil, err
	}

	if !mfaResponse.Success {
		// MFA verification failed
		auditEvent.Details["user_id"] = pendingLogin.UserID.String()
		return &VerifyMFAOutput{
			Body: *mfaResponse,
		}, nil
	}

	// MFA verification succeeded - complete the login

	// Complete the authentication and get tokens
	loginResponse, err := authSvc.CompleteMFALogin(ctx, mfaToken, input.Body.Method)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to complete MFA login")
	}

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Action = audit.ActionUserLogin // Change to login action
	auditEvent.Details["login_completed"] = true
	auditEvent.Details["user_id"] = loginResponse.User.ID.String()

	// Create response with login tokens
	response := &model.MFAVerifyResponse{
		Success:   true,
		Method:    input.Body.Method,
		Message:   "MFA verification and login completed successfully",
		LoginData: loginResponse, // Include full login response
	}

	verifyOutput := &VerifyMFAOutput{
		Body: *response,
	}

	// Set session cookie if configured
	if loginResponse.Session.Token != "" && c.di.Config().Auth.AllowSession {
		verifyOutput.SetCookie = c.createCookie(ctx, loginResponse.Session.Token)
	}

	return verifyOutput, nil
}

// extractMFAToken extracts MFA session token from request
func (c *authController) extractMFAToken(ctx context.Context, input *VerifyMFAInput) string {
	// Option 1: From request body
	if input.Body.MFAToken != "" {
		return input.Body.MFAToken
	}

	// Option 2: From Authorization header
	if authHeader := middleware.GetHeaderFromContext(ctx, "Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "MFA ") {
			return authHeader[4:] // Remove "MFA " prefix
		}
	}

	// Option 3: From X-MFA-Token header
	if mfaHeader := middleware.GetHeaderFromContext(ctx, "X-MFA-Token"); mfaHeader != "" {
		return mfaHeader
	}

	// Option 4: From cookie (if you want to support that)
	if mfaCookie := middleware.GetCookieFromContext(ctx, "mfa_token"); mfaCookie != "" {
		return mfaCookie
	}

	return ""
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
		logResp.SetCookie = c.createCookie(ctx, session.Token)
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

type OAuthAuthorize2Output struct {
	model.RedirectOutput
}

func (c *authController) oauthAuthorizeHandler(ctx context.Context, input *OAuthProviderPathInput) (*OAuthAuthorize2Output, error) {
	// OAuth authorization for external and end users requires organization context
	userType := c.getDetectedUserType(ctx)
	if err := c.validateOrganizationContext(ctx, userType, true); err != nil {
		return nil, err
	}

	authSvc := c.di.Auth()
	if authSvc == nil {
		return nil, errors.New(errors.CodeInternalServer, "auth service not available")
	}

	// Get OAuth URL for the provider
	redirectURL := "http://localhost:8080/auth/oauth/" + input.Provider + "/callback" // This should come from config

	// Include organization context in OAuth state if present
	orgContext := c.getOrganizationContext(ctx)
	var stateData string
	if orgContext != nil {
		stateData = "org_id=" + orgContext.ID.String()
	}

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

	oauthURL, err := authSvc.GetOAuthURLWithState(ctx, input.Provider, redirectURL, stateData)
	if err != nil {
		return nil, err
	}

	auditEvent.Status = audit.StatusSuccess

	return &OAuthAuthorize2Output{
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
		Status: audit.StatusFailure, // Will be updated if login succeeds
		Details: map[string]interface{}{
			"code":     input.Code,
			"provider": input.Provider,
			"method":   "oauth_" + input.Provider,
		},
		Source: audit.SourceWeb,
	}

	// Log authentication attempt
	defer c.logAuditEvent(ctx, auditEvent)

	// Extract organization context from OAuth state if present
	var orgID *xid.ID
	if strings.Contains(input.State, "org_id=") {
		parts := strings.Split(input.State, "org_id=")
		if len(parts) > 1 {
			if id, err := xid.FromString(parts[1]); err == nil {
				orgID = &id
			}
		}
	}

	response, err := authSvc.HandleOAuthCallbackWithOrg(ctx, input.Provider, input.Code, input.State, orgID)
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
		Body: response,
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
			"token_prefix": getTokenPrefix(accessToken),
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

type RefreshSessionInput struct {
}

type RefreshSessionOutput = model.Output[model.Session]

// Add this handler method to the authController
func (c *authController) refreshSessionHandler(ctx context.Context, input *RefreshSessionInput) (*RefreshSessionOutput, error) {
	logger := c.di.Logger().Named("refresh-session")

	// Get current user from context
	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	logger.Debug("Refreshing user session",
		logging.String("userId", user.ID.String()),
		logging.String("sessionId", user.SessionID.String()))

	sessionService := c.di.SessionService()
	if sessionService == nil {
		return nil, errors.New(errors.CodeInternalServer, "session service not available")
	}

	// First, verify the session exists and belongs to the current user
	session, err := sessionService.GetSession(ctx, user.SessionID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "session not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to retrieve session")
	}

	// Check ownership - users can only refresh their own sessions
	if session.UserID != user.ID {
		return nil, errors.New(errors.CodeForbidden, "you can only refresh your own sessions")
	}

	// Check if session is still active
	if !session.Active {
		return nil, errors.New(errors.CodeBadRequest, "cannot refresh inactive session")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil, errors.New(errors.CodeBadRequest, "cannot refresh expired session")
	}

	auditEvent := audit.AuditEvent{
		Action: audit.ActionSessionRefresh,
		Status: audit.StatusFailure,
		Details: map[string]interface{}{
			"session_id":      user.SessionID.String(),
			"original_expiry": session.ExpiresAt.Format(time.RFC3339),
		},
		Source: audit.SourceWeb,
	}

	defer c.logAuditEvent(ctx, auditEvent)

	// Refresh the session
	refreshedSession, err := sessionService.RefreshSession(ctx, user.SessionID)
	if err != nil {
		logger.Error("Failed to refresh session",
			logging.Error(err),
			logging.String("sessionId", user.SessionID.String()))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to refresh session")
	}

	auditEvent.Status = audit.StatusSuccess
	auditEvent.Details["new_expiry"] = refreshedSession.ExpiresAt.Format(time.RFC3339)
	auditEvent.Details["extended_by"] = refreshedSession.ExpiresAt.Sub(session.ExpiresAt).String()

	logger.Info("Session refreshed successfully",
		logging.String("userId", user.ID.String()),
		logging.String("sessionId", user.SessionID.String()),
		logging.Time("originalExpiry", session.ExpiresAt),
		logging.Time("newExpiry", refreshedSession.ExpiresAt))

	return &RefreshSessionOutput{
		Body: *refreshedSession,
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

func (c *authController) deleteCookie(ctx context.Context) http.Cookie {
	return http.Cookie{
		Name:     c.di.Config().Auth.SessionName,
		Value:    "",
		Domain:   c.getCookieDomain(ctx),
		Path:     "/",
		Secure:   c.di.Config().Auth.CookieSecure,
		HttpOnly: c.di.Config().Auth.CookieHTTPOnly,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	}
}

func (c *authController) getCookieDomain(ctx context.Context) string {
	if c.di.Config().Auth.CookieDomains == nil || len(c.di.Config().Auth.CookieDomains) == 0 {
		return c.di.Config().Auth.CookieDomain
	}

	domain, ok := lo.Find(c.di.Config().Auth.CookieDomains, func(item string) bool {
		req := contexts.GetRequestFromContext(ctx)
		host := c.getOriginHostFromRequest(req)
		fmt.Println(req.Host, item)
		return strings.HasSuffix(host, item)
	})
	if !ok {
		return c.di.Config().Auth.CookieDomain
	}

	return domain
}

func (c *authController) createCookie(ctx context.Context, token string) http.Cookie {
	sameSite := http.SameSiteDefaultMode
	if c.di.Config().Auth.CookieSameSite == "none" {
		sameSite = http.SameSiteNoneMode
	} else if c.di.Config().Auth.CookieSameSite == "strict" {
		sameSite = http.SameSiteStrictMode
	} else if c.di.Config().Auth.CookieSameSite == "lax" {
		sameSite = http.SameSiteLaxMode
	}

	return http.Cookie{
		Name:     c.di.Config().Auth.SessionName,
		Value:    token,
		Domain:   c.getCookieDomain(ctx),
		Path:     "/",
		Secure:   c.di.Config().Auth.CookieSecure,
		HttpOnly: c.di.Config().Auth.CookieHTTPOnly,
		MaxAge:   int(c.di.Config().Auth.CookieMaxAge.Seconds()),
		SameSite: sameSite,
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

func getTokenPrefix(token string) string {
	if len(token) > 8 {
		return token[:8] + "..."
	}
	return token
}

// validateOrganizationContext validates that organization context is provided for external and end users
func (c *authController) validateOrganizationContext(ctx context.Context, userType string, skipExternal bool) error {
	switch userType {
	case string(model.UserTypeInternal):
		// Internal users don't require organization context
		return nil

	case string(model.UserTypeExternal), string(model.UserTypeEndUser):
		// External and end users require organization context
		orgContext := c.getOrganizationContext(ctx)
		if skipExternal && userType == model.UserTypeExternal.String() {
			return nil
		}

		if orgContext == nil {
			return errors.New(errors.CodeBadRequest, "organization context is required for this user type. Provide organization context via API key (X-API-Key/X-Publishable-Key) or headers (X-Org-ID).")
		}

		// Validate organization is active
		if !orgContext.Active {
			return errors.New(errors.CodeForbidden, "organization is inactive")
		}

	default:
		// Unknown user type, default to requiring organization context
		orgContext := c.getOrganizationContext(ctx)
		if orgContext == nil {
			return errors.New(errors.CodeBadRequest, "organization context is required")
		}
	}

	return nil
}

// getOrganizationContext retrieves organization context from request
func (c *authController) getOrganizationContext(ctx context.Context) *contexts.OrganizationContext {
	// Try to get from tenant context
	if tenant := middleware.GetTenantFromContext(ctx); tenant != nil {
		return &contexts.OrganizationContext{
			ID:                     tenant.Organization.ID,
			Active:                 tenant.Organization.Active,
			Name:                   tenant.Organization.Name,
			Slug:                   tenant.Organization.Slug,
			Plan:                   tenant.Organization.Plan,
			Domain:                 tenant.Organization.Domain,
			IsPlatformOrganization: tenant.Organization.IsPlatformOrganization,
			OrgType:                tenant.Organization.OrgType,
			Metadata:               tenant.Organization.Metadata,
		}
	}

	// Try to get from organization context
	if org := contexts.GetOrganizationFromContext(ctx); org != nil {
		return org
	}

	return nil
}

// getDetectedUserType retrieves detected user type from context
func (c *authController) getDetectedUserType(ctx context.Context) string {
	return string(middleware.GetDetectedUserTypeFromContext(ctx))
}

// getDetectedOrganizationID retrieves detected organization ID from context
func (c *authController) getDetectedOrganizationID(ctx context.Context) *xid.ID {
	return middleware.GetDetectedOrganizationIDFromContext(ctx)
}

// validateUserBelongsToOrganization validates that a user belongs to the organization
func (c *authController) validateUserBelongsToOrganization(ctx context.Context, userID xid.ID, orgID xid.ID) error {
	user, err := c.di.Repo().User().GetByID(ctx, userID)
	if err != nil {
		return errors.New(errors.CodeNotFound, "user not found")
	}

	if user.OrganizationID.IsNil() || user.OrganizationID != orgID {
		return errors.New(errors.CodeForbidden, "user does not belong to this organization")
	}

	return nil
}

// createOrganizationScopedLoginRequest modifies login request to include organization context
func (c *authController) createOrganizationScopedLoginRequest(ctx context.Context, req model.LoginRequest) model.LoginRequest {
	orgContext := c.getOrganizationContext(ctx)
	if orgContext != nil {
		// req.OrganizationID = &orgContext.ID
	}
	return req
}

// createOrganizationScopedRegisterRequest modifies register request to include organization context
func (c *authController) createOrganizationScopedRegisterRequest(ctx context.Context, req model.RegisterRequest) model.RegisterRequest {
	orgContext := c.getOrganizationContext(ctx)
	if orgContext != nil {
		req.OrganizationID = &orgContext.ID
	}
	return req
}

// validateOrganizationAPIAccess validates API access based on organization context and user type
func (c *authController) validateOrganizationAPIAccess(ctx context.Context) error {
	user := middleware.GetUserFromContext(ctx)
	tenant := middleware.GetTenantFromContext(ctx)

	// Internal users can access any organization
	if user != nil && user.UserType == model.UserTypeInternal {
		return nil
	}

	// External and end users must belong to the tenant organization
	if user != nil && tenant != nil {
		if user.UserType == model.UserTypeExternal || user.UserType == model.UserTypeEndUser {
			if user.OrganizationID == nil || *user.OrganizationID != tenant.Organization.ID {
				return errors.New(errors.CodeForbidden, "user does not belong to this organization")
			}
		}
	}

	// For unauthenticated requests, check organization context requirements
	if user == nil {
		userType := c.getDetectedUserType(ctx)
		if userType == string(model.UserTypeExternal) || userType == string(model.UserTypeEndUser) {
			orgContext := c.getOrganizationContext(ctx)
			if orgContext == nil {
				return errors.New(errors.CodeBadRequest, "organization context is required")
			}
		}
	}

	return nil
}

// Helper methods for organization creation flow

func (c *authController) getOrganizationNameFromRequest(req model.RegisterRequest) string {
	if name, ok := req.Metadata["organization_name"].(string); ok && name != "" {
		return name
	}
	// Default organization name based on email domain
	parts := strings.Split(req.Email, "@")
	if len(parts) == 2 {
		domain := parts[1]
		// Remove .com, .org etc and capitalize
		domainParts := strings.Split(domain, ".")
		if len(domainParts) > 0 {
			return strings.Title(domainParts[0])
		}
	}
	return "My Organization"
}

func (c *authController) getOrganizationSlugFromRequest(req model.RegisterRequest) string {
	if slug, ok := req.Metadata["organization_slug"].(string); ok && slug != "" {
		return slug
	}
	// Default slug based on organization name
	name := c.getOrganizationNameFromRequest(req)
	return strings.ToLower(strings.ReplaceAll(name, " ", "-"))
}

func (c *authController) getDomainFromRequest(req model.RegisterRequest) string {
	if domain, ok := req.Metadata["domain"].(string); ok && domain != "" {
		return domain
	}
	// Extract domain from email
	parts := strings.Split(req.Email, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func (c *authController) getOriginHostFromRequest(r *http.Request) string {
	// 1. Try Origin header first (most reliable for CORS requests)
	if origin := r.Header.Get("Origin"); origin != "" {
		if parsedURL, err := url.Parse(origin); err == nil && parsedURL.Host != "" {
			return parsedURL.Host
		}
	}

	// 2. Try X-Forwarded-Host header (for requests through proxies)
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		// X-Forwarded-Host might contain multiple hosts, take the first one
		hosts := strings.Split(forwardedHost, ",")
		if len(hosts) > 0 {
			return strings.TrimSpace(hosts[0])
		}
	}

	// 3. Try Referer header
	if referer := r.Header.Get("Referer"); referer != "" {
		if parsedURL, err := url.Parse(referer); err == nil && parsedURL.Host != "" {
			return parsedURL.Host
		}
	}

	// 4. Final fallback to Host header
	return r.Host
}

func (c *authController) getPlanFromRequest(req model.RegisterRequest) string {
	if plan, ok := req.Metadata["plan"].(string); ok && plan != "" {
		return plan
	}
	return "free" // Default plan
}

// Helper function to check if the request has proper API access for auth operations
func (c *authController) hasAPIAccess(ctx context.Context) bool {
	// Check if request has API key access (including client keys)
	return middleware.HasAPIKeyAccess(ctx) || middleware.IsAuthenticated(ctx)
}

// Helper function to get organization context from API key or user
func (c *authController) getOrganizationFromAPIKey(ctx context.Context) *xid.ID {
	apiKey := middleware.GetAPIKeyFromContext(ctx)
	if apiKey != nil && apiKey.OrganizationID != nil {
		return apiKey.OrganizationID
	}
	return nil
}

// Helper function to convert organization ID to string for logging
func orgIDToString(orgID *xid.ID) string {
	if orgID == nil {
		return "none"
	}
	return orgID.String()
}

// Helper function to convert session to string for logging
func sessionIDToString(session *middleware.SessionContext) string {
	if session == nil {
		return "none"
	}
	return session.ID.String()
}
