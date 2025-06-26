package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// RegisterMFAAPI registers all MFA-related endpoints
func RegisterMFAAPI(api huma.API, di di.Container) {
	di.Logger().Info("Registering MFA API routes")

	mfaCtrl := &mfaController{
		api: api,
		di:  di,
	}

	// MFA method management
	registerListMFAMethods(api, mfaCtrl)
	registerGetMFAMethod(api, mfaCtrl)
	registerUpdateMFAMethod(api, mfaCtrl)
	registerDeleteMFAMethod(api, mfaCtrl)

	// TOTP operations
	registerSetupTOTP(api, mfaCtrl)
	registerVerifyTOTP(api, mfaCtrl)
	registerDisableTOTP(api, mfaCtrl)

	// SMS operations
	registerSetupSMS(api, mfaCtrl)
	registerSendSMSCode(api, mfaCtrl)
	registerVerifySMSCode(api, mfaCtrl)
	registerDisableSMS(api, mfaCtrl)

	// Email operations
	registerSetupEmailMFA(api, mfaCtrl)
	registerSendEmailCode(api, mfaCtrl)
	registerVerifyEmailCode(api, mfaCtrl)
	registerDisableEmailMFA(api, mfaCtrl)

	// Backup codes
	registerGenerateBackupCodes(api, mfaCtrl)
	registerVerifyBackupCode(api, mfaCtrl)
	registerRegenerateBackupCodes(api, mfaCtrl)

	// MFA verification and challenge
	registerVerifyMFA(api, mfaCtrl)
	registerCreateMFAChallenge(api, mfaCtrl)
	registerValidateMFAChallenge(api, mfaCtrl)
	registerCheckMFARequirement(api, mfaCtrl)

	// Recovery operations
	registerDisableAllMFA(api, mfaCtrl)
	registerGetRecoveryOptions(api, mfaCtrl)

	// Activity and analytics
	registerGetMFAActivity(api, mfaCtrl)
	registerResendMFACode(api, mfaCtrl)
}

// mfaController handles MFA-related API requests
type mfaController struct {
	api huma.API
	di  di.Container
}

// =============================================================================
// MFA Method Management
// =============================================================================

func registerListMFAMethods(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "listMFAMethods",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/methods",
		Summary:     "List MFA methods",
		Description: "List all MFA methods for a user with pagination and filtering options",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionReadMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.listMFAMethodsHandler)
}

func registerGetMFAMethod(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMFAMethod",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/methods/{id}",
		Summary:     "Get MFA method",
		Description: "Get details of a specific MFA method",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("MFA method not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionReadMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.getMFAMethodHandler)
}

func registerUpdateMFAMethod(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateMFAMethod",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/methods/{id}",
		Summary:     "Update MFA method",
		Description: "Update an existing MFA method configuration",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("MFA method not found"), model.ValidationError("Invalid MFA configuration")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.updateMFAMethodHandler)
}

func registerDeleteMFAMethod(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteMFAMethod",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/{userId}/mfa/methods/{id}",
		Summary:       "Delete MFA method",
		Description:   "Delete an MFA method",
		Tags:          []string{"MFA"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "MFA method deleted successfully",
			},
		}, true, model.NotFoundError("MFA method not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.deleteMFAMethodHandler)
}

// =============================================================================
// TOTP Operations
// =============================================================================

func registerSetupTOTP(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "setupTOTP",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/totp/setup",
		Summary:     "Setup TOTP",
		Description: "Setup Time-based One-Time Password (TOTP) authentication for a user",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.ConflictError("TOTP already setup")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.setupTOTPHandler)
}

func registerVerifyTOTP(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "verifyTOTP",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/totp/verify",
		Summary:     "Verify TOTP",
		Description: "Verify a TOTP code for authentication",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid TOTP code")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.verifyTOTPHandler)
}

func registerDisableTOTP(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID:   "disableTOTP",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/{userId}/mfa/totp",
		Summary:       "Disable TOTP",
		Description:   "Disable TOTP authentication for a user",
		Tags:          []string{"MFA"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "TOTP disabled successfully",
			},
		}, true, model.NotFoundError("TOTP not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.disableTOTPHandler)
}

// =============================================================================
// SMS Operations
// =============================================================================

func registerSetupSMS(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "setupSMS",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/sms/setup",
		Summary:     "Setup SMS MFA",
		Description: "Setup SMS-based multi-factor authentication for a user",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.ConflictError("SMS MFA already setup"), model.ValidationError("Invalid phone number")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.setupSMSHandler)
}

func registerSendSMSCode(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "sendSMSCode",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/sms/send",
		Summary:     "Send SMS code",
		Description: "Send an SMS verification code to the user's phone",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("SMS MFA not configured"), model.TooManyRequestsError()),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.sendSMSCodeHandler)
}

func registerVerifySMSCode(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "verifySMSCode",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/sms/verify",
		Summary:     "Verify SMS code",
		Description: "Verify an SMS verification code",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid SMS code")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.verifySMSCodeHandler)
}

func registerDisableSMS(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID:   "disableSMS",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/{userId}/mfa/sms",
		Summary:       "Disable SMS MFA",
		Description:   "Disable SMS-based multi-factor authentication for a user",
		Tags:          []string{"MFA"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "SMS MFA disabled successfully",
			},
		}, true, model.NotFoundError("SMS MFA not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.disableSMSHandler)
}

// =============================================================================
// Email Operations
// =============================================================================

func registerSetupEmailMFA(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "setupEmailMFA",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/email/setup",
		Summary:     "Setup email MFA",
		Description: "Setup email-based multi-factor authentication for a user",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.ConflictError("Email MFA already setup"), model.ValidationError("Invalid email address")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.setupEmailMFAHandler)
}

func registerSendEmailCode(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "sendEmailCode",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/email/send",
		Summary:     "Send email code",
		Description: "Send an email verification code to the user's email",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Email MFA not configured"), model.TooManyRequestsError()),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.sendEmailCodeHandler)
}

func registerVerifyEmailCode(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "verifyEmailCode",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/email/verify",
		Summary:     "Verify email code",
		Description: "Verify an email verification code",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid email code")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.verifyEmailCodeHandler)
}

func registerDisableEmailMFA(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID:   "disableEmailMFA",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/{userId}/mfa/email",
		Summary:       "Disable email MFA",
		Description:   "Disable email-based multi-factor authentication for a user",
		Tags:          []string{"MFA"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "Email MFA disabled successfully",
			},
		}, true, model.NotFoundError("Email MFA not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.disableEmailMFAHandler)
}

// =============================================================================
// Backup Codes
// =============================================================================

func registerGenerateBackupCodes(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "generateBackupCodes",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/backup-codes/generate",
		Summary:     "Generate backup codes",
		Description: "Generate backup codes for MFA recovery",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.generateBackupCodesHandler)
}

func registerVerifyBackupCode(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "verifyBackupCode",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/backup-codes/verify",
		Summary:     "Verify backup code",
		Description: "Verify a backup code for MFA authentication",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid backup code")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.verifyBackupCodeHandler)
}

func registerRegenerateBackupCodes(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "regenerateBackupCodes",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/backup-codes/regenerate",
		Summary:     "Regenerate backup codes",
		Description: "Regenerate backup codes, invalidating previous ones",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.regenerateBackupCodesHandler)
}

// =============================================================================
// MFA Verification and Challenge
// =============================================================================

func registerVerifyMFA(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "verifyMFA",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/verify",
		Summary:     "Verify MFA",
		Description: "Verify MFA using any available method",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid MFA code or method")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.verifyMFAHandler)
}

func registerCreateMFAChallenge(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "createMFAChallenge",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/challenge",
		Summary:     "Create MFA challenge",
		Description: "Create an MFA challenge for user verification",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionReadMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.createMFAChallengeHandler)
}

func registerValidateMFAChallenge(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "validateMFAChallenge",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/challenge/validate",
		Summary:     "Validate MFA challenge",
		Description: "Validate an MFA challenge response",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid challenge or code")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.validateMFAChallengeHandler)
}

func registerCheckMFARequirement(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "checkMFARequirement",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/requirement",
		Summary:     "Check MFA requirement",
		Description: "Check if MFA is required for a user and what methods are available",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionReadMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.checkMFARequirementHandler)
}

// =============================================================================
// Recovery Operations
// =============================================================================

func registerDisableAllMFA(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID:   "disableAllMFA",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/{userId}/mfa/all",
		Summary:       "Disable all MFA",
		Description:   "Disable all MFA methods for a user (recovery operation)",
		Tags:          []string{"MFA"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "All MFA methods disabled successfully",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.disableAllMFAHandler)
}

func registerGetRecoveryOptions(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "getRecoveryOptions",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/recovery",
		Summary:     "Get recovery options",
		Description: "Get available MFA recovery options for a user",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionReadMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.getRecoveryOptionsHandler)
}

// =============================================================================
// Activity and Analytics
// =============================================================================

func registerGetMFAActivity(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMFAActivity",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/activity",
		Summary:     "Get MFA activity",
		Description: "Get MFA activity logs for a user with pagination and filtering",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionReadMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.getMFAActivityHandler)
}

func registerResendMFACode(api huma.API, mfaCtrl *mfaController) {
	huma.Register(api, huma.Operation{
		OperationID: "resendMFACode",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/users/{userId}/mfa/resend",
		Summary:     "Resend MFA code",
		Description: "Resend MFA verification code for SMS or email methods",
		Tags:        []string{"MFA"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.TooManyRequestsError(), model.NotFoundError("MFA method not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, mfaCtrl.di.AuthZ().Checker(), mfaCtrl.di.Logger())(
			authz.PermissionWriteMFA, model.ResourceUser, "userId",
		)},
	}, mfaCtrl.resendMFACodeHandler)
}

// =============================================================================
// Handler Implementations
// =============================================================================

// Input/Output type definitions for MFA handlers

type ListMFAMethodsInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
	model.MFAListRequest
}

type ListMFAMethodsOutput = model.Output[*model.PaginatedOutput[*model.MFA]]

type GetMFAMethodInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
	ID     xid.ID `path:"id" doc:"MFA method ID"`
}

type GetMFAMethodOutput = model.Output[*model.MFA]

type UpdateMFAMethodInput struct {
	model.OrganisationPathParams
	UserID xid.ID                       `path:"userId" doc:"User ID"`
	ID     xid.ID                       `path:"id" doc:"MFA method ID"`
	Body   model.UpdateMFAMethodRequest `json:"body"`
}

type UpdateMFAMethodOutput = model.Output[*model.MFA]

type DeleteMFAMethodInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
	ID     xid.ID `path:"id" doc:"MFA method ID"`
}

// TOTP-related types
type SetupOrganizationTOTPInput struct {
	model.OrganisationPathParams
	UserID xid.ID                 `path:"userId" doc:"User ID"`
	Body   model.SetupTOTPRequest `json:"body"`
}

type SetupOrganizationTOTPOutput = model.Output[*model.TOTPSetupResponse]

type VerifyTOTPInput struct {
	model.OrganisationPathParams
	UserID xid.ID                  `path:"userId" doc:"User ID"`
	Body   model.VerifyTOTPRequest `json:"body"`
}

type VerifyTOTPOutput = model.Output[*model.MFAVerifyResponse]

type DisableTOTPInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
}

// SMS-related types
type SetupSMSInput struct {
	model.OrganisationPathParams
	UserID xid.ID                `path:"userId" doc:"User ID"`
	Body   model.SetupSMSRequest `json:"body"`
}

type SetupSMSOutput = model.Output[*model.SetupSMSResponse]

type SendSMSCodeInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type SendSMSCodeOutput = model.Output[*model.SMSCodeResponse]

type VerifySMSCodeInput struct {
	model.OrganisationPathParams
	UserID xid.ID                 `path:"userId" doc:"User ID"`
	Body   model.VerifySMSRequest `json:"body"`
}

type VerifySMSCodeOutput = model.Output[*model.MFAVerifyResponse]

// Email-related types
type SetupEmailMFAInput struct {
	model.OrganisationPathParams
	UserID xid.ID                  `path:"userId" doc:"User ID"`
	Body   model.SetupEmailRequest `json:"body"`
}

type SetupEmailMFAOutput = model.Output[*model.EmailMFASetupResponse]

type SendEmailCodeInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type SendEmailCodeOutput = model.Output[*model.EmailCodeResponse]

type VerifyEmailCodeInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
	Body   model.VerifyEmailRequestBody
}

type VerifyEmailCodeOutput = model.Output[*model.MFAVerifyResponse]

// Backup codes types
type GenerateOrganizationBackupCodesInput struct {
	model.OrganisationPathParams
	UserID xid.ID                           `path:"userId" doc:"User ID"`
	Body   model.GenerateBackupCodesRequest `json:"body"`
}

type GenerateOrganizationBackupCodesOutput = model.Output[*model.MFABackCodes]

type VerifyBackupCodeInput struct {
	model.OrganisationPathParams
	UserID xid.ID                     `path:"userId" doc:"User ID"`
	Body   model.UseBackupCodeRequest `json:"body"`
}

type VerifyBackupCodeOutput = model.Output[*model.MFAVerifyResponse]

// General MFA types
type VerifyOrganizationMFAInput struct {
	model.OrganisationPathParams
	UserID xid.ID                 `path:"userId" doc:"User ID"`
	Body   model.MFAVerifyRequest `json:"body"`
}

type VerifyOrganizationMFAOutput = model.Output[*model.MFAVerifyResponse]

type CreateMFAChallengeInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type CreateMFAChallengeOutput = model.Output[*model.MFAChallengeResponse]

type ValidateMFAChallengeInput struct {
	model.OrganisationPathParams
	UserID xid.ID                            `path:"userId" doc:"User ID"`
	Body   model.ValidateMFAChallengeRequest `json:"body"`
}

type ValidateMFAChallengeOutput = model.Output[*model.MFAVerifyResponse]

type CheckMFARequirementInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type CheckMFARequirementOutput = model.Output[*model.MFARequirementCheck]

type DisableAllMFAInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type GetRecoveryOptionsInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type GetRecoveryOptionsOutput = model.Output[*model.MFARecoveryOptions]

type GetMFAActivityInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
	model.MFAActivityRequest
}

type GetMFAActivityOutput = model.Output[*model.MFAActivityResponse]

type ResendMFACodeInput struct {
	model.OrganisationPathParams
	UserID xid.ID                     `path:"userId" doc:"User ID"`
	Body   model.ResendMFACodeRequest `json:"body"`
}

type ResendMFACodeOutput = model.Output[*model.ResendMFACodeResponse]

// Handler implementations

func (c *mfaController) listMFAMethodsHandler(ctx context.Context, input *ListMFAMethodsInput) (*ListMFAMethodsOutput, error) {
	methods, err := c.di.MFAService().ListUserMFAMethods(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	// Convert to paginated response (simplified for this example)
	return &ListMFAMethodsOutput{
		Body: &model.PaginatedOutput[*model.MFA]{
			Data: methods,
			Pagination: &model.Pagination{
				TotalCount:      len(methods),
				HasNextPage:     false,
				HasPreviousPage: false,
			},
		},
	}, nil
}

func (c *mfaController) getMFAMethodHandler(ctx context.Context, input *GetMFAMethodInput) (*GetMFAMethodOutput, error) {
	method, err := c.di.MFAService().GetMFAMethod(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &GetMFAMethodOutput{Body: method}, nil
}

func (c *mfaController) updateMFAMethodHandler(ctx context.Context, input *UpdateMFAMethodInput) (*UpdateMFAMethodOutput, error) {
	config := map[string]interface{}{
		"name": input.Body.Name,
	}

	method, err := c.di.MFAService().UpdateMFAMethod(ctx, input.ID, config)
	if err != nil {
		return nil, err
	}

	return &UpdateMFAMethodOutput{Body: method}, nil
}

func (c *mfaController) deleteMFAMethodHandler(ctx context.Context, input *DeleteMFAMethodInput) (*struct{}, error) {
	// Get method first to determine type
	method, err := c.di.MFAService().GetMFAMethod(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	err = c.di.MFAService().DisableMFA(ctx, input.UserID, method.Method)
	if err != nil {
		return nil, err
	}

	return &struct{}{}, nil
}

func (c *mfaController) setupTOTPHandler(ctx context.Context, input *SetupOrganizationTOTPInput) (*SetupOrganizationTOTPOutput, error) {
	response, err := c.di.MFAService().SetupTOTP(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	return &SetupOrganizationTOTPOutput{Body: response}, nil
}

func (c *mfaController) verifyTOTPHandler(ctx context.Context, input *VerifyTOTPInput) (*VerifyTOTPOutput, error) {
	response, err := c.di.MFAService().VerifyTOTP(ctx, input.UserID, input.Body.Code)
	if err != nil {
		return nil, err
	}

	return &VerifyTOTPOutput{Body: response}, nil
}

func (c *mfaController) disableTOTPHandler(ctx context.Context, input *DisableTOTPInput) (*struct{}, error) {
	err := c.di.MFAService().DisableTOTP(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	return &struct{}{}, nil
}

func (c *mfaController) setupSMSHandler(ctx context.Context, input *SetupSMSInput) (*SetupSMSOutput, error) {
	response, err := c.di.MFAService().SetupSMS(ctx, input.UserID, input.Body)
	if err != nil {
		return nil, err
	}

	return &SetupSMSOutput{Body: response}, nil
}

func (c *mfaController) sendSMSCodeHandler(ctx context.Context, input *SendSMSCodeInput) (*SendSMSCodeOutput, error) {
	response, err := c.di.MFAService().SendSMSCode(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	return &SendSMSCodeOutput{Body: response}, nil
}

func (c *mfaController) verifySMSCodeHandler(ctx context.Context, input *VerifySMSCodeInput) (*VerifySMSCodeOutput, error) {
	response, err := c.di.MFAService().VerifySMSCode(ctx, input.UserID, input.Body.Code)
	if err != nil {
		return nil, err
	}

	return &VerifySMSCodeOutput{Body: response}, nil
}

func (c *mfaController) disableSMSHandler(ctx context.Context, input *DisableTOTPInput) (*struct{}, error) {
	err := c.di.MFAService().DisableSMS(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	return &struct{}{}, nil
}

func (c *mfaController) setupEmailMFAHandler(ctx context.Context, input *SetupEmailMFAInput) (*SetupEmailMFAOutput, error) {
	response, err := c.di.MFAService().SetupEmail(ctx, input.UserID, input.Body.Email)
	if err != nil {
		return nil, err
	}

	return &SetupEmailMFAOutput{Body: response}, nil
}

func (c *mfaController) sendEmailCodeHandler(ctx context.Context, input *SendEmailCodeInput) (*SendEmailCodeOutput, error) {
	response, err := c.di.MFAService().SendEmailCode(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	return &SendEmailCodeOutput{Body: response}, nil
}

func (c *mfaController) verifyEmailCodeHandler(ctx context.Context, input *VerifyEmailCodeInput) (*VerifyEmailCodeOutput, error) {
	response, err := c.di.MFAService().VerifyEmailCode(ctx, input.UserID, input.Body.Code)
	if err != nil {
		return nil, err
	}

	return &VerifyEmailCodeOutput{Body: response}, nil
}

func (c *mfaController) disableEmailMFAHandler(ctx context.Context, input *DisableTOTPInput) (*struct{}, error) {
	err := c.di.MFAService().DisableEmailMFA(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	return &struct{}{}, nil
}

func (c *mfaController) generateBackupCodesHandler(ctx context.Context, input *GenerateOrganizationBackupCodesInput) (*GenerateOrganizationBackupCodesOutput, error) {
	response, err := c.di.MFAService().GenerateBackupCodes(ctx, input.UserID, &input.Body)
	if err != nil {
		return nil, err
	}

	return &GenerateOrganizationBackupCodesOutput{Body: response}, nil
}

func (c *mfaController) verifyBackupCodeHandler(ctx context.Context, input *VerifyBackupCodeInput) (*VerifyBackupCodeOutput, error) {
	response, err := c.di.MFAService().VerifyBackupCode(ctx, input.UserID, input.Body.Code)
	if err != nil {
		return nil, err
	}

	return &VerifyBackupCodeOutput{Body: response}, nil
}

func (c *mfaController) regenerateBackupCodesHandler(ctx context.Context, input *GenerateOrganizationBackupCodesInput) (*GenerateOrganizationBackupCodesOutput, error) {
	response, err := c.di.MFAService().RegenerateBackupCodes(ctx, input.UserID, &input.Body)
	if err != nil {
		return nil, err
	}

	return &GenerateOrganizationBackupCodesOutput{Body: response}, nil
}

func (c *mfaController) verifyMFAHandler(ctx context.Context, input *VerifyOrganizationMFAInput) (*VerifyOrganizationMFAOutput, error) {
	response, err := c.di.MFAService().VerifyMFA(ctx, input.UserID, input.Body.Method, input.Body.Code)
	if err != nil {
		return nil, err
	}

	return &VerifyOrganizationMFAOutput{Body: response}, nil
}

func (c *mfaController) createMFAChallengeHandler(ctx context.Context, input *CreateMFAChallengeInput) (*CreateMFAChallengeOutput, error) {
	response, err := c.di.MFAService().CreateMFAChallenge(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	return &CreateMFAChallengeOutput{Body: response}, nil
}

func (c *mfaController) validateMFAChallengeHandler(ctx context.Context, input *ValidateMFAChallengeInput) (*ValidateMFAChallengeOutput, error) {
	response, err := c.di.MFAService().ValidateMFAChallenge(ctx, input.Body.ChallengeID, input.Body.Method, input.Body.Code)
	if err != nil {
		return nil, err
	}

	return &ValidateMFAChallengeOutput{Body: response}, nil
}

func (c *mfaController) checkMFARequirementHandler(ctx context.Context, input *CheckMFARequirementInput) (*CheckMFARequirementOutput, error) {
	required, methods, err := c.di.MFAService().RequiresMFA(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	// Create a simplified MFA requirement check response
	response := &model.MFARequirementCheck{
		UserID:     input.UserID,
		Required:   required,
		Configured: len(methods) > 0,
		Methods:    methods,
	}

	return &CheckMFARequirementOutput{Body: response}, nil
}

func (c *mfaController) disableAllMFAHandler(ctx context.Context, input *DisableAllMFAInput) (*struct{}, error) {
	err := c.di.MFAService().DisableAllMFA(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	return &struct{}{}, nil
}

func (c *mfaController) getRecoveryOptionsHandler(ctx context.Context, input *GetRecoveryOptionsInput) (*GetRecoveryOptionsOutput, error) {
	response, err := c.di.MFAService().GetRecoveryOptions(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetRecoveryOptionsOutput{Body: response}, nil
}

func (c *mfaController) getMFAActivityHandler(ctx context.Context, input *GetMFAActivityInput) (*GetMFAActivityOutput, error) {
	// This would typically integrate with an audit service
	// For now, return empty activity
	response := &model.MFAActivityResponse{
		Data: []model.MFAActivity{},
		Pagination: &model.Pagination{
			TotalCount:      0,
			HasNextPage:     false,
			HasPreviousPage: false,
		},
	}

	return &GetMFAActivityOutput{Body: response}, nil
}

func (c *mfaController) resendMFACodeHandler(ctx context.Context, input *ResendMFACodeInput) (*ResendMFACodeOutput, error) {
	// Get the method to determine type
	method, err := c.di.MFAService().GetMFAMethod(ctx, input.Body.MethodID)
	if err != nil {
		return nil, err
	}

	var message string
	switch method.Method {
	case "sms":
		_, err = c.di.MFAService().SendSMSCode(ctx, input.UserID)
		message = "SMS code sent successfully"
	case "email":
		_, err = c.di.MFAService().SendEmailCode(ctx, input.UserID)
		message = "Email code sent successfully"
	default:
		return nil, errors.New(errors.CodeBadRequest, "resend not supported for this MFA method")
	}

	if err != nil {
		return nil, err
	}

	response := &model.ResendMFACodeResponse{
		Success: true,
		Message: message,
	}

	return &ResendMFACodeOutput{Body: response}, nil
}
