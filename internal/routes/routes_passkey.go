package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/juicycleff/frank/pkg/services/passkey"
	"github.com/rs/xid"
)

// RegisterPasskeyAPI registers protected passkey management endpoints
func RegisterPasskeyAPI(api huma.API, container di.Container) {
	passkeyCtrl := &passkeyController{
		api: api,
		di:  container,
	}

	// Passkey CRUD operations
	registerListOrganizationPasskeys(api, passkeyCtrl)
	registerCreatePasskey(api, passkeyCtrl)
	registerGetPasskey(api, passkeyCtrl)
	registerUpdatePasskey(api, passkeyCtrl)
	registerDeleteOrganizationPasskey(api, passkeyCtrl)

	// User-specific operations
	registerGetUserPasskeys(api, passkeyCtrl)
	registerDeactivateUserPasskeys(api, passkeyCtrl)

	// Bulk operations
	registerBulkDeletePasskeys(api, passkeyCtrl)
	registerUpdateBackupState(api, passkeyCtrl)

	// Analytics and reporting
	registerGetPasskeyStats(api, passkeyCtrl)
	registerGetPasskeyActivity(api, passkeyCtrl)
	registerExportPasskeyData(api, passkeyCtrl)

	// Utility operations
	registerVerifyPasskey(api, passkeyCtrl)
	registerValidateCredentialID(api, passkeyCtrl)
	registerCleanupUnusedPasskeys(api, passkeyCtrl)
	registerGetUnusedPasskeys(api, passkeyCtrl)
}

// RegisterPasskeyPublicAPI registers public passkey authentication endpoints
func RegisterPasskeyPublicAPI(api huma.API, container di.Container) {
	passkeyCtrl := &passkeyController{
		api: api,
		di:  container,
	}

	// Registration flow
	registerBeginRegistration(api, passkeyCtrl)
	registerFinishRegistration(api, passkeyCtrl)

	// Authentication flow
	registerBeginAuthentication(api, passkeyCtrl)
	registerFinishAuthentication(api, passkeyCtrl)

	// Discovery
	registerDiscoverPasskeys(api, passkeyCtrl)
}

// Passkey CRUD operations

func registerListOrganizationPasskeys(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listOrganizationPasskeys",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/passkeys",
		Summary:       "List passkeys",
		Description:   "List passkeys with filtering and pagination",
		Tags:          []string{"Passkeys"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "List of passkeys",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionReadPasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.listPasskeysHandler)
}

func registerCreatePasskey(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "createOrganizationPasskey",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/users/{userId}/passkeys",
		Summary:       "Create passkey",
		Description:   "Create a new passkey for a user",
		Tags:          []string{"Passkeys"},
		DefaultStatus: 201,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"201": {
				Description: "Passkey created successfully",
			},
		}, true, model.ConflictError("Passkey with this credential ID already exists")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionWritePasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.createPasskeyHandler)
}

func registerGetPasskey(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getOrganizationPasskey",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/passkeys/{id}",
		Summary:       "Get passkey",
		Description:   "Get a specific passkey by ID",
		Tags:          []string{"Passkeys"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Passkey not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionReadPasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.getPasskeyHandler)
}

func registerUpdatePasskey(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "updateOrganizationPasskey",
		Method:        http.MethodPut,
		Path:          "/organizations/{orgId}/passkeys/{id}",
		Summary:       "Update passkey",
		Description:   "Update a passkey's properties",
		Tags:          []string{"Passkeys"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Passkey not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionWritePasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.updatePasskeyHandler)
}

func registerDeleteOrganizationPasskey(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteOrganizationPasskey",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/passkeys/{id}",
		Summary:       "Delete passkey",
		Description:   "Delete a passkey by ID",
		Tags:          []string{"Passkeys"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "Passkey deleted successfully",
			},
		}, true, model.NotFoundError("Passkey not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionWritePasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.deletePasskeyHandler)
}

// User-specific operations

func registerGetUserPasskeys(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getUserPasskeys",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/users/{userId}/passkeys",
		Summary:       "Get user passkeys",
		Description:   "Get all passkeys for a specific user",
		Tags:          []string{"Passkeys", "Users"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionReadUser, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.getUserPasskeysHandler)
}

func registerDeactivateUserPasskeys(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deactivateUserPasskeys",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/users/{userId}/passkeys",
		Summary:       "Deactivate user passkeys",
		Description:   "Deactivate all passkeys for a specific user",
		Tags:          []string{"Passkeys", "Users"},
		DefaultStatus: 204,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionUpdateUser, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.deactivateUserPasskeysHandler)
}

// Bulk operations

func registerBulkDeletePasskeys(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "bulkDeletePasskeys",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/passkeys/bulk",
		Summary:       "Bulk delete passkeys",
		Description:   "Delete multiple passkeys at once",
		Tags:          []string{"Passkeys", "Bulk Operations"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Bulk delete results",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionWritePasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.bulkDeletePasskeysHandler)
}

func registerUpdateBackupState(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "updateBackupState",
		Method:        http.MethodPut,
		Path:          "/organizations/{orgId}/passkeys/backup",
		Summary:       "Update backup state",
		Description:   "Update backup state for multiple passkeys",
		Tags:          []string{"Passkeys", "Backup"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Backup state update results",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionWritePasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.updateBackupStateHandler)
}

// Analytics and reporting

func registerGetPasskeyStats(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getPasskeyStats",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/passkeys/stats",
		Summary:       "Get passkey statistics",
		Description:   "Get comprehensive passkey usage statistics",
		Tags:          []string{"Passkeys", "Analytics"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Passkey statistics",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionReadPasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.getPasskeyStatsHandler)
}

func registerGetPasskeyActivity(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getPasskeyActivity",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/passkeys/activity",
		Summary:       "Get passkey activity",
		Description:   "Get passkey activity logs with filtering",
		Tags:          []string{"Passkeys", "Activity"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Passkey activity logs",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionReadPasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.getPasskeyActivityHandler)
}

func registerExportPasskeyData(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "exportPasskeyData",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/passkeys/export",
		Summary:       "Export passkey data",
		Description:   "Export passkey data in various formats",
		Tags:          []string{"Passkeys", "Export"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Export initiated",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionReadPasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.exportPasskeyDataHandler)
}

// Utility operations

func registerVerifyPasskey(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "verifyPasskey",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/passkeys/verify",
		Summary:       "Verify passkey",
		Description:   "Verify a passkey credential",
		Tags:          []string{"Passkeys", "Verification"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Verification result",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionReadPasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.verifyPasskeyHandler)
}

func registerValidateCredentialID(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "validateCredentialID",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/passkeys/validate",
		Summary:       "Validate credential ID",
		Description:   "Validate a WebAuthn credential ID",
		Tags:          []string{"Passkeys", "Validation"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Validation result",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionReadPasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.validateCredentialIDHandler)
}

func registerCleanupUnusedPasskeys(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "cleanupUnusedPasskeys",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/passkeys/cleanup",
		Summary:       "Cleanup unused passkeys",
		Description:   "Remove passkeys that haven't been used for a specified period",
		Tags:          []string{"Passkeys", "Maintenance"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Cleanup results",
			},
		}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionWritePasskey, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.cleanupUnusedPasskeysHandler)
}

func registerGetUnusedPasskeys(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getUnusedPasskeys",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/users/{userId}/passkeys/unused",
		Summary:       "Get unused passkeys",
		Description:   "Get passkeys that haven't been used for a specified period",
		Tags:          []string{"Passkeys", "Users"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Unused passkeys",
			},
		}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, passkeyCtrl.di.AuthZ().Checker(), passkeyCtrl.di.Logger())(
			authz.PermissionReadUser, authz.ResourceOrganization, "orgId",
		)},
	}, passkeyCtrl.getUnusedPasskeysHandler)
}

// Public API endpoints - Registration/Authentication Flow

func registerBeginRegistration(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "beginPasskeyRegistration",
		Method:        http.MethodPost,
		Path:          "/passkeys/registration/begin",
		Summary:       "Begin passkey registration",
		Description:   "Start the WebAuthn passkey registration process",
		Tags:          []string{"Passkeys", "Authentication", "Public"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Registration challenge",
			},
		}, false, model.BadRequestError("Invalid registration request")),
	}, passkeyCtrl.beginRegistrationHandler)
}

func registerFinishRegistration(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "finishPasskeyRegistration",
		Method:        http.MethodPost,
		Path:          "/passkeys/registration/finish",
		Summary:       "Finish passkey registration",
		Description:   "Complete the WebAuthn passkey registration process",
		Tags:          []string{"Passkeys", "Authentication", "Public"},
		DefaultStatus: 201,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"201": {
				Description: "Passkey registered successfully",
			},
		}, false,
			model.BadRequestError("Invalid registration response"),
			model.UnauthorizedError(),
		),
	}, passkeyCtrl.finishRegistrationHandler)
}

func registerBeginAuthentication(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "beginPasskeyAuthentication",
		Method:        http.MethodPost,
		Path:          "/passkeys/authentication/begin",
		Summary:       "Begin passkey authentication",
		Description:   "Start the WebAuthn passkey authentication process",
		Tags:          []string{"Passkeys", "Authentication", "Public"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Authentication challenge",
			},
		}, false, model.BadRequestError("Invalid authentication request")),
	}, passkeyCtrl.beginAuthenticationHandler)
}

func registerFinishAuthentication(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "finishPasskeyAuthentication",
		Method:        http.MethodPost,
		Path:          "/passkeys/authentication/finish",
		Summary:       "Finish passkey authentication",
		Description:   "Complete the WebAuthn passkey authentication process",
		Tags:          []string{"Passkeys", "Authentication", "Public"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Authentication successful",
			},
		}, false,
			model.BadRequestError("Invalid authentication response"),
			model.UnauthorizedError(),
		),
	}, passkeyCtrl.finishAuthenticationHandler)
}

func registerDiscoverPasskeys(api huma.API, passkeyCtrl *passkeyController) {
	huma.Register(api, huma.Operation{
		OperationID:   "discoverPasskeys",
		Method:        http.MethodPost,
		Path:          "/passkeys/discover",
		Summary:       "Discover passkeys",
		Description:   "Discover available passkeys for a user",
		Tags:          []string{"Passkeys", "Discovery", "Public"},
		DefaultStatus: 200,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"200": {
				Description: "Passkey discovery results",
			},
		}, false),
	}, passkeyCtrl.discoverPasskeysHandler)
}

// passkeyController handles passkey-related API requests
type passkeyController struct {
	api huma.API
	di  di.Container
}

// Input/Output type definitions for passkey handlers

// ListOrganizationPasskeysInput represents input for listing passkeys
type ListOrganizationPasskeysInput struct {
	model.OrganisationPathParams
	model.PasskeyListRequest
}

type ListOrganizationPasskeysOutput = model.Output[*model.PasskeyListResponse]

// CreatePasskeyInput represents input for creating a passkey
type CreatePasskeyInput struct {
	model.OrganisationPathParams
	UserID xid.ID                     `path:"userId" doc:"User ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
	Body   model.CreatePasskeyRequest `json:"body"`
}

type CreatePasskeyOutput = model.Output[*model.Passkey]

// GetPasskeyInput represents input for getting a specific passkey
type GetPasskeyInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Passkey ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
}

type GetPasskeyOutput = model.Output[*model.Passkey]

// UpdatePasskeyInput represents input for updating a passkey
type UpdatePasskeyInput struct {
	model.OrganisationPathParams
	ID   xid.ID                     `path:"id" doc:"Passkey ID"`
	Body model.UpdatePasskeyRequest `json:"body"`
}

type UpdatePasskeyOutput = model.Output[*model.Passkey]

// DeleteOrganizationPasskeyInput represents input for deleting a passkey
type DeleteOrganizationPasskeyInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Passkey ID"`
}

type DeletePasskeyOutput = model.EmptyOutput

// GetUserPasskeysInput represents input for getting user passkeys
type GetUserPasskeysInput struct {
	model.OrganisationPathParams
	UserID     xid.ID `path:"userId" doc:"User ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
	ActiveOnly bool   `query:"activeOnly" doc:"Only return active passkeys" example:"true"`
}

type GetUserPasskeysOutput = model.Output[[]model.PasskeySummary]

// DeactivateUserPasskeysInput represents input for deactivating user passkeys
type DeactivateUserPasskeysInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
}

type DeactivateUserPasskeysOutput = model.EmptyOutput

// BulkDeletePasskeysInput represents input for bulk passkey deletion
type BulkDeletePasskeysInput struct {
	model.OrganisationPathParams
	Body model.BulkDeletePasskeysRequest `json:"body"`
}

type BulkDeletePasskeysOutput = model.Output[*model.BulkDeletePasskeysResponse]

// UpdateBackupStateInput represents input for updating backup state
type UpdateBackupStateInput struct {
	model.OrganisationPathParams
	Body model.PasskeyBackupRequest `json:"body"`
}

type UpdateBackupStateOutput = model.Output[*model.PasskeyBackupResponse]

// GetPasskeyStatsInput represents input for getting passkey statistics
type GetPasskeyStatsInput struct {
	model.OrganisationPathParams
	UserID model.OptionalParam[xid.ID] `query:"userId,omitempty" doc:"Filter by user ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
}

type GetPasskeyStatsOutput = model.Output[*model.PasskeyStats]

// GetPasskeyActivityInput represents input for getting passkey activity
type GetPasskeyActivityInput struct {
	model.OrganisationPathParams
	model.PasskeyActivityRequest
}

type GetPasskeyActivityOutput = model.Output[*model.PasskeyActivityResponse]

// ExportPasskeyDataInput represents input for exporting passkey data
type ExportPasskeyDataInput struct {
	model.OrganisationPathParams
	Body model.PasskeyExportRequest `json:"body"`
}

type ExportPasskeyDataOutput = model.Output[*model.PasskeyExportResponse]

// VerifyPasskeyInput represents input for passkey verification
type VerifyPasskeyInput struct {
	model.OrganisationPathParams
	Body model.PasskeyVerificationRequest `json:"body"`
}

type VerifyPasskeyOutput = model.Output[*model.PasskeyVerificationResponse]

// ValidateCredentialIDInput represents input for credential ID validation
type ValidateCredentialIDInput struct {
	model.OrganisationPathParams
	Body struct {
		CredentialID string `json:"credentialId" example:"credential_abc123" doc:"Credential ID to validate"`
	} `json:"body"`
}

type ValidateCredentialIDOutput = model.Output[*model.Passkey]

// CleanupUnusedPasskeysInput represents input for cleaning up unused passkeys
type CleanupUnusedPasskeysInput struct {
	model.OrganisationPathParams
	Days int `query:"days" doc:"Number of days of inactivity" example:"90"`
}

type CleanupUnusedPasskeysResponse struct {
	DeletedCount int `json:"deletedCount" example:"15" doc:"Number of passkeys deleted"`
}

type CleanupUnusedPasskeysOutput = model.Output[CleanupUnusedPasskeysResponse]

// GetUnusedPasskeysInput represents input for getting unused passkeys
type GetUnusedPasskeysInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
	Days   int    `query:"days" doc:"Number of days of inactivity" example:"90"`
}

type GetUnusedPasskeysOutput = model.Output[[]model.PasskeySummary]

// Public API Input/Output types

// BeginRegistrationInput represents input for beginning passkey registration
type BeginRegistrationInput struct {
	Body model.PasskeyRegistrationBeginRequest `json:"body"`
}

type BeginRegistrationOutput = model.Output[*model.PasskeyRegistrationBeginResponse]

// FinishRegistrationInput represents input for finishing passkey registration
type FinishRegistrationInput struct {
	Body model.PasskeyRegistrationFinishRequest `json:"body"`
}

type FinishRegistrationOutput = model.Output[*model.PasskeyRegistrationFinishResponse]

// BeginAuthenticationInput represents input for beginning passkey authentication
type BeginAuthenticationInput struct {
	Body model.PasskeyAuthenticationBeginRequest `json:"body"`
}

type BeginAuthenticationOutput = model.Output[*model.PasskeyAuthenticationBeginResponse]

// FinishAuthenticationInput represents input for finishing passkey authentication
type FinishAuthenticationInput struct {
	Body model.PasskeyAuthenticationFinishRequest `json:"body"`
}

type FinishAuthenticationOutput = model.Output[*model.PasskeyAuthenticationFinishResponse]

// DiscoverPasskeysInput represents input for passkey discovery
type DiscoverPasskeysInput struct {
	Body model.PasskeyDiscoveryRequest `json:"body"`
}

type DiscoverPasskeysOutput = model.Output[*model.PasskeyDiscoveryResponse]

// Handler implementations

// Protected endpoint handlers

func (ctrl *passkeyController) listPasskeysHandler(ctx context.Context, input *ListOrganizationPasskeysInput) (*ListOrganizationPasskeysOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	result, err := passkeyService.ListPasskeys(ctx, input.PasskeyListRequest)
	if err != nil {
		return nil, err
	}

	return &ListOrganizationPasskeysOutput{
		Body: result,
	}, nil
}

func (ctrl *passkeyController) createPasskeyHandler(ctx context.Context, input *CreatePasskeyInput) (*CreatePasskeyOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	passkey, err := passkeyService.CreatePasskey(ctx, input.UserID, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreatePasskeyOutput{
		Body: passkey,
	}, nil
}

func (ctrl *passkeyController) getPasskeyHandler(ctx context.Context, input *GetPasskeyInput) (*GetPasskeyOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	passkey, err := passkeyService.GetPasskey(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &GetPasskeyOutput{
		Body: passkey,
	}, nil
}

func (ctrl *passkeyController) updatePasskeyHandler(ctx context.Context, input *UpdatePasskeyInput) (*UpdatePasskeyOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	passkey, err := passkeyService.UpdatePasskey(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdatePasskeyOutput{
		Body: passkey,
	}, nil
}

func (ctrl *passkeyController) deletePasskeyHandler(ctx context.Context, input *DeleteOrganizationPasskeyInput) (*DeletePasskeyOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	err := passkeyService.DeletePasskey(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &DeletePasskeyOutput{}, nil
}

func (ctrl *passkeyController) getUserPasskeysHandler(ctx context.Context, input *GetUserPasskeysInput) (*GetUserPasskeysOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	passkeys, err := passkeyService.GetUserPasskeys(ctx, input.UserID, input.ActiveOnly)
	if err != nil {
		return nil, err
	}

	// Convert []*model.PasskeySummary to []model.PasskeySummary
	result := make([]model.PasskeySummary, len(passkeys))
	for i, passkey := range passkeys {
		result[i] = *passkey
	}

	return &GetUserPasskeysOutput{
		Body: result,
	}, nil
}

func (ctrl *passkeyController) deactivateUserPasskeysHandler(ctx context.Context, input *DeactivateUserPasskeysInput) (*DeactivateUserPasskeysOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	err := passkeyService.DeactivateUserPasskeys(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	return &DeactivateUserPasskeysOutput{}, nil
}

func (ctrl *passkeyController) bulkDeletePasskeysHandler(ctx context.Context, input *BulkDeletePasskeysInput) (*BulkDeletePasskeysOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	result, err := passkeyService.BulkDeletePasskeys(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &BulkDeletePasskeysOutput{
		Body: result,
	}, nil
}

func (ctrl *passkeyController) updateBackupStateHandler(ctx context.Context, input *UpdateBackupStateInput) (*UpdateBackupStateOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	result, err := passkeyService.UpdateBackupState(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateBackupStateOutput{
		Body: result,
	}, nil
}

func (ctrl *passkeyController) getPasskeyStatsHandler(ctx context.Context, input *GetPasskeyStatsInput) (*GetPasskeyStatsOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	var userID *xid.ID
	if input.UserID.IsSet {
		userID = &input.UserID.Value
	}

	stats, err := passkeyService.GetPasskeyStats(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &GetPasskeyStatsOutput{
		Body: stats,
	}, nil
}

func (ctrl *passkeyController) getPasskeyActivityHandler(ctx context.Context, input *GetPasskeyActivityInput) (*GetPasskeyActivityOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	activity, err := passkeyService.GetPasskeyActivity(ctx, input.PasskeyActivityRequest)
	if err != nil {
		return nil, err
	}

	return &GetPasskeyActivityOutput{
		Body: activity,
	}, nil
}

func (ctrl *passkeyController) exportPasskeyDataHandler(ctx context.Context, input *ExportPasskeyDataInput) (*ExportPasskeyDataOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	result, err := passkeyService.ExportPasskeyData(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &ExportPasskeyDataOutput{
		Body: result,
	}, nil
}

func (ctrl *passkeyController) verifyPasskeyHandler(ctx context.Context, input *VerifyPasskeyInput) (*VerifyPasskeyOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	result, err := passkeyService.VerifyPasskey(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &VerifyPasskeyOutput{
		Body: result,
	}, nil
}

func (ctrl *passkeyController) validateCredentialIDHandler(ctx context.Context, input *ValidateCredentialIDInput) (*ValidateCredentialIDOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	result, err := passkeyService.ValidateCredentialID(ctx, input.Body.CredentialID)
	if err != nil {
		return nil, err
	}

	return &ValidateCredentialIDOutput{
		Body: result,
	}, nil
}

func (ctrl *passkeyController) cleanupUnusedPasskeysHandler(ctx context.Context, input *CleanupUnusedPasskeysInput) (*CleanupUnusedPasskeysOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	deletedCount, err := passkeyService.CleanupUnusedPasskeys(ctx, input.Days)
	if err != nil {
		return nil, err
	}

	return &CleanupUnusedPasskeysOutput{
		Body: CleanupUnusedPasskeysResponse{
			DeletedCount: deletedCount,
		},
	}, nil
}

func (ctrl *passkeyController) getUnusedPasskeysHandler(ctx context.Context, input *GetUnusedPasskeysInput) (*GetUnusedPasskeysOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	passkeys, err := passkeyService.GetUnusedPasskeys(ctx, input.UserID, input.Days)
	if err != nil {
		return nil, err
	}

	// Convert []*model.PasskeySummary to []model.PasskeySummary
	result := make([]model.PasskeySummary, len(passkeys))
	for i, passkey := range passkeys {
		result[i] = *passkey
	}

	return &GetUnusedPasskeysOutput{
		Body: result,
	}, nil
}

// Public endpoint handlers

func (ctrl *passkeyController) beginRegistrationHandler(ctx context.Context, input *BeginRegistrationInput) (*BeginRegistrationOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	result, err := passkeyService.BeginRegistration(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &BeginRegistrationOutput{
		Body: result,
	}, nil
}

func (ctrl *passkeyController) finishRegistrationHandler(ctx context.Context, input *FinishRegistrationInput) (*FinishRegistrationOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	result, err := passkeyService.FinishRegistration(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &FinishRegistrationOutput{
		Body: result,
	}, nil
}

func (ctrl *passkeyController) beginAuthenticationHandler(ctx context.Context, input *BeginAuthenticationInput) (*BeginAuthenticationOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	result, err := passkeyService.BeginAuthentication(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &BeginAuthenticationOutput{
		Body: result,
	}, nil
}

func (ctrl *passkeyController) finishAuthenticationHandler(ctx context.Context, input *FinishAuthenticationInput) (*FinishAuthenticationOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	result, err := passkeyService.FinishAuthentication(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &FinishAuthenticationOutput{
		Body: result,
	}, nil
}

func (ctrl *passkeyController) discoverPasskeysHandler(ctx context.Context, input *DiscoverPasskeysInput) (*DiscoverPasskeysOutput, error) {
	passkeyService := ctrl.di.PasskeyService()

	result, err := passkeyService.DiscoverPasskeys(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &DiscoverPasskeysOutput{
		Body: result,
	}, nil
}

// Helper method to get passkey service (if needed for validation)
func (ctrl *passkeyController) getPasskeyService() passkey.Service {
	return ctrl.di.PasskeyService()
}
