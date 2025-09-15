package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/xid"
	"github.com/xraph/frank/internal/authz"
	"github.com/xraph/frank/internal/di"
	"github.com/xraph/frank/pkg/model"
)

// RegisterSSOAPI registers SSO management endpoints (protected routes)
func RegisterSSOAPI(group huma.API, di di.Container) {
	di.Logger().Info("Registering SSO API routes")

	ssoCtrl := &ssoController{
		api: group,
		di:  di,
	}

	// Provider management routes
	registerListProviders(group, ssoCtrl)
	registerCreateProvider(group, ssoCtrl)
	registerGetProvider(group, ssoCtrl)
	registerUpdateProvider(group, ssoCtrl)
	registerDeleteProvider(group, ssoCtrl)
	registerEnableProvider(group, ssoCtrl)
	registerDisableProvider(group, ssoCtrl)

	// Provider testing and health
	registerTestProviderConnection(group, ssoCtrl)
	registerCheckProviderHealth(group, ssoCtrl)
	registerGetProviderHealthStatus(group, ssoCtrl)

	// Provider configuration and metadata
	registerGetProviderMetadata(group, ssoCtrl)
	registerExportSSOData(group, ssoCtrl)

	// Domain management
	registerVerifyDomain(group, ssoCtrl)
	registerGetProviderByDomain(group, ssoCtrl)

	// User provisioning
	registerBulkProvisionUsers(group, ssoCtrl)

	// Analytics and metrics
	registerGetSSOStats(group, ssoCtrl)
	registerGetProviderStats(group, ssoCtrl)
	registerGetSSOActivity(group, ssoCtrl)
	registerGetProviderMetrics(group, ssoCtrl)

	// Provider catalog (templates)
	registerGetProviderCatalog(group, ssoCtrl)
	registerGetProviderTemplate(group, ssoCtrl)
	registerEnableProviderFromTemplate(group, ssoCtrl)
	registerGetOrganizationProviders(group, ssoCtrl)
	registerConfigureProvider(group, ssoCtrl)
}

// RegisterSSOPublicAPI registers public SSO endpoints (authentication flow)
func RegisterSSOPublicAPI(group huma.API, di di.Container) {
	di.Logger().Info("Registering public SSO API routes")

	ssoCtrl := &ssoController{
		api: group,
		di:  di,
	}

	// SSO authentication flow
	registerInitiateSSOLogin(group, ssoCtrl)
	registerHandleSSOCallback(group, ssoCtrl)
	registerHandleSAMLCallback(group, ssoCtrl)

	// Public metadata endpoints
	registerGetPublicProviderMetadata(group, ssoCtrl)
}

// ssoController handles SSO-related API requests
type ssoController struct {
	api huma.API
	di  di.Container
}

// Input/Output type definitions for SSO handlers

// ListProvidersInput represents input for listing SSO providers
type ListProvidersInput struct {
	model.OrganisationPathParams
	model.SSOProviderListRequest
}

type ListProvidersOutput = model.Output[*model.SSOProviderListResponse]

// CreateProviderInput represents input for creating an SSO provider
type CreateProviderInput struct {
	model.OrganisationPathParams
	Body model.CreateIdentityProviderRequest `json:"body"`
}

type CreateProviderOutput = model.Output[*model.IdentityProvider]

// GetProviderInput represents input for getting a specific SSO provider
type GetProviderInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Provider ID" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
}

type GetProviderOutput = model.Output[*model.IdentityProvider]

// UpdateProviderInput represents input for updating an SSO provider
type UpdateProviderInput struct {
	model.OrganisationPathParams
	ID   xid.ID                              `path:"id" doc:"Provider ID"`
	Body model.UpdateIdentityProviderRequest `json:"body"`
}

type UpdateProviderOutput = model.Output[*model.IdentityProvider]

// DeleteProviderInput represents input for deleting an SSO provider
type DeleteProviderInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Provider ID"`
}

type DeleteProviderOutput = model.Output[any]

// EnableProviderInput represents input for enabling an SSO provider
type EnableProviderInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Provider ID"`
}

type EnableProviderOutput = model.Output[any]

// DisableProviderInput represents input for disabling an SSO provider
type DisableProviderInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Provider ID"`
}

type DisableProviderOutput = model.Output[any]

// InitiateSSOLoginInput represents input for initiating SSO login
type InitiateSSOLoginInput struct {
	Body model.SSOLoginRequest `json:"body"`
}

type InitiateSSOLoginOutput = model.Output[*model.SSOLoginResponse]

// HandleSSOCallbackInput represents input for handling SSO callback
type HandleSSOCallbackInput struct {
	Body model.SSOCallbackRequest `json:"body"`
}

type HandleSSOCallbackOutput = model.Output[*model.SSOCallbackResponse]

// HandleSAMLCallbackInput represents input for handling SAML callback
type HandleSAMLCallbackInput struct {
	ProviderID   xid.ID `path:"providerId" doc:"Provider ID"`
	SAMLResponse string `form:"SAMLResponse" doc:"SAML Response"`
	RelayState   string `form:"RelayState" doc:"SAML Relay State"`
}

type HandleSAMLCallbackOutput = model.Output[*model.SSOCallbackResponse]

// TestProviderConnectionInput represents input for testing provider connection
type TestProviderConnectionInput struct {
	model.OrganisationPathParams
	ID   xid.ID                         `path:"id" doc:"Provider ID"`
	Body model.TestSSOConnectionRequest `json:"body"`
}

type TestProviderConnectionOutput = model.Output[*model.TestSSOConnectionResponse]

// BulkProvisionUsersInput represents input for bulk user provisioning
type BulkProvisionUsersInput struct {
	model.OrganisationPathParams
	Body model.SSOBulkProvisionRequest `json:"body"`
}

type BulkProvisionUsersOutput = model.Output[*model.SSOBulkProvisionResponse]

// VerifyDomainInput represents input for domain verification
type VerifyDomainInput struct {
	model.OrganisationPathParams
	Body model.SSODomainVerificationRequest `json:"body"`
}

type VerifyDomainOutput = model.Output[*model.SSODomainVerificationResponse]

// GetProviderByDomainInput represents input for getting provider by domain
type GetProviderByDomainInput struct {
	Domain string `query:"domain" doc:"Domain name" example:"acme.com"`
}

type GetProviderByDomainOutput = model.Output[*model.IdentityProvider]

// GetProviderMetadataInput represents input for getting provider metadata
type GetProviderMetadataInput struct {
	model.OrganisationPathParams
	ID     xid.ID `path:"id" doc:"Provider ID"`
	Format string `query:"format" doc:"Metadata format (xml, json)" example:"xml"`
}

type GetProviderMetadataOutput = model.Output[*model.SSOMetadataResponse]

// GetPublicProviderMetadataInput represents input for getting public provider metadata
type GetPublicProviderMetadataInput struct {
	ProviderID xid.ID `path:"providerId" doc:"Provider ID"`
	Format     string `query:"format" doc:"Metadata format (xml, json)" example:"xml"`
}

type GetPublicProviderMetadataOutput = model.Output[*model.SSOMetadataResponse]

// ExportSSODataInput represents input for exporting SSO data
type ExportSSODataInput struct {
	model.OrganisationPathParams
	Body model.SSOExportRequest `json:"body"`
}

type ExportSSODataOutput = model.Output[*model.SSOExportResponse]

// GetSSOStatsInput represents input for getting SSO statistics
type GetSSOStatsInput struct {
	model.OrganisationPathParams
}

type GetSSOStatsOutput = model.Output[*model.SSOStats]

// GetProviderStatsInput represents input for getting provider statistics
type GetProviderStatsInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Provider ID"`
}

type GetProviderStatsOutput = model.Output[*model.SSOProviderStats]

// GetSSOActivityInput represents input for getting SSO activity
type GetSSOActivityInput struct {
	model.OrganisationPathParams
	model.SSOActivityRequest
}

type GetSSOActivityOutput = model.Output[*model.SSOActivityResponse]

// GetProviderMetricsInput represents input for getting provider metrics
type GetProviderMetricsInput struct {
	model.OrganisationPathParams
	ID     xid.ID `path:"id" doc:"Provider ID"`
	Period string `query:"period" doc:"Metrics period (1h, 24h, 7d, 30d)" example:"24h"`
}

type GetProviderMetricsOutput = model.Output[*model.SSOProviderMetrics]

// CheckProviderHealthInput represents input for checking provider health
type CheckProviderHealthInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Provider ID"`
}

type CheckProviderHealthOutput = model.Output[*model.SSOHealthCheck]

// GetProviderHealthStatusInput represents input for getting provider health status
type GetProviderHealthStatusInput struct {
	model.OrganisationPathParams
}

type GetProviderHealthStatusOutput = model.Output[[]model.SSOHealthCheck]

// Provider catalog inputs/outputs
type GetProviderCatalogInput struct {
	model.ProviderCatalogListRequest
}

type GetProviderCatalogOutput = model.Output[*model.ProviderCatalogListResponse]

type GetProviderTemplateInput struct {
	TemplateKey string `path:"templateKey" doc:"Provider template key" example:"google"`
}

type GetProviderTemplateOutput = model.Output[*model.ProviderTemplate]

type EnableProviderFromTemplateInput struct {
	model.OrganisationPathParams
	Body model.EnableProviderBody
}

type EnableProviderFromTemplateOutput = model.Output[*model.IdentityProvider]

type GetOrganizationProvidersInput struct {
	model.OrganizationProviderListRequest
}

type GetOrganizationProvidersOutput = model.Output[*model.OrganizationProviderListResponse]

type ConfigureProviderInput struct {
	model.OrganisationPathParams
	ID   xid.ID                      `path:"id" doc:"Provider ID"`
	Body model.ProviderConfiguration `json:"body"`
}

type ConfigureProviderOutput = model.Output[*model.IdentityProvider]

// Route registration functions

func registerListProviders(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "listProviders",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/sso/providers",
		Summary:       "List SSO providers",
		Description:   "Get a paginated list of SSO providers for the organization",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.listProvidersHandler)
}

func registerCreateProvider(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "createProvider",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/sso/providers",
		Summary:       "Create SSO provider",
		Description:   "Create a new SSO provider for the organization",
		Tags:          []string{"SSO"},
		DefaultStatus: 201,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionWriteSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.createProviderHandler)
}

func registerGetProvider(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getProvider",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/sso/providers/{id}",
		Summary:       "Get SSO provider",
		Description:   "Get details of a specific SSO provider",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.getProviderHandler)
}

func registerUpdateProvider(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "updateProvider",
		Method:        http.MethodPut,
		Path:          "/organizations/{orgId}/sso/providers/{id}",
		Summary:       "Update SSO provider",
		Description:   "Update an existing SSO provider configuration",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionWriteSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.updateProviderHandler)
}

func registerDeleteProvider(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteProvider",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/sso/providers/{id}",
		Summary:       "Delete SSO provider",
		Description:   "Delete an SSO provider",
		Tags:          []string{"SSO"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "SSO provider deleted successfully",
			},
		}, true, model.NotFoundError("Provider not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionWriteSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.deleteProviderHandler)
}

func registerEnableProvider(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "enableProvider",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/sso/providers/{id}/enable",
		Summary:       "Enable SSO provider",
		Description:   "Enable an SSO provider for authentication",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionWriteSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.enableProviderHandler)
}

func registerDisableProvider(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "disableProvider",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/sso/providers/{id}/disable",
		Summary:       "Disable SSO provider",
		Description:   "Disable an SSO provider from authentication",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionWriteSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.disableProviderHandler)
}

func registerInitiateSSOLogin(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "initiateSSOLogin",
		Method:        http.MethodPost,
		Path:          "/auth/sso/login",
		Summary:       "Initiate SSO login",
		Description:   "OnStart the SSO authentication flow",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
	}, ssoCtrl.initiateSSOLoginHandler)
}

func registerHandleSSOCallback(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "handleSSOCallback",
		Method:        http.MethodPost,
		Path:          "/auth/sso/callback",
		Summary:       "Handle SSO callback",
		Description:   "Process SSO authentication callback",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
	}, ssoCtrl.handleSSOCallbackHandler)
}

func registerHandleSAMLCallback(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "handleSAMLCallback",
		Method:        http.MethodPost,
		Path:          "/auth/saml/callback/{providerId}",
		Summary:       "Handle SAML callback",
		Description:   "Process SAML authentication callback",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
	}, ssoCtrl.handleSAMLCallbackHandler)
}

func registerTestProviderConnection(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "testProviderConnection",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/sso/providers/{id}/test",
		Summary:       "Test SSO provider connection",
		Description:   "Test connectivity and configuration of an SSO provider",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.testProviderConnectionHandler)
}

func registerBulkProvisionUsers(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "bulkProvisionUsers",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/sso/bulk-provision",
		Summary:       "Bulk provision users",
		Description:   "Provision multiple users through SSO",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionCreateUser, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.bulkProvisionUsersHandler)
}

func registerVerifyDomain(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "verifyDomain",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/sso/domains/verify",
		Summary:       "Verify domain ownership",
		Description:   "Verify domain ownership for SSO configuration",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionWriteSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.verifyDomainHandler)
}

func registerGetProviderByDomain(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getProviderByDomain",
		Method:        http.MethodGet,
		Path:          "/auth/sso/discover",
		Summary:       "Discover SSO provider by domain",
		Description:   "Find SSO provider configuration for a given domain",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("No provider found for domain")),
	}, ssoCtrl.getProviderByDomainHandler)
}

func registerGetProviderMetadata(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getProviderMetadata",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/sso/providers/{id}/metadata",
		Summary:       "Get SSO provider metadata",
		Description:   "Get SAML metadata or OIDC configuration for an SSO provider",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.getProviderMetadataHandler)
}

func registerGetPublicProviderMetadata(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getPublicProviderMetadata",
		Method:        http.MethodGet,
		Path:          "/auth/sso/metadata/{providerId}",
		Summary:       "Get public SSO provider metadata",
		Description:   "Get publicly accessible SAML metadata or OIDC configuration",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
	}, ssoCtrl.getPublicProviderMetadataHandler)
}

func registerExportSSOData(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "exportSSOData",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/sso/export",
		Summary:       "Export SSO data",
		Description:   "Export SSO configuration and activity data",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.exportSSODataHandler)
}

func registerGetSSOStats(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getSSOStats",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/sso/stats",
		Summary:       "Get SSO statistics",
		Description:   "Get SSO usage statistics for the organization",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.getSSOStatsHandler)
}

func registerGetProviderStats(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getProviderStats",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/sso/providers/{id}/stats",
		Summary:       "Get provider statistics",
		Description:   "Get detailed statistics for a specific SSO provider",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.getProviderStatsHandler)
}

func registerGetSSOActivity(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getSSOActivity",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/sso/activity",
		Summary:       "Get SSO activity",
		Description:   "Get SSO activity logs and events",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.getSSOActivityHandler)
}

func registerGetProviderMetrics(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getProviderMetrics",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/sso/providers/{id}/metrics",
		Summary:       "Get provider metrics",
		Description:   "Get detailed metrics for a specific SSO provider",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.getProviderMetricsHandler)
}

func registerCheckProviderHealth(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "checkProviderHealth",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/sso/providers/{id}/health",
		Summary:       "Check provider health",
		Description:   "Check the health status of an SSO provider",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.checkProviderHealthHandler)
}

func registerGetProviderHealthStatus(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getProviderHealthStatus",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/sso/health",
		Summary:       "Get provider health status",
		Description:   "Get health status for all SSO providers in the organization",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.getProviderHealthStatusHandler)
}

// Provider catalog routes
func registerGetProviderCatalog(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getProviderCatalog",
		Method:        http.MethodGet,
		Path:          "/sso/catalog",
		Summary:       "Get provider catalog",
		Description:   "Get available SSO provider templates from the catalog",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, ssoCtrl.getProviderCatalogHandler)
}

func registerGetProviderTemplate(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getProviderTemplate",
		Method:        http.MethodGet,
		Path:          "/sso/catalog/{templateKey}",
		Summary:       "Get provider template",
		Description:   "Get details of a specific provider template",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider template not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, ssoCtrl.getProviderTemplateHandler)
}

func registerEnableProviderFromTemplate(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID: "enableProviderFromTemplate",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/sso/catalog/enable",
		Summary:     "Enable provider from template",
		Description: "Enable an SSO provider for the organization using a catalog template",
		Tags:        []string{"SSO"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider template not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionWriteSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.enableProviderFromTemplateHandler)
}

func registerGetOrganizationProviders(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getOrganizationProviders",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/sso/organization-providers",
		Summary:       "Get organization providers",
		Description:   "Get SSO providers configured for the organization with template details",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionReadSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.getOrganizationProvidersHandler)
}

func registerConfigureProvider(api huma.API, ssoCtrl *ssoController) {
	huma.Register(api, huma.Operation{
		OperationID:   "configureProvider",
		Method:        http.MethodPut,
		Path:          "/organizations/{orgId}/sso/providers/{id}/configure",
		Summary:       "Configure provider",
		Description:   "Update provider configuration with advanced settings",
		Tags:          []string{"SSO"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Provider not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ssoCtrl.di.AuthZ().Checker(), ssoCtrl.di.Logger())(
			authz.PermissionWriteSSO, model.ResourceOrganization, "orgId",
		)},
	}, ssoCtrl.configureProviderHandler)
}

// Handler implementations

func (ctrl *ssoController) listProvidersHandler(ctx context.Context, input *ListProvidersInput) (*ListProvidersOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.ListProviders(ctx, input.SSOProviderListRequest)
	if err != nil {
		return nil, err
	}

	return &ListProvidersOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) createProviderHandler(ctx context.Context, input *CreateProviderInput) (*CreateProviderOutput, error) {
	ssoService := ctrl.di.SSOService()

	provider, err := ssoService.CreateProvider(ctx, input.PathOrgID, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreateProviderOutput{
		Body: provider,
	}, nil
}

func (ctrl *ssoController) getProviderHandler(ctx context.Context, input *GetProviderInput) (*GetProviderOutput, error) {
	ssoService := ctrl.di.SSOService()

	provider, err := ssoService.GetProvider(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &GetProviderOutput{
		Body: provider,
	}, nil
}

func (ctrl *ssoController) updateProviderHandler(ctx context.Context, input *UpdateProviderInput) (*UpdateProviderOutput, error) {
	ssoService := ctrl.di.SSOService()

	provider, err := ssoService.UpdateProvider(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateProviderOutput{
		Body: provider,
	}, nil
}

func (ctrl *ssoController) deleteProviderHandler(ctx context.Context, input *DeleteProviderInput) (*DeleteProviderOutput, error) {
	ssoService := ctrl.di.SSOService()

	err := ssoService.DeleteProvider(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &DeleteProviderOutput{}, nil
}

func (ctrl *ssoController) enableProviderHandler(ctx context.Context, input *EnableProviderInput) (*EnableProviderOutput, error) {
	ssoService := ctrl.di.SSOService()

	err := ssoService.EnableProvider(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &EnableProviderOutput{}, nil
}

func (ctrl *ssoController) disableProviderHandler(ctx context.Context, input *DisableProviderInput) (*DisableProviderOutput, error) {
	ssoService := ctrl.di.SSOService()

	err := ssoService.DisableProvider(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &DisableProviderOutput{}, nil
}

func (ctrl *ssoController) initiateSSOLoginHandler(ctx context.Context, input *InitiateSSOLoginInput) (*InitiateSSOLoginOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.InitiateSSOLogin(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &InitiateSSOLoginOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) handleSSOCallbackHandler(ctx context.Context, input *HandleSSOCallbackInput) (*HandleSSOCallbackOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.HandleSSOCallback(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &HandleSSOCallbackOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) handleSAMLCallbackHandler(ctx context.Context, input *HandleSAMLCallbackInput) (*HandleSAMLCallbackOutput, error) {
	ssoService := ctrl.di.SSOService()

	callbackRequest := model.SSOCallbackRequest{
		ProviderID:   input.ProviderID,
		SAMLResponse: input.SAMLResponse,
		RelayState:   input.RelayState,
	}

	result, err := ssoService.HandleSSOCallback(ctx, callbackRequest)
	if err != nil {
		return nil, err
	}

	return &HandleSAMLCallbackOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) testProviderConnectionHandler(ctx context.Context, input *TestProviderConnectionInput) (*TestProviderConnectionOutput, error) {
	ssoService := ctrl.di.SSOService()

	// Set provider ID in the test request
	input.Body.ProviderID = input.ID

	result, err := ssoService.TestConnection(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &TestProviderConnectionOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) bulkProvisionUsersHandler(ctx context.Context, input *BulkProvisionUsersInput) (*BulkProvisionUsersOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.BulkProvisionUsers(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &BulkProvisionUsersOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) verifyDomainHandler(ctx context.Context, input *VerifyDomainInput) (*VerifyDomainOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.VerifyDomain(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &VerifyDomainOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) getProviderByDomainHandler(ctx context.Context, input *GetProviderByDomainInput) (*GetProviderByDomainOutput, error) {
	ssoService := ctrl.di.SSOService()

	provider, err := ssoService.GetProviderByDomain(ctx, input.Domain)
	if err != nil {
		return nil, err
	}

	return &GetProviderByDomainOutput{
		Body: provider,
	}, nil
}

func (ctrl *ssoController) getProviderMetadataHandler(ctx context.Context, input *GetProviderMetadataInput) (*GetProviderMetadataOutput, error) {
	ssoService := ctrl.di.SSOService()

	req := model.SSOMetadataRequest{
		ProviderID: input.ID,
		Format:     input.Format,
	}

	result, err := ssoService.GetSSOMetadata(ctx, req)
	if err != nil {
		return nil, err
	}

	return &GetProviderMetadataOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) getPublicProviderMetadataHandler(ctx context.Context, input *GetPublicProviderMetadataInput) (*GetPublicProviderMetadataOutput, error) {
	ssoService := ctrl.di.SSOService()

	req := model.SSOMetadataRequest{
		ProviderID: input.ProviderID,
		Format:     input.Format,
	}

	result, err := ssoService.GetSSOMetadata(ctx, req)
	if err != nil {
		return nil, err
	}

	return &GetPublicProviderMetadataOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) exportSSODataHandler(ctx context.Context, input *ExportSSODataInput) (*ExportSSODataOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.ExportSSOData(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &ExportSSODataOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) getSSOStatsHandler(ctx context.Context, input *GetSSOStatsInput) (*GetSSOStatsOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.GetSSOStats(ctx, &input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &GetSSOStatsOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) getProviderStatsHandler(ctx context.Context, input *GetProviderStatsInput) (*GetProviderStatsOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.GetProviderStats(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &GetProviderStatsOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) getSSOActivityHandler(ctx context.Context, input *GetSSOActivityInput) (*GetSSOActivityOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.GetSSOActivity(ctx, input.SSOActivityRequest)
	if err != nil {
		return nil, err
	}

	return &GetSSOActivityOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) getProviderMetricsHandler(ctx context.Context, input *GetProviderMetricsInput) (*GetProviderMetricsOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.GetProviderMetrics(ctx, input.ID, input.Period)
	if err != nil {
		return nil, err
	}

	return &GetProviderMetricsOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) checkProviderHealthHandler(ctx context.Context, input *CheckProviderHealthInput) (*CheckProviderHealthOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.CheckProviderHealth(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &CheckProviderHealthOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) getProviderHealthStatusHandler(ctx context.Context, input *GetProviderHealthStatusInput) (*GetProviderHealthStatusOutput, error) {
	ssoService := ctrl.di.SSOService()

	result, err := ssoService.GetHealthStatus(ctx, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &GetProviderHealthStatusOutput{
		Body: result,
	}, nil
}

// Provider catalog handlers
func (ctrl *ssoController) getProviderCatalogHandler(ctx context.Context, input *GetProviderCatalogInput) (*GetProviderCatalogOutput, error) {
	catalogService := ctrl.di.ProviderCatalogService()

	result, err := catalogService.ListProviderTemplates(ctx, input.ProviderCatalogListRequest)
	if err != nil {
		return nil, err
	}

	return &GetProviderCatalogOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) getProviderTemplateHandler(ctx context.Context, input *GetProviderTemplateInput) (*GetProviderTemplateOutput, error) {
	catalogService := ctrl.di.ProviderCatalogService()

	template, err := catalogService.GetProviderTemplate(ctx, input.TemplateKey)
	if err != nil {
		return nil, err
	}

	return &GetProviderTemplateOutput{
		Body: template,
	}, nil
}

func (ctrl *ssoController) enableProviderFromTemplateHandler(ctx context.Context, input *EnableProviderFromTemplateInput) (*EnableProviderFromTemplateOutput, error) {
	catalogService := ctrl.di.ProviderCatalogService()

	// Set organization ID from path parameter
	input.Body.OrganizationID = input.PathOrgID

	provider, err := catalogService.EnableProviderForOrganization(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &EnableProviderFromTemplateOutput{
		Body: provider,
	}, nil
}

func (ctrl *ssoController) getOrganizationProvidersHandler(ctx context.Context, input *GetOrganizationProvidersInput) (*GetOrganizationProvidersOutput, error) {
	catalogService := ctrl.di.ProviderCatalogService()

	providers, err := catalogService.GetOrganizationProviders(ctx, input.OrganizationID)
	if err != nil {
		return nil, err
	}

	// Convert to paginated response
	result := &model.OrganizationProviderListResponse{
		Data: providers,
		Pagination: &model.Pagination{
			TotalCount:      len(providers),
			HasNextPage:     false,
			HasPreviousPage: false,
		},
	}

	return &GetOrganizationProvidersOutput{
		Body: result,
	}, nil
}

func (ctrl *ssoController) configureProviderHandler(ctx context.Context, input *ConfigureProviderInput) (*ConfigureProviderOutput, error) {
	catalogService := ctrl.di.ProviderCatalogService()

	provider, err := catalogService.ConfigureProvider(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &ConfigureProviderOutput{
		Body: provider,
	}, nil
}
