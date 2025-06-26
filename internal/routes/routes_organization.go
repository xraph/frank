package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/juicycleff/frank/pkg/services/organization"
	"github.com/rs/xid"
)

// RegisterPersonalOrganizationAPI registers all organization management endpoints
func RegisterPersonalOrganizationAPI(api huma.API, di di.Container) {
	orgCtrl := &organizationController{
		api: api,
		di:  di,
	}

	// Organization CRUD endpoints
	registerCreateOrganization(api, orgCtrl)
	registerGetOrganization(api, orgCtrl)
	registerListOrganizations(api, orgCtrl)
}

// RegisterOrganizationAPI registers all organization management endpoints
func RegisterOrganizationAPI(api huma.API, di di.Container) {
	orgCtrl := &organizationController{
		api: api,
		di:  di,
	}

	// Organization CRUD endpoints
	registerUpdateOrganization(api, orgCtrl)
	registerDeleteOrganization(api, orgCtrl)

	// Organization settings and configuration
	registerGetOrganizationSettings(api, orgCtrl)
	registerUpdateOrganizationSettings(api, orgCtrl)

	// Domain management
	registerListOrganizationDomains(api, orgCtrl)
	registerAddOrganizationDomain(api, orgCtrl)
	registerVerifyOrganizationDomain(api, orgCtrl)
	registerRemoveOrganizationDomain(api, orgCtrl)

	// Billing and subscription management
	registerGetOrganizationBilling(api, orgCtrl)
	registerUpdateOrganizationBilling(api, orgCtrl)
	registerGetOrganizationUsage(api, orgCtrl)
	registerGetOrganizationInvoices(api, orgCtrl)

	// Feature management
	registerListOrganizationFeatures(api, orgCtrl)
	registerEnableOrganizationFeature(api, orgCtrl)
	registerDisableOrganizationFeature(api, orgCtrl)

	// Organization statistics and analytics
	registerGetOrganizationStats(api, orgCtrl)
	registerGetOrganizationActivity(api, orgCtrl)
	registerExportOrganizationData(api, orgCtrl)

	// Organization ownership and transfer
	registerTransferOrganizationOwnership(api, orgCtrl)
	registerGetOrganizationOwnership(api, orgCtrl)
}

// organizationController handles organization management API requests
type organizationController struct {
	api huma.API
	di  di.Container
}

// Organization CRUD Endpoints

func registerListOrganizations(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "listOrganizations",
		Method:      http.MethodGet,
		Path:        "/organizations",
		Summary:     "List organizations",
		Description: "List organizations with pagination and filtering (admin only for all orgs, users see their orgs)",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, orgCtrl.listOrganizationsHandler)
}

func registerGetOrganization(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganization",
		Method:      http.MethodGet,
		Path:        "/organizations/{id}",
		Summary:     "Get organization",
		Description: "Get organization details by ID",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.getOrganizationHandler)
}

func registerCreateOrganization(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "createOrganization",
		Method:      http.MethodPost,
		Path:        "/organizations",
		Summary:     "Create organization",
		Description: "Create a new organization",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, orgCtrl.createOrganizationHandler)
}

func registerUpdateOrganization(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateOrganization",
		Method:      http.MethodPut,
		Path:        "/organizations/{id}",
		Summary:     "Update organization",
		Description: "Update organization information",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionUpdateOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.updateOrganizationHandler)
}

func registerDeleteOrganization(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteOrganization",
		Method:        http.MethodDelete,
		Path:          "/organizations/{id}",
		Summary:       "Delete organization",
		Description:   "Delete organization and all associated data",
		Tags:          []string{"Organizations"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Organization successfully deleted"},
		}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionDeleteOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.deleteOrganizationHandler)
}

// Organization Settings Endpoints

func registerGetOrganizationSettings(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganizationSettings",
		Method:      http.MethodGet,
		Path:        "/organizations/{id}/settings",
		Summary:     "Get organization settings",
		Description: "Get organization configuration and settings",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.getOrganizationSettingsHandler)
}

func registerUpdateOrganizationSettings(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateOrganizationSettings",
		Method:      http.MethodPut,
		Path:        "/organizations/{id}/settings",
		Summary:     "Update organization settings",
		Description: "Update organization configuration and settings",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionUpdateOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.updateOrganizationSettingsHandler)
}

// Domain Management Endpoints

func registerListOrganizationDomains(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "listOrganizationDomains",
		Method:      http.MethodGet,
		Path:        "/organizations/{id}/domains",
		Summary:     "List organization domains",
		Description: "List all domains associated with the organization",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.listOrganizationDomainsHandler)
}

func registerAddOrganizationDomain(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "addOrganizationDomain",
		Method:      http.MethodPost,
		Path:        "/organizations/{id}/domains",
		Summary:     "Add organization domain",
		Description: "Add a new domain to the organization",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionUpdateOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.addOrganizationDomainHandler)
}

func registerVerifyOrganizationDomain(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "verifyOrganizationDomain",
		Method:      http.MethodPost,
		Path:        "/organizations/{id}/domains/{domain}/verify",
		Summary:     "Verify organization domain",
		Description: "Verify domain ownership via DNS records",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization or domain not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionUpdateOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.verifyOrganizationDomainHandler)
}

func registerRemoveOrganizationDomain(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID:   "removeOrganizationDomain",
		Method:        http.MethodDelete,
		Path:          "/organizations/{id}/domains/{domain}",
		Summary:       "Remove organization domain",
		Description:   "Remove a domain from the organization",
		Tags:          []string{"Organizations"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Domain successfully removed"},
		}, false, model.NotFoundError("Organization or domain not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionUpdateOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.removeOrganizationDomainHandler)
}

// Billing and Subscription Endpoints

func registerGetOrganizationBilling(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganizationBilling",
		Method:      http.MethodGet,
		Path:        "/organizations/{id}/billing",
		Summary:     "Get organization billing",
		Description: "Get billing information and subscription details",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewBilling, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.getOrganizationBillingHandler)
}

func registerUpdateOrganizationBilling(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateOrganizationBilling",
		Method:      http.MethodPut,
		Path:        "/organizations/{id}/billing",
		Summary:     "Update organization billing",
		Description: "Update billing information and subscription plan",
		Tags:        []string{"Organizations Billing"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionManageBilling, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.updateOrganizationBillingHandler)
}

func registerGetOrganizationUsage(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganizationUsage",
		Method:      http.MethodGet,
		Path:        "/organizations/{id}/usage",
		Summary:     "Get organization usage",
		Description: "Get current usage statistics and limits",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.getOrganizationUsageHandler)
}

func registerGetOrganizationInvoices(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganizationInvoices",
		Method:      http.MethodGet,
		Path:        "/organizations/{id}/invoices",
		Summary:     "Get organization invoices",
		Description: "Get billing invoices and payment history",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewBilling, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.getOrganizationInvoicesHandler)
}

// Feature Management Endpoints

func registerListOrganizationFeatures(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "listOrganizationFeatures",
		Method:      http.MethodGet,
		Path:        "/organizations/{id}/features",
		Summary:     "List organization features",
		Description: "List enabled and available features for the organization",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.listOrganizationFeaturesHandler)
}

func registerEnableOrganizationFeature(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "enableOrganizationFeature",
		Method:      http.MethodPost,
		Path:        "/organizations/{id}/features/{feature}/enable",
		Summary:     "Enable organization feature",
		Description: "Enable a specific feature for the organization",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionUpdateOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.enableOrganizationFeatureHandler)
}

func registerDisableOrganizationFeature(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID:   "disableOrganizationFeature",
		Method:        http.MethodDelete,
		Path:          "/organizations/{id}/features/{feature}",
		Summary:       "Disable organization feature",
		Description:   "Disable a specific feature for the organization",
		Tags:          []string{"Organizations"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Feature successfully disabled"},
		}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionUpdateOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.disableOrganizationFeatureHandler)
}

// Statistics and Analytics Endpoints

func registerGetOrganizationStats(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganizationStats",
		Method:      http.MethodGet,
		Path:        "/organizations/{id}/stats",
		Summary:     "Get organization statistics",
		Description: "Get comprehensive organization statistics and metrics",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewAnalytics, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.getOrganizationStatsHandler)
}

func registerGetOrganizationActivity(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganizationActivity",
		Method:      http.MethodGet,
		Path:        "/organizations/{id}/activity",
		Summary:     "Get organization activity",
		Description: "Get organization activity log and audit trail",
		Tags:        []string{"Activity"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewAuditLogs, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.getOrganizationActivityHandler)
}

func registerExportOrganizationData(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "exportOrganizationData",
		Method:      http.MethodPost,
		Path:        "/organizations/{id}/export",
		Summary:     "Export organization data",
		Description: "Export organization data for backup or compliance",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionExportData, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.exportOrganizationDataHandler)
}

// Ownership Transfer Endpoints

func registerTransferOrganizationOwnership(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "transferOrganizationOwnership",
		Method:      http.MethodPost,
		Path:        "/organizations/{id}/transfer-ownership",
		Summary:     "Transfer organization ownership",
		Description: "Transfer ownership of the organization to another user",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionTransferOwnership, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.transferOrganizationOwnershipHandler)
}

func registerGetOrganizationOwnership(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganizationOwnership",
		Method:      http.MethodGet,
		Path:        "/organizations/{id}/ownership",
		Summary:     "Get organization ownership",
		Description: "Get current ownership information for the organization",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewOrganization, model.ResourceOrganization, "id",
		)},
	}, orgCtrl.getOrganizationOwnershipHandler)
}

// Input/Output type definitions

type ListOrganizationsInput struct {
	model.OrganizationListRequest
}

type ListOrganizationsOutput = model.Output[*model.OrganizationListResponse]

type GetOrganizationInput struct {
	ID string `path:"id" doc:"Organization ID"`
}

type GetOrganizationOutput = model.Output[*model.Organization]

type CreateOrganizationInput struct {
	Body model.CreateOrganizationRequest
}

type CreateOrganizationOutput = model.Output[*model.Organization]

type UpdateOrganizationInput struct {
	ID   xid.ID `path:"id" doc:"Organization ID"`
	Body model.UpdateOrganizationRequest
}

type UpdateOrganizationOutput = model.Output[*model.Organization]

type DeleteOrganizationInput struct {
	ID   xid.ID `path:"id" doc:"Organization ID"`
	Body model.DeleteOrganizationRequest
}

type GetOrganizationSettingsOutput = model.Output[*model.OrganizationSettings]

type UpdateOrganizationSettingsInput struct {
	ID   xid.ID `path:"id" doc:"Organization ID"`
	Body model.UpdateOrganizationSettingsRequest
}

type UpdateOrganizationSettingsOutput = model.Output[*model.OrganizationSettings]

type AddOrganizationDomainInput struct {
	ID   xid.ID `path:"id" doc:"Organization ID"`
	Body model.DomainVerificationRequest
}

type VerifyOrganizationDomainInput struct {
	ID     xid.ID `path:"id" doc:"Organization ID"`
	Domain string `path:"domain" doc:"Domain name"`
}

type VerifyOrganizationDomainOutput = model.Output[*model.DomainVerificationResponse]

type RemoveOrganizationDomainInput struct {
	ID     xid.ID `path:"id" doc:"Organization ID"`
	Domain string `path:"domain" doc:"Domain name"`
}

type GetOrganizationBillingOutput = model.Output[*model.OrganizationBilling]

type UpdateOrganizationBillingInput struct {
	ID   xid.ID `path:"id" doc:"Organization ID"`
	Body model.UpdateBillingRequest
}

type UpdateOrganizationBillingOutput = model.Output[*model.OrganizationBilling]

type GetOrganizationUsageOutput = model.Output[*model.OrganizationUsage]

type EnableOrganizationFeatureInput struct {
	ID      xid.ID `path:"id" doc:"Organization ID"`
	Feature string `path:"feature" doc:"Feature name"`
}

type DisableOrganizationFeatureInput struct {
	ID      xid.ID `path:"id" doc:"Organization ID"`
	Feature string `path:"feature" doc:"Feature name"`
}

type GetOrganizationStatsOutput = model.Output[*model.OrgStats]

type TransferOrganizationOwnershipInput struct {
	ID   xid.ID `path:"id" doc:"Organization ID"`
	Body model.TransferUserOwnershipRequest
}

type TransferOwnershipResponse struct {
	Message    string `json:"message"`
	NewOwnerID xid.ID `json:"newOwnerId"`
}
type TransferOrganizationOwnershipOutput = model.Output[TransferOwnershipResponse]

// Handler implementations

func (c *organizationController) listOrganizationsHandler(ctx context.Context, input *ListOrganizationsInput) (*ListOrganizationsOutput, error) {
	orgService := c.di.OrganizationService()

	user, err := middleware.GetUserFromContextSafe(ctx)
	if err != nil {
		return nil, err
	}

	response, err := orgService.ListUserOrganizations(ctx, user.ID, input.OrganizationListRequest)
	if err != nil {
		return nil, err
	}

	return &ListOrganizationsOutput{
		Body: response,
	}, nil
}

func (c *organizationController) getOrganizationByIdOrSlug(ctx context.Context, strId string) (*model.Organization, error) {
	orgService := c.di.OrganizationService()

	var org *model.Organization
	if id, err := xid.FromString(strId); err != nil {
		org, err = orgService.GetOrganizationBySlug(ctx, strId)
		if err != nil {
			return nil, err
		}
	} else {
		org, err = orgService.GetOrganization(ctx, id)
		if err != nil {
			return nil, err
		}
	}

	return org, nil
}

func (c *organizationController) getOrganizationHandler(ctx context.Context, input *GetOrganizationInput) (*GetOrganizationOutput, error) {
	org, err := c.getOrganizationByIdOrSlug(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationOutput{
		Body: org,
	}, nil
}

func (c *organizationController) createOrganizationHandler(ctx context.Context, input *CreateOrganizationInput) (*CreateOrganizationOutput, error) {
	orgService := c.di.OrganizationService()

	org, err := orgService.CreateOrganization(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreateOrganizationOutput{
		Body: org,
	}, nil
}

func (c *organizationController) updateOrganizationHandler(ctx context.Context, input *UpdateOrganizationInput) (*UpdateOrganizationOutput, error) {
	orgService := c.di.OrganizationService()

	organization, err := orgService.UpdateOrganization(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateOrganizationOutput{
		Body: organization,
	}, nil
}

func (c *organizationController) deleteOrganizationHandler(ctx context.Context, input *DeleteOrganizationInput) (*model.EmptyOutput, error) {
	orgService := c.di.OrganizationService()

	err := orgService.DeleteOrganization(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *organizationController) getOrganizationSettingsHandler(ctx context.Context, input *GetOrganizationInput) (*GetOrganizationSettingsOutput, error) {
	orgService := c.di.OrganizationService()

	org, err := c.getOrganizationByIdOrSlug(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	settings, err := orgService.GetOrganizationSettings(ctx, org.ID)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationSettingsOutput{
		Body: settings,
	}, nil
}

func (c *organizationController) updateOrganizationSettingsHandler(ctx context.Context, input *UpdateOrganizationSettingsInput) (*UpdateOrganizationSettingsOutput, error) {
	orgService := c.di.OrganizationService()

	settings, err := orgService.UpdateOrganizationSettings(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateOrganizationSettingsOutput{
		Body: settings,
	}, nil
}

type DomainsResponse struct {
	Domains []string `json:"domains"`
}

type ListOrganizationDomainsOutput = model.Output[*DomainsResponse]

func (c *organizationController) listOrganizationDomainsHandler(ctx context.Context, input *GetOrganizationInput) (*ListOrganizationDomainsOutput, error) {
	orgService := c.di.OrganizationService()

	org, err := c.getOrganizationByIdOrSlug(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	domains, err := orgService.ListDomains(ctx, org.ID)
	if err != nil {
		return nil, err
	}

	return &ListOrganizationDomainsOutput{
		Body: &DomainsResponse{
			Domains: domains,
		},
	}, nil
}

type DomainResponse struct {
	Message string `json:"message"`
	Domain  string `json:"domain"`
}

type AddOrganizationDomainOutput = model.Output[DomainResponse]

func (c *organizationController) addOrganizationDomainHandler(ctx context.Context, input *AddOrganizationDomainInput) (*AddOrganizationDomainOutput, error) {
	orgService := c.di.OrganizationService()

	err := orgService.AddDomain(ctx, input.ID, input.Body.Domain)
	if err != nil {
		return nil, err
	}

	return &AddOrganizationDomainOutput{
		Body: DomainResponse{
			Message: "Domain added successfully",
			Domain:  input.Body.Domain,
		},
	}, nil
}

func (c *organizationController) verifyOrganizationDomainHandler(ctx context.Context, input *VerifyOrganizationDomainInput) (*VerifyOrganizationDomainOutput, error) {
	orgService := c.di.OrganizationService()

	req := model.DomainVerificationRequest{
		Domain: input.Domain,
	}

	response, err := orgService.VerifyDomain(ctx, req)
	if err != nil {
		return nil, err
	}

	return &VerifyOrganizationDomainOutput{
		Body: response,
	}, nil
}

func (c *organizationController) removeOrganizationDomainHandler(ctx context.Context, input *RemoveOrganizationDomainInput) (*model.EmptyOutput, error) {
	orgService := c.di.OrganizationService()

	err := orgService.RemoveDomain(ctx, input.ID, input.Domain)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *organizationController) getOrganizationBillingHandler(ctx context.Context, input *GetOrganizationInput) (*GetOrganizationBillingOutput, error) {
	orgService := c.di.OrganizationService()

	org, err := c.getOrganizationByIdOrSlug(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	billing, err := orgService.GetOrganizationBilling(ctx, org.ID)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationBillingOutput{
		Body: billing,
	}, nil
}

func (c *organizationController) updateOrganizationBillingHandler(ctx context.Context, input *UpdateOrganizationBillingInput) (*UpdateOrganizationBillingOutput, error) {
	orgService := c.di.OrganizationService()

	billing, err := orgService.UpdateBilling(ctx, input.ID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateOrganizationBillingOutput{
		Body: billing,
	}, nil
}

func (c *organizationController) getOrganizationUsageHandler(ctx context.Context, input *GetOrganizationInput) (*GetOrganizationUsageOutput, error) {
	orgService := c.di.OrganizationService()
	org, err := c.getOrganizationByIdOrSlug(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	usage, err := orgService.GetOrganizationUsage(ctx, org.ID)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationUsageOutput{
		Body: usage,
	}, nil
}

type ListOrganizationInvoicesInput struct {
	GetOrganizationInput
	model.ListInvoicesParams
}
type ListOrganizationInvoicesOutput = model.Output[*model.InvoiceListResponse]

func (c *organizationController) getOrganizationInvoicesHandler(ctx context.Context, input *ListOrganizationInvoicesInput) (*ListOrganizationInvoicesOutput, error) {
	orgService := c.di.BillingService()
	org, err := c.getOrganizationByIdOrSlug(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	invoices, err := orgService.GetInvoices(ctx, org.ID, input.ListInvoicesParams)
	if err != nil {
		return nil, err
	}

	return &ListOrganizationInvoicesOutput{
		Body: invoices,
	}, nil
}

type OrganizationFeatureResponse struct {
	Message string `json:"message"`
	Feature string `json:"feature"`
}

type OrganizationFeatureOutput = model.Output[[]model.FeatureSummary]

func (c *organizationController) listOrganizationFeaturesHandler(ctx context.Context, input *GetOrganizationInput) (*OrganizationFeatureOutput, error) {
	orgService := c.di.OrganizationService()
	org, err := c.getOrganizationByIdOrSlug(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	features, err := orgService.ListEnabledFeatures(ctx, org.ID)
	if err != nil {
		return nil, err
	}

	return &OrganizationFeatureOutput{
		Body: features,
	}, nil
}

type EnableOrganizationFeatureResponse struct {
	Message string `json:"message"`
	Feature string `json:"feature"`
}

type EnableOrganizationFeatureOutput = model.Output[EnableOrganizationFeatureResponse]

func (c *organizationController) enableOrganizationFeatureHandler(ctx context.Context, input *EnableOrganizationFeatureInput) (*EnableOrganizationFeatureOutput, error) {
	orgService := c.di.OrganizationService()

	err := orgService.EnableFeature(ctx, input.ID, input.Feature, nil)
	if err != nil {
		return nil, err
	}

	return &EnableOrganizationFeatureOutput{
		Body: EnableOrganizationFeatureResponse{
			Message: "Feature enabled successfully",
			Feature: input.Feature,
		},
	}, nil
}

func (c *organizationController) disableOrganizationFeatureHandler(ctx context.Context, input *DisableOrganizationFeatureInput) (*model.EmptyOutput, error) {
	orgService := c.di.OrganizationService()

	err := orgService.DisableFeature(ctx, input.ID, input.Feature)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *organizationController) getOrganizationStatsHandler(ctx context.Context, input *GetOrganizationInput) (*GetOrganizationStatsOutput, error) {
	orgService := c.di.OrganizationService()
	org, err := c.getOrganizationByIdOrSlug(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	stats, err := orgService.GetOrganizationStats(ctx, org.ID)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationStatsOutput{
		Body: stats,
	}, nil
}

type GetOrganizationActivityOutput = model.Output[*organization.OrganizationActivity]

func (c *organizationController) getOrganizationActivityHandler(ctx context.Context, input *GetOrganizationInput) (*GetOrganizationActivityOutput, error) {
	orgService := c.di.OrganizationService()
	org, err := c.getOrganizationByIdOrSlug(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	activity, err := orgService.GetOrganizationActivity(ctx, org.ID, 30) // Last 30 days
	if err != nil {
		return nil, err
	}

	return &GetOrganizationActivityOutput{
		Body: activity,
	}, nil
}

type ExportOrganizationDataResponse struct {
	Message  string `json:"message"`
	Status   string `json:"status"`
	ExportID string `json:"export_id"`
}

type ExportOrganizationDataOutput = model.Output[ExportOrganizationDataResponse]

func (c *organizationController) exportOrganizationDataHandler(ctx context.Context, input *GetOrganizationInput) (*ExportOrganizationDataOutput, error) {
	// TODO: Implement data export functionality
	return &ExportOrganizationDataOutput{
		Body: ExportOrganizationDataResponse{
			Message:  "Data export initiated",
			Status:   "processing",
			ExportID: xid.New().String(),
		},
	}, nil
}

func (c *organizationController) transferOrganizationOwnershipHandler(ctx context.Context, input *TransferOrganizationOwnershipInput) (*TransferOrganizationOwnershipOutput, error) {
	membershipService := c.di.MembershipService()
	currentOwnerID := middleware.GetUserIDFromContext(ctx)

	err := membershipService.TransferOwnership(ctx, input.ID, *currentOwnerID, input.Body.NewOwnerID)
	if err != nil {
		return nil, err
	}

	return &TransferOrganizationOwnershipOutput{
		Body: TransferOwnershipResponse{
			Message:    "Ownership transferred successfully",
			NewOwnerID: input.Body.NewOwnerID,
		},
	}, nil
}

type OrganizationOwnershipOutput = model.Output[*model.UserSummary]

func (c *organizationController) getOrganizationOwnershipHandler(ctx context.Context, input *GetOrganizationInput) (*OrganizationOwnershipOutput, error) {
	orgService := c.di.OrganizationService()
	org, err := c.getOrganizationByIdOrSlug(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	owner, err := orgService.GetOwner(ctx, org.ID)
	if err != nil {
		return nil, err
	}

	return &OrganizationOwnershipOutput{
		Body: owner,
	}, nil
}
