package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/model"
	"github.com/rs/xid"
)

// RegisterMembershipAPI registers all membership management endpoints
func RegisterMembershipAPI(api huma.API, di di.Container) {
	memberCtrl := &membershipController{
		api: api,
		di:  di,
	}

	// Membership CRUD endpoints
	registerListMemberships(api, memberCtrl)
	registerGetMembership(api, memberCtrl)
	registerUpdateMembership(api, memberCtrl)
	registerDeleteMembership(api, memberCtrl)
	registerBulkMembershipOperations(api, memberCtrl)

	// Member management endpoints
	registerListMembers(api, memberCtrl)
	registerGetMember(api, memberCtrl)
	registerRemoveMember(api, memberCtrl)
	registerUpdateMemberRole(api, memberCtrl)
	registerBulkMemberOperations(api, memberCtrl)

	// Invitation workflow endpoints
	registerCreateInvitation(api, memberCtrl)
	registerListInvitations(api, memberCtrl)
	registerGetInvitation(api, memberCtrl)
	registerAcceptInvitation(api, memberCtrl)
	registerDeclineInvitation(api, memberCtrl)
	registerResendInvitation(api, memberCtrl)
	registerCancelInvitation(api, memberCtrl)
	registerValidateInvitation(api, memberCtrl)
	registerBulkInvitations(api, memberCtrl)

	// Public invitation endpoints (no auth required)
	registerPublicAcceptInvitation(api, memberCtrl)
	registerPublicDeclineInvitation(api, memberCtrl)
	registerPublicValidateInvitation(api, memberCtrl)

	// Membership statistics and analytics
	registerGetMembershipStats(api, memberCtrl)
	registerGetMembershipActivity(api, memberCtrl)
	registerGetMembershipMetrics(api, memberCtrl)
	registerExportMemberships(api, memberCtrl)

	// Membership transfer and ownership
	registerTransferMembership(api, memberCtrl)
	registerGetMembershipHistory(api, memberCtrl)
}

// membershipController handles membership management API requests
type membershipController struct {
	api huma.API
	di  di.Container
}

// Membership CRUD Endpoints

func registerListMemberships(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "listMemberships",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/memberships",
		Summary:     "List memberships",
		Description: "List all memberships in an organization with pagination and filtering",
		Tags:        []string{"Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionViewMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.listMembershipsHandler)
}

func registerGetMembership(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMembership",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/memberships/{id}",
		Summary:     "Get membership",
		Description: "Get membership details by ID",
		Tags:        []string{"Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Membership not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionViewMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.getMembershipHandler)
}

func registerUpdateMembership(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateMembership",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/memberships/{id}",
		Summary:     "Update membership",
		Description: "Update membership information and settings",
		Tags:        []string{"Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Membership not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionManageMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.updateMembershipHandler)
}

func registerDeleteMembership(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteMembership",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/memberships/{id}",
		Summary:       "Delete membership",
		Description:   "Remove a membership from the organization",
		Tags:          []string{"Memberships"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Membership successfully deleted"},
		}, true, model.NotFoundError("Membership not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionManageMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.deleteMembershipHandler)
}

func registerBulkMembershipOperations(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "bulkMembershipOperations",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/memberships/bulk",
		Summary:     "Bulk membership operations",
		Description: "Perform bulk operations on multiple memberships",
		Tags:        []string{"Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionManageMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.bulkMembershipOperationsHandler)
}

// Member Management Endpoints

func registerListMembers(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "listMembers",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/members",
		Summary:     "List members",
		Description: "List all members in an organization with pagination and filtering",
		Tags:        []string{"Members"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionViewMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.listMembersHandler)
}

func registerGetMember(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMember",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/members/{userId}",
		Summary:     "Get member",
		Description: "Get member details by user ID",
		Tags:        []string{"Members"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionViewMembers, authz.ResourceUser, "userId",
		)},
	}, memberCtrl.getMemberHandler)
}

func registerRemoveMember(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID:   "removeMember",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/members/{userId}",
		Summary:       "Remove member",
		Description:   "Remove a member from the organization",
		Tags:          []string{"Members"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Member successfully removed"},
		}, true, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionManageMembers, authz.ResourceUser, "userId",
		)},
	}, memberCtrl.removeMemberHandler)
}

func registerUpdateMemberRole(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateMemberRole",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/members/{userId}/role",
		Summary:     "Update member role",
		Description: "Update a member's role within the organization",
		Tags:        []string{"Members"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionManageMembers, authz.ResourceUser, "userId",
		)},
	}, memberCtrl.updateMemberRoleHandler)
}

func registerBulkMemberOperations(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "bulkMemberOperations",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/members/bulk",
		Summary:     "Bulk member operations",
		Description: "Perform bulk operations on multiple members",
		Tags:        []string{"Members"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionManageMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.bulkMemberOperationsHandler)
}

// Invitation Workflow Endpoints

func registerCreateInvitation(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "createInvitation",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/invitations",
		Summary:     "Create invitation",
		Description: "Create and send an invitation to join the organization",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionInviteMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.createInvitationHandler)
}

func registerListInvitations(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "listInvitations",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/invitations",
		Summary:     "List invitations",
		Description: "List all invitations for the organization with pagination and filtering",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionViewInvitations, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.listInvitationsHandler)
}

func registerGetInvitation(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getInvitation",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/invitations/{id}",
		Summary:     "Get invitation",
		Description: "Get invitation details by ID",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Invitation not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionViewInvitations, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.getInvitationHandler)
}

func registerAcceptInvitation(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "acceptInvitation",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/invitations/{id}/accept",
		Summary:     "Accept invitation",
		Description: "Accept an invitation to join the organization",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Invitation not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, memberCtrl.acceptInvitationHandler)
}

func registerDeclineInvitation(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID:   "declineInvitation",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/invitations/{id}/decline",
		Summary:       "Decline invitation",
		Description:   "Decline an invitation to join the organization",
		Tags:          []string{"Invitations"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Invitation successfully declined"},
		}, true, model.NotFoundError("Invitation not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, memberCtrl.declineInvitationHandler)
}

func registerResendInvitation(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "resendInvitation",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/invitations/{id}/resend",
		Summary:     "Resend invitation",
		Description: "Resend an invitation email",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Invitation not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionInviteMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.resendInvitationHandler)
}

func registerCancelInvitation(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID:   "cancelInvitation",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/invitations/{id}",
		Summary:       "Cancel invitation",
		Description:   "Cancel a pending invitation",
		Tags:          []string{"Invitations"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Invitation successfully cancelled"},
		}, true, model.NotFoundError("Invitation not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionInviteMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.cancelInvitationHandler)
}

func registerValidateInvitation(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "validateInvitation",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/invitations/validate",
		Summary:     "Validate invitation",
		Description: "Validate an invitation token",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, memberCtrl.validateInvitationHandler)
}

func registerBulkInvitations(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "bulkInvitations",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/invitations/bulk",
		Summary:     "Bulk invitations",
		Description: "Send multiple invitations at once",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionInviteMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.bulkInvitationsHandler)
}

// Public Invitation Endpoints (no auth required)

func registerPublicAcceptInvitation(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "publicAcceptInvitation",
		Method:      http.MethodPost,
		Path:        "/invitations/accept",
		Summary:     "Accept invitation (public)",
		Description: "Accept an invitation using token (no authentication required)",
		Tags:        []string{"Public", "Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, memberCtrl.publicAcceptInvitationHandler)
}

func registerPublicDeclineInvitation(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID:   "publicDeclineInvitation",
		Method:        http.MethodPost,
		Path:          "/invitations/decline",
		Summary:       "Decline invitation (public)",
		Description:   "Decline an invitation using token (no authentication required)",
		Tags:          []string{"Public", "Invitations"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Invitation successfully declined"},
		}, false),
	}, memberCtrl.publicDeclineInvitationHandler)
}

func registerPublicValidateInvitation(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "publicValidateInvitation",
		Method:      http.MethodPost,
		Path:        "/invitations/validate",
		Summary:     "Validate invitation (public)",
		Description: "Validate an invitation token (no authentication required)",
		Tags:        []string{"Public", "Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, memberCtrl.publicValidateInvitationHandler)
}

// Statistics and Analytics Endpoints

func registerGetMembershipStats(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMembershipStats",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/memberships/stats",
		Summary:     "Get membership statistics",
		Description: "Get comprehensive membership statistics for the organization",
		Tags:        []string{"Memberships", "Analytics"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionViewAnalytics, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.getMembershipStatsHandler)
}

func registerGetMembershipActivity(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMembershipActivity",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/memberships/activity",
		Summary:     "Get membership activity",
		Description: "Get membership activity log with pagination and filtering",
		Tags:        []string{"Memberships", "Activity"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionViewAuditLogs, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.getMembershipActivityHandler)
}

func registerGetMembershipMetrics(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMembershipMetrics",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/memberships/metrics",
		Summary:     "Get membership metrics",
		Description: "Get detailed membership metrics and analytics",
		Tags:        []string{"Memberships", "Analytics"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionViewAnalytics, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.getMembershipMetricsHandler)
}

func registerExportMemberships(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "exportMemberships",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/memberships/export",
		Summary:     "Export memberships",
		Description: "Export membership data to CSV or JSON format",
		Tags:        []string{"Memberships", "Export"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionExportData, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.exportMembershipsHandler)
}

// Transfer and History Endpoints

func registerTransferMembership(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "transferMembership",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/memberships/{id}/transfer",
		Summary:     "Transfer membership",
		Description: "Transfer membership to another organization",
		Tags:        []string{"Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Membership not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionManageMembers, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.transferMembershipHandler)
}

func registerGetMembershipHistory(api huma.API, memberCtrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMembershipHistory",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/memberships/{id}/history",
		Summary:     "Get membership history",
		Description: "Get change history for a membership",
		Tags:        []string{"Memberships", "History"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Membership not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, memberCtrl.di.AuthZ().Checker(), memberCtrl.di.Logger())(
			authz.PermissionViewAuditLogs, authz.ResourceOrganization, "orgId",
		)},
	}, memberCtrl.getMembershipHistoryHandler)
}

// Input/Output type definitions

type ListMembershipsInput struct {
	model.OrganisationPathParams
	model.ListMembershipsParams
}

type ListMembershipsOutput = model.Output[*model.MembershipListResponse]

type GetMembershipInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Membership ID"`
}

type GetMembershipOutput = model.Output[*model.Membership]

type UpdateMembershipInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"Membership ID"`
	Body model.UpdateMembershipRequest
}

type UpdateMembershipOutput = model.Output[*model.Membership]

type DeleteMembershipInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"Membership ID"`
	Body model.RemoveMemberRequest
}

type BulkMembershipOperationsInput struct {
	model.OrganisationPathParams
	Body model.BulkMembershipOperation
}

type BulkMembershipOperationsOutput = model.Output[*model.BulkMembershipOperationResponse]

type ListMembersInput struct {
	model.OrganisationPathParams
	model.ListMembershipsParams
}

type ListMembersOutput = model.Output[*model.MemberListResponse]

type GetMemberInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type GetMemberOutput = model.Output[*model.MemberSummary]

type RemoveMemberInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
	Body   model.RemoveMemberRequest
}

type UpdateMemberRoleInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
	Body   model.BulkMemberRoleUpdate
}

type UpdateMemberRoleOutput = model.Output[*model.Membership]

type BulkMemberOperationsInput struct {
	model.OrganisationPathParams
	Body model.BulkMembershipOperation
}

type BulkMemberOperationsOutput = model.Output[*model.BulkUpdateResponse]

type CreateInvitationInput struct {
	model.OrganisationPathParams
	Body model.CreateInvitationRequest
}

type CreateInvitationOutput = model.Output[*model.CreateMembershipResponse]

type ListInvitationsInput struct {
	model.OrganisationPathParams
	model.ListInvitationsParams
}

type ListInvitationsOutput = model.Output[*model.InvitationListResponse]

type GetInvitationInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Invitation ID"`
}

type GetInvitationOutput = model.Output[*model.Invitation]

type AcceptInvitationInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"Invitation ID"`
	Body model.AcceptInvitationRequest
}

type AcceptInvitationOutput = model.Output[*model.AcceptInvitationResponse]

type DeclineInvitationInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"Invitation ID"`
	Body model.DeclineInvitationRequest
}

type ResendInvitationInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"Invitation ID"`
	Body model.ResendInvitationRequest
}

type CancelInvitationInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"Invitation ID"`
	Body model.CancelInvitationRequest
}

type ValidateInvitationInput struct {
	model.OrganisationPathParams
	Body model.InvitationValidationRequest
}

type ValidateInvitationOutput = model.Output[*model.InvitationValidationResponse]

type BulkInvitationsInput struct {
	model.OrganisationPathParams
	Body model.BulkCreateInvitationsRequest
}

type BulkInvitationsOutput = model.Output[*model.BulkInvitationResponse]

type PublicAcceptInvitationInput struct {
	Body model.AcceptInvitationRequest
}

type PublicDeclineInvitationInput struct {
	Body model.DeclineInvitationRequest
}

type PublicValidateInvitationInput struct {
	Body model.InvitationValidationRequest
}

type GetMembershipStatsOutput = model.Output[*model.MembershipStats]

type GetMembershipActivityInput struct {
	model.OrganisationPathParams
	model.MembershipActivityRequest
}

type GetMembershipActivityOutput = model.Output[*model.MembershipActivityResponse]

type GetMembershipMetricsOutput = model.Output[*model.MemberMetrics]

type TransferMembershipInput struct {
	model.OrganisationPathParams
	ID   xid.ID `path:"id" doc:"Membership ID"`
	Body model.TransferUserOwnershipRequest
}

type GetMembershipHistoryInput struct {
	model.OrganisationPathParams
	ID xid.ID `path:"id" doc:"Membership ID"`
	model.MembershipChangeLogParams
}

type GetMembershipHistoryOutput = model.Output[*model.MembershipChangeLogResponse]

// Handler implementations

func (c *membershipController) listMembershipsHandler(ctx context.Context, input *ListMembershipsInput) (*ListMembershipsOutput, error) {
	// TODO: Implement list memberships logic
	// 1. Apply filters and pagination
	// 2. Get memberships for organization
	// 3. Return paginated membership list
	return nil, nil
}

func (c *membershipController) getMembershipHandler(ctx context.Context, input *GetMembershipInput) (*GetMembershipOutput, error) {
	// TODO: Implement get membership logic
	// 1. Validate membership exists in organization
	// 2. Check permissions to view membership
	// 3. Return membership details
	return nil, nil
}

func (c *membershipController) updateMembershipHandler(ctx context.Context, input *UpdateMembershipInput) (*UpdateMembershipOutput, error) {
	// TODO: Implement update membership logic
	// 1. Validate membership exists
	// 2. Check permissions to update
	// 3. Update membership information
	// 4. Log membership change
	// 5. Return updated membership
	return nil, nil
}

func (c *membershipController) deleteMembershipHandler(ctx context.Context, input *DeleteMembershipInput) (*model.EmptyOutput, error) {
	// TODO: Implement delete membership logic
	// 1. Validate membership exists
	// 2. Check permissions to delete
	// 3. Handle data transfer if specified
	// 4. Remove membership
	// 5. Log membership removal
	// 6. Return success response
	return nil, nil
}

func (c *membershipController) bulkMembershipOperationsHandler(ctx context.Context, input *BulkMembershipOperationsInput) (*BulkMembershipOperationsOutput, error) {
	// TODO: Implement bulk membership operations logic
	// 1. Validate operation type
	// 2. Check permissions for all target memberships
	// 3. Perform bulk operation
	// 4. Log changes
	// 5. Return operation results
	return nil, nil
}

func (c *membershipController) listMembersHandler(ctx context.Context, input *ListMembersInput) (*ListMembersOutput, error) {
	// TODO: Implement list members logic
	// 1. Apply filters and pagination
	// 2. Get active members for organization
	// 3. Return paginated member list
	return nil, nil
}

func (c *membershipController) getMemberHandler(ctx context.Context, input *GetMemberInput) (*GetMemberOutput, error) {
	// TODO: Implement get member logic
	// 1. Validate member exists in organization
	// 2. Check permissions to view member
	// 3. Return member details
	return nil, nil
}

func (c *membershipController) removeMemberHandler(ctx context.Context, input *RemoveMemberInput) (*model.EmptyOutput, error) {
	// TODO: Implement remove member logic
	// 1. Validate member exists
	// 2. Check permissions to remove
	// 3. Find and remove membership
	// 4. Handle data transfer if specified
	// 5. Log member removal
	// 6. Return success response
	return nil, nil
}

func (c *membershipController) updateMemberRoleHandler(ctx context.Context, input *UpdateMemberRoleInput) (*UpdateMemberRoleOutput, error) {
	// TODO: Implement update member role logic
	// 1. Validate member exists
	// 2. Check permissions to update role
	// 3. Update membership role
	// 4. Log role change
	// 5. Return updated membership
	return nil, nil
}

func (c *membershipController) bulkMemberOperationsHandler(ctx context.Context, input *BulkMemberOperationsInput) (*BulkMemberOperationsOutput, error) {
	// TODO: Implement bulk member operations logic
	// 1. Validate operation type
	// 2. Check permissions for all target members
	// 3. Perform bulk operation on memberships
	// 4. Log changes
	// 5. Return operation results
	return nil, nil
}

func (c *membershipController) createInvitationHandler(ctx context.Context, input *CreateInvitationInput) (*CreateInvitationOutput, error) {
	// TODO: Implement create invitation logic
	// 1. Validate invitation data
	// 2. Check if user already exists or invited
	// 3. Create invitation record
	// 4. Generate invitation token
	// 5. Send invitation email if requested
	// 6. Return invitation details
	return nil, nil
}

func (c *membershipController) listInvitationsHandler(ctx context.Context, input *ListInvitationsInput) (*ListInvitationsOutput, error) {
	// TODO: Implement list invitations logic
	// 1. Apply filters and pagination
	// 2. Get invitations for organization
	// 3. Return paginated invitation list
	return nil, nil
}

func (c *membershipController) getInvitationHandler(ctx context.Context, input *GetInvitationInput) (*GetInvitationOutput, error) {
	// TODO: Implement get invitation logic
	// 1. Validate invitation exists
	// 2. Check permissions to view invitation
	// 3. Return invitation details
	return nil, nil
}

func (c *membershipController) acceptInvitationHandler(ctx context.Context, input *AcceptInvitationInput) (*AcceptInvitationOutput, error) {
	// TODO: Implement accept invitation logic
	// 1. Validate invitation is pending and not expired
	// 2. Check if current user matches invitation email
	// 3. Create membership from invitation
	// 4. Mark invitation as accepted
	// 5. Send welcome notifications
	// 6. Return acceptance response
	return nil, nil
}

func (c *membershipController) declineInvitationHandler(ctx context.Context, input *DeclineInvitationInput) (*model.EmptyOutput, error) {
	// TODO: Implement decline invitation logic
	// 1. Validate invitation is pending
	// 2. Mark invitation as declined
	// 3. Log decline reason if provided
	// 4. Return success response
	return nil, nil
}

func (c *membershipController) resendInvitationHandler(ctx context.Context, input *ResendInvitationInput) (*model.EmptyOutput, error) {
	// TODO: Implement resend invitation logic
	// 1. Validate invitation is still pending
	// 2. Check rate limiting for resends
	// 3. Update invitation with new expiry if requested
	// 4. Send invitation email
	// 5. Update last sent timestamp
	// 6. Return success response
	return nil, nil
}

func (c *membershipController) cancelInvitationHandler(ctx context.Context, input *CancelInvitationInput) (*model.EmptyOutput, error) {
	// TODO: Implement cancel invitation logic
	// 1. Validate invitation is pending
	// 2. Check permissions to cancel
	// 3. Mark invitation as cancelled
	// 4. Log cancellation reason if provided
	// 5. Return success response
	return nil, nil
}

func (c *membershipController) validateInvitationHandler(ctx context.Context, input *ValidateInvitationInput) (*ValidateInvitationOutput, error) {
	// TODO: Implement validate invitation logic
	// 1. Validate invitation token format
	// 2. Check if invitation exists and is valid
	// 3. Check expiration and status
	// 4. Return validation result
	return nil, nil
}

func (c *membershipController) bulkInvitationsHandler(ctx context.Context, input *BulkInvitationsInput) (*BulkInvitationsOutput, error) {
	// TODO: Implement bulk invitations logic
	// 1. Validate all invitation requests
	// 2. Check for duplicate emails
	// 3. Create multiple invitations
	// 4. Send invitation emails if requested
	// 5. Return bulk operation results
	return nil, nil
}

func (c *membershipController) publicAcceptInvitationHandler(ctx context.Context, input *PublicAcceptInvitationInput) (*AcceptInvitationOutput, error) {
	// TODO: Implement public accept invitation logic
	// 1. Validate invitation token
	// 2. Check if invitation is pending and not expired
	// 3. Create user account if needed
	// 4. Create membership
	// 5. Mark invitation as accepted
	// 6. Return acceptance response with login tokens
	return nil, nil
}

func (c *membershipController) publicDeclineInvitationHandler(ctx context.Context, input *PublicDeclineInvitationInput) (*model.EmptyOutput, error) {
	// TODO: Implement public decline invitation logic
	// 1. Validate invitation token
	// 2. Mark invitation as declined
	// 3. Log decline reason if provided
	// 4. Return success response
	return nil, nil
}

func (c *membershipController) publicValidateInvitationHandler(ctx context.Context, input *PublicValidateInvitationInput) (*ValidateInvitationOutput, error) {
	// TODO: Implement public validate invitation logic
	// 1. Validate invitation token format
	// 2. Check if invitation exists and is valid
	// 3. Check expiration and status
	// 4. Return validation result with organization info
	return nil, nil
}

func (c *membershipController) getMembershipStatsHandler(ctx context.Context, input *model.OrganisationPathParams) (*GetMembershipStatsOutput, error) {
	// TODO: Implement get membership stats logic
	// 1. Calculate membership statistics
	// 2. Include invitation statistics
	// 3. Calculate growth metrics
	// 4. Return comprehensive stats
	return nil, nil
}

func (c *membershipController) getMembershipActivityHandler(ctx context.Context, input *GetMembershipActivityInput) (*GetMembershipActivityOutput, error) {
	// TODO: Implement get membership activity logic
	// 1. Get membership activity logs
	// 2. Apply filters and pagination
	// 3. Return activity history
	return nil, nil
}

func (c *membershipController) getMembershipMetricsHandler(ctx context.Context, input *model.OrganisationPathParams) (*GetMembershipMetricsOutput, error) {
	// TODO: Implement get membership metrics logic
	// 1. Calculate detailed membership metrics
	// 2. Include cohort analysis
	// 3. Generate trend data
	// 4. Return comprehensive metrics
	return nil, nil
}

func (c *membershipController) exportMembershipsHandler(ctx context.Context, input *model.OrganisationPathParams) (*model.EmptyOutput, error) {
	// TODO: Implement export memberships logic
	// 1. Validate export request
	// 2. Generate membership export file
	// 3. Create download link
	// 4. Return export details
	return nil, nil
}

func (c *membershipController) transferMembershipHandler(ctx context.Context, input *TransferMembershipInput) (*model.EmptyOutput, error) {
	// TODO: Implement transfer membership logic
	// 1. Validate membership exists
	// 2. Validate target organization
	// 3. Check permissions for transfer
	// 4. Create new membership in target org
	// 5. Remove from current org
	// 6. Log transfer
	// 7. Return success response
	return nil, nil
}

func (c *membershipController) getMembershipHistoryHandler(ctx context.Context, input *GetMembershipHistoryInput) (*GetMembershipHistoryOutput, error) {
	// TODO: Implement get membership history logic
	// 1. Get membership change logs
	// 2. Apply filters and pagination
	// 3. Return change history
	return nil, nil
}
