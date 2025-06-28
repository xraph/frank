package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/xid"
	"github.com/xraph/frank/internal/authz"
	"github.com/xraph/frank/internal/di"
	"github.com/xraph/frank/pkg/model"
	organization2 "github.com/xraph/frank/pkg/services/organization"
)

// RegisterMembershipAPI registers all membership management endpoints
func RegisterMembershipAPI(api huma.API, di di.Container) {
	ctrl := &membershipController{
		api: api,
		di:  di,
	}

	// Member management endpoints
	registerListOrganizationMembers(api, ctrl)
	registerGetMember(api, ctrl)
	registerAddMember(api, ctrl)
	registerUpdateMember(api, ctrl)
	registerRemoveMember(api, ctrl)
	registerUpdateMemberRole(api, ctrl)
	registerUpdateMemberStatus(api, ctrl)

	// Invitation management endpoints
	registerCreateInvitation(api, ctrl)
	registerListInvitations(api, ctrl)
	registerGetInvitation(api, ctrl)
	registerAcceptInvitation(api, ctrl)
	registerDeclineInvitation(api, ctrl)
	registerResendInvitation(api, ctrl)
	registerCancelInvitation(api, ctrl)
	registerBulkInvitations(api, ctrl)
	registerValidateInvitation(api, ctrl)

	// Member analytics and stats
	registerGetMembershipStats(api, ctrl)
	registerGetMemberActivity(api, ctrl)
	registerGetMemberMetrics(api, ctrl)

	// Bulk operations
	registerBulkUpdateMemberRoles(api, ctrl)
	registerBulkUpdateMemberStatus(api, ctrl)
	registerBulkRemoveMembers(api, ctrl)

	// Contact management
	registerSetPrimaryContact(api, ctrl)
	registerSetBillingContact(api, ctrl)
	registerRemoveBillingContact(api, ctrl)

	// Permission management
	registerGetMemberPermissions(api, ctrl)
	registerCheckMemberPermission(api, ctrl)
}

// membershipController handles membership and invitation API requests
type membershipController struct {
	api huma.API
	di  di.Container
}

// Member Management Endpoints

func registerListOrganizationMembers(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "listOrganizationMembers",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/members",
		Summary:     "List organization members",
		Description: "List all members of an organization with filtering and pagination",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionViewMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.listOrganizationMembersHandler)
}

func registerGetMember(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMember",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/members/{userId}",
		Summary:     "Get member details",
		Description: "Get detailed information about a specific organization member",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionViewMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.getMemberHandler)
}

func registerAddMember(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "addMember",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/members",
		Summary:     "Add organization member",
		Description: "Add an existing user as a member of the organization",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.addMemberHandler)
}

func registerUpdateMember(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateMember",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/members/{userId}",
		Summary:     "Update member",
		Description: "Update member information and settings",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.updateMemberHandler)
}

func registerRemoveMember(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID:   "removeMember",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/members/{userId}",
		Summary:       "Remove member",
		Description:   "Remove a member from the organization",
		Tags:          []string{"Membership"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Member successfully removed"},
		}, false, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.removeMemberHandler)
}

func registerUpdateMemberRole(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateMemberRole",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/members/{userId}/role",
		Summary:     "Update member role",
		Description: "Update a member's role in the organization",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.updateMemberRoleHandler)
}

func registerUpdateMemberStatus(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateMemberStatus",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/members/{userId}/status",
		Summary:     "Update member status",
		Description: "Update a member's status (active, inactive, suspended)",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.updateMemberStatusHandler)
}

// Invitation Management Endpoints

func registerCreateInvitation(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "createInvitation",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/invitations",
		Summary:     "Create invitation",
		Description: "Create and send an invitation to join the organization",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.createInvitationHandler)
}

func registerListInvitations(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "listInvitations",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/invitations",
		Summary:     "List invitations",
		Description: "List all invitations for the organization",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionViewMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.listInvitationsHandler)
}

func registerGetInvitation(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getInvitation",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/invitations/{invitationId}",
		Summary:     "Get invitation",
		Description: "Get invitation details by ID",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Invitation not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionViewMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.getInvitationHandler)
}

func registerAcceptInvitation(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "acceptInvitation",
		Method:      http.MethodPost,
		Path:        "/invitations/accept",
		Summary:     "Accept invitation",
		Description: "Accept an organization invitation using the invitation token",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Invitation not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, ctrl.acceptInvitationHandler)
}

func registerDeclineInvitation(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "declineInvitation",
		Method:      http.MethodPost,
		Path:        "/invitations/decline",
		Summary:     "Decline invitation",
		Description: "Decline an organization invitation using the invitation token",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Invitation not found")),
	}, ctrl.declineInvitationHandler)
}

func registerResendInvitation(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "resendInvitation",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/invitations/{invitationId}/resend",
		Summary:     "Resend invitation",
		Description: "Resend an invitation email to the invitee",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Invitation not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.resendInvitationHandler)
}

func registerCancelInvitation(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID:   "cancelInvitation",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/invitations/{invitationId}",
		Summary:       "Cancel invitation",
		Description:   "Cancel a pending invitation",
		Tags:          []string{"Invitations"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Invitation successfully cancelled"},
		}, false, model.NotFoundError("Invitation not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.cancelInvitationHandler)
}

func registerBulkInvitations(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "bulkInvitations",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/invitations/bulk",
		Summary:     "Bulk create invitations",
		Description: "Create multiple invitations at once",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.bulkInvitationsHandler)
}

func registerValidateInvitation(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "validateInvitation",
		Method:      http.MethodPost,
		Path:        "/invitations/validate",
		Summary:     "Validate invitation",
		Description: "Validate an invitation token without accepting it",
		Tags:        []string{"Invitations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
	}, ctrl.validateInvitationHandler)
}

// Analytics and Stats Endpoints

func registerGetMembershipStats(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMembershipStats",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/members/stats",
		Summary:     "Get membership statistics",
		Description: "Get comprehensive membership statistics for the organization",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionViewAnalytics, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.getMembershipStatsHandler)
}

func registerGetMemberActivity(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMemberActivity",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/members/activity",
		Summary:     "Get member activity",
		Description: "Get recent member activity and changes",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionViewAnalytics, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.getMemberActivityHandler)
}

func registerGetMemberMetrics(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMemberMetrics",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/members/metrics",
		Summary:     "Get member metrics",
		Description: "Get member metrics for a specific time period",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionViewAnalytics, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.getMemberMetricsHandler)
}

// Bulk Operations Endpoints

func registerBulkUpdateMemberRoles(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "bulkUpdateMemberRoles",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/members/bulk/roles",
		Summary:     "Bulk update member roles",
		Description: "Update roles for multiple members at once",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.bulkUpdateMemberRolesHandler)
}

func registerBulkUpdateMemberStatus(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "bulkUpdateMemberStatus",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/members/bulk/status",
		Summary:     "Bulk update member status",
		Description: "Update status for multiple members at once",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.bulkUpdateMemberStatusHandler)
}

func registerBulkRemoveMembers(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "bulkRemoveMembers",
		Method:      http.MethodDelete,
		Path:        "/organizations/{orgId}/members/bulk",
		Summary:     "Bulk remove members",
		Description: "Remove multiple members from the organization at once",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.bulkRemoveMembersHandler)
}

// Contact Management Endpoints

func registerSetPrimaryContact(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "setPrimaryContact",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/members/{userId}/primary-contact",
		Summary:     "Set primary contact",
		Description: "Set a member as the primary contact for the organization",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.setPrimaryContactHandler)
}

func registerSetBillingContact(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "setBillingContact",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/members/{userId}/billing-contact",
		Summary:     "Set billing contact",
		Description: "Set a member as a billing contact for the organization",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageBilling, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.setBillingContactHandler)
}

func registerRemoveBillingContact(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID:   "removeBillingContact",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/members/{userId}/billing-contact",
		Summary:       "Remove billing contact",
		Description:   "Remove a member as a billing contact for the organization",
		Tags:          []string{"Membership"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {Description: "Billing contact successfully removed"},
		}, false, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionManageBilling, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.removeBillingContactHandler)
}

// Permission Management Endpoints

func registerGetMemberPermissions(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMemberPermissions",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/members/{userId}/permissions",
		Summary:     "Get member permissions",
		Description: "Get all permissions for a specific member",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionViewMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.getMemberPermissionsHandler)
}

func registerCheckMemberPermission(api huma.API, ctrl *membershipController) {
	huma.Register(api, huma.Operation{
		OperationID: "checkMemberPermission",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/members/{userId}/permissions/{permission}",
		Summary:     "Check member permission",
		Description: "Check if a member has a specific permission",
		Tags:        []string{"Membership"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, false, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionViewMembers, model.ResourceOrganization, "orgId",
		)},
	}, ctrl.checkMemberPermissionHandler)
}

// Input/Output type definitions

type ListOrganizationMembersInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
	model.ListMembershipsParams
}

type ListOrganizationMembersOutput = model.Output[*model.MemberListResponse]

type GetMemberInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type GetMemberOutput = model.Output[*model.Membership]

type AddMemberInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
	Body  model.CreateMembershipRequest
}

type AddMemberOutput = model.Output[*model.CreateMembershipResponse]

type UpdateMemberInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
	Body   model.UpdateMembershipRequest
}

type UpdateMemberOutput = model.Output[*model.Membership]

type RemoveMemberInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
	Body   model.RemoveMemberRequest
}

type UpdateMemberRoleInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
	Body   struct {
		RoleID xid.ID `json:"roleId" doc:"New role ID"`
		Reason string `json:"reason,omitempty" doc:"Reason for role change"`
	}
}

type UpdateMemberRoleOutput = model.Output[*model.Membership]

type UpdateMemberStatusInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
	Body   struct {
		Status string `json:"status" doc:"New status"`
		Reason string `json:"reason,omitempty" doc:"Reason for status change"`
	}
}

type UpdateMemberStatusOutput = model.Output[*model.Membership]

type CreateInvitationInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
	Body  model.CreateInvitationRequest
}

type CreateInvitationOutput = model.Output[*model.Invitation]

type ListInvitationsInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
	model.ListInvitationsParams
}

type ListInvitationsOutput = model.Output[*model.InvitationListResponse]

type GetInvitationInput struct {
	OrgID        xid.ID `path:"orgId" doc:"Organization ID"`
	InvitationID xid.ID `path:"invitationId" doc:"Invitation ID"`
}

type GetInvitationOutput = model.Output[*model.Invitation]

type AcceptInvitationInput struct {
	Body model.AcceptInvitationRequest
}

type AcceptInvitationOutput = model.Output[*model.AcceptInvitationResponse]

type DeclineInvitationInput struct {
	Body model.DeclineInvitationRequest
}

type ResendInvitationInput struct {
	OrgID        xid.ID `path:"orgId" doc:"Organization ID"`
	InvitationID xid.ID `path:"invitationId" doc:"Invitation ID"`
	Body         model.ResendInvitationRequest
}

type CancelInvitationInput struct {
	OrgID        xid.ID `path:"orgId" doc:"Organization ID"`
	InvitationID xid.ID `path:"invitationId" doc:"Invitation ID"`
	Body         model.CancelInvitationRequest
}

type BulkInvitationsInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
	Body  model.BulkCreateInvitationsRequest
}

type BulkInvitationsOutput = model.Output[*model.BulkInvitationResponse]

type ValidateInvitationInput struct {
	Body model.InvitationValidationRequest
}

type ValidateInvitationOutput = model.Output[*model.InvitationValidationResponse]

type GetMembershipStatsInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
}

type GetMembershipStatsOutput = model.Output[*model.MembershipStats]

type GetMemberActivityInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
	Days  int    `query:"days" doc:"Number of days to look back" default:"30"`
}

type GetMemberActivityOutput = model.Output[*model.MembershipActivityResponse]

type GetMemberMetricsInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	Period string `query:"period" doc:"Time period (30d, 90d, 1y)" default:"30d"`
}

type GetMemberMetricsOutput = model.Output[*model.MemberMetrics]

type BulkUpdateMemberRolesInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
	Body  []model.BulkMemberRoleUpdate
}

type BulkUpdateMemberRolesOutput = model.Output[*model.BulkMembershipOperationResponse]

type BulkUpdateMemberStatusInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
	Body  []model.BulkMemberStatusUpdate
}

type BulkUpdateMemberStatusOutput = model.Output[*model.BulkMembershipOperationResponse]

type BulkRemoveMembersInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
	Body  struct {
		UserIDs []xid.ID `json:"userIds" doc:"User IDs to remove"`
		Reason  string   `json:"reason,omitempty" doc:"Reason for removal"`
	}
}

type BulkRemoveMembersOutput = model.Output[*model.BulkMembershipOperationResponse]

type GetMemberPermissionsInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type GetMemberPermissionsOutput = model.Output[map[string]interface{}]

type CheckMemberPermissionInput struct {
	OrgID      xid.ID `path:"orgId" doc:"Organization ID"`
	UserID     xid.ID `path:"userId" doc:"User ID"`
	Permission string `path:"permission" doc:"Permission name"`
}

type CheckMemberPermissionOutput = model.Output[map[string]interface{}]

// Handler implementations

func (c *membershipController) listOrganizationMembersHandler(ctx context.Context, input *ListOrganizationMembersInput) (*ListOrganizationMembersOutput, error) {
	membershipService := c.di.MembershipService()

	response, err := membershipService.ListOrganizationMembers(ctx, input.OrgID, input.ListMembershipsParams)
	if err != nil {
		return nil, err
	}

	return &ListOrganizationMembersOutput{
		Body: response,
	}, nil
}

func (c *membershipController) getMemberHandler(ctx context.Context, input *GetMemberInput) (*GetMemberOutput, error) {
	membershipService := c.di.MembershipService()

	membership, err := membershipService.GetMembership(ctx, input.OrgID, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetMemberOutput{
		Body: membership,
	}, nil
}

func (c *membershipController) addMemberHandler(ctx context.Context, input *AddMemberInput) (*AddMemberOutput, error) {
	membershipService := c.di.MembershipService()

	// Get inviter from context (should be set by auth middleware)
	inviterID := xid.New() // This should come from authenticated user context

	addMemberInput := organization2.AddMemberInput{
		OrganizationID: input.OrgID,
		UserID:         *input.Body.UserID,
		RoleID:         input.Body.RoleID,
		InvitedBy:      &inviterID,
		IsBilling:      input.Body.IsBillingContact,
		IsPrimary:      input.Body.IsPrimaryContact,
		CustomFields:   input.Body.Metadata,
	}

	membership, err := membershipService.AddMember(ctx, addMemberInput)
	if err != nil {
		return nil, err
	}

	response := &model.CreateMembershipResponse{
		Membership:     *membership,
		InvitationSent: false,
		UserCreated:    false,
	}

	return &AddMemberOutput{
		Body: response,
	}, nil
}

func (c *membershipController) updateMemberHandler(ctx context.Context, input *UpdateMemberInput) (*UpdateMemberOutput, error) {
	membershipService := c.di.MembershipService()

	// Handle role update if specified
	if input.Body.RoleID.IsSet {
		membership, err := membershipService.UpdateMemberRole(ctx, input.OrgID, input.UserID, input.Body.RoleID.Value)
		if err != nil {
			return nil, err
		}
		return &UpdateMemberOutput{Body: membership}, nil
	}

	// Handle status update if specified
	if input.Body.Status.IsSet {
		status := model.ParseMembershipStatus(input.Body.Status.Value)
		membership, err := membershipService.UpdateMemberStatus(ctx, input.OrgID, input.UserID, status)
		if err != nil {
			return nil, err
		}
		return &UpdateMemberOutput{Body: membership}, nil
	}

	// Get current membership if no specific updates
	membership, err := membershipService.GetMembership(ctx, input.OrgID, input.UserID)
	if err != nil {
		return nil, err
	}

	return &UpdateMemberOutput{
		Body: membership,
	}, nil
}

func (c *membershipController) removeMemberHandler(ctx context.Context, input *RemoveMemberInput) (*model.EmptyOutput, error) {
	membershipService := c.di.MembershipService()

	err := membershipService.RemoveMember(ctx, input.OrgID, input.UserID, input.Body.Reason)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *membershipController) updateMemberRoleHandler(ctx context.Context, input *UpdateMemberRoleInput) (*UpdateMemberRoleOutput, error) {
	membershipService := c.di.MembershipService()

	membership, err := membershipService.UpdateMemberRole(ctx, input.OrgID, input.UserID, input.Body.RoleID)
	if err != nil {
		return nil, err
	}

	return &UpdateMemberRoleOutput{
		Body: membership,
	}, nil
}

func (c *membershipController) updateMemberStatusHandler(ctx context.Context, input *UpdateMemberStatusInput) (*UpdateMemberStatusOutput, error) {
	membershipService := c.di.MembershipService()

	status := model.ParseMembershipStatus(input.Body.Status)
	membership, err := membershipService.UpdateMemberStatus(ctx, input.OrgID, input.UserID, status)
	if err != nil {
		return nil, err
	}

	return &UpdateMemberStatusOutput{
		Body: membership,
	}, nil
}

func (c *membershipController) createInvitationHandler(ctx context.Context, input *CreateInvitationInput) (*CreateInvitationOutput, error) {
	// Get invitation service from DI container
	invitationService := c.di.InvitationService()

	// Get inviter from context
	inviterID := xid.New() // This should come from authenticated user context

	createInvitationInput := organization2.CreateInvitationInput{
		OrganizationID: input.OrgID,
		Email:          input.Body.Email,
		RoleID:         input.Body.RoleID,
		InvitedBy:      inviterID,
		Message:        input.Body.Message,
		ExpiresAt:      input.Body.ExpiresAt,
		RedirectURL:    input.Body.RedirectURL,
		CustomFields:   input.Body.CustomFields,
		SendEmail:      input.Body.SendEmail,
	}

	invitation, err := invitationService.CreateInvitation(ctx, createInvitationInput)
	if err != nil {
		return nil, err
	}

	return &CreateInvitationOutput{
		Body: invitation,
	}, nil
}

func (c *membershipController) listInvitationsHandler(ctx context.Context, input *ListInvitationsInput) (*ListInvitationsOutput, error) {
	// Get invitation service from DI container
	invitationService := c.di.InvitationService()

	response, err := invitationService.ListInvitations(ctx, input.OrgID, input.ListInvitationsParams)
	if err != nil {
		return nil, err
	}

	return &ListInvitationsOutput{
		Body: response,
	}, nil
}

func (c *membershipController) getInvitationHandler(ctx context.Context, input *GetInvitationInput) (*GetInvitationOutput, error) {
	// Get invitation service from DI container
	invitationService := c.di.InvitationService()

	invitation, err := invitationService.GetInvitation(ctx, input.InvitationID)
	if err != nil {
		return nil, err
	}

	return &GetInvitationOutput{
		Body: invitation,
	}, nil
}

func (c *membershipController) acceptInvitationHandler(ctx context.Context, input *AcceptInvitationInput) (*AcceptInvitationOutput, error) {
	// Get invitation service from DI container
	invitationService := c.di.InvitationService()

	// Get accepting user from context
	acceptedBy := xid.New() // This should come from authenticated user context

	membership, err := invitationService.AcceptInvitation(ctx, input.Body.Token, acceptedBy)
	if err != nil {
		return nil, err
	}

	response := &model.AcceptInvitationResponse{
		Success:    true,
		Membership: *membership,
		// User and Organization would be populated by getting the related data
	}

	return &AcceptInvitationOutput{
		Body: response,
	}, nil
}

type SimpleMessage struct {
	Message string `json:"message"`
}
type SimpleMessageOutput = model.Output[SimpleMessage]

func (c *membershipController) declineInvitationHandler(ctx context.Context, input *DeclineInvitationInput) (*SimpleMessageOutput, error) {
	// Get invitation service from DI container
	invitationService := c.di.InvitationService()

	err := invitationService.DeclineInvitation(ctx, input.Body.Token, input.Body.Reason)
	if err != nil {
		return nil, err
	}

	return &SimpleMessageOutput{
		Body: SimpleMessage{
			Message: "Invitation declined successfully",
		},
	}, nil
}

func (c *membershipController) resendInvitationHandler(ctx context.Context, input *ResendInvitationInput) (*SimpleMessageOutput, error) {
	// Get invitation service from DI container
	invitationService := c.di.InvitationService()

	err := invitationService.ResendInvitation(ctx, input.InvitationID)
	if err != nil {
		return nil, err
	}

	return &SimpleMessageOutput{
		Body: SimpleMessage{
			Message: "Invitation resent successfully",
		},
	}, nil
}

func (c *membershipController) cancelInvitationHandler(ctx context.Context, input *CancelInvitationInput) (*SimpleMessageOutput, error) {
	// Get invitation service from DI container
	invitationService := c.di.InvitationService()

	err := invitationService.CancelInvitation(ctx, input.InvitationID, input.Body.Reason)
	if err != nil {
		return nil, err
	}

	return &SimpleMessageOutput{
		Body: SimpleMessage{
			Message: "Invitation cancelled successfully",
		},
	}, nil
}

func (c *membershipController) bulkInvitationsHandler(ctx context.Context, input *BulkInvitationsInput) (*BulkInvitationsOutput, error) {
	// Get invitation service from DI container
	invitationService := c.di.InvitationService()

	// Convert request to bulk invitation input
	bulkInput := make([]organization2.BulkInvitationInput, len(input.Body.Invitations))
	for i, inv := range input.Body.Invitations {
		bulkInput[i] = organization2.BulkInvitationInput{
			Email:        inv.Email,
			RoleID:       inv.RoleID,
			Message:      inv.Message,
			CustomFields: inv.CustomFields,
		}
	}

	response, err := invitationService.CreateBulkInvitations(ctx, input.OrgID, bulkInput)
	if err != nil {
		return nil, err
	}

	return &BulkInvitationsOutput{
		Body: response,
	}, nil
}

func (c *membershipController) validateInvitationHandler(ctx context.Context, input *ValidateInvitationInput) (*ValidateInvitationOutput, error) {
	// Get invitation service from DI container
	invitationService := c.di.InvitationService()

	invitation, err := invitationService.ValidateInvitationToken(ctx, input.Body.Token)
	if err != nil {
		return &ValidateInvitationOutput{
			Body: &model.InvitationValidationResponse{
				Valid: false,
				Error: err.Error(),
			},
		}, nil
	}

	response := &model.InvitationValidationResponse{
		Valid:       true,
		Expired:     false,
		AlreadyUsed: false,
		Invitation:  invitation,
		ExpiresAt:   invitation.ExpiresAt,
	}

	return &ValidateInvitationOutput{
		Body: response,
	}, nil
}

func (c *membershipController) getMembershipStatsHandler(ctx context.Context, input *GetMembershipStatsInput) (*GetMembershipStatsOutput, error) {
	membershipService := c.di.MembershipService()

	stats, err := membershipService.GetMembershipStats(ctx, input.OrgID)
	if err != nil {
		return nil, err
	}

	return &GetMembershipStatsOutput{
		Body: stats,
	}, nil
}

func (c *membershipController) getMemberActivityHandler(ctx context.Context, input *GetMemberActivityInput) (*GetMemberActivityOutput, error) {
	membershipService := c.di.MembershipService()

	activity, err := membershipService.GetRecentActivity(ctx, input.OrgID, input.Days)
	if err != nil {
		return nil, err
	}

	return &GetMemberActivityOutput{
		Body: activity,
	}, nil
}

func (c *membershipController) getMemberMetricsHandler(ctx context.Context, input *GetMemberMetricsInput) (*GetMemberMetricsOutput, error) {
	membershipService := c.di.MembershipService()

	metrics, err := membershipService.GetMemberMetrics(ctx, input.OrgID, input.Period)
	if err != nil {
		return nil, err
	}

	return &GetMemberMetricsOutput{
		Body: metrics,
	}, nil
}

func (c *membershipController) bulkUpdateMemberRolesHandler(ctx context.Context, input *BulkUpdateMemberRolesInput) (*BulkUpdateMemberRolesOutput, error) {
	membershipService := c.di.MembershipService()

	response, err := membershipService.BulkUpdateMemberRoles(ctx, input.OrgID, input.Body)
	if err != nil {
		return nil, err
	}

	return &BulkUpdateMemberRolesOutput{
		Body: response,
	}, nil
}

func (c *membershipController) bulkUpdateMemberStatusHandler(ctx context.Context, input *BulkUpdateMemberStatusInput) (*BulkUpdateMemberStatusOutput, error) {
	membershipService := c.di.MembershipService()

	response, err := membershipService.BulkUpdateMemberStatus(ctx, input.OrgID, input.Body)
	if err != nil {
		return nil, err
	}

	return &BulkUpdateMemberStatusOutput{
		Body: response,
	}, nil
}

func (c *membershipController) bulkRemoveMembersHandler(ctx context.Context, input *BulkRemoveMembersInput) (*BulkRemoveMembersOutput, error) {
	membershipService := c.di.MembershipService()

	response := &model.BulkMembershipOperationResponse{
		SuccessCount: 0,
		FailureCount: 0,
		Errors:       []string{},
	}

	for _, userID := range input.Body.UserIDs {
		err := membershipService.RemoveMember(ctx, input.OrgID, userID, input.Body.Reason)
		if err != nil {
			response.FailureCount++
			response.Errors = append(response.Errors, err.Error())
		} else {
			response.SuccessCount++
		}
	}

	return &BulkRemoveMembersOutput{
		Body: response,
	}, nil
}

func (c *membershipController) setPrimaryContactHandler(ctx context.Context, input *GetMemberInput) (*SimpleMessageOutput, error) {
	membershipService := c.di.MembershipService()

	err := membershipService.SetPrimaryContact(ctx, input.OrgID, input.UserID)
	if err != nil {
		return nil, err
	}

	return &SimpleMessageOutput{
		Body: SimpleMessage{
			Message: "Primary contact set successfully",
		},
	}, nil
}

func (c *membershipController) setBillingContactHandler(ctx context.Context, input *GetMemberInput) (*SimpleMessageOutput, error) {
	membershipService := c.di.MembershipService()

	err := membershipService.AddBillingContact(ctx, input.OrgID, input.UserID)
	if err != nil {
		return nil, err
	}

	return &SimpleMessageOutput{
		Body: SimpleMessage{
			Message: "Billing contact set successfully",
		},
	}, nil
}

func (c *membershipController) removeBillingContactHandler(ctx context.Context, input *GetMemberInput) (*model.EmptyOutput, error) {
	membershipService := c.di.MembershipService()

	err := membershipService.RemoveBillingContact(ctx, input.OrgID, input.UserID)
	if err != nil {
		return nil, err
	}

	return &model.EmptyOutput{}, nil
}

func (c *membershipController) getMemberPermissionsHandler(ctx context.Context, input *GetMemberPermissionsInput) (*GetMemberPermissionsOutput, error) {
	membershipService := c.di.MembershipService()

	permissions, err := membershipService.GetMemberPermissions(ctx, input.OrgID, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetMemberPermissionsOutput{
		Body: map[string]interface{}{
			"permissions": permissions,
		},
	}, nil
}

func (c *membershipController) checkMemberPermissionHandler(ctx context.Context, input *CheckMemberPermissionInput) (*CheckMemberPermissionOutput, error) {
	membershipService := c.di.MembershipService()

	hasPermission, err := membershipService.HasPermission(ctx, input.OrgID, input.UserID, input.Permission)
	if err != nil {
		return nil, err
	}

	return &CheckMemberPermissionOutput{
		Body: map[string]interface{}{
			"hasPermission": hasPermission,
			"permission":    input.Permission,
		},
	}, nil
}
