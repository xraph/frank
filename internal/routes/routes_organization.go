package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/membership"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/internal/services/organization"
	"github.com/rs/xid"
)

// RegisterOrganizationAPI registers all organization-related endpoints
func RegisterOrganizationAPI(api huma.API, di di.Container) {
	orgCtrl := &organizationController{
		api: api,
		di:  di,
	}

	// Organization management endpoints
	registerCreateOrganization(api, orgCtrl)
	registerGetOrganization(api, orgCtrl)
	registerUpdateOrganization(api, orgCtrl)
	registerDeleteOrganization(api, orgCtrl)
	registerListOrganizations(api, orgCtrl)
	registerGetOrganizationStats(api, orgCtrl)

	// Membership management endpoints
	registerInviteMember(api, orgCtrl)
	registerAcceptInvitation(api, orgCtrl)
	registerListMembers(api, orgCtrl)
	registerGetMember(api, orgCtrl)
	registerUpdateMemberRole(api, orgCtrl)
	registerRemoveMember(api, orgCtrl)
	registerResendInvitation(api, orgCtrl)
	registerRevokeInvitation(api, orgCtrl)
}

// organizationController handles organization-related API requests
type organizationController struct {
	api huma.API
	di  di.Container
}

// Organization Management Endpoints

func registerCreateOrganization(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "createOrganization",
		Method:      http.MethodPost,
		Path:        "/organizations",
		Summary:     "Create a new organization",
		Description: "Create a new organization with the authenticated user as the owner",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionCreateOrganization, authz.ResourceGlobal, "",
		)},
	}, orgCtrl.createOrganizationHandler)
}

func registerGetOrganization(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganization",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}",
		Summary:     "Get organization details",
		Description: "Get detailed information about an organization",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewOrganization, authz.ResourceOrganization, "orgId",
		)},
	}, orgCtrl.getOrganizationHandler)
}

func registerUpdateOrganization(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateOrganization",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}",
		Summary:     "Update organization",
		Description: "Update organization details",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionUpdateOrganization, authz.ResourceOrganization, "orgId",
		)},
	}, orgCtrl.updateOrganizationHandler)
}

func registerDeleteOrganization(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID:   "deleteOrganization",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}",
		Summary:       "Delete organization",
		Description:   "Delete an organization (soft delete)",
		Tags:          []string{"Organizations"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "Organization successfully deleted",
			},
		}, true, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionDeleteOrganization, authz.ResourceOrganization, "orgId",
		)},
	}, orgCtrl.deleteOrganizationHandler)
}

func registerListOrganizations(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "listOrganizations",
		Method:      http.MethodGet,
		Path:        "/organizations",
		Summary:     "List organizations",
		Description: "List organizations with pagination and filtering",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionListOrganizations, authz.ResourceSystem, "",
		)},
	}, orgCtrl.listOrganizationsHandler)
}

func registerGetOrganizationStats(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "getOrganizationStats",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/stats",
		Summary:     "Get organization statistics",
		Description: "Get detailed statistics about an organization",
		Tags:        []string{"Organizations"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Organization not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewOrganization, authz.ResourceOrganization, "orgId",
		)},
	}, orgCtrl.getOrganizationStatsHandler)
}

// Membership Management Endpoints

func registerInviteMember(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "inviteMember",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/members/invite",
		Summary:     "Invite a member",
		Description: "Invite a user to join the organization",
		Tags:        []string{"Organizations", "Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionInviteMembers, authz.ResourceOrganization, "orgId",
		)},
	}, orgCtrl.inviteMemberHandler)
}

func registerAcceptInvitation(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "acceptInvitation",
		Method:      http.MethodPost,
		Path:        "/organizations/invitations/accept",
		Summary:     "Accept organization invitation",
		Description: "Accept an invitation to join an organization",
		Tags:        []string{"Organizations", "Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
	}, orgCtrl.acceptInvitationHandler)
}

func registerListMembers(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "listMembers",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/members",
		Summary:     "List organization members",
		Description: "List all members of an organization with pagination",
		Tags:        []string{"Organizations", "Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewMembers, authz.ResourceOrganization, "orgId",
		)},
	}, orgCtrl.listMembersHandler)
}

func registerGetMember(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "getMember",
		Method:      http.MethodGet,
		Path:        "/organizations/{orgId}/members/{userId}",
		Summary:     "Get member details",
		Description: "Get detailed information about an organization member",
		Tags:        []string{"Organizations", "Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionViewMembers, authz.ResourceOrganization, "orgId",
		)},
	}, orgCtrl.getMemberHandler)
}

func registerUpdateMemberRole(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "updateMemberRole",
		Method:      http.MethodPut,
		Path:        "/organizations/{orgId}/members/{userId}/role",
		Summary:     "Update member role",
		Description: "Update a member's role in the organization",
		Tags:        []string{"Organizations", "Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionManageMembers, authz.ResourceOrganization, "orgId",
		)},
	}, orgCtrl.updateMemberRoleHandler)
}

func registerRemoveMember(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID:   "removeMember",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/members/{userId}",
		Summary:       "Remove member",
		Description:   "Remove a member from the organization",
		Tags:          []string{"Organizations", "Memberships"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "Member successfully removed",
			},
		}, true, model.NotFoundError("Member not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionManageMembers, authz.ResourceOrganization, "orgId",
		)},
	}, orgCtrl.removeMemberHandler)
}

func registerResendInvitation(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID: "resendInvitation",
		Method:      http.MethodPost,
		Path:        "/organizations/{orgId}/members/{userId}/resend-invitation",
		Summary:     "Resend invitation",
		Description: "Resend an invitation to a pending member",
		Tags:        []string{"Organizations", "Memberships"},
		Responses:   model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionInviteMembers, authz.ResourceOrganization, "orgId",
		)},
	}, orgCtrl.resendInvitationHandler)
}

func registerRevokeInvitation(api huma.API, orgCtrl *organizationController) {
	huma.Register(api, huma.Operation{
		OperationID:   "revokeInvitation",
		Method:        http.MethodDelete,
		Path:          "/organizations/{orgId}/invitations/{userId}",
		Summary:       "Revoke invitation",
		Description:   "Revoke a pending invitation",
		Tags:          []string{"Organizations", "Memberships"},
		DefaultStatus: 204,
		Responses: model.MergeErrorResponses(map[string]*huma.Response{
			"204": {
				Description: "Invitation successfully revoked",
			},
		}, true, model.NotFoundError("Invitation not found")),
		Security: []map[string][]string{
			{"jwt": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, orgCtrl.di.AuthZ().Checker(), orgCtrl.di.Logger())(
			authz.PermissionManageMembers, authz.ResourceOrganization, "orgId",
		)},
	}, orgCtrl.revokeInvitationHandler)
}

// Input/Output Type Definitions

// Organization Management Types
type CreateOrganizationInput struct {
	Body organization.CreateOrganizationInput `json:"body"`
}

type CreateOrganizationOutput = model.Output[*ent.Organization]

type GetOrganizationInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
}

type GetOrganizationOutput = model.Output[*ent.Organization]

type UpdateOrganizationInput struct {
	OrgID xid.ID                               `path:"orgId" doc:"Organization ID"`
	Body  organization.UpdateOrganizationInput `json:"body"`
}

type UpdateOrganizationOutput = model.Output[*ent.Organization]

type DeleteOrganizationInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
}

type ListOrganizationsInput struct {
	model.PaginationParams
	OrgType *string `query:"org_type" doc:"Filter by organization type"`
	Active  *bool   `query:"active" doc:"Filter by active status"`
}

type ListOrganizationsOutput = model.Output[*model.PaginatedOutput[*ent.Organization]]

type GetOrganizationStatsInput struct {
	OrgID xid.ID `path:"orgId" doc:"Organization ID"`
}

type GetOrganizationStatsOutput = model.Output[*organization.OrganizationStats]

// Membership Management Types
type InviteMemberInput struct {
	OrgID xid.ID                         `path:"orgId" doc:"Organization ID"`
	Body  organization.InviteMemberInput `json:"body"`
}

type InviteMemberOutput = model.Output[*ent.Membership]

type AcceptInvitationInput struct {
	Body organization.AcceptInvitationInput `json:"body"`
}

type AcceptInvitationOutput = model.Output[*ent.Membership]

type ListMembersInput struct {
	model.PaginationParams
	OrgID  xid.ID             `path:"orgId" doc:"Organization ID"`
	Status *membership.Status `query:"status" doc:"Filter by membership status"`
	RoleID *xid.ID            `query:"role_id" doc:"Filter by role ID"`
}

type ListMembersOutput = model.Output[*model.PaginatedOutput[*ent.Membership]]

type GetMemberInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type GetMemberOutput = model.Output[*ent.Membership]

type UpdateMemberRoleInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
	Body   struct {
		RoleID xid.ID `json:"role_id" validate:"required" doc:"New role ID"`
	} `json:"body"`
}

type UpdateMemberRoleOutput = model.Output[*ent.Membership]

type RemoveMemberInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type ResendInvitationInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type RevokeInvitationInput struct {
	OrgID  xid.ID `path:"orgId" doc:"Organization ID"`
	UserID xid.ID `path:"userId" doc:"User ID"`
}

// Handler Implementations

// Organization Management Handlers

func (c *organizationController) createOrganizationHandler(ctx context.Context, input *CreateOrganizationInput) (*CreateOrganizationOutput, error) {
	// Get current user from context
	userID, err := c.di.Auth().GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Set the owner ID to current user
	input.Body.OwnerID = userID

	org, err := c.di.OrganizationService().CreateOrganization(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreateOrganizationOutput{
		Body: org,
	}, nil
}

func (c *organizationController) getOrganizationHandler(ctx context.Context, input *GetOrganizationInput) (*GetOrganizationOutput, error) {
	org, err := c.di.OrganizationService().GetOrganization(ctx, input.OrgID)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationOutput{
		Body: org,
	}, nil
}

func (c *organizationController) updateOrganizationHandler(ctx context.Context, input *UpdateOrganizationInput) (*UpdateOrganizationOutput, error) {
	org, err := c.di.OrganizationService().UpdateOrganization(ctx, input.OrgID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateOrganizationOutput{
		Body: org,
	}, nil
}

func (c *organizationController) deleteOrganizationHandler(ctx context.Context, input *DeleteOrganizationInput) (*model.EmptyOutput, error) {
	// For now, we'll soft delete by setting active to false
	_, err := c.di.OrganizationService().UpdateOrganization(ctx, input.OrgID, organization.UpdateOrganizationInput{
		// We need to add Active field to UpdateOrganizationInput
	})
	return nil, err
}

func (c *organizationController) listOrganizationsHandler(ctx context.Context, input *ListOrganizationsInput) (*ListOrganizationsOutput, error) {
	// This would need to be implemented in the organization service
	// For now, return empty result
	return &ListOrganizationsOutput{
		Body: &model.PaginatedOutput[*ent.Organization]{
			Data:       []*ent.Organization{},
			Pagination: &model.Pagination{},
		},
	}, nil
}

func (c *organizationController) getOrganizationStatsHandler(ctx context.Context, input *GetOrganizationStatsInput) (*GetOrganizationStatsOutput, error) {
	stats, err := c.di.OrganizationService().GetOrganizationStats(ctx, input.OrgID)
	if err != nil {
		return nil, err
	}

	return &GetOrganizationStatsOutput{
		Body: stats,
	}, nil
}

// Membership Management Handlers

func (c *organizationController) inviteMemberHandler(ctx context.Context, input *InviteMemberInput) (*InviteMemberOutput, error) {
	// Get current user from context
	userID, err := c.di.Auth().GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Set the inviter
	input.Body.OrganizationID = input.OrgID
	input.Body.InvitedBy = userID

	membership, err := c.di.OrganizationService().InviteMember(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &InviteMemberOutput{
		Body: membership,
	}, nil
}

func (c *organizationController) acceptInvitationHandler(ctx context.Context, input *AcceptInvitationInput) (*AcceptInvitationOutput, error) {
	// Get current user from context
	userID, err := c.di.Auth().GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	input.Body.UserID = userID

	membership, err := c.di.OrganizationService().AcceptInvitation(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &AcceptInvitationOutput{
		Body: membership,
	}, nil
}

func (c *organizationController) listMembersHandler(ctx context.Context, input *ListMembersInput) (*ListMembersOutput, error) {
	members, err := c.di.OrganizationService().ListMembers(ctx, input.OrgID, input.Status)
	if err != nil {
		return nil, err
	}

	// Convert to paginated output
	return &ListMembersOutput{
		Body: &model.PaginatedOutput[*ent.Membership]{
			Data: members,
			Pagination: &model.Pagination{
				TotalCount: len(members),
			},
		},
	}, nil
}

func (c *organizationController) getMemberHandler(ctx context.Context, input *GetMemberInput) (*GetMemberOutput, error) {
	membership, err := c.di.OrganizationService().GetMembershipByUser(ctx, input.OrgID, input.UserID)
	if err != nil {
		return nil, err
	}

	return &GetMemberOutput{
		Body: membership,
	}, nil
}

func (c *organizationController) updateMemberRoleHandler(ctx context.Context, input *UpdateMemberRoleInput) (*UpdateMemberRoleOutput, error) {
	membership, err := c.di.OrganizationService().UpdateMemberRole(ctx, input.OrgID, input.UserID, input.Body.RoleID)
	if err != nil {
		return nil, err
	}

	return &UpdateMemberRoleOutput{
		Body: membership,
	}, nil
}

func (c *organizationController) removeMemberHandler(ctx context.Context, input *RemoveMemberInput) (*model.EmptyOutput, error) {
	err := c.di.OrganizationService().RemoveMember(ctx, input.OrgID, input.UserID)
	return nil, err
}

func (c *organizationController) resendInvitationHandler(ctx context.Context, input *ResendInvitationInput) (*model.EmptyOutput, error) {
	// This would need to be implemented in the organization service
	// It would regenerate the invitation token and send a new email
	return nil, nil
}

func (c *organizationController) revokeInvitationHandler(ctx context.Context, input *RevokeInvitationInput) (*model.EmptyOutput, error) {
	// This would remove the pending membership
	err := c.di.OrganizationService().RemoveMember(ctx, input.OrgID, input.UserID)
	return nil, err
}
