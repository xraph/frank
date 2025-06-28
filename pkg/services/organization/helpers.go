package organization

import (
	"fmt"

	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/pkg/model"
)

// Helper methods

func ConvertEntOrgToSummary(org *ent.Organization) model.OrganizationSummary {
	memCount := 0
	if org.Edges.Memberships != nil {
		memCount = len(org.Edges.Memberships)
	}

	return model.OrganizationSummary{
		ID:          org.ID,
		Name:        org.Name,
		Slug:        org.Slug,
		LogoURL:     org.LogoURL,
		Plan:        org.Plan,
		Active:      org.Active,
		OrgType:     org.OrgType,
		MemberCount: memCount,
	}
}

func ConvertEntOrgToPlatformSummary(org *ent.Organization) model.PlatformOrganizationSummary {
	return model.PlatformOrganizationSummary{
		Organization: *ConvertEntOrgToModel(org),
	}
}

func ConvertEntOrgToModel(entOrg *ent.Organization) *model.Organization {
	return &model.Organization{
		Base: model.Base{
			ID:        entOrg.ID,
			CreatedAt: entOrg.CreatedAt,
			UpdatedAt: entOrg.UpdatedAt,
		},
		Name:                   entOrg.Name,
		Slug:                   entOrg.Slug,
		Domains:                entOrg.Domains,
		VerifiedDomains:        entOrg.VerifiedDomains,
		Domain:                 entOrg.Domain,
		LogoURL:                entOrg.LogoURL,
		Plan:                   entOrg.Plan,
		Active:                 entOrg.Active,
		Metadata:               entOrg.Metadata,
		TrialEndsAt:            entOrg.TrialEndsAt,
		TrialUsed:              entOrg.TrialUsed,
		OwnerID:                &entOrg.OwnerID,
		OrgType:                entOrg.OrgType,
		IsPlatformOrganization: entOrg.IsPlatformOrganization,
		ExternalUserLimit:      entOrg.ExternalUserLimit,
		EndUserLimit:           entOrg.EndUserLimit,
		SSOEnabled:             entOrg.SSOEnabled,
		SSODomain:              entOrg.SSODomain,
		SubscriptionID:         entOrg.SubscriptionID,
		CustomerID:             entOrg.CustomerID,
		SubscriptionStatus:     entOrg.SubscriptionStatus.String(),
		AuthServiceEnabled:     entOrg.AuthServiceEnabled,
		AuthConfig:             entOrg.AuthConfig,
		AuthDomain:             entOrg.AuthDomain,
		APIRequestLimit:        entOrg.APIRequestLimit,
		APIRequestsUsed:        entOrg.APIRequestsUsed,
		CurrentExternalUsers:   entOrg.CurrentExternalUsers,
		CurrentEndUsers:        entOrg.CurrentEndUsers,
	}
}

// ConvertEntMembershipToModel converts ent.Membership to model.Membership
func ConvertEntMembershipToModel(entMembership *ent.Membership) *model.Membership {
	return &model.Membership{
		Base: model.Base{
			ID:        entMembership.ID,
			CreatedAt: entMembership.CreatedAt,
			UpdatedAt: entMembership.UpdatedAt,
		},
		UserID:           entMembership.UserID,
		OrganizationID:   entMembership.OrganizationID,
		RoleID:           entMembership.RoleID,
		Status:           entMembership.Status,
		JoinedAt:         entMembership.JoinedAt,
		LeftAt:           entMembership.LeftAt,
		InvitedBy:        &entMembership.InvitedBy,
		IsBillingContact: entMembership.IsBillingContact,
		IsPrimaryContact: entMembership.IsPrimaryContact,
		CustomFields:     entMembership.CustomFields,
		Role:             ConvertEntToRoleSummary(entMembership.Edges.Role),
	}
}

// ConvertEntToRoleSummary converts ent.Membership to model.MemberSummary
func ConvertEntToRoleSummary(entMembership *ent.Role) *model.RoleSummary {
	return &model.RoleSummary{
		Name:        entMembership.Name,
		ID:          entMembership.ID,
		RoleType:    entMembership.RoleType,
		Description: entMembership.Description,
		Active:      entMembership.Active,
		DisplayName: entMembership.DisplayName,
		Priority:    entMembership.Priority,
	}
}

// ConvertEntToMemberSummary converts ent.Membership to model.MemberSummary
func ConvertEntToMemberSummary(entMembership *ent.Membership) model.MemberSummary {
	mem := model.MemberSummary{
		UserID:    entMembership.UserID,
		Status:    entMembership.Status,
		JoinedAt:  entMembership.JoinedAt,
		IsBilling: entMembership.IsBillingContact,
		IsPrimary: entMembership.IsPrimaryContact,
		RoleID:    entMembership.RoleID,
		InvitedBy: &entMembership.InvitedBy,
	}

	if mem.JoinedAt == nil {
		mem.JoinedAt = &entMembership.CreatedAt
	}

	if entMembership.Edges.Role != nil {
		mem.RoleID = entMembership.Edges.Role.ID
		mem.RoleName = entMembership.Edges.Role.Name
		mem.RoleDisplay = entMembership.Edges.Role.DisplayName
	}

	if entMembership.Edges.User != nil {
		mem.Email = entMembership.Edges.User.Email
		mem.FullName = fmt.Sprintf("%s %s", entMembership.Edges.User.FirstName, entMembership.Edges.User.LastName)
		mem.LastName = entMembership.Edges.User.LastName
		mem.FirstName = entMembership.Edges.User.FirstName
		mem.Avatar = entMembership.Edges.User.ProfileImageURL
	}

	return mem
}

// ConvertEntToMembershipSummary converts ent.Membership to model.MembershipSummary
func ConvertEntToMembershipSummary(entMembership *ent.Membership) model.MembershipSummary {
	roleName := entMembership.RoleID.String()
	if entMembership.Edges.Role != nil {
		roleName = entMembership.Edges.Role.Name
	}
	return model.MembershipSummary{
		ID:               entMembership.ID,
		OrganizationID:   entMembership.OrganizationID,
		RoleName:         roleName,
		Status:           entMembership.Status,
		JoinedAt:         entMembership.JoinedAt,
		IsBillingContact: entMembership.IsBillingContact,
		IsPrimaryContact: entMembership.IsPrimaryContact,
	}
}

// ConvertEntRoleToModel converts ent.Role to model.Role
func ConvertEntRoleToModel(entRole *ent.Role) *model.Role {
	return &model.Role{
		Base: model.Base{
			ID:        entRole.ID,
			CreatedAt: entRole.CreatedAt,
			UpdatedAt: entRole.UpdatedAt,
		},
		Name:        entRole.Name,
		DisplayName: entRole.DisplayName,
		Description: entRole.Description,
		RoleType:    entRole.RoleType,
		IsDefault:   entRole.IsDefault,
		// Metadata:    entRole.Metadata,
	}
}
