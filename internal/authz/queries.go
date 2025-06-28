package authz

import (
	"context"

	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	entMembership "github.com/xraph/frank/ent/membership"
	entRole "github.com/xraph/frank/ent/role"
	"github.com/xraph/frank/pkg/data"
)

// MembershipQueries provides convenient methods for querying membership relationships
type MembershipQueries struct {
	client *data.Clients
}

// NewMembershipQueries creates a new membership queries helper
func NewMembershipQueries(client *data.Clients) *MembershipQueries {
	return &MembershipQueries{
		client: client,
	}
}

// GetOrganizationUsers returns all active users in an organization
func (mq *MembershipQueries) GetOrganizationUsers(ctx context.Context, orgID xid.ID) ([]*ent.User, error) {
	// Query users through memberships
	memberships, err := mq.client.DB.Membership.Query().
		Where(
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
		).
		WithUser().
		All(ctx)

	if err != nil {
		return nil, err
	}

	users := make([]*ent.User, 0, len(memberships))
	for _, membership := range memberships {
		if membership.Edges.User != nil {
			users = append(users, membership.Edges.User)
		}
	}

	return users, nil
}

// GetUserOrganizations returns all organizations a user belongs to
func (mq *MembershipQueries) GetUserOrganizations(ctx context.Context, userID xid.ID) ([]*ent.Organization, error) {
	// Query organizations through memberships
	memberships, err := mq.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.StatusEQ("active"),
		).
		WithOrganization().
		All(ctx)

	if err != nil {
		return nil, err
	}

	orgs := make([]*ent.Organization, 0, len(memberships))
	for _, membership := range memberships {
		if membership.Edges.Organization != nil {
			orgs = append(orgs, membership.Edges.Organization)
		}
	}

	return orgs, nil
}

// GetOrganizationUsersWithRoles returns users with their roles in an organization
func (mq *MembershipQueries) GetOrganizationUsersWithRoles(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error) {
	return mq.client.DB.Membership.Query().
		Where(
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
		).
		WithUser().
		WithRole().
		All(ctx)
}

// GetUserMembershipsWithDetails returns user's memberships with full details
func (mq *MembershipQueries) GetUserMembershipsWithDetails(ctx context.Context, userID xid.ID) ([]*ent.Membership, error) {
	return mq.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.StatusEQ("active"),
		).
		WithOrganization().
		WithRole().
		All(ctx)
}

// IsUserInOrganization checks if a user is an active member of an organization
func (mq *MembershipQueries) IsUserInOrganization(ctx context.Context, userID xid.ID, orgID xid.ID) (bool, error) {
	count, err := mq.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
		).
		Count(ctx)

	return count > 0, err
}

// GetUserRoleInOrganization returns the user's role in a specific organization
func (mq *MembershipQueries) GetUserRoleInOrganization(ctx context.Context, userID xid.ID, orgID xid.ID) (*ent.Role, error) {
	membership, err := mq.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
		).
		WithRole().
		Only(ctx)

	if err != nil {
		return nil, err
	}

	return membership.Edges.Role, nil
}

// GetOrganizationMemberCount returns the number of active members in an organization
func (mq *MembershipQueries) GetOrganizationMemberCount(ctx context.Context, orgID xid.ID) (int, error) {
	return mq.client.DB.Membership.Query().
		Where(
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
		).
		Count(ctx)
}

// GetOrganizationAdmins returns all users with admin or owner roles in an organization
func (mq *MembershipQueries) GetOrganizationAdmins(ctx context.Context, orgID xid.ID) ([]*ent.User, error) {
	memberships, err := mq.client.DB.Membership.Query().
		Where(
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
			entMembership.HasRoleWith(
				// Assuming you have role names - adjust based on your role setup
				entRole.NameIn("owner", "admin"),
			),
		).
		WithUser().
		All(ctx)

	if err != nil {
		return nil, err
	}

	admins := make([]*ent.User, 0, len(memberships))
	for _, membership := range memberships {
		if membership.Edges.User != nil {
			admins = append(admins, membership.Edges.User)
		}
	}

	return admins, nil
}

// GetUsersByRole returns all users with a specific role in an organization
func (mq *MembershipQueries) GetUsersByRole(ctx context.Context, orgID xid.ID, roleName string) ([]*ent.User, error) {
	memberships, err := mq.client.DB.Membership.Query().
		Where(
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
			entMembership.HasRoleWith(
				entRole.Name(roleName),
			),
		).
		WithUser().
		All(ctx)

	if err != nil {
		return nil, err
	}

	users := make([]*ent.User, 0, len(memberships))
	for _, membership := range memberships {
		if membership.Edges.User != nil {
			users = append(users, membership.Edges.User)
		}
	}

	return users, nil
}

// GetInviterForMembership returns the user who invited someone (if any)
func (mq *MembershipQueries) GetInviterForMembership(ctx context.Context, membershipID xid.ID) (*ent.User, error) {
	membership, err := mq.client.DB.Membership.Get(ctx, membershipID)
	if err != nil {
		return nil, err
	}

	if membership.InvitedBy.IsNil() {
		return nil, nil // No inviter (e.g., organization owner)
	}

	return mq.client.DB.User.Get(ctx, membership.InvitedBy)
}

// GetMembershipHistory returns all memberships (including inactive) for audit purposes
func (mq *MembershipQueries) GetMembershipHistory(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Membership, error) {
	return mq.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.OrganizationID(orgID),
		).
		WithRole().
		Order(ent.Desc(entMembership.FieldCreatedAt)).
		All(ctx)
}
