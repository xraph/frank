package authz

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/juicycleff/frank/ent"
	entMembership "github.com/juicycleff/frank/ent/membership"
	entOrganization "github.com/juicycleff/frank/ent/organization"
	entRole "github.com/juicycleff/frank/ent/role"
	entUser "github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

// MembershipService handles organization membership operations
type MembershipService struct {
	client *data.Clients
}

// NewMembershipService creates a new membership service
func NewMembershipService(client *data.Clients) *MembershipService {
	return &MembershipService{
		client: client,
	}
}

// InviteUserRequest represents a request to invite a user to an organization
type InviteUserRequest struct {
	Email          string    `json:"email"`
	RoleName       string    `json:"role_name"`
	InvitedByID    xid.ID    `json:"invited_by_id"`
	OrganizationID xid.ID    `json:"organization_id"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
}

// InviteUser invites a user to join an organization
func (ms *MembershipService) InviteUser(ctx context.Context, req InviteUserRequest) (*ent.Membership, error) {
	// Set default expiration if not provided
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = time.Now().Add(7 * 24 * time.Hour) // 7 days
	}

	// Check if organization exists and is active
	org, err := ms.client.DB.Organization.Query().
		Where(
			entOrganization.IDEQ(req.OrganizationID),
			entOrganization.Active(true),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeResourceNotFound, "organization not found")
		}
		return nil, err
	}

	// Check member limit
	activeMembers, err := ms.client.DB.Membership.Query().
		Where(
			entMembership.OrganizationID(req.OrganizationID),
			entMembership.StatusEQ("active"),
		).
		Count(ctx)
	if err != nil {
		return nil, err
	}

	if activeMembers >= org.ExternalUserLimit {
		return nil, errors.New(errors.CodeLimitExceeded, "organization member limit reached")
	}

	// Find or create user
	user, err := ms.findOrCreateUser(ctx, req.Email)
	if err != nil {
		return nil, err
	}

	// Check if user is already a member
	existingMembership, err := ms.client.DB.Membership.Query().
		Where(
			entMembership.UserID(user.ID),
			entMembership.OrganizationID(req.OrganizationID),
			entMembership.StatusIn(entMembership.StatusPending, entMembership.StatusActive),
		).
		Only(ctx)
	if err == nil {
		// User already has a membership
		if existingMembership.Status == "active" {
			return nil, errors.New(errors.CodeConflict, "user is already a member")
		}
		// Update existing pending invitation
		return ms.updatePendingInvitation(ctx, existingMembership, req)
	}
	if !ent.IsNotFound(err) {
		return nil, err
	}

	// Get role
	role, err := ms.client.DB.Role.Query().
		Where(
			entRole.Name(req.RoleName),
			entRole.OrganizationID(req.OrganizationID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeResourceNotFound, "role not found")
		}
		return nil, err
	}

	// Generate invitation token
	token, err := generateInvitationToken()
	if err != nil {
		return nil, err
	}

	// Create membership
	membership, err := ms.client.DB.Membership.Create().
		SetUserID(user.ID).
		SetOrganizationID(req.OrganizationID).
		SetRoleID(role.ID).
		SetStatus("pending").
		SetInvitedBy(req.InvitedByID).
		SetInvitedAt(time.Now()).
		SetExpiresAt(req.ExpiresAt).
		SetInvitationToken(token).
		Save(ctx)

	if err != nil {
		return nil, err
	}

	return membership, nil
}

// AcceptInvitation accepts a pending invitation
func (ms *MembershipService) AcceptInvitation(ctx context.Context, token string, userID xid.ID) (*ent.Membership, error) {
	// Find pending membership by token
	membership, err := ms.client.DB.Membership.Query().
		Where(
			entMembership.InvitationToken(token),
			entMembership.StatusEQ("pending"),
			entMembership.ExpiresAtGT(time.Now()),
		).
		WithOrganization().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeResourceNotFound, "invalid or expired invitation")
		}
		return nil, err
	}

	// Verify the user ID matches
	if membership.UserID != userID {
		return nil, errors.New(errors.CodeForbidden, "invitation is for a different user")
	}

	// Check organization is still active
	if !membership.Edges.Organization.Active {
		return nil, errors.New(errors.CodeConflict, "organization is not active")
	}

	// Check member limit again
	activeMembers, err := ms.client.DB.Membership.Query().
		Where(
			entMembership.OrganizationID(membership.OrganizationID),
			entMembership.StatusEQ("active"),
		).
		Count(ctx)
	if err != nil {
		return nil, err
	}

	if activeMembers >= membership.Edges.Organization.EndUserLimit {
		return nil, errors.New(errors.CodeLimitExceeded, "organization member limit reached")
	}

	// Accept the invitation
	membership, err = membership.Update().
		SetStatus("active").
		SetJoinedAt(time.Now()).
		ClearInvitationToken().
		Save(ctx)

	if err != nil {
		return nil, err
	}

	return membership, nil
}

// RemoveMember removes a user from an organization
func (ms *MembershipService) RemoveMember(ctx context.Context, orgID xid.ID, userID xid.ID) error {
	// Find active membership
	membership, err := ms.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeResourceNotFound, "membership not found")
		}
		return err
	}

	// Check if user is the organization owner
	org, err := ms.client.DB.Organization.Get(ctx, orgID)
	if err != nil {
		return err
	}

	if org.OwnerID.IsNil() && org.OwnerID == userID {
		return errors.New(errors.CodeConflict, "cannot remove organization owner")
	}

	// Remove membership
	return ms.client.DB.Membership.DeleteOne(membership).Exec(ctx)
}

// UpdateMemberRole updates a member's role in an organization
func (ms *MembershipService) UpdateMemberRole(ctx context.Context, orgID xid.ID, userID xid.ID, newRoleName string) (*ent.Membership, error) {
	// Find active membership
	membership, err := ms.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("active"),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeResourceNotFound, "membership not found")
		}
		return nil, err
	}

	// Find new role
	newRole, err := ms.client.DB.Role.Query().
		Where(
			entRole.Name(newRoleName),
			entRole.OrganizationID(orgID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeResourceNotFound, "role not found")
		}
		return nil, err
	}

	// Update membership
	membership, err = membership.Update().
		SetRoleID(newRole.ID).
		Save(ctx)

	if err != nil {
		return nil, err
	}

	return membership, nil
}

// GetPendingInvitations returns all pending invitations for an organization
func (ms *MembershipService) GetPendingInvitations(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error) {
	return ms.client.DB.Membership.Query().
		Where(
			entMembership.OrganizationID(orgID),
			entMembership.StatusEQ("pending"),
			entMembership.ExpiresAtGT(time.Now()),
		).
		WithUser().
		WithRole().
		All(ctx)
}

// GetUserMemberships returns all active memberships for a user
func (ms *MembershipService) GetUserMemberships(ctx context.Context, userID xid.ID) ([]*ent.Membership, error) {
	return ms.client.DB.Membership.Query().
		Where(
			entMembership.UserID(userID),
			entMembership.StatusEQ("active"),
		).
		WithOrganization().
		WithRole().
		All(ctx)
}

// RevokeInvitation revokes a pending invitation
func (ms *MembershipService) RevokeInvitation(ctx context.Context, token string) error {
	membership, err := ms.client.DB.Membership.Query().
		Where(
			entMembership.InvitationToken(token),
			entMembership.StatusEQ("pending"),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeResourceNotFound, "invitation not found")
		}
		return err
	}

	return ms.client.DB.Membership.DeleteOne(membership).Exec(ctx)
}

// CleanupExpiredInvitations removes expired invitations
func (ms *MembershipService) CleanupExpiredInvitations(ctx context.Context) (int, error) {
	return ms.client.DB.Membership.Delete().
		Where(
			entMembership.StatusEQ("pending"),
			entMembership.ExpiresAtLT(time.Now()),
		).
		Exec(ctx)
}

// Helper functions

func (ms *MembershipService) findOrCreateUser(ctx context.Context, email string) (*ent.User, error) {
	// Try to find existing user
	user, err := ms.client.DB.User.Query().
		Where(entUser.Email(email)).
		Only(ctx)
	if err == nil {
		return user, nil
	}
	if !ent.IsNotFound(err) {
		return nil, err
	}

	// Create new user
	user, err = ms.client.DB.User.Create().
		SetEmail(email).
		SetActive(false). // User is inactive until they accept invitation
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (ms *MembershipService) updatePendingInvitation(ctx context.Context, membership *ent.Membership, req InviteUserRequest) (*ent.Membership, error) {
	// Get new role
	role, err := ms.client.DB.Role.Query().
		Where(
			entRole.Name(req.RoleName),
			entRole.OrganizationID(req.OrganizationID),
		).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	// Generate new token
	token, err := generateInvitationToken()
	if err != nil {
		return nil, err
	}

	// Update existing invitation
	return membership.Update().
		SetRoleID(role.ID).
		SetInvitedBy(req.InvitedByID).
		SetInvitedAt(time.Now()).
		SetExpiresAt(req.ExpiresAt).
		SetInvitationToken(token).
		Save(ctx)
}

func generateInvitationToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
