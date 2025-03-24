package organization

import (
	"context"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/ent/role"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/utils"
)

// MembershipManager manages organization memberships
type MembershipManager struct {
	client *ent.Client
}

// MembershipRole represents a role for a member
type MembershipRole struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	System      bool   `json:"system"`
}

// Membership represents a user's membership in an organization
type Membership struct {
	OrganizationID   string           `json:"organization_id"`
	OrganizationName string           `json:"organization_name"`
	OrganizationSlug string           `json:"organization_slug"`
	UserID           string           `json:"user_id"`
	Roles            []MembershipRole `json:"roles"`
	JoinedAt         time.Time        `json:"joined_at"`
	IsPrimary        bool             `json:"is_primary"`
}

// MembershipInvite represents an invitation to join an organization
type MembershipInvite struct {
	ID             string    `json:"id"`
	Email          string    `json:"email"`
	OrganizationID string    `json:"organization_id"`
	InviterID      string    `json:"inviter_id"`
	Roles          []string  `json:"roles"`
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
}

// NewMembershipManager creates a new membership manager
func NewMembershipManager(client *ent.Client) *MembershipManager {
	return &MembershipManager{
		client: client,
	}
}

// GetUserMemberships gets all organizations that a user is a member of
func (m *MembershipManager) GetUserMemberships(ctx context.Context, userID string) ([]Membership, error) {
	// Check if user exists
	userExists, err := m.client.User.
		Query().
		Where(user.ID(userID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !userExists {
		return nil, errors.New(errors.CodeNotFound, "user not found")
	}

	// Get user details including primary organization
	userDetails, err := m.client.User.
		Query().
		Where(user.ID(userID)).
		Only(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get user details")
	}

	// Get organizations user is a member of
	userOrgs, err := m.client.Organization.
		Query().
		Where(organization.HasUsersWith(user.ID(userID))).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query user organizations")
	}

	// Build membership results
	var memberships []Membership
	for _, org := range userOrgs {
		// Get user's roles in this organization
		userRoles, err := m.client.Role.
			Query().
			Where(
				role.HasUsersWith(user.ID(userID)),
				role.OrganizationIDEQ(org.ID),
			).
			All(ctx)

		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query user roles")
		}

		// Map roles to membership roles
		roles := make([]MembershipRole, len(userRoles))
		for i, r := range userRoles {
			roles[i] = MembershipRole{
				ID:          r.ID,
				Name:        r.Name,
				Description: r.Description,
				System:      r.System,
			}
		}

		// Get when user joined the organization
		// This is approximated by the earliest created role
		joinedAt := time.Now()
		if len(userRoles) > 0 {
			for _, r := range userRoles {
				if r.CreatedAt.Before(joinedAt) {
					joinedAt = r.CreatedAt
				}
			}
		}

		memberships = append(memberships, Membership{
			OrganizationID:   org.ID,
			OrganizationName: org.Name,
			OrganizationSlug: org.Slug,
			UserID:           userID,
			Roles:            roles,
			JoinedAt:         joinedAt,
			IsPrimary:        org.ID == userDetails.PrimaryOrganizationID,
		})
	}

	return memberships, nil
}

// SetPrimaryOrganization sets a user's primary organization
func (m *MembershipManager) SetPrimaryOrganization(ctx context.Context, userID, orgID string) error {
	// Check if user exists
	userExists, err := m.client.User.
		Query().
		Where(user.ID(userID)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !userExists {
		return errors.New(errors.CodeNotFound, "user not found")
	}

	// Check if organization exists
	orgExists, err := m.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !orgExists {
		return errors.New(errors.CodeNotFound, "organization not found")
	}

	// Check if user is a member of the organization
	isMember, err := m.client.User.
		Query().
		Where(
			user.ID(userID),
			user.HasOrganizationsWith(organization.ID(orgID)),
		).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check membership")
	}

	if !isMember {
		return errors.New(errors.CodeForbidden, "user is not a member of this organization")
	}

	// Set primary organization
	err = m.client.User.
		UpdateOneID(userID).
		SetPrimaryOrganizationID(orgID).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to set primary organization")
	}

	return nil
}

// CreateInvite creates a new invitation to join an organization
func (m *MembershipManager) CreateInvite(ctx context.Context, orgID, inviterID, email string, roles []string, expiresIn time.Duration) (*MembershipInvite, error) {
	// Check if organization exists
	orgExists, err := m.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !orgExists {
		return nil, errors.New(errors.CodeNotFound, "organization not found")
	}

	// Check if inviter exists and is a member of the organization
	inviterIsMember, err := m.client.User.
		Query().
		Where(
			user.ID(inviterID),
			user.HasOrganizationsWith(organization.ID(orgID)),
		).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check inviter membership")
	}

	if !inviterIsMember {
		return nil, errors.New(errors.CodeForbidden, "inviter is not a member of this organization")
	}

	// Check if email already exists in the organization
	emailExists, err := m.client.User.
		Query().
		Where(
			user.Email(email),
			user.HasOrganizationsWith(organization.ID(orgID)),
		).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check email existence")
	}

	if emailExists {
		return nil, errors.New(errors.CodeConflict, "user with this email is already a member of the organization")
	}

	// Generate ID for invite
	id := utils.NewID()

	// Set expiration time
	expiresAt := time.Now().Add(expiresIn)

	// Create invite object (this would typically be stored in the database)
	// For this example, we're not implementing the full invite storage
	invite := &MembershipInvite{
		ID:             id.String(),
		Email:          email,
		OrganizationID: orgID,
		InviterID:      inviterID,
		Roles:          roles,
		ExpiresAt:      expiresAt,
		CreatedAt:      time.Now(),
	}

	// In a real implementation, we would store the invite in the database
	// and send an email to the invitee

	return invite, nil
}

// GetOrganizationMembers gets all members of an organization with their roles
func (m *MembershipManager) GetOrganizationMembers(ctx context.Context, orgID string, offset, limit int) ([]*ent.User, int, error) {
	// Check if organization exists
	orgExists, err := m.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !orgExists {
		return nil, 0, errors.New(errors.CodeNotFound, "organization not found")
	}

	// Query users in the organization
	query := m.client.User.
		Query().
		Where(user.HasOrganizationsWith(organization.ID(orgID)))

	// Count total members
	count, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to count organization members")
	}

	// Apply pagination and fetch users with roles
	users, err := query.
		Limit(limit).
		Offset(offset).
		WithRoles(func(q *ent.RoleQuery) {
			q.Where(role.OrganizationIDEQ(orgID))
		}).
		All(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to query organization members")
	}

	return users, count, nil
}

// GetOrganizationRoles gets all roles defined for an organization
func (m *MembershipManager) GetOrganizationRoles(ctx context.Context, orgID string) ([]*ent.Role, error) {
	// Check if organization exists
	orgExists, err := m.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !orgExists {
		return nil, errors.New(errors.CodeNotFound, "organization not found")
	}

	// Get roles for organization
	roles, err := m.client.Role.
		Query().
		Where(role.OrganizationIDEQ(orgID)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query organization roles")
	}

	return roles, nil
}

// EnsureDefaultRoles ensures that default roles exist for an organization
func (m *MembershipManager) EnsureDefaultRoles(ctx context.Context, orgID string) error {
	// Check if organization exists
	orgExists, err := m.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !orgExists {
		return errors.New(errors.CodeNotFound, "organization not found")
	}

	// Define default roles
	defaultRoles := []struct {
		Name        string
		Description string
	}{
		{
			Name:        "owner",
			Description: "Organization owner with full access",
		},
		{
			Name:        "admin",
			Description: "Administrator with management capabilities",
		},
		{
			Name:        "member",
			Description: "Regular organization member",
		},
	}

	// Begin transaction
	tx, err := m.client.Tx(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to start transaction")
	}

	// Create default roles if they don't exist
	for _, r := range defaultRoles {
		exists, err := tx.Role.
			Query().
			Where(
				role.Name(r.Name),
				role.OrganizationIDEQ(orgID),
			).
			Exist(ctx)

		if err != nil {
			_ = tx.Rollback()
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to check role existence")
		}

		if !exists {
			// Generate ID for the role
			id := utils.NewID()

			// Create the role
			_, err = tx.Role.
				Create().
				SetID(id.String()).
				SetName(r.Name).
				SetDescription(r.Description).
				SetOrganizationID(orgID).
				SetSystem(true).
				Save(ctx)

			if err != nil {
				_ = tx.Rollback()
				return errors.Wrap(errors.CodeDatabaseError, err, "failed to create role")
			}
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to commit transaction")
	}

	return nil
}
