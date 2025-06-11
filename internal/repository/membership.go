package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/membership"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// MembershipRepository defines the interface for membership data access
type MembershipRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateMembershipInput) (*ent.Membership, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Membership, error)
	GetByUserAndOrganization(ctx context.Context, userID, organizationID xid.ID) (*ent.Membership, error)
	GetByInvitationToken(ctx context.Context, token string) (*ent.Membership, error)
	Update(ctx context.Context, id xid.ID, input UpdateMembershipInput) (*ent.Membership, error)
	Delete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params ListMembershipsParams) (*model.PaginatedOutput[*ent.Membership], error)
	ListByUser(ctx context.Context, userID xid.ID, params ListMembershipsParams) (*model.PaginatedOutput[*ent.Membership], error)
	ListByOrganization(ctx context.Context, organizationID xid.ID, params ListMembershipsParams) (*model.PaginatedOutput[*ent.Membership], error)
	// ListByStatus(ctx context.Context, status string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Membership], error)
	ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error)
	ListPendingByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error)

	// // Role-based queries
	// ListByRole(ctx context.Context, role string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Membership], error)
	// ListAdminsByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error)
	// ListOwnersByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error)
	// GetUserRoleInOrganization(ctx context.Context, userID, orgID xid.ID) (string, error)

	// Invitation management
	CreateInvitation(ctx context.Context, input CreateInvitationInput) (*ent.Membership, error)
	AcceptInvitation(ctx context.Context, token string, acceptedBy xid.ID) (*ent.Membership, error)
	DeclineInvitation(ctx context.Context, token string) error
	ResendInvitation(ctx context.Context, id xid.ID, newToken string, expiresAt time.Time) (*ent.Membership, error)
	GetPendingInvitations(ctx context.Context, organizationID xid.ID) ([]*ent.Membership, error)
	GetExpiredInvitations(ctx context.Context) ([]*ent.Membership, error)
	CleanupExpiredInvitations(ctx context.Context) (int, error)

	// Status management
	Activate(ctx context.Context, id xid.ID) error
	Deactivate(ctx context.Context, id xid.ID) error
	Suspend(ctx context.Context, id xid.ID) error
	UpdateStatus(ctx context.Context, id xid.ID, status membership.Status) error

	// Role management
	UpdateRole(ctx context.Context, id xid.ID, roleID xid.ID) error
	GetMembershipsWithRole(ctx context.Context, organizationID, roleID xid.ID) ([]*ent.Membership, error)

	// Member management
	GetActiveMembers(ctx context.Context, organizationID xid.ID) ([]*ent.Membership, error)
	GetMemberCount(ctx context.Context, organizationID xid.ID, status *membership.Status) (int, error)
	GetBillingContacts(ctx context.Context, organizationID xid.ID) ([]*ent.Membership, error)
	GetPrimaryContact(ctx context.Context, organizationID xid.ID) (*ent.Membership, error)
	SetPrimaryContact(ctx context.Context, id xid.ID) error
	AddBillingContact(ctx context.Context, id xid.ID) error
	RemoveBillingContact(ctx context.Context, id xid.ID) error

	// Analytics and reporting
	GetMembershipStats(ctx context.Context, organizationID xid.ID) (*MembershipStats, error)
	GetRecentJoins(ctx context.Context, organizationID xid.ID, days int) ([]*ent.Membership, error)
	GetInvitationStats(ctx context.Context, organizationID xid.ID, days int) (*InvitationStats, error)

	// Existence checks
	ExistsByUserAndOrganization(ctx context.Context, userID, organizationID xid.ID) (bool, error)
	HasActiveMembership(ctx context.Context, userID, organizationID xid.ID) (bool, error)
}

// CreateMembershipInput represents input for creating a membership
type CreateMembershipInput struct {
	UserID           xid.ID                 `json:"user_id"`
	OrganizationID   xid.ID                 `json:"organization_id"`
	RoleID           xid.ID                 `json:"role_id"`
	Status           membership.Status      `json:"status"`
	InvitedBy        *xid.ID                `json:"invited_by,omitempty"`
	InvitedAt        time.Time              `json:"invited_at"`
	JoinedAt         *time.Time             `json:"joined_at,omitempty"`
	ExpiresAt        *time.Time             `json:"expires_at,omitempty"`
	InvitationToken  *string                `json:"invitation_token,omitempty"`
	IsBillingContact bool                   `json:"is_billing_contact"`
	IsPrimaryContact bool                   `json:"is_primary_contact"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CustomFields     map[string]interface{} `json:"customFields,omitempty"`
}

// CreateInvitationInput represents input for creating an invitation
type CreateInvitationInput struct {
	UserID           xid.ID                 `json:"user_id"`
	OrganizationID   xid.ID                 `json:"organization_id"`
	Token            *string                `json:"token,omitempty"`
	Status           membership.Status      `json:"status"`
	Email            string                 `json:"email"`
	RoleID           xid.ID                 `json:"role_id"`
	InvitedBy        xid.ID                 `json:"invited_by"`
	InvitationToken  string                 `json:"invitation_token"`
	ExpiresAt        time.Time              `json:"expires_at"`
	IsBillingContact bool                   `json:"is_billing_contact"`
	IsPrimaryContact bool                   `json:"is_primary_contact"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CustomFields     map[string]interface{} `json:"customFields,omitempty"`
	Message          string                 `json:"message,omitempty"`
	RedirectURL      string                 `json:"redirect_url,omitempty"`
}

// UpdateMembershipInput represents input for updating a membership
type UpdateMembershipInput struct {
	RoleID           *xid.ID                `json:"role_id,omitempty"`
	Status           *membership.Status     `json:"status,omitempty"`
	JoinedAt         *time.Time             `json:"joined_at,omitempty"`
	ExpiresAt        *time.Time             `json:"expires_at,omitempty"`
	IsBillingContact *bool                  `json:"is_billing_contact,omitempty"`
	IsPrimaryContact *bool                  `json:"is_primary_contact,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// ListMembershipsParams represents parameters for listing memberships
type ListMembershipsParams struct {
	model.PaginationParams
	OrganizationID   *xid.ID            `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization"`
	Status           *membership.Status `json:"status,omitempty"`
	RoleID           *xid.ID            `json:"role_id,omitempty"`
	IsBillingContact *bool              `json:"is_billing_contact,omitempty"`
	IsPrimaryContact *bool              `json:"is_primary_contact,omitempty"`
	InvitedBy        *xid.ID            `json:"invited_by,omitempty"`
	Search           string             `json:"search,omitempty" example:"john" doc:"Search in user name/email"`
}

// MembershipStats represents membership statistics for an organization
type MembershipStats struct {
	TotalMembers     int                       `json:"total_members"`
	ActiveMembers    int                       `json:"active_members"`
	PendingMembers   int                       `json:"pending_members"`
	InactiveMembers  int                       `json:"inactive_members"`
	SuspendedMembers int                       `json:"suspended_members"`
	StatusBreakdown  map[membership.Status]int `json:"status_breakdown"`
	RecentJoins      int                       `json:"recent_joins"`   // Last 30 days
	RecentInvites    int                       `json:"recent_invites"` // Last 30 days
}

// InvitationStats represents invitation statistics
type InvitationStats struct {
	TotalInvites    int     `json:"total_invites"`
	AcceptedInvites int     `json:"accepted_invites"`
	PendingInvites  int     `json:"pending_invites"`
	ExpiredInvites  int     `json:"expired_invites"`
	AcceptanceRate  float64 `json:"acceptance_rate"`
}

// membershipRepository implements MembershipRepository
type membershipRepository struct {
	client *ent.Client
	logger logging.Logger
}

// NewMembershipRepository creates a new membership repository
func NewMembershipRepository(client *ent.Client, logger logging.Logger) MembershipRepository {
	return &membershipRepository{
		client: client,
		logger: logger,
	}
}

// Create creates a new membership
func (r *membershipRepository) Create(ctx context.Context, input CreateMembershipInput) (*ent.Membership, error) {
	create := r.client.Membership.Create().
		SetUserID(input.UserID).
		SetOrganizationID(input.OrganizationID).
		SetRoleID(input.RoleID).
		SetStatus(input.Status).
		SetInvitedAt(input.InvitedAt).
		SetIsBillingContact(input.IsBillingContact).
		SetIsPrimaryContact(input.IsPrimaryContact)

	// Set optional fields
	if input.InvitedBy != nil {
		create.SetInvitedBy(*input.InvitedBy)
	}
	if input.JoinedAt != nil {
		create.SetJoinedAt(*input.JoinedAt)
	}
	if input.ExpiresAt != nil {
		create.SetExpiresAt(*input.ExpiresAt)
	}
	if input.InvitationToken != nil {
		create.SetInvitationToken(*input.InvitationToken)
	}
	if input.Metadata != nil {
		create.SetMetadata(input.Metadata)
	}

	membership, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "Membership already exists for this user and organization")
		}
		return nil, fmt.Errorf("failed to create membership: %w", err)
	}

	return membership, nil
}

// GetByID retrieves a membership by ID
func (r *membershipRepository) GetByID(ctx context.Context, id xid.ID) (*ent.Membership, error) {
	membership, err := r.client.Membership.Query().
		Where(membership.ID(id)).
		WithUser().
		WithOrganization().
		WithRole().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Membership not found")
		}
		return nil, fmt.Errorf("failed to get membership by ID: %w", err)
	}
	return membership, nil
}

// GetByUserAndOrganization retrieves a membership by user and organization
func (r *membershipRepository) GetByUserAndOrganization(ctx context.Context, userID, organizationID xid.ID) (*ent.Membership, error) {
	membership, err := r.client.Membership.Query().
		Where(
			membership.UserID(userID),
			membership.OrganizationID(organizationID),
		).
		WithUser().
		WithOrganization().
		WithRole().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Membership not found")
		}
		return nil, fmt.Errorf("failed to get membership by user and organization: %w", err)
	}
	return membership, nil
}

// GetByInvitationToken retrieves a membership by invitation token
func (r *membershipRepository) GetByInvitationToken(ctx context.Context, token string) (*ent.Membership, error) {
	membership, err := r.client.Membership.Query().
		Where(membership.InvitationToken(token)).
		WithUser().
		WithOrganization().
		WithRole().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Invalid invitation token")
		}
		return nil, fmt.Errorf("failed to get membership by invitation token: %w", err)
	}
	return membership, nil
}

// Update updates a membership
func (r *membershipRepository) Update(ctx context.Context, id xid.ID, input UpdateMembershipInput) (*ent.Membership, error) {
	update := r.client.Membership.UpdateOneID(id)

	if input.RoleID != nil {
		update.SetRoleID(*input.RoleID)
	}
	if input.Status != nil {
		update.SetStatus(*input.Status)
	}
	if input.JoinedAt != nil {
		update.SetJoinedAt(*input.JoinedAt)
	}
	if input.ExpiresAt != nil {
		update.SetExpiresAt(*input.ExpiresAt)
	}
	if input.IsBillingContact != nil {
		update.SetIsBillingContact(*input.IsBillingContact)
	}
	if input.IsPrimaryContact != nil {
		update.SetIsPrimaryContact(*input.IsPrimaryContact)
	}
	if input.Metadata != nil {
		update.SetMetadata(input.Metadata)
	}

	membership, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Membership not found")
		}
		return nil, fmt.Errorf("failed to update membership: %w", err)
	}
	return membership, nil
}

// Delete deletes a membership
func (r *membershipRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.Membership.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Membership not found")
		}
		return fmt.Errorf("failed to delete membership: %w", err)
	}
	return nil
}

// List retrieves memberships with pagination and filtering
func (r *membershipRepository) List(ctx context.Context, params ListMembershipsParams) (*model.PaginatedOutput[*ent.Membership], error) {
	query := r.client.Membership.Query().
		WithUser().
		WithOrganization().
		WithRole()

	// Apply filters
	if params.Status != nil {
		query = query.Where(membership.StatusEQ(*params.Status))
	}
	if params.RoleID != nil {
		query = query.Where(membership.RoleID(*params.RoleID))
	}
	if params.IsBillingContact != nil {
		query = query.Where(membership.IsBillingContact(*params.IsBillingContact))
	}
	if params.IsPrimaryContact != nil {
		query = query.Where(membership.IsPrimaryContact(*params.IsPrimaryContact))
	}
	if params.InvitedBy != nil {
		query = query.Where(membership.InvitedBy(*params.InvitedBy))
	}

	// Apply pagination
	return model.WithPaginationAndOptions[*ent.Membership, *ent.MembershipQuery](ctx, query, params.PaginationParams)
}

// ListByUser retrieves memberships for a specific user
func (r *membershipRepository) ListByUser(ctx context.Context, userID xid.ID, params ListMembershipsParams) (*model.PaginatedOutput[*ent.Membership], error) {
	query := r.client.Membership.Query().
		Where(membership.UserID(userID)).
		WithUser().
		WithOrganization().
		WithRole()

	// Apply filters
	if params.Status != nil {
		query = query.Where(membership.StatusEQ(*params.Status))
	}
	if params.RoleID != nil {
		query = query.Where(membership.RoleID(*params.RoleID))
	}

	return model.WithPaginationAndOptions[*ent.Membership, *ent.MembershipQuery](ctx, query, params.PaginationParams)
}

// ListByOrganization retrieves memberships for a specific organization
func (r *membershipRepository) ListByOrganization(ctx context.Context, organizationID xid.ID, params ListMembershipsParams) (*model.PaginatedOutput[*ent.Membership], error) {
	query := r.client.Membership.Query().
		Where(membership.OrganizationID(organizationID)).
		WithUser().
		WithOrganization().
		WithRole()

	// Apply filters
	if params.Status != nil {
		query = query.Where(membership.StatusEQ(*params.Status))
	}
	if params.RoleID != nil {
		query = query.Where(membership.RoleID(*params.RoleID))
	}
	if params.InvitedBy != nil {
		query = query.Where(membership.InvitedBy(*params.InvitedBy))
	}

	return model.WithPaginationAndOptions[*ent.Membership, *ent.MembershipQuery](ctx, query, params.PaginationParams)
}

// ListActiveByOrganizationID retrieves all active memberships for an organization
func (r *membershipRepository) ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error) {
	memberships, err := r.client.Membership.
		Query().
		Where(
			membership.OrganizationID(orgID),
			membership.StatusEQ(membership.StatusActive),
		).
		WithUser().
		WithOrganization().
		WithInviter().
		Order(ent.Desc(membership.FieldJoinedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list active memberships")
	}

	return memberships, nil
}

// ListPendingByOrganizationID retrieves all pending memberships for an organization
func (r *membershipRepository) ListPendingByOrganizationID(ctx context.Context, orgID xid.ID) ([]*ent.Membership, error) {
	memberships, err := r.client.Membership.
		Query().
		Where(
			membership.OrganizationID(orgID),
			membership.StatusEQ(membership.StatusPending),
		).
		WithUser().
		WithOrganization().
		WithInviter().
		Order(ent.Desc(membership.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list pending memberships")
	}

	return memberships, nil
}

// Invitation management methods

func (r *membershipRepository) CreateInvitation(ctx context.Context, input CreateInvitationInput) (*ent.Membership, error) {
	membership, err := r.Create(ctx, CreateMembershipInput{
		UserID:           input.UserID,
		OrganizationID:   input.OrganizationID,
		RoleID:           input.RoleID,
		Status:           membership.StatusPending,
		InvitedBy:        &input.InvitedBy,
		InvitedAt:        time.Now(),
		ExpiresAt:        &input.ExpiresAt,
		InvitationToken:  &input.InvitationToken,
		IsBillingContact: input.IsBillingContact,
		IsPrimaryContact: input.IsPrimaryContact,
		Metadata:         input.Metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}
	return membership, nil
}

func (r *membershipRepository) AcceptInvitation(ctx context.Context, token string, acceptedBy xid.ID) (*ent.Membership, error) {
	// First, get the membership by token
	member, err := r.GetByInvitationToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Check if invitation is still valid
	if member.ExpiresAt != nil && time.Now().After(*member.ExpiresAt) {
		return nil, errors.New(errors.CodeBadRequest, "Invitation has expired")
	}

	if member.Status != membership.StatusPending {
		return nil, errors.New(errors.CodeBadRequest, "Invitation has already been processed")
	}

	// Accept the invitation
	status := membership.StatusActive
	now := time.Now()
	updated, err := r.Update(ctx, member.ID, UpdateMembershipInput{
		Status:   &status,
		JoinedAt: &now,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to accept invitation: %w", err)
	}

	return updated, nil
}

func (r *membershipRepository) DeclineInvitation(ctx context.Context, token string) error {
	member, err := r.GetByInvitationToken(ctx, token)
	if err != nil {
		return err
	}

	if member.Status != membership.StatusPending {
		return errors.New(errors.CodeBadRequest, "Invitation has already been processed")
	}

	// Delete the membership (decline invitation)
	return r.Delete(ctx, member.ID)
}

func (r *membershipRepository) ResendInvitation(ctx context.Context, id xid.ID, newToken string, expiresAt time.Time) (*ent.Membership, error) {
	updated, err := r.Update(ctx, id, UpdateMembershipInput{
		ExpiresAt: &expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to resend invitation: %w", err)
	}

	// Update the invitation token
	err = r.client.Membership.UpdateOneID(id).
		SetInvitationToken(newToken).
		Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update invitation token: %w", err)
	}

	return updated, nil
}

func (r *membershipRepository) GetPendingInvitations(ctx context.Context, organizationID xid.ID) ([]*ent.Membership, error) {
	memberships, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.StatusEQ(membership.StatusPending),
		).
		WithUser().
		WithRole().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending invitations: %w", err)
	}
	return memberships, nil
}

func (r *membershipRepository) GetExpiredInvitations(ctx context.Context) ([]*ent.Membership, error) {
	memberships, err := r.client.Membership.Query().
		Where(
			membership.StatusEQ(membership.StatusPending),
			membership.ExpiresAtLT(time.Now()),
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get expired invitations: %w", err)
	}
	return memberships, nil
}

func (r *membershipRepository) CleanupExpiredInvitations(ctx context.Context) (int, error) {
	deleted, err := r.client.Membership.Delete().
		Where(
			membership.StatusEQ(membership.StatusPending),
			membership.ExpiresAtLT(time.Now()),
		).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired invitations: %w", err)
	}
	return deleted, nil
}

// Status management methods

func (r *membershipRepository) Activate(ctx context.Context, id xid.ID) error {
	status := membership.StatusActive
	_, err := r.Update(ctx, id, UpdateMembershipInput{
		Status: &status,
	})
	return err
}

func (r *membershipRepository) Deactivate(ctx context.Context, id xid.ID) error {
	status := membership.StatusInactive
	_, err := r.Update(ctx, id, UpdateMembershipInput{
		Status: &status,
	})
	return err
}

func (r *membershipRepository) Suspend(ctx context.Context, id xid.ID) error {
	status := membership.StatusSuspended
	_, err := r.Update(ctx, id, UpdateMembershipInput{
		Status: &status,
	})
	return err
}

func (r *membershipRepository) UpdateStatus(ctx context.Context, id xid.ID, status membership.Status) error {
	_, err := r.Update(ctx, id, UpdateMembershipInput{
		Status: &status,
	})
	return err
}

// Role management methods

func (r *membershipRepository) UpdateRole(ctx context.Context, id xid.ID, roleID xid.ID) error {
	_, err := r.Update(ctx, id, UpdateMembershipInput{
		RoleID: &roleID,
	})
	return err
}

func (r *membershipRepository) GetMembershipsWithRole(ctx context.Context, organizationID, roleID xid.ID) ([]*ent.Membership, error) {
	memberships, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.RoleID(roleID),
		).
		WithUser().
		WithRole().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get memberships with role: %w", err)
	}
	return memberships, nil
}

// Member management methods

func (r *membershipRepository) GetActiveMembers(ctx context.Context, organizationID xid.ID) ([]*ent.Membership, error) {
	memberships, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.StatusEQ(membership.StatusActive),
		).
		WithUser().
		WithRole().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active members: %w", err)
	}
	return memberships, nil
}

func (r *membershipRepository) GetMemberCount(ctx context.Context, organizationID xid.ID, status *membership.Status) (int, error) {
	query := r.client.Membership.Query().
		Where(membership.OrganizationID(organizationID))

	if status != nil {
		query = query.Where(membership.StatusEQ(*status))
	}

	count, err := query.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get member count: %w", err)
	}
	return count, nil
}

func (r *membershipRepository) GetBillingContacts(ctx context.Context, organizationID xid.ID) ([]*ent.Membership, error) {
	memberships, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.IsBillingContact(true),
			membership.StatusEQ(membership.StatusActive),
		).
		WithUser().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get billing contacts: %w", err)
	}
	return memberships, nil
}

func (r *membershipRepository) GetPrimaryContact(ctx context.Context, organizationID xid.ID) (*ent.Membership, error) {
	membership, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.IsPrimaryContact(true),
			membership.StatusEQ(membership.StatusActive),
		).
		WithUser().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Primary contact not found")
		}
		return nil, fmt.Errorf("failed to get primary contact: %w", err)
	}
	return membership, nil
}

func (r *membershipRepository) SetPrimaryContact(ctx context.Context, id xid.ID) error {
	// Get the membership to find the organization
	member, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Start a transaction to ensure atomicity
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Remove primary contact status from all other members in the organization
	err = tx.Membership.Update().
		Where(
			membership.OrganizationID(member.OrganizationID),
			membership.IDNEQ(id),
		).
		SetIsPrimaryContact(false).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to clear other primary contacts: %w", err)
	}

	// Set this membership as primary contact
	err = tx.Membership.UpdateOneID(id).
		SetIsPrimaryContact(true).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to set primary contact: %w", err)
	}

	return tx.Commit()
}

func (r *membershipRepository) AddBillingContact(ctx context.Context, id xid.ID) error {
	isPrimary := true
	_, err := r.Update(ctx, id, UpdateMembershipInput{
		IsBillingContact: &isPrimary,
	})
	return err
}

func (r *membershipRepository) RemoveBillingContact(ctx context.Context, id xid.ID) error {
	isPrimary := false
	_, err := r.Update(ctx, id, UpdateMembershipInput{
		IsBillingContact: &isPrimary,
	})
	return err
}

// Analytics and reporting methods

func (r *membershipRepository) GetMembershipStats(ctx context.Context, organizationID xid.ID) (*MembershipStats, error) {
	// Get total count
	total, err := r.GetMemberCount(ctx, organizationID, nil)
	if err != nil {
		return nil, err
	}

	statsActive := membership.StatusActive
	statsPending := membership.StatusPending
	statsInactive := membership.StatusInactive
	statsSuspended := membership.StatusSuspended

	// Get count by status
	active, err := r.GetMemberCount(ctx, organizationID, &statsActive)
	if err != nil {
		return nil, err
	}

	pending, err := r.GetMemberCount(ctx, organizationID, &statsPending)
	if err != nil {
		return nil, err
	}

	inactive, err := r.GetMemberCount(ctx, organizationID, &statsInactive)
	if err != nil {
		return nil, err
	}

	suspended, err := r.GetMemberCount(ctx, organizationID, &statsSuspended)
	if err != nil {
		return nil, err
	}

	// Get recent joins (last 30 days)
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	recentJoins, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.JoinedAtGTE(thirtyDaysAgo),
		).
		Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent joins: %w", err)
	}

	// Get recent invites (last 30 days)
	recentInvites, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.InvitedAtGTE(thirtyDaysAgo),
		).
		Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent invites: %w", err)
	}

	return &MembershipStats{
		TotalMembers:    total,
		ActiveMembers:   active,
		PendingMembers:  pending,
		InactiveMembers: inactive,
		StatusBreakdown: map[membership.Status]int{
			membership.StatusActive:    active,
			membership.StatusPending:   pending,
			membership.StatusInactive:  inactive,
			membership.StatusSuspended: suspended,
		},
		RecentJoins:   recentJoins,
		RecentInvites: recentInvites,
	}, nil
}

func (r *membershipRepository) GetRecentJoins(ctx context.Context, organizationID xid.ID, days int) ([]*ent.Membership, error) {
	since := time.Now().AddDate(0, 0, -days)
	memberships, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.JoinedAtGTE(since),
		).
		WithUser().
		WithRole().
		Order(membership.ByJoinedAt()).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent joins: %w", err)
	}
	return memberships, nil
}

func (r *membershipRepository) GetInvitationStats(ctx context.Context, organizationID xid.ID, days int) (*InvitationStats, error) {
	since := time.Now().AddDate(0, 0, -days)

	// Total invites
	total, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.InvitedAtGTE(since),
		).
		Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get total invites: %w", err)
	}

	// Accepted invites
	accepted, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.InvitedAtGTE(since),
			membership.StatusEQ(membership.StatusActive),
		).
		Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get accepted invites: %w", err)
	}

	// Pending invites
	pending, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.InvitedAtGTE(since),
			membership.StatusEQ(membership.StatusPending),
		).
		Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending invites: %w", err)
	}

	// Expired invites
	expired, err := r.client.Membership.Query().
		Where(
			membership.OrganizationID(organizationID),
			membership.InvitedAtGTE(since),
			membership.StatusEQ(membership.StatusPending),
			membership.ExpiresAtLT(time.Now()),
		).
		Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get expired invites: %w", err)
	}

	// Calculate acceptance rate
	var acceptanceRate float64
	if total > 0 {
		acceptanceRate = float64(accepted) / float64(total) * 100
	}

	return &InvitationStats{
		TotalInvites:    total,
		AcceptedInvites: accepted,
		PendingInvites:  pending,
		ExpiredInvites:  expired,
		AcceptanceRate:  acceptanceRate,
	}, nil
}

// Existence check methods

func (r *membershipRepository) ExistsByUserAndOrganization(ctx context.Context, userID, organizationID xid.ID) (bool, error) {
	exists, err := r.client.Membership.Query().
		Where(
			membership.UserID(userID),
			membership.OrganizationID(organizationID),
		).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check if membership exists: %w", err)
	}
	return exists, nil
}

func (r *membershipRepository) HasActiveMembership(ctx context.Context, userID, organizationID xid.ID) (bool, error) {
	exists, err := r.client.Membership.Query().
		Where(
			membership.UserID(userID),
			membership.OrganizationID(organizationID),
			membership.StatusEQ(membership.StatusActive),
		).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check if active membership exists: %w", err)
	}
	return exists, nil
}
