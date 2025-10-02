package repository

import (
	"context"
	"database/sql"
	errors2 "errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/rs/xid"
	"github.com/uptrace/bun"
	"github.com/xraph/frank/internal/models"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

type MembershipRepository interface {
	Create(ctx context.Context, input CreateMembershipInput) (*models.Membership, error)
	GetByID(ctx context.Context, id xid.ID) (*models.Membership, error)
	GetByUserAndOrganization(ctx context.Context, userID, organizationID xid.ID) (*models.Membership, error)
	GetByInvitationToken(ctx context.Context, token string) (*models.Membership, error)
	Update(ctx context.Context, id xid.ID, input UpdateMembershipInput) (*models.Membership, error)
	Delete(ctx context.Context, id xid.ID) error

	List(ctx context.Context, params ListMembershipsParams) (*model.PaginatedOutput[*models.Membership], error)
	ListByUser(ctx context.Context, userID xid.ID, params ListMembershipsParams) (*model.PaginatedOutput[*models.Membership], error)
	ListByOrganization(ctx context.Context, organizationID xid.ID, params ListMembershipsParams) (*model.PaginatedOutput[*models.Membership], error)
	ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*models.Membership, error)

	CreateInvitation(ctx context.Context, input CreateInvitationInput) (*models.Membership, error)
	AcceptInvitation(ctx context.Context, token string, acceptedBy xid.ID) (*models.Membership, error)
	DeclineInvitation(ctx context.Context, token string) error

	Activate(ctx context.Context, id xid.ID) error
	Deactivate(ctx context.Context, id xid.ID) error
	UpdateRole(ctx context.Context, id xid.ID, roleID xid.ID) error

	GetMemberCount(ctx context.Context, organizationID xid.ID, status *models.MembershipStatus) (int, error)
	GetMembershipStats(ctx context.Context, organizationID xid.ID) (*MembershipStats, error)
	ExistsByUserAndOrganization(ctx context.Context, userID, organizationID xid.ID) (bool, error)
}

type membershipRepository struct {
	db     *bun.DB
	logger logging.Logger
}

func NewMembershipRepository(db *bun.DB, logger logging.Logger) MembershipRepository {
	return &membershipRepository{
		db:     db,
		logger: logger,
	}
}

type CreateMembershipInput struct {
	UserID           xid.ID
	OrganizationID   xid.ID
	RoleID           xid.ID
	Status           models.MembershipStatus
	InvitedBy        *xid.ID
	InvitedAt        time.Time
	JoinedAt         *time.Time
	ExpiresAt        *time.Time
	InvitationToken  *string
	IsBillingContact bool
	IsPrimaryContact bool
	Metadata         map[string]interface{}
	CustomFields     map[string]interface{}
}

type CreateInvitationInput struct {
	UserID           xid.ID
	OrganizationID   xid.ID
	Email            string
	RoleID           xid.ID
	InvitedBy        xid.ID
	InvitationToken  string
	ExpiresAt        time.Time
	IsBillingContact bool
	IsPrimaryContact bool
	Metadata         map[string]interface{}
	CustomFields     map[string]interface{}
}

type UpdateMembershipInput struct {
	RoleID           *xid.ID
	Status           *models.MembershipStatus
	JoinedAt         *time.Time
	ExpiresAt        *time.Time
	IsBillingContact *bool
	IsPrimaryContact *bool
	Metadata         map[string]interface{}
}

type ListMembershipsParams struct {
	model.PaginationParams
	OrganizationID   *xid.ID
	Status           *models.MembershipStatus
	RoleID           *xid.ID
	IsBillingContact *bool
	IsPrimaryContact *bool
	InvitedBy        *xid.ID
	Search           string
}

type MembershipStats struct {
	TotalMembers    int
	ActiveMembers   int
	PendingMembers  int
	InactiveMembers int
	RecentJoins     int
	RecentInvites   int
}

func (r *membershipRepository) Create(ctx context.Context, input CreateMembershipInput) (*models.Membership, error) {
	// Get user to retrieve email
	var user models.User
	err := r.db.NewSelect().
		Model(&user).
		Where("id = ?", input.UserID.String()).
		Scan(ctx)
	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "User not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	membership := &models.Membership{
		CommonModel:      models.CommonModel{ID: xid.New().String()},
		UserID:           input.UserID.String(),
		Email:            user.Email,
		OrganizationID:   input.OrganizationID.String(),
		RoleID:           input.RoleID.String(),
		Status:           input.Status,
		InvitedAt:        input.InvitedAt,
		IsBillingContact: input.IsBillingContact,
		IsPrimaryContact: input.IsPrimaryContact,
	}

	if input.InvitedBy != nil {
		invitedBy := input.InvitedBy.String()
		membership.InvitedBy = &invitedBy
	}
	if input.JoinedAt != nil {
		membership.JoinedAt = input.JoinedAt
	}
	if input.ExpiresAt != nil {
		membership.ExpiresAt = input.ExpiresAt
	}
	if input.InvitationToken != nil {
		membership.InvitationToken = input.InvitationToken
	}
	if input.Metadata != nil {
		membership.Metadata = input.Metadata
	}
	if input.CustomFields != nil {
		membership.CustomFields = input.CustomFields
	}

	_, err = r.db.NewInsert().
		Model(membership).
		Exec(ctx)

	if err != nil {
		// Check for unique constraint violation
		if errors2.Is(err, &pq.Error{Code: "23505"}) {
			return nil, errors.New(errors.CodeConflict, "Membership already exists for this user and organization")
		}
		return nil, fmt.Errorf("failed to create membership: %w", err)
	}

	return membership, nil
}

func (r *membershipRepository) GetByID(ctx context.Context, id xid.ID) (*models.Membership, error) {
	var membership models.Membership

	err := r.db.NewSelect().
		Model(&membership).
		Where("id = ?", id.String()).
		Where("deleted_at IS NULL").
		Relation("User").
		Relation("Organization").
		Relation("Role").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "Membership not found")
		}
		return nil, fmt.Errorf("failed to get membership by ID: %w", err)
	}

	return &membership, nil
}

func (r *membershipRepository) GetByUserAndOrganization(ctx context.Context, userID, organizationID xid.ID) (*models.Membership, error) {
	var membership models.Membership

	err := r.db.NewSelect().
		Model(&membership).
		Where("user_id = ?", userID.String()).
		Where("organization_id = ?", organizationID.String()).
		Where("deleted_at IS NULL").
		Relation("User").
		Relation("Organization").
		Relation("Role").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "Membership not found")
		}
		return nil, fmt.Errorf("failed to get membership: %w", err)
	}

	return &membership, nil
}

func (r *membershipRepository) GetByInvitationToken(ctx context.Context, token string) (*models.Membership, error) {
	var membership models.Membership

	err := r.db.NewSelect().
		Model(&membership).
		Where("invitation_token = ?", token).
		Where("deleted_at IS NULL").
		Relation("User").
		Relation("Organization").
		Relation("Role").
		Scan(ctx)

	if err != nil {
		if errors2.Is(err, sql.ErrNoRows) {
			return nil, errors.New(errors.CodeNotFound, "Invalid invitation token")
		}
		return nil, fmt.Errorf("failed to get membership by invitation token: %w", err)
	}

	return &membership, nil
}

func (r *membershipRepository) Update(ctx context.Context, id xid.ID, input UpdateMembershipInput) (*models.Membership, error) {
	update := r.db.NewUpdate().
		Model((*models.Membership)(nil)).
		Where("id = ?", id.String())

	if input.RoleID != nil {
		update = update.Set("role_id = ?", input.RoleID.String())
	}
	if input.Status != nil {
		update = update.Set("status = ?", *input.Status)
	}
	if input.JoinedAt != nil {
		update = update.Set("joined_at = ?", *input.JoinedAt)
	}
	if input.ExpiresAt != nil {
		update = update.Set("expires_at = ?", *input.ExpiresAt)
	}
	if input.IsBillingContact != nil {
		update = update.Set("is_billing_contact = ?", *input.IsBillingContact)
	}
	if input.IsPrimaryContact != nil {
		update = update.Set("is_primary_contact = ?", *input.IsPrimaryContact)
	}
	if input.Metadata != nil {
		update = update.Set("metadata = ?", input.Metadata)
	}

	result, err := update.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update membership: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, errors.New(errors.CodeNotFound, "Membership not found")
	}

	return r.GetByID(ctx, id)
}

func (r *membershipRepository) Delete(ctx context.Context, id xid.ID) error {
	result, err := r.db.NewDelete().
		Model((*models.Membership)(nil)).
		Where("id = ?", id.String()).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to delete membership: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New(errors.CodeNotFound, "Membership not found")
	}

	return nil
}

func (r *membershipRepository) List(ctx context.Context, params ListMembershipsParams) (*model.PaginatedOutput[*models.Membership], error) {
	query := r.db.NewSelect().
		Model((*models.Membership)(nil)).
		Where("deleted_at IS NULL").
		Relation("User").
		Relation("Organization").
		Relation("Role")

	// Apply filters
	if params.Status != nil {
		query = query.Where("status = ?", *params.Status)
	}
	if params.RoleID != nil {
		query = query.Where("role_id = ?", params.RoleID.String())
	}
	if params.IsBillingContact != nil {
		query = query.Where("is_billing_contact = ?", *params.IsBillingContact)
	}
	if params.IsPrimaryContact != nil {
		query = query.Where("is_primary_contact = ?", *params.IsPrimaryContact)
	}
	if params.InvitedBy != nil {
		query = query.Where("invited_by = ?", params.InvitedBy.String())
	}
	if params.Search != "" {
		query = query.Where("email ILIKE ?", "%"+params.Search+"%")
	}

	// Count total
	total, err := query.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count memberships: %w", err)
	}

	// Apply pagination
	limit := params.Limit
	if limit == 0 {
		limit = 20
	}
	query = query.Limit(limit).Offset(params.Offset)
	query = query.Order("created_at DESC")

	var memberships []*models.Membership
	err = query.Scan(ctx, &memberships)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships: %w", err)
	}

	return &model.PaginatedOutput[*models.Membership]{
		Data: memberships,
		Pagination: &model.Pagination{
			TotalCount: total,
			Limit:      limit,
			Offset:     params.Offset,
		},
	}, nil
}

func (r *membershipRepository) ListByUser(ctx context.Context, userID xid.ID, params ListMembershipsParams) (*model.PaginatedOutput[*models.Membership], error) {
	query := r.db.NewSelect().
		Model((*models.Membership)(nil)).
		Where("user_id = ?", userID.String()).
		Where("deleted_at IS NULL").
		Relation("User").
		Relation("Organization").
		Relation("Role")

	if params.Status != nil {
		query = query.Where("status = ?", *params.Status)
	}

	total, err := query.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count memberships: %w", err)
	}

	limit := params.Limit
	if limit == 0 {
		limit = 20
	}
	query = query.Limit(limit).Offset(params.Offset).Order("created_at DESC")

	var memberships []*models.Membership
	err = query.Scan(ctx, &memberships)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships by user: %w", err)
	}

	return &model.PaginatedOutput[*models.Membership]{
		Data: memberships,
		Pagination: &model.Pagination{
			TotalCount: total,
			Limit:      limit,
			Offset:     params.Offset,
		},
	}, nil
}

func (r *membershipRepository) ListByOrganization(ctx context.Context, organizationID xid.ID, params ListMembershipsParams) (*model.PaginatedOutput[*models.Membership], error) {
	query := r.db.NewSelect().
		Model((*models.Membership)(nil)).
		Where("organization_id = ?", organizationID.String()).
		Where("deleted_at IS NULL").
		Relation("User").
		Relation("Organization").
		Relation("Role")

	if params.Status != nil {
		query = query.Where("status = ?", *params.Status)
	}
	if params.RoleID != nil {
		query = query.Where("role_id = ?", params.RoleID.String())
	}
	if params.InvitedBy != nil {
		query = query.Where("invited_by = ?", params.InvitedBy.String())
	}

	total, err := query.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count memberships: %w", err)
	}

	limit := params.Limit
	if limit == 0 {
		limit = 20
	}
	query = query.Limit(limit).Offset(params.Offset).Order("created_at DESC")

	var memberships []*models.Membership
	err = query.Scan(ctx, &memberships)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships by organization: %w", err)
	}

	return &model.PaginatedOutput[*models.Membership]{
		Data: memberships,
		Pagination: &model.Pagination{
			TotalCount: total,
			Limit:      limit,
			Offset:     params.Offset,
		},
	}, nil
}

func (r *membershipRepository) ListActiveByOrganizationID(ctx context.Context, orgID xid.ID) ([]*models.Membership, error) {
	var memberships []*models.Membership

	err := r.db.NewSelect().
		Model(&memberships).
		Where("organization_id = ?", orgID.String()).
		Where("status = ?", models.MembershipStatusActive).
		Where("deleted_at IS NULL").
		Relation("User").
		Relation("Organization").
		Relation("Inviter").
		Order("joined_at DESC").
		Scan(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list active memberships")
	}

	return memberships, nil
}

func (r *membershipRepository) CreateInvitation(ctx context.Context, input CreateInvitationInput) (*models.Membership, error) {
	return r.Create(ctx, CreateMembershipInput{
		UserID:           input.UserID,
		OrganizationID:   input.OrganizationID,
		RoleID:           input.RoleID,
		Status:           models.MembershipStatusPending,
		InvitedBy:        &input.InvitedBy,
		InvitedAt:        time.Now(),
		ExpiresAt:        &input.ExpiresAt,
		InvitationToken:  &input.InvitationToken,
		IsBillingContact: input.IsBillingContact,
		IsPrimaryContact: input.IsPrimaryContact,
		Metadata:         input.Metadata,
	})
}

func (r *membershipRepository) AcceptInvitation(ctx context.Context, token string, acceptedBy xid.ID) (*models.Membership, error) {
	member, err := r.GetByInvitationToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Check if invitation is still valid
	if member.ExpiresAt != nil && time.Now().After(*member.ExpiresAt) {
		return nil, errors.New(errors.CodeBadRequest, "Invitation has expired")
	}

	if member.Status != models.MembershipStatusPending {
		return nil, errors.New(errors.CodeBadRequest, "Invitation has already been processed")
	}

	// Accept the invitation
	status := models.MembershipStatusActive
	now := time.Now()

	memberID, _ := xid.FromString(member.ID)
	return r.Update(ctx, memberID, UpdateMembershipInput{
		Status:   &status,
		JoinedAt: &now,
	})
}

func (r *membershipRepository) DeclineInvitation(ctx context.Context, token string) error {
	member, err := r.GetByInvitationToken(ctx, token)
	if err != nil {
		return err
	}

	if member.Status != models.MembershipStatusPending {
		return errors.New(errors.CodeBadRequest, "Invitation has already been processed")
	}

	memberID, _ := xid.FromString(member.ID)
	return r.Delete(ctx, memberID)
}

func (r *membershipRepository) Activate(ctx context.Context, id xid.ID) error {
	status := models.MembershipStatusActive
	_, err := r.Update(ctx, id, UpdateMembershipInput{
		Status: &status,
	})
	return err
}

func (r *membershipRepository) Deactivate(ctx context.Context, id xid.ID) error {
	status := models.MembershipStatusInactive
	_, err := r.Update(ctx, id, UpdateMembershipInput{
		Status: &status,
	})
	return err
}

func (r *membershipRepository) UpdateRole(ctx context.Context, id xid.ID, roleID xid.ID) error {
	_, err := r.Update(ctx, id, UpdateMembershipInput{
		RoleID: &roleID,
	})
	return err
}

func (r *membershipRepository) GetMemberCount(ctx context.Context, organizationID xid.ID, status *models.MembershipStatus) (int, error) {
	query := r.db.NewSelect().
		Model((*models.Membership)(nil)).
		Where("organization_id = ?", organizationID.String()).
		Where("deleted_at IS NULL")

	if status != nil {
		query = query.Where("status = ?", *status)
	}

	count, err := query.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get member count: %w", err)
	}

	return count, nil
}

func (r *membershipRepository) GetMembershipStats(ctx context.Context, organizationID xid.ID) (*MembershipStats, error) {
	total, err := r.GetMemberCount(ctx, organizationID, nil)
	if err != nil {
		return nil, err
	}

	activeStatus := models.MembershipStatusActive
	active, err := r.GetMemberCount(ctx, organizationID, &activeStatus)
	if err != nil {
		return nil, err
	}

	pendingStatus := models.MembershipStatusPending
	pending, err := r.GetMemberCount(ctx, organizationID, &pendingStatus)
	if err != nil {
		return nil, err
	}

	inactiveStatus := models.MembershipStatusInactive
	inactive, err := r.GetMemberCount(ctx, organizationID, &inactiveStatus)
	if err != nil {
		return nil, err
	}

	// Get recent joins (last 30 days)
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	recentJoins, err := r.db.NewSelect().
		Model((*models.Membership)(nil)).
		Where("organization_id = ?", organizationID.String()).
		Where("joined_at >= ?", thirtyDaysAgo).
		Where("deleted_at IS NULL").
		Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent joins: %w", err)
	}

	// Get recent invites (last 30 days)
	recentInvites, err := r.db.NewSelect().
		Model((*models.Membership)(nil)).
		Where("organization_id = ?", organizationID.String()).
		Where("invited_at >= ?", thirtyDaysAgo).
		Where("deleted_at IS NULL").
		Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent invites: %w", err)
	}

	return &MembershipStats{
		TotalMembers:    total,
		ActiveMembers:   active,
		PendingMembers:  pending,
		InactiveMembers: inactive,
		RecentJoins:     recentJoins,
		RecentInvites:   recentInvites,
	}, nil
}

func (r *membershipRepository) ExistsByUserAndOrganization(ctx context.Context, userID, organizationID xid.ID) (bool, error) {
	count, err := r.db.NewSelect().
		Model((*models.Membership)(nil)).
		Where("user_id = ?", userID.String()).
		Where("organization_id = ?", organizationID.String()).
		Where("deleted_at IS NULL").
		Count(ctx)

	if err != nil {
		return false, fmt.Errorf("failed to check if membership exists: %w", err)
	}

	return count > 0, nil
}
