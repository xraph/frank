package organization

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/membership"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// MembershipService defines the interface for membership business logic
type MembershipService interface {
	// Member management
	AddMember(ctx context.Context, input AddMemberInput) (*model.Membership, error)
	RemoveMember(ctx context.Context, organizationID, userID xid.ID, reason string) error
	UpdateMemberRole(ctx context.Context, organizationID, userID, roleID xid.ID) (*model.Membership, error)
	UpdateMemberStatus(ctx context.Context, organizationID, userID xid.ID, status membership.Status) (*model.Membership, error)

	// Member queries
	GetMembership(ctx context.Context, organizationID, userID xid.ID) (*model.Membership, error)
	GetMembershipByID(ctx context.Context, membershipID xid.ID) (*model.Membership, error)
	ListOrganizationMembers(ctx context.Context, organizationID xid.ID, params model.ListMembershipsParams) (*model.MemberListResponse, error)
	ListUserMemberships(ctx context.Context, userID xid.ID, params model.ListMembershipsParams) (*model.MembershipListResponse, error)

	// Role and permission queries
	GetMemberRole(ctx context.Context, organizationID, userID xid.ID) (*model.Role, error)
	GetMemberPermissions(ctx context.Context, organizationID, userID xid.ID) ([]string, error)
	HasPermission(ctx context.Context, organizationID, userID xid.ID, permission string) (bool, error)

	// Organization management
	TransferOwnership(ctx context.Context, organizationID, currentOwnerID, newOwnerID xid.ID) error
	SetPrimaryContact(ctx context.Context, organizationID, userID xid.ID) error
	AddBillingContact(ctx context.Context, organizationID, userID xid.ID) error
	RemoveBillingContact(ctx context.Context, organizationID, userID xid.ID) error

	// Member analytics
	GetMembershipStats(ctx context.Context, organizationID xid.ID) (*model.MembershipStats, error)
	GetRecentActivity(ctx context.Context, organizationID xid.ID, days int) (*model.MembershipActivityResponse, error)
	GetMemberMetrics(ctx context.Context, organizationID xid.ID, period string) (*model.MemberMetrics, error)

	// Bulk operations
	BulkUpdateMemberRoles(ctx context.Context, organizationID xid.ID, updates []model.BulkMemberRoleUpdate) (*model.BulkMembershipOperationResponse, error)
	BulkUpdateMemberStatus(ctx context.Context, organizationID xid.ID, updates []model.BulkMemberStatusUpdate) (*model.BulkMembershipOperationResponse, error)

	// Validation
	CanAddMember(ctx context.Context, organizationID xid.ID) (bool, error)
	ValidateMembershipChange(ctx context.Context, organizationID, userID xid.ID, change model.MembershipChange) error
}

// membershipService implements MembershipService
type membershipService struct {
	membershipRepo   repository.MembershipRepository
	organizationRepo repository.OrganizationRepository
	userRepo         repository.UserRepository
	roleRepo         repository.RoleRepository
	auditRepo        repository.AuditRepository
	logger           logging.Logger
}

// NewMembershipService creates a new membership service
func NewMembershipService(
	repo repository.Repository,
	logger logging.Logger,
) MembershipService {
	return &membershipService{
		membershipRepo:   repo.Membership(),
		organizationRepo: repo.Organization(),
		userRepo:         repo.User(),
		roleRepo:         repo.Role(),
		auditRepo:        repo.Audit(),
		logger:           logger,
	}
}

// AddMember adds a new member to an organization
func (s *membershipService) AddMember(ctx context.Context, input AddMemberInput) (*model.Membership, error) {
	// Validate organization exists
	org, err := s.organizationRepo.GetByID(ctx, input.OrganizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	// Validate user exists
	user, err := s.userRepo.GetByID(ctx, input.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "User not found")
	}

	// Check if membership already exists
	exists, err := s.membershipRepo.ExistsByUserAndOrganization(ctx, input.UserID, input.OrganizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to check existing membership")
	}
	if exists {
		return nil, errors.New(errors.CodeConflict, "User is already a member of this organization")
	}

	// Check organization member limits
	canAdd, err := s.CanAddMember(ctx, input.OrganizationID)
	if err != nil {
		return nil, err
	}
	if !canAdd {
		return nil, errors.New(errors.CodeBadRequest, "Organization has reached member limit")
	}

	// Validate role exists and is appropriate for organization
	role, err := s.roleRepo.GetByID(ctx, input.RoleID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Role not found")
	}

	joinedAt := time.Now()

	// Create membership
	createInput := repository.CreateMembershipInput{
		UserID:           input.UserID,
		OrganizationID:   input.OrganizationID,
		RoleID:           input.RoleID,
		Status:           membership.StatusActive,
		JoinedAt:         &joinedAt,
		InvitedBy:        input.InvitedBy,
		IsBillingContact: input.IsBilling,
		IsPrimaryContact: input.IsPrimary,
		CustomFields:     input.CustomFields,
	}

	entMembership, err := s.membershipRepo.Create(ctx, createInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create membership")
	}

	// Update organization user count
	err = s.organizationRepo.UpdateUserCounts(ctx, input.OrganizationID, repository.UpdateUserCountsInput{
		ExternalUsersDelta: 1,
	})
	if err != nil {
		s.logger.Error("Failed to update organization user count", logging.Error(err))
	}

	// Create audit log
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &input.OrganizationID,
		UserID:         input.InvitedBy,
		Action:         "membership.created",
		ResourceType:   "membership",
		ResourceID:     &entMembership.ID,
		Status:         "success",
		Details: map[string]interface{}{
			"target_user_id":    input.UserID,
			"organization_id":   input.OrganizationID,
			"role_id":           input.RoleID,
			"role_name":         role.Name,
			"user_email":        user.Email,
			"organization_name": org.Name,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for membership creation", logging.Error(err))
	}

	// Convert to model
	membership := s.entToModel(entMembership)
	return membership, nil
}

// RemoveMember removes a member from an organization
func (s *membershipService) RemoveMember(ctx context.Context, organizationID, userID xid.ID, reason string) error {
	// Get membership
	membership, err := s.membershipRepo.GetByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Membership not found")
	}

	// Check if user is the owner
	org, err := s.organizationRepo.GetByID(ctx, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	if !org.OwnerID.IsNil() && org.OwnerID == userID {
		return errors.New(errors.CodeBadRequest, "Cannot remove organization owner. Transfer ownership first")
	}

	// Delete membership
	err = s.membershipRepo.Delete(ctx, membership.ID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to remove member")
	}

	// Update organization user count
	err = s.organizationRepo.UpdateUserCounts(ctx, organizationID, repository.UpdateUserCountsInput{
		ExternalUsersDelta: -1,
	})
	if err != nil {
		s.logger.Error("Failed to update organization user count", logging.Error(err))
	}

	// Create audit log
	user, _ := s.userRepo.GetByID(ctx, userID)
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &organizationID,
		Action:         "membership.removed",
		ResourceType:   "membership",
		ResourceID:     &membership.ID,
		Status:         "success",
		Details: map[string]interface{}{
			"target_user_id":    userID,
			"organization_id":   organizationID,
			"reason":            reason,
			"user_email":        user.Email,
			"organization_name": org.Name,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for membership removal", logging.Error(err))
	}

	return nil
}

// UpdateMemberRole updates a member's role
func (s *membershipService) UpdateMemberRole(ctx context.Context, organizationID, userID, roleID xid.ID) (*model.Membership, error) {
	// Get existing membership
	membership, err := s.membershipRepo.GetByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Membership not found")
	}

	// Validate new role
	newRole, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Role not found")
	}

	// Get old role for audit
	oldRole, _ := s.roleRepo.GetByID(ctx, membership.RoleID)

	// Update role
	err = s.membershipRepo.UpdateRole(ctx, membership.ID, roleID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update member role")
	}

	// Get updated membership
	updatedMembership, err := s.membershipRepo.GetByID(ctx, membership.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get updated membership")
	}

	// Create audit log
	user, _ := s.userRepo.GetByID(ctx, userID)
	org, _ := s.organizationRepo.GetByID(ctx, organizationID)
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &organizationID,
		Action:         "membership.role_updated",
		ResourceType:   "membership",
		ResourceID:     &membership.ID,
		Status:         "success",
		Details: map[string]interface{}{
			"target_user_id":    userID,
			"organization_id":   organizationID,
			"old_role_id":       membership.RoleID,
			"new_role_id":       roleID,
			"old_role_name":     oldRole.Name,
			"new_role_name":     newRole.Name,
			"user_email":        user.Email,
			"organization_name": org.Name,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for role update", logging.Error(err))
	}

	return s.entToModel(updatedMembership), nil
}

// UpdateMemberStatus updates a member's status
func (s *membershipService) UpdateMemberStatus(ctx context.Context, organizationID, userID xid.ID, status membership.Status) (*model.Membership, error) {
	// Get existing membership
	entMembership, err := s.membershipRepo.GetByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Membership not found")
	}

	oldStatus := entMembership.Status

	// Update status
	err = s.membershipRepo.UpdateStatus(ctx, entMembership.ID, status)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update member status")
	}

	// Get updated membership
	updatedMembership, err := s.membershipRepo.GetByID(ctx, entMembership.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get updated membership")
	}

	// Create audit log
	user, _ := s.userRepo.GetByID(ctx, userID)
	org, _ := s.organizationRepo.GetByID(ctx, organizationID)
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &organizationID,
		Action:         "membership.status_updated",
		ResourceType:   "membership",
		ResourceID:     &entMembership.ID,
		Status:         "success",
		Details: map[string]interface{}{
			"target_user_id":    userID,
			"organization_id":   organizationID,
			"old_status":        oldStatus,
			"new_status":        status,
			"user_email":        user.Email,
			"organization_name": org.Name,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for status update", logging.Error(err))
	}

	return s.entToModel(updatedMembership), nil
}

// GetMembership retrieves a specific membership
func (s *membershipService) GetMembership(ctx context.Context, organizationID, userID xid.ID) (*model.Membership, error) {
	entMembership, err := s.membershipRepo.GetByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Membership not found")
	}

	return s.entToModel(entMembership), nil
}

// GetMembershipByID retrieves a membership by ID
func (s *membershipService) GetMembershipByID(ctx context.Context, membershipID xid.ID) (*model.Membership, error) {
	entMembership, err := s.membershipRepo.GetByID(ctx, membershipID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Membership not found")
	}

	return s.entToModel(entMembership), nil
}

// ListOrganizationMembers lists members of an organization
func (s *membershipService) ListOrganizationMembers(ctx context.Context, organizationID xid.ID, params model.ListMembershipsParams) (*model.MemberListResponse, error) {
	repoParams := repository.ListMembershipsParams{
		PaginationParams: params.PaginationParams,
		OrganizationID:   &organizationID,
		Search:           params.Search,
	}

	if params.RoleID.IsSet {
		repoParams.RoleID = &params.RoleID.Value
	}
	if params.IsPrimaryContact.IsSet {
		repoParams.IsPrimaryContact = &params.IsPrimaryContact.Value
	}
	if params.IsBillingContact.IsSet {
		repoParams.IsBillingContact = &params.IsBillingContact.Value
	}
	if params.Status.IsSet {
		repoParams.Status = &params.Status.Value
	}
	if params.InvitedBy.IsSet {
		repoParams.InvitedBy = &params.InvitedBy.Value
	}

	result, err := s.membershipRepo.ListByOrganization(ctx, organizationID, repoParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list organization members")
	}

	// Convert to model response
	members := make([]model.MemberSummary, len(result.Data))
	for i, entMembership := range result.Data {
		members[i] = s.entToMemberSummary(entMembership)
	}

	return &model.MemberListResponse{
		Data:       members,
		Pagination: result.Pagination,
	}, nil
}

// ListUserMemberships lists memberships for a user
func (s *membershipService) ListUserMemberships(ctx context.Context, userID xid.ID, params model.ListMembershipsParams) (*model.MembershipListResponse, error) {
	// Convert params to repository params
	repoParams := repository.ListMembershipsParams{
		PaginationParams: params.PaginationParams,
		Search:           params.Search,
	}

	if params.OrganizationID.IsSet {
		repoParams.OrganizationID = &params.OrganizationID.Value
	}
	if params.RoleID.IsSet {
		repoParams.RoleID = &params.RoleID.Value
	}
	if params.Status.IsSet {
		repoParams.Status = &params.Status.Value
	}
	if params.IsPrimaryContact.IsSet {
		repoParams.IsPrimaryContact = &params.IsPrimaryContact.Value
	}
	if params.IsBillingContact.IsSet {
		repoParams.IsBillingContact = &params.IsBillingContact.Value
	}

	result, err := s.membershipRepo.ListByUser(ctx, userID, repoParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list user memberships")
	}

	// Convert to model response
	memberships := make([]model.MembershipSummary, len(result.Data))
	for i, entMembership := range result.Data {
		memberships[i] = s.entToMembershipSummary(entMembership)
	}

	return &model.MembershipListResponse{
		Data:       memberships,
		Pagination: result.Pagination,
	}, nil
}

// GetMemberRole gets a member's role in an organization
func (s *membershipService) GetMemberRole(ctx context.Context, organizationID, userID xid.ID) (*model.Role, error) {
	membership, err := s.membershipRepo.GetByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Membership not found")
	}

	role, err := s.roleRepo.GetByID(ctx, membership.RoleID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get role")
	}

	return s.entRoleToModel(role), nil
}

// GetMemberPermissions gets a member's permissions in an organization
func (s *membershipService) GetMemberPermissions(ctx context.Context, organizationID, userID xid.ID) ([]string, error) {
	membership, err := s.membershipRepo.GetByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Membership not found")
	}

	// Get role permissions
	permissions, err := s.roleRepo.GetPermissions(ctx, membership.RoleID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get role permissions")
	}

	permissionNames := make([]string, len(permissions))
	for i, perm := range permissions {
		permissionNames[i] = perm.Name
	}

	return permissionNames, nil
}

// HasPermission checks if a member has a specific permission
func (s *membershipService) HasPermission(ctx context.Context, organizationID, userID xid.ID, permission string) (bool, error) {
	permissions, err := s.GetMemberPermissions(ctx, organizationID, userID)
	if err != nil {
		return false, err
	}

	for _, perm := range permissions {
		if perm == permission {
			return true, nil
		}
	}

	return false, nil
}

// TransferOwnership transfers organization ownership to another member
func (s *membershipService) TransferOwnership(ctx context.Context, organizationID, currentOwnerID, newOwnerID xid.ID) error {
	// Validate current owner
	org, err := s.organizationRepo.GetByID(ctx, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	if org.OwnerID.IsNil() || org.OwnerID != currentOwnerID {
		return errors.New(errors.CodeForbidden, "Current user is not the organization owner")
	}

	// Validate new owner is a member
	_, err = s.membershipRepo.GetByUserAndOrganization(ctx, newOwnerID, organizationID)
	if err != nil {
		return errors.New(errors.CodeBadRequest, "New owner must be a member of the organization")
	}

	// Update organization owner
	_, err = s.organizationRepo.Update(ctx, organizationID, repository.UpdateOrganizationInput{
		OwnerID: &newOwnerID,
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to transfer ownership")
	}

	// Create audit log
	oldOwner, _ := s.userRepo.GetByID(ctx, currentOwnerID)
	newOwner, _ := s.userRepo.GetByID(ctx, newOwnerID)
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &organizationID,
		UserID:         &currentOwnerID,
		Action:         "organization.ownership_transferred",
		ResourceType:   "organization",
		ResourceID:     &organizationID,
		Status:         "success",
		Details: map[string]interface{}{
			"old_owner_id":      currentOwnerID,
			"new_owner_id":      newOwnerID,
			"old_owner_email":   oldOwner.Email,
			"new_owner_email":   newOwner.Email,
			"organization_name": org.Name,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for ownership transfer", logging.Error(err))
	}

	return nil
}

// SetPrimaryContact sets a member as the primary contact
func (s *membershipService) SetPrimaryContact(ctx context.Context, organizationID, userID xid.ID) error {
	err := s.membershipRepo.SetPrimaryContact(ctx, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to set primary contact")
	}

	// Create audit log
	user, _ := s.userRepo.GetByID(ctx, userID)
	org, _ := s.organizationRepo.GetByID(ctx, organizationID)
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &organizationID,
		Action:         "membership.primary_contact_set",
		ResourceType:   "membership",
		Status:         "success",
		Details: map[string]interface{}{
			"user_id":           userID,
			"user_email":        user.Email,
			"organization_name": org.Name,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for primary contact", logging.Error(err))
	}

	return nil
}

// AddBillingContact adds a member as a billing contact
func (s *membershipService) AddBillingContact(ctx context.Context, organizationID, userID xid.ID) error {
	membership, err := s.membershipRepo.GetByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Membership not found")
	}

	err = s.membershipRepo.AddBillingContact(ctx, membership.ID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to add billing contact")
	}

	return nil
}

// RemoveBillingContact removes a member as a billing contact
func (s *membershipService) RemoveBillingContact(ctx context.Context, organizationID, userID xid.ID) error {
	membership, err := s.membershipRepo.GetByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Membership not found")
	}

	err = s.membershipRepo.RemoveBillingContact(ctx, membership.ID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to remove billing contact")
	}

	return nil
}

// GetMembershipStats gets membership statistics for an organization
func (s *membershipService) GetMembershipStats(ctx context.Context, organizationID xid.ID) (*model.MembershipStats, error) {
	stats, err := s.membershipRepo.GetMembershipStats(ctx, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get membership stats")
	}

	return &model.MembershipStats{
		TotalMembers:       stats.TotalMembers,
		ActiveMembers:      stats.ActiveMembers,
		PendingInvitations: stats.PendingMembers,
		InactiveMembers:    stats.InactiveMembers,
		SuspendedMembers:   stats.SuspendedMembers,
		RecentJoins:        stats.RecentJoins,
		// MembersByRole:      stats.MembersByRole,
		// GrowthRate:         stats.GrowthRate,
	}, nil
}

// GetRecentActivity gets recent membership activity
func (s *membershipService) GetRecentActivity(ctx context.Context, organizationID xid.ID, days int) (*model.MembershipActivityResponse, error) {
	// Get recent joins
	recentJoins, err := s.membershipRepo.GetRecentJoins(ctx, organizationID, days)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get recent joins")
	}

	// Convert to model
	activities := make([]model.MembershipActivity, len(recentJoins))
	for i, member := range recentJoins {
		activities[i] = model.MembershipActivity{
			Action: "join",
			UserID: member.UserID,

			Timestamp:   *member.JoinedAt,
			Description: fmt.Sprintf("User joined organization"),
		}
	}

	return &model.MembershipActivityResponse{
		Data: activities,
		Pagination: &model.Pagination{
			TotalCount: len(activities),
		},
	}, nil
}

// GetMemberMetrics gets member metrics for a period
func (s *membershipService) GetMemberMetrics(ctx context.Context, organizationID xid.ID, period string) (*model.MemberMetrics, error) {
	// This would typically aggregate data over the specified period
	// For now, return current stats as an example
	stats, err := s.GetMembershipStats(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	return &model.MemberMetrics{
		Period:        period,
		TotalMembers:  stats.TotalMembers,
		ActiveMembers: stats.ActiveMembers,
		NewMembers:    stats.RecentJoins,
		ChurnRate:     0.0, // Would calculate based on period
		GrowthRate:    stats.GrowthRate,
	}, nil
}

// BulkUpdateMemberRoles updates multiple member roles
func (s *membershipService) BulkUpdateMemberRoles(ctx context.Context, organizationID xid.ID, updates []model.BulkMemberRoleUpdate) (*model.BulkMembershipOperationResponse, error) {
	response := &model.BulkMembershipOperationResponse{
		SuccessCount: 0,
		FailureCount: 0,
		Errors:       []string{},
	}

	for _, update := range updates {
		_, err := s.UpdateMemberRole(ctx, organizationID, update.UserID, update.RoleID)
		if err != nil {
			response.FailureCount++
			response.Errors = append(response.Errors, fmt.Sprintf("Failed to update role for user %s: %s", update.UserID, err.Error()))
		} else {
			response.SuccessCount++
		}
	}

	return response, nil
}

// BulkUpdateMemberStatus updates multiple member statuses
func (s *membershipService) BulkUpdateMemberStatus(ctx context.Context, organizationID xid.ID, updates []model.BulkMemberStatusUpdate) (*model.BulkMembershipOperationResponse, error) {
	response := &model.BulkMembershipOperationResponse{
		SuccessCount: 0,
		FailureCount: 0,
		Errors:       []string{},
	}

	for _, update := range updates {
		_, err := s.UpdateMemberStatus(ctx, organizationID, update.UserID, update.Status)
		if err != nil {
			response.FailureCount++
			response.Errors = append(response.Errors, fmt.Sprintf("Failed to update status for user %s: %s", update.UserID, err.Error()))
		} else {
			response.SuccessCount++
		}
	}

	return response, nil
}

// CanAddMember checks if organization can add more members
func (s *membershipService) CanAddMember(ctx context.Context, organizationID xid.ID) (bool, error) {
	return s.organizationRepo.CanAddExternalUser(ctx, organizationID)
}

// ValidateMembershipChange validates a membership change
func (s *membershipService) ValidateMembershipChange(ctx context.Context, organizationID, userID xid.ID, change model.MembershipChange) error {
	// Check if membership exists
	_, err := s.membershipRepo.GetByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Membership not found")
	}

	// Validate specific changes
	switch change.Type {
	case "role_change":
		if change.NewRoleID == nil {
			return errors.New(errors.CodeBadRequest, "New role ID is required for role change")
		}
		// Validate role exists
		_, err := s.roleRepo.GetByID(ctx, *change.NewRoleID)
		if err != nil {
			return errors.Wrap(err, errors.CodeNotFound, "New role not found")
		}
	case "status_change":
		if change.NewStatus == nil {
			return errors.New(errors.CodeBadRequest, "New status is required for status change")
		}
	default:
		return errors.New(errors.CodeBadRequest, "Invalid membership change type")
	}

	return nil
}

// Helper methods

// entToModel converts ent.Membership to model.Membership
func (s *membershipService) entToModel(entMembership *ent.Membership) *model.Membership {
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
	}
}

// entToMemberSummary converts ent.Membership to model.MemberSummary
func (s *membershipService) entToMemberSummary(entMembership *ent.Membership) model.MemberSummary {
	return model.MemberSummary{
		UserID:    entMembership.UserID,
		RoleName:  "", // Would need to join with role table
		Status:    string(entMembership.Status),
		JoinedAt:  entMembership.JoinedAt,
		IsBilling: entMembership.IsBillingContact,
		IsPrimary: entMembership.IsPrimaryContact,
	}
}

// entToMembershipSummary converts ent.Membership to model.MembershipSummary
func (s *membershipService) entToMembershipSummary(entMembership *ent.Membership) model.MembershipSummary {
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

// entRoleToModel converts ent.Role to model.Role
func (s *membershipService) entRoleToModel(entRole *ent.Role) *model.Role {
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

// Audit helper methods

func (s *membershipService) auditMembershipCreation(ctx context.Context, membershipID, orgID, userID xid.ID, invitedBy *xid.ID) {
	metadata := map[string]interface{}{
		"membership_id": membershipID,
		"user_id":       userID,
	}
	if invitedBy != nil {
		metadata["invited_by"] = *invitedBy
	}

	actorId := userID
	if invitedBy != nil {
		actorId = *invitedBy
	}

	input := repository.CreateAuditInput{
		OrganizationID: &orgID,
		UserID:         &actorId,
		Action:         "membership.created",
		ResourceType:   "membership",
		ResourceID:     &membershipID,
		Status:         "success",
		Metadata:       metadata,
	}
	s.auditRepo.Create(ctx, input)
}

func (s *membershipService) auditMembershipUpdate(ctx context.Context, membershipID, orgID, userID, updatedBy xid.ID, reason string) {
	input := repository.CreateAuditInput{
		OrganizationID: &orgID,
		UserID:         &updatedBy,
		Action:         "membership.updated",
		ResourceType:   "membership",
		ResourceID:     &membershipID,
		Status:         "success",
		Metadata: map[string]interface{}{
			"reason":  reason,
			"user_id": userID,
		},
	}
	s.auditRepo.Create(ctx, input)
}
