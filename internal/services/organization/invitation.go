package organization

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/membership"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// InvitationService defines the interface for invitation business logic
type InvitationService interface {
	// Invitation management
	CreateInvitation(ctx context.Context, input CreateInvitationInput) (*model.Invitation, error)
	SendInvitation(ctx context.Context, invitationID xid.ID) error
	AcceptInvitation(ctx context.Context, token string, acceptedBy xid.ID) (*model.Membership, error)
	DeclineInvitation(ctx context.Context, token string, reason string) error
	ResendInvitation(ctx context.Context, invitationID xid.ID) error
	CancelInvitation(ctx context.Context, invitationID xid.ID, reason string) error

	// Invitation queries
	GetInvitation(ctx context.Context, invitationID xid.ID) (*model.Invitation, error)
	GetInvitationByToken(ctx context.Context, token string) (*model.Invitation, error)
	ListInvitations(ctx context.Context, organizationID xid.ID, params model.ListInvitationsParams) (*model.InvitationListResponse, error)
	ListPendingInvitations(ctx context.Context, organizationID xid.ID) ([]*model.Invitation, error)
	ListUserInvitations(ctx context.Context, email string, params model.ListInvitationsParams) (*model.InvitationListResponse, error)

	// Bulk operations
	CreateBulkInvitations(ctx context.Context, organizationID xid.ID, invitations []BulkInvitationInput) (*model.BulkInvitationResponse, error)
	ResendBulkInvitations(ctx context.Context, invitationIDs []xid.ID) (*model.BulkInvitationResponse, error)
	CancelBulkInvitations(ctx context.Context, invitationIDs []xid.ID, reason string) (*model.BulkInvitationResponse, error)

	// Invitation analytics
	GetInvitationStats(ctx context.Context, organizationID xid.ID) (*model.InvitationStats, error)
	GetInvitationMetrics(ctx context.Context, organizationID xid.ID, period string) (*model.InvitationMetrics, error)

	// Utility operations
	ValidateInvitationToken(ctx context.Context, token string) (*model.Invitation, error)
	IsInvitationValid(ctx context.Context, token string) (bool, error)
	CleanupExpiredInvitations(ctx context.Context) (int, error)
	GetInvitationLink(ctx context.Context, token string) (string, error)
}

// CreateInvitationInput represents input for creating an invitation
type CreateInvitationInput struct {
	OrganizationID xid.ID                 `json:"organizationId"`
	Email          string                 `json:"email"`
	RoleID         xid.ID                 `json:"roleId"`
	InvitedBy      xid.ID                 `json:"invitedBy"`
	Message        string                 `json:"message,omitempty"`
	ExpiresAt      *time.Time             `json:"expiresAt,omitempty"`
	RedirectURL    string                 `json:"redirectUrl,omitempty"`
	CustomFields   map[string]interface{} `json:"customFields,omitempty"`
	SendEmail      bool                   `json:"sendEmail"`
}

// BulkInvitationInput represents input for bulk invitations
type BulkInvitationInput struct {
	Email        string                 `json:"email"`
	RoleID       xid.ID                 `json:"roleId"`
	Message      string                 `json:"message,omitempty"`
	CustomFields map[string]interface{} `json:"customFields,omitempty"`
}

// invitationService implements InvitationService
type invitationService struct {
	membershipRepo   repository.MembershipRepository
	organizationRepo repository.OrganizationRepository
	userRepo         repository.UserRepository
	roleRepo         repository.RoleRepository
	auditRepo        repository.AuditRepository
	emailService     EmailService // Interface for sending emails
	logger           logging.Logger
	baseURL          string
}

// EmailService defines the interface for sending emails
type EmailService interface {
	SendInvitationEmail(ctx context.Context, to string, invitation *model.Invitation, invitationLink string) error
}

// NewInvitationService creates a new invitation service
func NewInvitationService(
	membershipRepo repository.MembershipRepository,
	organizationRepo repository.OrganizationRepository,
	userRepo repository.UserRepository,
	roleRepo repository.RoleRepository,
	auditRepo repository.AuditRepository,
	emailService EmailService,
	logger logging.Logger,
	baseURL string,
) InvitationService {
	return &invitationService{
		membershipRepo:   membershipRepo,
		organizationRepo: organizationRepo,
		userRepo:         userRepo,
		roleRepo:         roleRepo,
		auditRepo:        auditRepo,
		emailService:     emailService,
		logger:           logger,
		baseURL:          baseURL,
	}
}

// CreateInvitation creates a new invitation
func (s *invitationService) CreateInvitation(ctx context.Context, input CreateInvitationInput) (*model.Invitation, error) {
	// Validate organization exists
	org, err := s.organizationRepo.GetByID(ctx, input.OrganizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	// Validate role exists
	role, err := s.roleRepo.GetByID(ctx, input.RoleID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Role not found")
	}

	// Validate inviter exists
	inviter, err := s.userRepo.GetByID(ctx, input.InvitedBy)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Inviter not found")
	}

	// Check if user is already a member
	existingUser, err := s.userRepo.GetByEmail(ctx, input.Email, user.UserTypeExternal, &input.OrganizationID)
	if err == nil {
		// User exists, check for existing membership
		exists, err := s.membershipRepo.ExistsByUserAndOrganization(ctx, existingUser.ID, input.OrganizationID)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to check existing membership")
		}
		if exists {
			return nil, errors.New(errors.CodeConflict, "User is already a member of this organization")
		}
	}

	// Check for existing pending invitation
	pendingInvitations, err := s.membershipRepo.GetPendingInvitations(ctx, input.OrganizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to check pending invitations")
	}

	for _, invitation := range pendingInvitations {
		if invitation.Email == input.Email && invitation.Status == membership.StatusPending {
			return nil, errors.New(errors.CodeConflict, "Invitation already exists for this email")
		}
	}

	// Check organization member limits
	canAdd, err := s.organizationRepo.CanAddExternalUser(ctx, input.OrganizationID)
	if err != nil {
		return nil, err
	}
	if !canAdd {
		return nil, errors.New(errors.CodeBadRequest, "Organization has reached member limit")
	}

	// Generate invitation token
	token, err := s.generateInvitationToken()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to generate invitation token")
	}

	// Set default expiration (7 days)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	if input.ExpiresAt != nil {
		expiresAt = *input.ExpiresAt
	}

	// Create invitation through membership repository
	createInput := repository.CreateInvitationInput{
		OrganizationID: input.OrganizationID,
		Email:          input.Email,
		RoleID:         input.RoleID,
		InvitedBy:      input.InvitedBy,
		Token:          &token,
		Status:         membership.StatusPending,
		ExpiresAt:      expiresAt,
		Message:        input.Message,
		RedirectURL:    input.RedirectURL,
		CustomFields:   input.CustomFields,
	}

	entMembership, err := s.membershipRepo.CreateInvitation(ctx, createInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create invitation")
	}

	// Convert to model
	invitation := s.entToInvitationModel(entMembership, org, role, inviter)

	// Send invitation email if requested
	if input.SendEmail {
		err = s.SendInvitation(ctx, entMembership.ID)
		if err != nil {
			s.logger.Error("Failed to send invitation email", logging.Error(err))
		}
	}

	// Create audit log
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &input.OrganizationID,
		UserID:         &input.InvitedBy,
		Action:         "invitation.created",
		ResourceType:   "invitation",
		ResourceID:     &entMembership.ID,
		Status:         "success",
		Details: map[string]interface{}{
			"invitee_email":     input.Email,
			"organization_id":   input.OrganizationID,
			"role_id":           input.RoleID,
			"role_name":         role.Name,
			"inviter_email":     inviter.Email,
			"organization_name": org.Name,
			"expires_at":        expiresAt,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for invitation", logging.Error(err))
	}

	return invitation, nil
}

// SendInvitation sends an invitation email
func (s *invitationService) SendInvitation(ctx context.Context, invitationID xid.ID) error {
	// Get invitation details
	entMembership, err := s.membershipRepo.GetByID(ctx, invitationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Invitation not found")
	}

	if entMembership.Status != membership.StatusPending {
		return errors.New(errors.CodeBadRequest, "Invitation is not pending")
	}

	// Get related data
	org, err := s.organizationRepo.GetByID(ctx, entMembership.OrganizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to get organization")
	}

	role, err := s.roleRepo.GetByID(ctx, entMembership.RoleID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to get role")
	}

	var inviter *ent.User
	if !entMembership.InvitedBy.IsNil() {
		inviter, err = s.userRepo.GetByID(ctx, entMembership.InvitedBy)
		if err != nil {
			s.logger.Error("Failed to get inviter", logging.Error(err))
		}
	}

	// Convert to model
	invitation := s.entToInvitationModel(entMembership, org, role, inviter)

	// Generate invitation link
	invitationLink, err := s.GetInvitationLink(ctx, entMembership.InvitationToken)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to generate invitation link")
	}

	// Send email
	err = s.emailService.SendInvitationEmail(ctx, entMembership.Email, invitation, invitationLink)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to send invitation email")
	}

	// Update last sent timestamp (if we tracked this)
	// For now, we'll create an audit log
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &entMembership.OrganizationID,
		Action:         "invitation.sent",
		ResourceType:   "invitation",
		ResourceID:     &invitationID,
		Status:         "success",
		Details: map[string]interface{}{
			"invitee_email":     entMembership.Email,
			"organization_name": org.Name,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for invitation sent", logging.Error(err))
	}

	return nil
}

// AcceptInvitation accepts an invitation
func (s *invitationService) AcceptInvitation(ctx context.Context, token string, acceptedBy xid.ID) (*model.Membership, error) {
	// Get invitation by token
	entMembership, err := s.membershipRepo.GetByInvitationToken(ctx, token)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Invitation not found")
	}

	// Validate invitation
	if entMembership.Status != membership.StatusPending {
		return nil, errors.New(errors.CodeBadRequest, "Invitation is not pending")
	}

	if time.Now().After(*entMembership.ExpiresAt) {
		return nil, errors.New(errors.CodeBadRequest, "Invitation has expired")
	}

	// Check if accepting user matches invitation email
	acceptingUser, err := s.userRepo.GetByID(ctx, acceptedBy)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Accepting user not found")
	}

	if acceptingUser.Email != entMembership.Email {
		return nil, errors.New(errors.CodeBadRequest, "Invitation email does not match accepting user email")
	}

	// Accept invitation
	acceptedMembership, err := s.membershipRepo.AcceptInvitation(ctx, token, acceptedBy)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to accept invitation")
	}

	// Update organization user count
	err = s.organizationRepo.UpdateUserCounts(ctx, entMembership.OrganizationID, repository.UpdateUserCountsInput{
		ExternalUsersDelta: 1,
	})
	if err != nil {
		s.logger.Error("Failed to update organization user count", logging.Error(err))
	}

	// Create audit log
	org, _ := s.organizationRepo.GetByID(ctx, entMembership.OrganizationID)
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &entMembership.OrganizationID,
		UserID:         &acceptedBy,
		Action:         "invitation.accepted",
		ResourceType:   "invitation",
		ResourceID:     &entMembership.ID,
		Status:         "success",
		Details: map[string]interface{}{
			"invitee_email":     entMembership.Email,
			"organization_id":   entMembership.OrganizationID,
			"organization_name": org.Name,
			"accepted_by":       acceptedBy,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for invitation acceptance", logging.Error(err))
	}

	// Convert to model membership
	mem := &model.Membership{
		Base: model.Base{
			ID:        acceptedMembership.ID,
			CreatedAt: acceptedMembership.CreatedAt,
			UpdatedAt: acceptedMembership.UpdatedAt,
		},
		UserID:           acceptedMembership.UserID,
		OrganizationID:   acceptedMembership.OrganizationID,
		RoleID:           acceptedMembership.RoleID,
		Status:           acceptedMembership.Status,
		JoinedAt:         acceptedMembership.JoinedAt,
		InvitedBy:        &acceptedMembership.InvitedBy,
		IsBillingContact: acceptedMembership.IsBillingContact,
		IsPrimaryContact: acceptedMembership.IsPrimaryContact,
		CustomFields:     acceptedMembership.CustomFields,
	}

	return mem, nil
}

// DeclineInvitation declines an invitation
func (s *invitationService) DeclineInvitation(ctx context.Context, token string, reason string) error {
	// Get invitation by token
	entMembership, err := s.membershipRepo.GetByInvitationToken(ctx, token)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Invitation not found")
	}

	// Validate invitation
	if entMembership.Status != membership.StatusPending {
		return errors.New(errors.CodeBadRequest, "Invitation is not pending")
	}

	// Decline invitation
	err = s.membershipRepo.DeclineInvitation(ctx, token)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to decline invitation")
	}

	// Create audit log
	org, _ := s.organizationRepo.GetByID(ctx, entMembership.OrganizationID)
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &entMembership.OrganizationID,
		Action:         "invitation.declined",
		ResourceType:   "invitation",
		ResourceID:     &entMembership.ID,
		Status:         "success",
		Details: map[string]interface{}{
			"invitee_email":     entMembership.Email,
			"organization_id":   entMembership.OrganizationID,
			"organization_name": org.Name,
			"decline_reason":    reason,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for invitation decline", logging.Error(err))
	}

	return nil
}

// ResendInvitation resends an invitation
func (s *invitationService) ResendInvitation(ctx context.Context, invitationID xid.ID) error {
	// Get invitation
	entMembership, err := s.membershipRepo.GetByID(ctx, invitationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Invitation not found")
	}

	if entMembership.Status != membership.StatusPending {
		return errors.New(errors.CodeBadRequest, "Invitation is not pending")
	}

	// Generate new token and extend expiration
	newToken, err := s.generateInvitationToken()
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to generate new token")
	}

	newExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	// Update invitation
	_, err = s.membershipRepo.ResendInvitation(ctx, invitationID, newToken, newExpiresAt)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to update invitation")
	}

	// Send invitation email
	err = s.SendInvitation(ctx, invitationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to send invitation email")
	}

	// Create audit log
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &entMembership.OrganizationID,
		Action:         "invitation.resent",
		ResourceType:   "invitation",
		ResourceID:     &invitationID,
		Status:         "success",
		Details: map[string]interface{}{
			"invitee_email":  entMembership.Email,
			"new_expires_at": newExpiresAt,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for invitation resend", logging.Error(err))
	}

	return nil
}

// CancelInvitation cancels an invitation
func (s *invitationService) CancelInvitation(ctx context.Context, invitationID xid.ID, reason string) error {
	// Get invitation
	entMembership, err := s.membershipRepo.GetByID(ctx, invitationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Invitation not found")
	}

	if entMembership.Status != membership.StatusPending {
		return errors.New(errors.CodeBadRequest, "Invitation is not pending")
	}

	// Delete invitation
	err = s.membershipRepo.Delete(ctx, invitationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to cancel invitation")
	}

	// Create audit log
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &entMembership.OrganizationID,
		Action:         "invitation.cancelled",
		ResourceType:   "invitation",
		ResourceID:     &invitationID,
		Status:         "success",
		Details: map[string]interface{}{
			"invitee_email":       entMembership.Email,
			"cancellation_reason": reason,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for invitation cancellation", logging.Error(err))
	}

	return nil
}

// GetInvitation gets an invitation by ID
func (s *invitationService) GetInvitation(ctx context.Context, invitationID xid.ID) (*model.Invitation, error) {
	entMembership, err := s.membershipRepo.GetByID(ctx, invitationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Invitation not found")
	}

	// Get related data
	org, err := s.organizationRepo.GetByID(ctx, entMembership.OrganizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get organization")
	}

	role, err := s.roleRepo.GetByID(ctx, entMembership.RoleID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get role")
	}

	var inviter *ent.User
	if !entMembership.InvitedBy.IsNil() {
		inviter, _ = s.userRepo.GetByID(ctx, entMembership.InvitedBy)
	}

	return s.entToInvitationModel(entMembership, org, role, inviter), nil
}

// GetInvitationByToken gets an invitation by token
func (s *invitationService) GetInvitationByToken(ctx context.Context, token string) (*model.Invitation, error) {
	entMembership, err := s.membershipRepo.GetByInvitationToken(ctx, token)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Invitation not found")
	}

	// Get related data
	org, err := s.organizationRepo.GetByID(ctx, entMembership.OrganizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get organization")
	}

	role, err := s.roleRepo.GetByID(ctx, entMembership.RoleID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get role")
	}

	var inviter *ent.User
	if !entMembership.InvitedBy.IsNil() {
		inviter, _ = s.userRepo.GetByID(ctx, entMembership.InvitedBy)
	}

	return s.entToInvitationModel(entMembership, org, role, inviter), nil
}

// ListInvitations lists invitations for an organization
func (s *invitationService) ListInvitations(ctx context.Context, organizationID xid.ID, params model.ListInvitationsParams) (*model.InvitationListResponse, error) {
	// Convert params
	repoParams := repository.ListMembershipsParams{
		PaginationParams: params.PaginationParams,
		Search:           params.Search,
	}

	if params.Status.IsSet {
		sta := params.Status.Value
		repoParams.Status = (*membership.Status)(&sta)
	}

	result, err := s.membershipRepo.ListByOrganization(ctx, organizationID, repoParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list invitations")
	}

	// Filter only invitations (pending status)
	invitations := make([]model.InvitationSummary, 0)
	for _, entMembership := range result.Data {
		if entMembership.Status == membership.StatusPending {
			invitations = append(invitations, s.entToInvitationSummary(entMembership))
		}
	}

	return &model.InvitationListResponse{
		Data:       invitations,
		Pagination: result.Pagination,
	}, nil
}

// ListPendingInvitations lists pending invitations for an organization
func (s *invitationService) ListPendingInvitations(ctx context.Context, organizationID xid.ID) ([]*model.Invitation, error) {
	entMemberships, err := s.membershipRepo.GetPendingInvitations(ctx, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list pending invitations")
	}

	invitations := make([]*model.Invitation, len(entMemberships))
	for i, entMembership := range entMemberships {
		// Get related data for each invitation
		org, _ := s.organizationRepo.GetByID(ctx, entMembership.OrganizationID)
		role, _ := s.roleRepo.GetByID(ctx, entMembership.RoleID)
		var inviter *ent.User
		if !entMembership.InvitedBy.IsNil() {
			inviter, _ = s.userRepo.GetByID(ctx, entMembership.InvitedBy)
		}

		invitations[i] = s.entToInvitationModel(entMembership, org, role, inviter)
	}

	return invitations, nil
}

// ListUserInvitations lists invitations for a user by email
func (s *invitationService) ListUserInvitations(ctx context.Context, email string, params model.ListInvitationsParams) (*model.InvitationListResponse, error) {
	// This would require a different repository method to search by email
	// For now, return empty result
	return &model.InvitationListResponse{
		Data:       []model.InvitationSummary{},
		Pagination: &model.Pagination{},
	}, nil
}

// CreateBulkInvitations creates multiple invitations at once
func (s *invitationService) CreateBulkInvitations(ctx context.Context, organizationID xid.ID, invitations []BulkInvitationInput) (*model.BulkInvitationResponse, error) {
	response := &model.BulkInvitationResponse{
		SuccessCount: 0,
		FailureCount: 0,
		Invitations:  []model.InvitationSummary{},
		Errors:       []model.BulkInvitationError{},
	}

	// Get the inviter from context (this would typically come from the authenticated user)
	// For now, we'll need to pass this as a parameter or get from context
	inviterID := xid.New() // This should come from authenticated user context

	for _, invInput := range invitations {
		createInput := CreateInvitationInput{
			OrganizationID: organizationID,
			Email:          invInput.Email,
			RoleID:         invInput.RoleID,
			InvitedBy:      inviterID,
			Message:        invInput.Message,
			CustomFields:   invInput.CustomFields,
			SendEmail:      true,
		}

		invitation, err := s.CreateInvitation(ctx, createInput)
		if err != nil {
			response.FailureCount++
			response.Errors = append(response.Errors, model.BulkInvitationError{
				Email:  invInput.Email,
				Error:  fmt.Sprintf("Failed to invite %s: %s", invInput.Email, err.Error()),
				RoleID: invInput.RoleID,
				Field:  invInput.Message,
			})
		} else {
			response.SuccessCount++
			response.Invitations = append(response.Invitations, model.InvitationSummary{
				ID:             invitation.ID,
				Email:          invitation.Email,
				OrganizationID: invitation.OrganizationID,
				Status:         invitation.Status,
				CreatedAt:      invitation.CreatedAt,
				ExpiresAt:      invitation.ExpiresAt,
			})
		}
	}

	return response, nil
}

// ResendBulkInvitations resends multiple invitations
func (s *invitationService) ResendBulkInvitations(ctx context.Context, invitationIDs []xid.ID) (*model.BulkInvitationResponse, error) {
	response := &model.BulkInvitationResponse{
		SuccessCount: 0,
		FailureCount: 0,
		Errors:       []model.BulkInvitationError{},
	}

	for _, invitationID := range invitationIDs {
		err := s.ResendInvitation(ctx, invitationID)
		if err != nil {
			response.FailureCount++
			response.Errors = append(response.Errors, model.BulkInvitationError{
				InvitationID: invitationID,
				Error:        fmt.Sprintf("Failed to resend invitation %s: %s", invitationID, err.Error()),
			})
		} else {
			response.SuccessCount++
		}
	}

	return response, nil
}

// CancelBulkInvitations cancels multiple invitations
func (s *invitationService) CancelBulkInvitations(ctx context.Context, invitationIDs []xid.ID, reason string) (*model.BulkInvitationResponse, error) {
	response := &model.BulkInvitationResponse{
		SuccessCount: 0,
		FailureCount: 0,
		Errors:       []model.BulkInvitationError{},
	}

	for _, invitationID := range invitationIDs {
		err := s.CancelInvitation(ctx, invitationID, reason)
		if err != nil {
			response.FailureCount++
			response.Errors = append(response.Errors, model.BulkInvitationError{
				InvitationID: invitationID,
				Error:        fmt.Sprintf("Failed to cancel invitation %s: %s", invitationID, err.Error()),
			})
		} else {
			response.SuccessCount++
		}
	}

	return response, nil
}

// GetInvitationStats gets invitation statistics
func (s *invitationService) GetInvitationStats(ctx context.Context, organizationID xid.ID) (*model.InvitationStats, error) {
	stats, err := s.membershipRepo.GetInvitationStats(ctx, organizationID, 30) // Last 30 days
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get invitation stats")
	}

	return &model.InvitationStats{
		TotalSent:     stats.TotalInvites,
		TotalAccepted: stats.AcceptedInvites,
		// TotalDeclined:  stats.TotalDeclined,
		TotalPending:   stats.PendingInvites,
		TotalExpired:   stats.ExpiredInvites,
		AcceptanceRate: stats.AcceptanceRate,
		// RecentSent:     stats.RecentSent,
	}, nil
}

// GetInvitationMetrics gets invitation metrics for a period
func (s *invitationService) GetInvitationMetrics(ctx context.Context, organizationID xid.ID, period string) (*model.InvitationMetrics, error) {
	// This would calculate metrics over the specified period
	stats, err := s.GetInvitationStats(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	return &model.InvitationMetrics{
		Period:          period,
		TotalSent:       stats.TotalSent,
		TotalAccepted:   stats.TotalAccepted,
		AcceptanceRate:  stats.AcceptanceRate,
		AvgResponseTime: 24.0, // Would calculate actual average
	}, nil
}

// ValidateInvitationToken validates an invitation token
func (s *invitationService) ValidateInvitationToken(ctx context.Context, token string) (*model.Invitation, error) {
	invitation, err := s.GetInvitationByToken(ctx, token)
	if err != nil {
		return nil, err
	}

	if invitation.Status != "pending" {
		return nil, errors.New(errors.CodeBadRequest, "Invitation is not pending")
	}

	if time.Now().After(*invitation.ExpiresAt) {
		return nil, errors.New(errors.CodeBadRequest, "Invitation has expired")
	}

	return invitation, nil
}

// IsInvitationValid checks if an invitation token is valid
func (s *invitationService) IsInvitationValid(ctx context.Context, token string) (bool, error) {
	_, err := s.ValidateInvitationToken(ctx, token)
	return err == nil, nil
}

// CleanupExpiredInvitations removes expired invitations
func (s *invitationService) CleanupExpiredInvitations(ctx context.Context) (int, error) {
	count, err := s.membershipRepo.CleanupExpiredInvitations(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to cleanup expired invitations")
	}

	// Create audit log for cleanup
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		Action:       "invitations.cleanup_expired",
		ResourceType: "invitation",
		Status:       "success",
		Details: map[string]interface{}{
			"cleanup_count": count,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for invitation cleanup", logging.Error(err))
	}

	return count, nil
}

// GetInvitationLink generates an invitation link
func (s *invitationService) GetInvitationLink(ctx context.Context, token string) (string, error) {
	return fmt.Sprintf("%s/accept-invitation?token=%s", s.baseURL, token), nil
}

// Helper methods

// generateInvitationToken generates a secure random token
func (s *invitationService) generateInvitationToken() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// entToInvitationModel converts ent.Membership to model.Invitation
func (s *invitationService) entToInvitationModel(entMembership *ent.Membership, org *ent.Organization, role *ent.Role, inviter *ent.User) *model.Invitation {
	invitation := &model.Invitation{
		Base: model.Base{
			ID:        entMembership.ID,
			CreatedAt: entMembership.CreatedAt,
			UpdatedAt: entMembership.UpdatedAt,
		},
		Email:          entMembership.Email,
		OrganizationID: entMembership.OrganizationID,
		RoleID:         entMembership.RoleID,
		Status:         string(entMembership.Status),
		ExpiresAt:      entMembership.ExpiresAt,
		Token:          entMembership.InvitationToken,
		CustomFields:   entMembership.CustomFields,
	}

	if org != nil {
		invitation.Organization = &model.OrganizationSummary{
			ID:   org.ID,
			Name: org.Name,
			Slug: org.Slug,
		}
	}

	if role != nil {
		invitation.Role = &model.RoleSummary{
			ID:          role.ID,
			Name:        role.Name,
			DisplayName: role.DisplayName,
		}
	}

	if inviter != nil {
		invitation.InvitedBy = &inviter.ID
		invitation.Inviter = &model.UserSummary{
			ID:        inviter.ID,
			Email:     inviter.Email,
			FirstName: inviter.FirstName,
			LastName:  inviter.LastName,
		}
	}

	return invitation
}

// entToInvitationSummary converts ent.Membership to model.InvitationSummary
func (s *invitationService) entToInvitationSummary(entMembership *ent.Membership) model.InvitationSummary {
	return model.InvitationSummary{
		ID:             entMembership.ID,
		Email:          entMembership.Email,
		OrganizationID: entMembership.OrganizationID,
		RoleID:         entMembership.RoleID,
		Status:         string(entMembership.Status),
		CreatedAt:      entMembership.CreatedAt,
		ExpiresAt:      entMembership.ExpiresAt,
		InvitedBy:      &entMembership.InvitedBy,
	}
}
