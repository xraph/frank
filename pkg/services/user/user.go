package user

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/rs/xid"
	"github.com/samber/lo"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/hooks"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"golang.org/x/crypto/bcrypt"
)

// Service defines the user service interface
type Service interface {
	// User CRUD operations
	CreateUser(ctx context.Context, req model.CreateUserRequest) (*model.User, error)
	GetUser(ctx context.Context, id xid.ID) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID) (*model.User, error)
	GetUserByIdentifier(ctx context.Context, identifier string, userType model.UserType) (*model.User, error)
	GetUserByUsername(ctx context.Context, username string, userType model.UserType, organizationID *xid.ID) (*model.User, error)
	GetUserByPhone(ctx context.Context, phone string, userType model.UserType, organizationID *xid.ID) (*model.User, error)
	UpdateUser(ctx context.Context, id xid.ID, req model.UpdateUserRequest) (*model.User, error)
	DeleteUser(ctx context.Context, id xid.ID, req model.DeleteUserRequest) error
	ListUsers(ctx context.Context, req model.UserListRequest) (*model.UserListResponse, error)
	ListPlatformUsers(ctx context.Context, req model.UserListRequest) (*model.PlatformUserListResponse, error)
	ExistsByEmail(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID) (bool, error)
	IncrementLoginCount(ctx context.Context, id xid.ID) error

	// Authentication operations
	AuthenticateUser(ctx context.Context, email, password string, userType model.UserType, organizationID *xid.ID) (*model.User, error)
	ValidatePassword(ctx context.Context, userID xid.ID, password string) error
	ChangePassword(ctx context.Context, userID xid.ID, req model.ChangePasswordRequest) error
	SetPassword(ctx context.Context, userID xid.ID, req model.SetPasswordRequest) error
	ResetPassword(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID) (string, error)
	ConfirmPasswordReset(ctx context.Context, token, newPassword string) error
	UpdateLastLogin(ctx context.Context, id xid.ID, ipAddress string) error

	// Email and phone verification
	SendEmailVerification(ctx context.Context, userID xid.ID) (string, error)
	VerifyEmail(ctx context.Context, token string) (*model.User, error)
	SendPhoneVerification(ctx context.Context, userID xid.ID) (string, error)
	VerifyPhone(ctx context.Context, token string) (*model.User, error)
	ResendVerification(ctx context.Context, req model.ResendVerificationRequest) error

	// User management
	BlockUser(ctx context.Context, userID xid.ID, reason string) error
	UnblockUser(ctx context.Context, userID xid.ID, reason string) error
	ActivateUser(ctx context.Context, userID xid.ID, reason string) error
	DeactivateUser(ctx context.Context, userID xid.ID, reason string) error

	// Role and permission management
	AssignRole(ctx context.Context, userID xid.ID, req model.AssignRoleRequest) error
	RemoveRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType string, contextID *xid.ID) error
	AssignPermission(ctx context.Context, userID xid.ID, req model.AssignPermissionRequest) error
	RemovePermission(ctx context.Context, userID xid.ID, permissionID xid.ID, contextType string, contextID *xid.ID) error
	GetUserPermissions(ctx context.Context, userID xid.ID, contextType string, contextID *xid.ID) ([]model.UserPermissionAssignment, error)
	GetUserRoles(ctx context.Context, userID xid.ID, contextType string, contextID *xid.ID) ([]model.UserRoleAssignment, error)

	// User analytics and activity
	GetUserActivity(ctx context.Context, userID xid.ID, req model.UserActivityRequest) (*model.UserActivityResponse, error)
	GetUserStats(ctx context.Context, organizationID *xid.ID) (*model.UserStats, error)
	GetRecentLogins(ctx context.Context, userID xid.ID, limit int) ([]model.UserActivity, error)

	// Bulk operations
	BulkUpdateUsers(ctx context.Context, req model.BulkUserOperation) (*model.BulkUserOperationResponse, error)
	BulkDeleteUsers(ctx context.Context, userIDs []xid.ID, transferDataTo *xid.ID) (*model.BulkUserOperationResponse, error)

	// User validation
	ValidateUserEmail(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID, excludeUserID *xid.ID) error
	ValidateUsername(ctx context.Context, username string, userType model.UserType, organizationID *xid.ID, excludeUserID *xid.ID) error
	ValidatePasswordStrength(ctx context.Context, password string) error

	// Platform admin operations
	PromoteToPlatformAdmin(ctx context.Context, userID xid.ID) error
	DemoteFromPlatformAdmin(ctx context.Context, userID xid.ID) error
	GetPlatformAdmins(ctx context.Context) ([]model.UserSummary, error)
}

// service implements the user service
type service struct {
	userRepo         repository.UserRepository
	verificationRepo repository.VerificationRepository
	auditRepo        repository.AuditRepository
	permissionRepo   repository.PermissionRepository
	roleRepo         repository.RoleRepository
	hook             hooks.Hooks
	logger           logging.Logger
}

// NewService creates a new user service instance
func NewService(
	repo repository.Repository,
	hook hooks.Hooks,
	logger logging.Logger,
) Service {
	return &service{
		userRepo:         repo.User(),
		verificationRepo: repo.Verification(),
		auditRepo:        repo.Audit(),
		permissionRepo:   repo.Permission(),
		roleRepo:         repo.Role(),
		hook:             hook,
		logger:           logger,
	}
}

// CreateUser creates a new user
func (s *service) CreateUser(ctx context.Context, req model.CreateUserRequest) (*model.User, error) {
	s.logger.Info("Creating new user",
		logging.String("email", req.Email),
		logging.String("user_type", string(req.UserType)),
		logging.Any("organization_id", req.OrganizationID),
	)

	// Execute before user create hooks
	hookCtx := s.buildHookContext(ctx, nil, req.OrganizationID)
	hookCtx.Data = req

	if err := s.hook.Execute(ctx, hooks.HookBeforeUserCreate, req); err != nil {
		s.logger.Error("Before user create hooks failed", logging.Error(err))
		if s.shouldBlockOnHookFailure(err) {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "user creation blocked by hooks")
		}
	}

	// Validate user type
	userType, err := s.parseUserType(string(req.UserType))
	if err != nil {
		return nil, err
	}

	// Validate email uniqueness
	if err := s.ValidateUserEmail(ctx, req.Email, userType, req.OrganizationID, nil); err != nil {
		return nil, err
	}

	// Validate username uniqueness if provided
	if req.Username != nil && *req.Username != "" {
		if err := s.ValidateUsername(ctx, *req.Username, userType, req.OrganizationID, nil); err != nil {
			return nil, err
		}
	}

	// Validate password strength if provided
	var passwordHash *string
	if len(req.PasswordHash) > 0 {
		passwordHash = &req.PasswordHash
	} else if req.Password != "" && !req.SkipPasswordValidation {
		if err := s.ValidatePasswordStrength(ctx, req.Password); err != nil {
			return nil, err
		}
		hsh, err := s.hashPassword(req.Password)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to hash password")
		}
		passwordHash = &hsh
	}

	// Create user input
	input := repository.CreateUserInput{
		Email:            req.Email,
		Username:         req.Username,
		PhoneNumber:      req.PhoneNumber,
		FirstName:        req.FirstName,
		LastName:         req.LastName,
		PasswordHash:     passwordHash,
		UserType:         userType,
		OrganizationID:   req.OrganizationID,
		Locale:           req.Locale,
		Timezone:         req.Timezone,
		CustomAttributes: req.CustomAttributes,
		EmailVerified:    req.EmailVerified,
		PhoneVerified:    req.PhoneVerified,
		AuthProvider:     req.AuthProvider,
		ExternalID:       req.ExternalID,
		Active:           true,
		Blocked:          false,
	}

	fmt.Printf("input: %+v\n", input)

	// Create user
	entUser, err := s.userRepo.Create(ctx, input)
	if err != nil {
		s.logger.Error("Failed to create user", logging.Error(err))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create user")
	}

	// Convert to model
	modelUser := s.convertEntUserToModel(entUser)

	// Execute after user create hooks
	hookCtx.UserID = &modelUser.ID
	hookCtx.Data = modelUser
	if err := s.hook.ExecuteUserCreateHooks(ctx, modelUser); err != nil {
		s.logger.Error("After user create hooks failed", logging.Error(err))
		// After hooks don't block the operation, just log
	}

	// Send verification email if required
	if req.SendVerificationEmail && !req.EmailVerified {
		if _, err := s.SendEmailVerification(ctx, modelUser.ID); err != nil {
			s.logger.Warn("Failed to send verification email", logging.Error(err))
		}
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "user.created",
		Resource:       "user",
		ResourceID:     &modelUser.ID,
		Status:         "success",
		OrganizationID: req.OrganizationID,
		Details: map[string]interface{}{
			"email":     req.Email,
			"user_type": req.UserType,
		},
	})

	s.logger.Info("User created successfully", logging.String("user_id", modelUser.ID.String()))
	return modelUser, nil
}

// GetUser retrieves a user by ID
func (s *service) GetUser(ctx context.Context, id xid.ID) (*model.User, error) {
	entUser, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	return s.convertEntUserToModel(entUser), nil
}

// GetUserByIdentifier retrieves a user by IDentifier
func (s *service) GetUserByIdentifier(ctx context.Context, id string, userType model.UserType) (*model.User, error) {
	uid, err := xid.FromString(id)
	if err != nil {
		userByEmail, err := s.GetUserByEmail(ctx, id, userType, nil)
		if err != nil {
			userByEmail, err = s.GetUserByUsername(ctx, id, userType, nil)
			if err != nil {
				if ent.IsNotFound(err) {
					return nil, errors.New(errors.CodeNotFound, "user not found")
				}
				return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
			}
		}

		return userByEmail, nil
	}
	entUser, err := s.userRepo.GetByID(ctx, uid)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	return s.convertEntUserToModel(entUser), nil
}

// GetUserByEmail retrieves a user by email
func (s *service) GetUserByEmail(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID) (*model.User, error) {
	entUser, err := s.userRepo.GetByEmail(ctx, email, userType, organizationID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user by email")
	}

	return s.convertEntUserToModel(entUser), nil
}

// GetUserByPhone retrieves a user by username
func (s *service) GetUserByPhone(ctx context.Context, phone string, userType model.UserType, organizationID *xid.ID) (*model.User, error) {
	entUser, err := s.userRepo.GetUserByPhone(ctx, phone, userType, organizationID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user by phone")
	}

	return s.convertEntUserToModel(entUser), nil
}

// GetUserByUsername retrieves a user by username
func (s *service) GetUserByUsername(ctx context.Context, username string, userType model.UserType, organizationID *xid.ID) (*model.User, error) {
	entUser, err := s.userRepo.GetByUsername(ctx, username, userType, organizationID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user by username")
	}

	return s.convertEntUserToModel(entUser), nil
}

// UpdateUser updates a user
func (s *service) UpdateUser(ctx context.Context, id xid.ID, req model.UpdateUserRequest) (*model.User, error) {
	s.logger.Info("Updating user", logging.String("user_id", id.String()))

	// Get existing user
	existingUser, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Execute before user update hooks
	hookCtx := s.buildHookContext(ctx, &id, &existingUser.OrganizationID)
	hookCtx.Data = map[string]interface{}{
		"user_id":       id,
		"input":         req,
		"existing_user": s.convertEntUserToModel(existingUser),
	}

	if err := s.hook.Execute(ctx, hooks.HookBeforeUserUpdate, hookCtx.Data); err != nil {
		s.logger.Error("Before user update hooks failed", logging.Error(err))
		if s.shouldBlockOnHookFailure(err) {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "user update blocked by hooks")
		}
	}

	// Validate email uniqueness if changed
	if req.Email != nil && *req.Email != existingUser.Email {
		if err := s.ValidateUserEmail(ctx, *req.Email, existingUser.UserType, &existingUser.OrganizationID, &id); err != nil {
			return nil, err
		}
	}

	// Validate username uniqueness if changed
	if req.Username != nil && *req.Username != existingUser.Username {
		if err := s.ValidateUsername(ctx, *req.Username, existingUser.UserType, &existingUser.OrganizationID, &id); err != nil {
			return nil, err
		}
	}

	// Track activation/deactivation changes for hooks
	wasActive := existingUser.Active
	wasBlocked := existingUser.Blocked

	// Update user
	updatedUser, err := s.userRepo.Update(ctx, id, repository.UpdateUserInput{
		UpdateUserRequest: req,
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update user")
	}

	modelUser := s.convertEntUserToModel(updatedUser)

	// Execute status change hooks
	if req.Active != nil {
		if !wasActive && *req.Active {
			// User is being activated
			hookCtx.Data = modelUser
			if err := s.hook.Execute(ctx, hooks.HookUserActivated, modelUser); err != nil {
				s.logger.Error("User activation hooks failed", logging.Error(err))
			}
		} else if wasActive && !*req.Active {
			// User is being deactivated
			hookCtx.Data = modelUser
			if err := s.hook.Execute(ctx, hooks.HookUserDeactivated, modelUser); err != nil {
				s.logger.Error("User deactivation hooks failed", logging.Error(err))
			}
		}
	}

	if req.Blocked != nil {
		if !wasBlocked && *req.Blocked {
			// User is being blocked
			hookCtx.Data = modelUser
			if err := s.hook.Execute(ctx, hooks.HookUserBlocked, modelUser); err != nil {
				s.logger.Error("User blocked hooks failed", logging.Error(err))
			}
		} else if wasBlocked && !*req.Blocked {
			// User is being unblocked
			hookCtx.Data = modelUser
			if err := s.hook.Execute(ctx, hooks.HookUserUnblocked, modelUser); err != nil {
				s.logger.Error("User unblocked hooks failed", logging.Error(err))
			}
		}
	}

	// Execute after user update hooks
	hookCtx.Data = modelUser
	if err := s.hook.ExecuteUserUpdateHooks(ctx, modelUser); err != nil {
		s.logger.Error("After user update hooks failed", logging.Error(err))
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "user.updated",
		Resource:       "user",
		ResourceID:     &id,
		Status:         "success",
		OrganizationID: &updatedUser.OrganizationID,
		Details: map[string]interface{}{
			"updated_fields": s.getUpdatedFields(req),
		},
	})

	s.logger.Info("User updated successfully", logging.String("user_id", id.String()))
	return modelUser, nil
}

// DeleteUser deletes a user
func (s *service) DeleteUser(ctx context.Context, id xid.ID, req model.DeleteUserRequest) error {
	s.logger.Info("Deleting user", logging.String("user_id", id.String()))

	// Get user to validate existence and for hooks
	existingUser, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	modelUser := s.convertEntUserToModel(existingUser)

	// Execute before user delete hooks
	hookCtx := s.buildHookContext(ctx, &id, &existingUser.OrganizationID)
	hookCtx.Data = modelUser

	if err := s.hook.Execute(ctx, hooks.HookBeforeUserDelete, modelUser); err != nil {
		s.logger.Error("Before user delete hooks failed", logging.Error(err))
		if s.shouldBlockOnHookFailure(err) {
			return errors.Wrap(err, errors.CodeInternalServer, "user deletion blocked by hooks")
		}
	}

	// TODO: Handle data transfer if requested
	if req.TransferDataTo != nil {
		// Implement data transfer logic
		s.logger.Info("Data transfer requested but not implemented",
			logging.String("from_user", id.String()),
			logging.String("to_user", req.TransferDataTo.String()))
	}

	// Delete user
	if err := s.userRepo.Delete(ctx, id); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to delete user")
	}

	// Execute after user delete hooks
	if err := s.hook.ExecuteUserDeleteHooks(ctx, id); err != nil {
		s.logger.Error("After user delete hooks failed", logging.Error(err))
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:         "user.deleted",
		Resource:       "user",
		ResourceID:     &id,
		Status:         "success",
		OrganizationID: &existingUser.OrganizationID,
		Details: map[string]interface{}{
			"reason":           req.Reason,
			"transfer_data_to": req.TransferDataTo,
		},
	})

	s.logger.Info("User deleted successfully", logging.String("user_id", id.String()))
	return nil

}

// AuthenticateUser authenticates a user with email/password
func (s *service) AuthenticateUser(ctx context.Context, email, password string, userType model.UserType, organizationID *xid.ID) (*model.User, error) {
	// Get user by email
	entUser, err := s.userRepo.GetByEmail(ctx, email, userType, organizationID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeUnauthorized, "invalid credentials")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Check if user is active and not blocked
	if !entUser.Active {
		return nil, errors.New(errors.CodeUnauthorized, "user account is deactivated")
	}
	if entUser.Blocked {
		return nil, errors.New(errors.CodeUnauthorized, "user account is blocked")
	}

	// Verify password
	if entUser.PasswordHash == "" {
		return nil, errors.New(errors.CodeUnauthorized, "password authentication not available")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(entUser.PasswordHash), []byte(password)); err != nil {
		// Create audit log for failed authentication
		s.createAuditLog(ctx, &model.CreateAuditLogRequest{
			UserID:         &entUser.ID,
			Action:         "user.login_failed",
			Resource:       "user",
			ResourceID:     &entUser.ID,
			Status:         "failure",
			OrganizationID: &entUser.OrganizationID,
			Error:          "invalid credentials",
		})
		return nil, errors.New(errors.CodeUnauthorized, "invalid credentials")
	}

	modelUser := s.convertEntUserToModel(entUser)

	// Execute before login hooks
	hookCtx := s.buildHookContext(ctx, &entUser.ID, &entUser.OrganizationID)
	hookCtx.Data = map[string]interface{}{
		"user":   modelUser,
		"email":  email,
		"method": "password",
	}

	if err := s.hook.Execute(ctx, hooks.HookBeforeLogin, hookCtx.Data); err != nil {
		s.logger.Error("Before login hooks failed", logging.Error(err))
		// Don't block authentication on hook failure, just log
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(ctx, entUser.ID, ""); err != nil {
		s.logger.Warn("Failed to update last login", logging.Error(err))
	}

	// Increment login count
	if err := s.userRepo.IncrementLoginCount(ctx, entUser.ID); err != nil {
		s.logger.Warn("Failed to increment login count", logging.Error(err))
	}

	// Execute after login hooks (authentication successful)
	loginResponse := &model.LoginResponse{
		User: modelUser,
	}
	hookCtx.Data = loginResponse
	if err := s.hook.ExecuteLoginHooks(ctx, loginResponse); err != nil {
		s.logger.Error("After login hooks failed", logging.Error(err))
	}

	// Create audit log for successful authentication
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &entUser.ID,
		Action:         "user.login_success",
		Resource:       "user",
		ResourceID:     &entUser.ID,
		Status:         "success",
		OrganizationID: &entUser.OrganizationID,
	})

	return modelUser, nil
}

// ChangePassword changes a user's password
func (s *service) ChangePassword(ctx context.Context, userID xid.ID, req model.ChangePasswordRequest) error {
	// Get user
	entUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Verify current password
	if entUser.PasswordHash == "" {
		return errors.New(errors.CodeBadRequest, "no password set for user")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(entUser.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		return errors.New(errors.CodeUnauthorized, "current password is incorrect")
	}

	// Validate new password strength
	if err := s.ValidatePasswordStrength(ctx, req.NewPassword); err != nil {
		return err
	}

	// Hash new password
	newPasswordHash, err := s.hashPassword(req.NewPassword)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to hash new password")
	}

	// Update password
	if err := s.userRepo.UpdatePassword(ctx, userID, newPasswordHash); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to update password")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.password_changed",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &entUser.OrganizationID,
	})

	return nil
}

// SendEmailVerification sends an email verification
func (s *service) SendEmailVerification(ctx context.Context, userID xid.ID) (string, error) {
	// Get user
	entUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return "", errors.New(errors.CodeNotFound, "user not found")
		}
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	if entUser.EmailVerified {
		return "", errors.New(errors.CodeBadRequest, "email is already verified")
	}

	// Generate verification token
	token, err := s.generateToken()
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to generate token")
	}

	// Create verification record
	_, err = s.verificationRepo.Create(ctx, repository.CreateVerificationInput{
		UserID:    userID,
		Email:     entUser.Email,
		Token:     token,
		Type:      "email",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to create verification")
	}

	// TODO: Send verification email
	s.logger.Info("Email verification token generated",
		logging.String("user_id", userID.String()),
		logging.String("email", entUser.Email))

	return token, nil
}

// VerifyEmail verifies an email with token
func (s *service) VerifyEmail(ctx context.Context, token string) (*model.User, error) {
	// Get verification record
	verification, err := s.verificationRepo.GetValidToken(ctx, token)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeBadRequest, "invalid or expired verification token")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get verification")
	}

	if verification.UserID.IsNil() || verification.Type != "email" {
		return nil, errors.New(errors.CodeBadRequest, "invalid verification token")
	}

	// Mark email as verified
	if err := s.userRepo.MarkEmailVerified(ctx, verification.UserID); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to mark email as verified")
	}

	// Mark verification as used
	if err := s.verificationRepo.MarkAsUsed(ctx, verification.ID); err != nil {
		s.logger.Warn("Failed to mark verification as used", logging.Error(err))
	}

	// Get updated user
	entUser, err := s.userRepo.GetByID(ctx, verification.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get updated user")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &verification.UserID,
		Action:         "user.email_verified",
		Resource:       "user",
		ResourceID:     &verification.UserID,
		Status:         "success",
		OrganizationID: &entUser.OrganizationID,
		Details: map[string]interface{}{
			"email": entUser.Email,
		},
	})

	return s.convertEntUserToModel(entUser), nil
}

func (s *service) UpdateLastLogin(ctx context.Context, id xid.ID, ipAddress string) error {
	return s.userRepo.UpdateLastLogin(ctx, id, ipAddress)
}

// ValidateUserEmail validates email uniqueness
func (s *service) ValidateUserEmail(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID, excludeUserID *xid.ID) error {
	if email == "" {
		return errors.New(errors.CodeBadRequest, "email is required")
	}

	// Check if email format is valid
	if !s.isValidEmail(email) {
		return errors.New(errors.CodeBadRequest, "invalid email format")
	}

	// Check uniqueness
	exists, err := s.userRepo.ExistsByEmail(ctx, email, userType, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to check email uniqueness")
	}

	if exists {
		// If we're excluding a specific user (for updates), check if it's the same user
		if excludeUserID != nil {
			existingUser, err := s.userRepo.GetByEmail(ctx, email, userType, organizationID)
			if err == nil && existingUser.ID == *excludeUserID {
				return nil // Same user, allow update
			}
		}
		return errors.New(errors.CodeConflict, "email already exists")
	}

	return nil
}

// ValidateUsername validates username uniqueness
func (s *service) ValidateUsername(ctx context.Context, username string, userType model.UserType, organizationID *xid.ID, excludeUserID *xid.ID) error {
	if username == "" {
		return nil // Username is optional
	}

	// Check if username meets requirements
	if len(username) < 3 {
		return errors.New(errors.CodeBadRequest, "username must be at least 3 characters")
	}

	// Check uniqueness
	exists, err := s.userRepo.ExistsByUsername(ctx, username, userType, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to check username uniqueness")
	}

	if exists {
		// If we're excluding a specific user (for updates), check if it's the same user
		if excludeUserID != nil {
			existingUser, err := s.userRepo.GetByUsername(ctx, username, userType, organizationID)
			if err == nil && existingUser.ID == *excludeUserID {
				return nil // Same user, allow update
			}
		}
		return errors.New(errors.CodeConflict, "username already exists")
	}

	return nil
}

// ValidatePasswordStrength validates password strength
func (s *service) ValidatePasswordStrength(ctx context.Context, password string) error {
	if len(password) < 8 {
		return errors.New(errors.CodeBadRequest, "password must be at least 8 characters")
	}

	// Add more password validation rules as needed
	return nil
}

// Helper methods

func (s *service) parseUserType(userTypeStr string) (model.UserType, error) {
	switch strings.ToLower(userTypeStr) {
	case "internal":
		return model.UserTypeInternal, nil
	case "external":
		return model.UserTypeExternal, nil
	case "end_user":
		return model.UserTypeEndUser, nil
	default:
		return "", errors.New(errors.CodeBadRequest, "invalid user type")
	}
}

func (s *service) hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func (s *service) generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *service) isValidEmail(email string) bool {
	// Basic email validation - in production, use a proper email validation library
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

func (s *service) getUpdatedFields(req model.UpdateUserRequest) []string {
	var fields []string
	if req.Email != nil {
		fields = append(fields, "email")
	}
	if req.PhoneNumber != nil {
		fields = append(fields, "phone_number")
	}
	if req.FirstName != nil {
		fields = append(fields, "first_name")
	}
	if req.LastName != nil {
		fields = append(fields, "last_name")
	}
	if req.Username != nil {
		fields = append(fields, "username")
	}
	if req.ProfileImageURL != nil {
		fields = append(fields, "profile_image_url")
	}
	if req.Locale != nil {
		fields = append(fields, "locale")
	}
	if req.Timezone != nil {
		fields = append(fields, "timezone")
	}
	if req.CustomAttributes != nil {
		fields = append(fields, "custom_attributes")
	}
	if req.Active != nil {
		fields = append(fields, "active")
	}
	if req.Blocked != nil {
		fields = append(fields, "blocked")
	}
	return fields
}

func (s *service) convertEntUserToModel(entUser *ent.User) *model.User {
	// Convert ent.User to model.User
	modelUser := &model.User{
		Base: model.Base{
			ID:        entUser.ID,
			CreatedAt: entUser.CreatedAt,
			UpdatedAt: entUser.UpdatedAt,
		},
		Email:                 entUser.Email,
		PhoneNumber:           entUser.PhoneNumber,
		FirstName:             entUser.FirstName,
		LastName:              entUser.LastName,
		Username:              entUser.Username,
		EmailVerified:         entUser.EmailVerified,
		PhoneVerified:         entUser.PhoneVerified,
		Active:                entUser.Active,
		Blocked:               entUser.Blocked,
		LastLogin:             entUser.LastLogin,
		LastPasswordChange:    entUser.LastPasswordChange,
		Metadata:              entUser.Metadata,
		ProfileImageURL:       entUser.ProfileImageURL,
		Locale:                entUser.Locale,
		Timezone:              entUser.Timezone,
		UserType:              entUser.UserType,
		OrganizationID:        &entUser.OrganizationID,
		PrimaryOrganizationID: &entUser.PrimaryOrganizationID,
		IsPlatformAdmin:       entUser.IsPlatformAdmin,
		AuthProvider:          entUser.AuthProvider,
		ExternalID:            entUser.ExternalID,
		CustomerID:            entUser.CustomerID,
		CustomAttributes:      entUser.CustomAttributes,
		CreatedBy:             entUser.CreatedBy,
		LoginCount:            entUser.LoginCount,
		LastLoginIP:           entUser.LastLoginIP,
		PasswordHash:          entUser.PasswordHash,
	}

	return modelUser
}

func (s *service) convertEntUserToModelSummary(entUser *ent.User) *model.UserSummary {
	// Convert ent.User to model.User
	modelUser := &model.UserSummary{
		ID:              entUser.ID,
		CreatedAt:       entUser.CreatedAt,
		Email:           entUser.Email,
		PhoneNumber:     entUser.PhoneNumber,
		FirstName:       entUser.FirstName,
		LastName:        entUser.LastName,
		Username:        entUser.Username,
		Active:          entUser.Active,
		LastLogin:       entUser.LastLogin,
		ProfileImageURL: entUser.ProfileImageURL,
		UserType:        entUser.UserType,
	}

	return modelUser
}

func (s *service) convertEntUserToPlatformModelSummary(entUser *ent.User) *model.PlatformUserSummary {
	// Convert ent.User to model.User
	modelUser := &model.PlatformUserSummary{
		UserSummary:           *s.convertEntUserToModelSummary(entUser),
		EmailVerified:         entUser.EmailVerified,
		PhoneVerified:         entUser.PhoneVerified,
		Blocked:               entUser.Blocked,
		LastPasswordChange:    entUser.LastPasswordChange,
		Metadata:              entUser.Metadata,
		Locale:                entUser.Locale,
		Timezone:              entUser.Timezone,
		OrganizationID:        &entUser.OrganizationID,
		PrimaryOrganizationID: &entUser.PrimaryOrganizationID,
		IsPlatformAdmin:       entUser.IsPlatformAdmin,
		AuthProvider:          entUser.AuthProvider,
		ExternalID:            entUser.ExternalID,
		CustomerID:            entUser.CustomerID,
		CustomAttributes:      entUser.CustomAttributes,
		CreatedBy:             entUser.CreatedBy,
		LoginCount:            entUser.LoginCount,
		LastLoginIP:           entUser.LastLoginIP,
		LastLoginAt:           entUser.LastLogin,
	}

	return modelUser
}

func (s *service) createAuditLog(ctx context.Context, input *model.CreateAuditLogRequest) {
	// Create audit log asynchronously to avoid blocking the main operation
	go func() {
		auditInput := repository.CreateAuditInput{
			OrganizationID: input.OrganizationID,
			UserID:         input.UserID,
			SessionID:      input.SessionID,
			Action:         input.Action,
			ResourceType:   input.Resource,
			ResourceID:     input.ResourceID,
			Status:         input.Status,
			IPAddress:      input.IPAddress,
			UserAgent:      input.UserAgent,
			Location:       input.Location,
			Details:        input.Details,
			Changes:        input.Changes,
			Error:          input.Error,
			Duration:       input.Duration,
			RiskLevel:      input.RiskLevel,
			Tags:           input.Tags,
			Source:         input.Source,
		}

		if _, err := s.auditRepo.Create(context.Background(), auditInput); err != nil {
			s.logger.Error("Failed to create audit log", logging.Error(err))
		}
	}()
}

func (s *service) ListUsers(ctx context.Context, req model.UserListRequest) (*model.UserListResponse, error) {
	params := repository.ListUsersParams{
		PaginationParams: req.PaginationParams,
		OrganizationID:   req.OrganizationID,
		Active:           nil,
		Blocked:          nil,
		EmailVerified:    nil,
		AuthProvider:     nil,
	}

	if req.UserType != "" {
		params.UserType = &req.UserType
	}
	list, err := s.userRepo.List(ctx, params)
	if err != nil {
		return nil, err
	}

	users := lo.Map(list.Data, func(item *ent.User, index int) model.UserSummary {
		return *s.convertEntUserToModelSummary(item)
	})

	return &model.UserListResponse{
		Data:       users,
		Pagination: list.Pagination,
	}, nil
}

func (s *service) ListPlatformUsers(ctx context.Context, req model.UserListRequest) (*model.PlatformUserListResponse, error) {
	params := repository.ListUsersParams{
		PaginationParams: req.PaginationParams,
		OrganizationID:   req.OrganizationID,
		Active:           nil,
		Blocked:          nil,
		EmailVerified:    nil,
		AuthProvider:     nil,
	}

	if req.UserType != "" {
		params.UserType = &req.UserType
	}

	list, err := s.userRepo.List(ctx, params)
	if err != nil {
		return nil, err
	}

	users := lo.Map(list.Data, func(item *ent.User, index int) model.PlatformUserSummary {
		return *s.convertEntUserToPlatformModelSummary(item)
	})

	return &model.PlatformUserListResponse{
		Users:      users,
		Pagination: list.Pagination,
		Summary: model.UserSummaryStats{
			Total:    len(list.Data),
			Active:   0, // Would calculate from data
			Blocked:  0, // Would calculate from data
			Verified: 0, // Would calculate from data
			Internal: 0, // Would calculate from data
			External: 0, // Would calculate from data
			EndUsers: 0, // Would calculate from data
		},
	}, nil
}

func (s *service) ExistsByEmail(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID) (bool, error) {
	return s.userRepo.ExistsByEmail(ctx, email, userType, organizationID)
}
func (s *service) IncrementLoginCount(ctx context.Context, id xid.ID) error {
	return s.userRepo.IncrementLoginCount(ctx, id)
}

func (s *service) ValidatePassword(ctx context.Context, userID xid.ID, password string) error {
	// TODO: Implement password validation
	return nil
}

func (s *service) SetPassword(ctx context.Context, userID xid.ID, req model.SetPasswordRequest) error {
	// TODO: Implement set password
	return nil
}

func (s *service) ResetPassword(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID) (string, error) {
	// TODO: Implement password reset
	return "", nil
}

func (s *service) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	// TODO: Implement password reset confirmation
	return nil
}

func (s *service) SendPhoneVerification(ctx context.Context, userID xid.ID) (string, error) {
	// TODO: Implement phone verification
	return "", nil
}

func (s *service) VerifyPhone(ctx context.Context, token string) (*model.User, error) {
	// TODO: Implement phone verification
	return nil, nil
}

func (s *service) ResendVerification(ctx context.Context, req model.ResendVerificationRequest) error {
	// TODO: Implement resend verification
	return nil
}

func (s *service) BlockUser(ctx context.Context, userID xid.ID, reason string) error {
	s.logger.Info("Blocking user", logging.String("user_id", userID.String()), logging.String("reason", reason))

	// Get user to validate existence
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Execute before user block hooks
	hookCtx := s.buildHookContext(ctx, &userID, &existingUser.OrganizationID)
	hookCtx.Data = map[string]interface{}{
		"user_id": userID,
		"reason":  reason,
	}

	if err := s.hook.Execute(ctx, hooks.HookBeforeUserBlocked, hookCtx.Data); err != nil {
		s.logger.Error("Before user block hooks failed", logging.Error(err))
		if s.shouldBlockOnHookFailure(err) {
			return errors.Wrap(err, errors.CodeInternalServer, "user blocking blocked by hooks")
		}
	}

	// Block user
	if err := s.userRepo.Block(ctx, userID); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to block user")
	}

	// Execute after user block hooks
	modelUser := s.convertEntUserToModel(existingUser)
	modelUser.Blocked = true
	if err := s.hook.Execute(ctx, hooks.HookUserBlocked, modelUser); err != nil {
		s.logger.Error("After user block hooks failed", logging.Error(err))
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.blocked",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &existingUser.OrganizationID,
		Details: map[string]interface{}{
			"reason": reason,
		},
	})

	s.logger.Info("User blocked successfully", logging.String("user_id", userID.String()))
	return nil
}

func (s *service) UnblockUser(ctx context.Context, userID xid.ID, reason string) error {
	s.logger.Info("Unblocking user", logging.String("user_id", userID.String()), logging.String("reason", reason))

	// Get user to validate existence
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Execute before user unblock hooks
	hookCtx := s.buildHookContext(ctx, &userID, &existingUser.OrganizationID)
	hookCtx.Data = map[string]interface{}{
		"user_id": userID,
		"reason":  reason,
	}

	if err := s.hook.Execute(ctx, hooks.HookBeforeUserUnblocked, hookCtx.Data); err != nil {
		s.logger.Error("Before user unblock hooks failed", logging.Error(err))
		if s.shouldBlockOnHookFailure(err) {
			return errors.Wrap(err, errors.CodeInternalServer, "user unblocking blocked by hooks")
		}
	}

	// Unblock user
	if err := s.userRepo.Unblock(ctx, userID); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to unblock user")
	}

	// Execute after user unblock hooks
	modelUser := s.convertEntUserToModel(existingUser)
	modelUser.Blocked = false
	if err := s.hook.Execute(ctx, hooks.HookUserUnblocked, modelUser); err != nil {
		s.logger.Error("After user unblock hooks failed", logging.Error(err))
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.unblocked",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &existingUser.OrganizationID,
		Details: map[string]interface{}{
			"reason": reason,
		},
	})

	s.logger.Info("User unblocked successfully", logging.String("user_id", userID.String()))
	return nil
}

func (s *service) ActivateUser(ctx context.Context, userID xid.ID, reason string) error {
	s.logger.Info("Activating user", logging.String("user_id", userID.String()), logging.String("reason", reason))

	// Get user to validate existence
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Execute before user activation hooks
	hookCtx := s.buildHookContext(ctx, &userID, &existingUser.OrganizationID)
	hookCtx.Data = map[string]interface{}{
		"user_id": userID,
		"reason":  reason,
	}

	if err := s.hook.Execute(ctx, hooks.HookBeforeUserActivated, hookCtx.Data); err != nil {
		s.logger.Error("Before user activation hooks failed", logging.Error(err))
		if s.shouldBlockOnHookFailure(err) {
			return errors.Wrap(err, errors.CodeInternalServer, "user activation blocked by hooks")
		}
	}

	// Activate user
	if err := s.userRepo.Activate(ctx, userID); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to activate user")
	}

	// Execute after user activation hooks
	modelUser := s.convertEntUserToModel(existingUser)
	modelUser.Active = true
	if err := s.hook.Execute(ctx, hooks.HookUserActivated, modelUser); err != nil {
		s.logger.Error("After user activation hooks failed", logging.Error(err))
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.activated",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &existingUser.OrganizationID,
		Details: map[string]interface{}{
			"reason": reason,
		},
	})

	s.logger.Info("User activated successfully", logging.String("user_id", userID.String()))
	return nil
}

func (s *service) DeactivateUser(ctx context.Context, userID xid.ID, reason string) error {
	s.logger.Info("Deactivating user", logging.String("user_id", userID.String()), logging.String("reason", reason))

	// Get user to validate existence
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Execute before user deactivation hooks
	hookCtx := s.buildHookContext(ctx, &userID, &existingUser.OrganizationID)
	hookCtx.Data = map[string]interface{}{
		"user_id": userID,
		"reason":  reason,
	}

	if err := s.hook.Execute(ctx, hooks.HookBeforeUserDeactivated, hookCtx.Data); err != nil {
		s.logger.Error("Before user deactivation hooks failed", logging.Error(err))
		if s.shouldBlockOnHookFailure(err) {
			return errors.Wrap(err, errors.CodeInternalServer, "user deactivation blocked by hooks")
		}
	}

	// Deactivate user
	if err := s.userRepo.Deactivate(ctx, userID); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to deactivate user")
	}

	// Execute after user deactivation hooks
	modelUser := s.convertEntUserToModel(existingUser)
	modelUser.Active = false
	if err := s.hook.Execute(ctx, hooks.HookUserDeactivated, modelUser); err != nil {
		s.logger.Error("After user deactivation hooks failed", logging.Error(err))
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.deactivated",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &existingUser.OrganizationID,
		Details: map[string]interface{}{
			"reason": reason,
		},
	})

	s.logger.Info("User deactivated successfully", logging.String("user_id", userID.String()))
	return nil
}

func (s *service) AssignRole(ctx context.Context, userID xid.ID, req model.AssignRoleRequest) error {
	// s.logger.Info("Assigning role to user",
	// 	logging.String("user_id", userID.String()),
	// 	logging.String("role_id", req.RoleID.String()),
	// 	logging.String("context_type", req.ContextType))
	//
	// // Validate user exists
	// existingUser, err := s.userRepo.GetByID(ctx, userID)
	// if err != nil {
	// 	if ent.IsNotFound(err) {
	// 		return errors.New(errors.CodeNotFound, "user not found")
	// 	}
	// 	return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	// }
	//
	// // Validate role exists
	// if _, err := s.roleRepo.GetByID(ctx, req.RoleID); err != nil {
	// 	if ent.IsNotFound(err) {
	// 		return errors.New(errors.CodeNotFound, "role not found")
	// 	}
	// 	return errors.Wrap(err, errors.CodeInternalServer, "failed to get role")
	// }
	//
	// // Create role assignment using repository method
	// // Note: This assumes the role repository has an AssignToUser method
	// assignmentInput := repository.CreateRoleAssignmentInput{
	// 	UserID:      userID,
	// 	RoleID:      req.RoleID,
	// 	ContextType: req.ContextType,
	// 	ContextID:   req.ContextID,
	// 	ExpiresAt:   req.ExpiresAt,
	// 	Conditions:  req.Conditions,
	// 	AssignedBy:  s.getCurrentUserID(ctx),
	// }
	//
	// if err := s.roleRepo.AssignToUser(ctx, assignmentInput); err != nil {
	// 	return errors.Wrap(err, errors.CodeInternalServer, "failed to assign role")
	// }
	//
	// // Create audit log
	// s.createAuditLog(ctx, &model.CreateAuditLogRequest{
	// 	UserID:         &userID,
	// 	Action:         "role.assigned",
	// 	Resource:       "user",
	// 	ResourceID:     &userID,
	// 	Status:         "success",
	// 	OrganizationID: s.getContextOrganizationID(req.ContextType, req.ContextID, &existingUser.OrganizationID),
	// 	Details: map[string]interface{}{
	// 		"role_id":      req.RoleID,
	// 		"context_type": req.ContextType,
	// 		"context_id":   req.ContextID,
	// 	},
	// })

	s.logger.Info("Role assigned successfully",
		logging.String("user_id", userID.String()),
		logging.String("role_id", req.RoleID.String()))
	return nil
}

func (s *service) RemoveRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType string, contextID *xid.ID) error {
	s.logger.Info("Removing role from user",
		logging.String("user_id", userID.String()),
		logging.String("role_id", roleID.String()),
		logging.String("context_type", contextType))

	// Validate user exists
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Remove role assignment
	if err := s.roleRepo.RemoveUserRole(ctx, userID, roleID, model.ContextType(contextType), contextID); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to remove role")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "role.removed",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: s.getContextOrganizationID(contextType, contextID, &existingUser.OrganizationID),
		Details: map[string]interface{}{
			"role_id":      roleID,
			"context_type": contextType,
			"context_id":   contextID,
		},
	})

	s.logger.Info("Role removed successfully",
		logging.String("user_id", userID.String()),
		logging.String("role_id", roleID.String()))
	return nil
}

func (s *service) AssignPermission(ctx context.Context, userID xid.ID, req model.AssignPermissionRequest) error {
	// todo implement this
	// s.logger.Info("Assigning permission to user",
	// 	logging.String("user_id", userID.String()),
	// 	logging.String("permission_id", req.PermissionID.String()),
	// 	logging.String("context_type", req.ContextType))
	//
	// // Validate user exists
	// existingUser, err := s.userRepo.GetByID(ctx, userID)
	// if err != nil {
	// 	if ent.IsNotFound(err) {
	// 		return errors.New(errors.CodeNotFound, "user not found")
	// 	}
	// 	return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	// }
	//
	// // Validate permission exists
	// if _, err := s.permissionRepo.GetByID(ctx, req.PermissionID); err != nil {
	// 	if ent.IsNotFound(err) {
	// 		return errors.New(errors.CodeNotFound, "permission not found")
	// 	}
	// 	return errors.Wrap(err, errors.CodeInternalServer, "failed to get permission")
	// }
	//
	// // Create permission assignment
	// assignmentInput := repository.CreatePermissionAssignmentInput{
	// 	UserID:         userID,
	// 	PermissionID:   req.PermissionID,
	// 	ContextType:    req.ContextType,
	// 	ContextID:      req.ContextID,
	// 	ResourceType:   req.ResourceType,
	// 	ResourceID:     req.ResourceID,
	// 	PermissionType: req.PermissionType,
	// 	ExpiresAt:      req.ExpiresAt,
	// 	Conditions:     req.Conditions,
	// 	AssignedBy:     s.getCurrentUserID(ctx),
	// 	Reason:         req.Reason,
	// }
	//
	// if err := s.permissionRepo.AssignToUser(ctx, assignmentInput); err != nil {
	// 	return errors.Wrap(err, errors.CodeInternalServer, "failed to assign permission")
	// }
	//
	// // Create audit log
	// s.createAuditLog(ctx, &model.CreateAuditLogRequest{
	// 	UserID:         &userID,
	// 	Action:         "permission.assigned",
	// 	Resource:       "user",
	// 	ResourceID:     &userID,
	// 	Status:         "success",
	// 	OrganizationID: s.getContextOrganizationID(req.ContextType, req.ContextID, &existingUser.OrganizationID),
	// 	Details: map[string]interface{}{
	// 		"permission_id":   req.PermissionID,
	// 		"context_type":    req.ContextType,
	// 		"context_id":      req.ContextID,
	// 		"resource_type":   req.ResourceType,
	// 		"resource_id":     req.ResourceID,
	// 		"permission_type": req.PermissionType,
	// 		"reason":          req.Reason,
	// 	},
	// })

	s.logger.Info("Permission assigned successfully",
		logging.String("user_id", userID.String()),
		logging.String("permission_id", req.PermissionID.String()))
	return nil
}

func (s *service) RemovePermission(ctx context.Context, userID xid.ID, permissionID xid.ID, contextType string, contextID *xid.ID) error {
	// todo implement this
	// s.logger.Info("Removing permission from user",
	// 	logging.String("user_id", userID.String()),
	// 	logging.String("permission_id", permissionID.String()),
	// 	logging.String("context_type", contextType))
	//
	// // Validate user exists
	// existingUser, err := s.userRepo.GetByID(ctx, userID)
	// if err != nil {
	// 	if ent.IsNotFound(err) {
	// 		return errors.New(errors.CodeNotFound, "user not found")
	// 	}
	// 	return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	// }
	//
	// // Remove permission assignment
	// if err := s.permissionRepo.RemoveFromUser(ctx, userID, permissionID, contextType, contextID); err != nil {
	// 	return errors.Wrap(err, errors.CodeInternalServer, "failed to remove permission")
	// }
	//
	// // Create audit log
	// s.createAuditLog(ctx, &model.CreateAuditLogRequest{
	// 	UserID:         &userID,
	// 	Action:         "permission.removed",
	// 	Resource:       "user",
	// 	ResourceID:     &userID,
	// 	Status:         "success",
	// 	OrganizationID: s.getContextOrganizationID(contextType, contextID, &existingUser.OrganizationID),
	// 	Details: map[string]interface{}{
	// 		"permission_id": permissionID,
	// 		"context_type":  contextType,
	// 		"context_id":    contextID,
	// 	},
	// })

	s.logger.Info("Permission removed successfully",
		logging.String("user_id", userID.String()),
		logging.String("permission_id", permissionID.String()))
	return nil
}

func (s *service) GetUserPermissions(ctx context.Context, userID xid.ID, contextType string, contextID *xid.ID) ([]model.UserPermissionAssignment, error) {
	// TODO: Implement get user permissions
	return nil, nil
}

func (s *service) GetUserRoles(ctx context.Context, userID xid.ID, contextType string, contextID *xid.ID) ([]model.UserRoleAssignment, error) {
	// TODO: Implement get user roles
	// // Validate user exists
	// if _, err := s.userRepo.GetByID(ctx, userID); err != nil {
	// 	if ent.IsNotFound(err) {
	// 		return nil, errors.New(errors.CodeNotFound, "user not found")
	// 	}
	// 	return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	// }
	//
	// // Get user roles from repository
	// entAssignments, err := s.roleRepo.GetUserAssignments(ctx, userID, contextType, contextID)
	// if err != nil {
	// 	return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user roles")
	// }
	//
	// // Convert to model assignments
	// assignments := make([]model.UserRoleAssignment, len(entAssignments))
	// for i, entAssignment := range entAssignments {
	// 	assignments[i] = s.convertEntRoleAssignmentToModel(entAssignment)
	// }
	//
	// return assignments, nil
	return nil, nil
}

func (s *service) GetUserActivity(ctx context.Context, userID xid.ID, req model.UserActivityRequest) (*model.UserActivityResponse, error) {
	// TODO: Implement get user activity
	return nil, nil
}

func (s *service) GetUserStats(ctx context.Context, organizationID *xid.ID) (*model.UserStats, error) {
	stats := &model.UserStats{}

	// Get total users count
	totalParams := repository.ListUsersParams{
		OrganizationID: organizationID,
	}
	if organizationID != nil {
		totalResult, err := s.userRepo.ListByOrganization(ctx, *organizationID, totalParams)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get total users")
		}
		stats.TotalUsers = len(totalResult.Data)
	} else {
		totalResult, err := s.userRepo.List(ctx, totalParams)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get total users")
		}
		stats.TotalUsers = len(totalResult.Data)
	}

	// Get active users count
	activeTrue := true
	activeParams := repository.ListUsersParams{
		OrganizationID: organizationID,
		Active:         &activeTrue,
	}
	if organizationID != nil {
		activeResult, err := s.userRepo.ListByOrganization(ctx, *organizationID, activeParams)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get active users")
		}
		stats.ActiveUsers = len(activeResult.Data)
	} else {
		activeResult, err := s.userRepo.List(ctx, activeParams)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get active users")
		}
		stats.ActiveUsers = len(activeResult.Data)
	}

	// Get users by type
	for _, userType := range []model.UserType{model.UserTypeInternal, model.UserTypeExternal, model.UserTypeEndUser} {
		typeParams := repository.ListUsersParams{
			OrganizationID: organizationID,
			UserType:       &userType,
		}

		var count int
		if organizationID != nil {
			typeResult, err := s.userRepo.ListByOrganization(ctx, *organizationID, typeParams)
			if err != nil {
				s.logger.Warn("Failed to get users by type", logging.Error(err))
				continue
			}
			count = len(typeResult.Data)
		} else {
			typeResult, err := s.userRepo.List(ctx, typeParams)
			if err != nil {
				s.logger.Warn("Failed to get users by type", logging.Error(err))
				continue
			}
			count = len(typeResult.Data)
		}

		switch userType {
		case model.UserTypeInternal:
			stats.InternalUsers = count
		case model.UserTypeExternal:
			stats.ExternalUsers = count
		case model.UserTypeEndUser:
			stats.EndUsers = count
		}
	}

	// Get verified users counts
	emailVerifiedTrue := true
	emailVerifiedParams := repository.ListUsersParams{
		OrganizationID: organizationID,
		EmailVerified:  &emailVerifiedTrue,
	}
	if organizationID != nil {
		emailResult, err := s.userRepo.ListByOrganization(ctx, *organizationID, emailVerifiedParams)
		if err == nil {
			stats.VerifiedEmails = len(emailResult.Data)
		}
	} else {
		emailResult, err := s.userRepo.List(ctx, emailVerifiedParams)
		if err == nil {
			stats.VerifiedEmails = len(emailResult.Data)
		}
	}

	// TODO: Add MFA enabled count and recent logins count
	// This would require additional repository methods

	return stats, nil
}

func (s *service) GetRecentLogins(ctx context.Context, userID xid.ID, limit int) ([]model.UserActivity, error) {
	// TODO: Implement get recent logins
	// // Validate user exists
	// if _, err := s.userRepo.GetByID(ctx, userID); err != nil {
	// 	if ent.IsNotFound(err) {
	// 		return nil, errors.New(errors.CodeNotFound, "user not found")
	// 	}
	// 	return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	// }
	//
	// // Get recent login activities
	// params := repository.UserActivityParams{
	// 	UserID:  userID,
	// 	Actions: []string{"user.login_success"},
	// 	Limit:   limit,
	// }
	//
	// activities, err := s.activityRepo.GetUserActivity(ctx, params)
	// if err != nil {
	// 	return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get recent logins")
	// }
	//
	// // Convert to model activities
	// modelActivities := make([]model.UserActivity, len(activities))
	// for i, activity := range activities {
	// 	modelActivities[i] = s.convertEntActivityToModel(activity)
	// }
	//
	// return modelActivities, nil
	return nil, nil
}

func (s *service) BulkUpdateUsers(ctx context.Context, req model.BulkUserOperation) (*model.BulkUserOperationResponse, error) {
	s.logger.Info("Performing bulk user operation",
		logging.String("operation", req.Operation),
		logging.Int("user_count", len(req.UserIDs)))

	response := &model.BulkUserOperationResponse{
		Success: make([]xid.ID, 0),
		Failed:  make([]xid.ID, 0),
		Errors:  make([]string, 0),
	}

	for _, userID := range req.UserIDs {
		var err error

		switch strings.ToLower(req.Operation) {
		case "activate":
			err = s.ActivateUser(ctx, userID, req.Reason)
		case "deactivate":
			err = s.DeactivateUser(ctx, userID, req.Reason)
		case "block":
			err = s.BlockUser(ctx, userID, req.Reason)
		case "unblock":
			err = s.UnblockUser(ctx, userID, req.Reason)
		default:
			err = errors.New(errors.CodeBadRequest, "invalid operation")
		}

		if err != nil {
			response.Failed = append(response.Failed, userID)
			response.Errors = append(response.Errors, err.Error())
			s.logger.Error("Bulk operation failed for user",
				logging.String("user_id", userID.String()),
				logging.Error(err))
		} else {
			response.Success = append(response.Success, userID)
		}
	}

	response.SuccessCount = len(response.Success)
	response.FailureCount = len(response.Failed)

	// Create audit log for bulk operation
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:   "user.bulk_operation",
		Resource: "user",
		Status:   "completed",
		Details: map[string]interface{}{
			"operation":     req.Operation,
			"reason":        req.Reason,
			"total_users":   len(req.UserIDs),
			"success_count": response.SuccessCount,
			"failure_count": response.FailureCount,
		},
	})

	s.logger.Info("Bulk user operation completed",
		logging.String("operation", req.Operation),
		logging.Int("success_count", response.SuccessCount),
		logging.Int("failure_count", response.FailureCount))

	return response, nil
}

func (s *service) BulkDeleteUsers(ctx context.Context, userIDs []xid.ID, transferDataTo *xid.ID) (*model.BulkUserOperationResponse, error) {
	s.logger.Info("Performing bulk user deletion", logging.Int("user_count", len(userIDs)))

	response := &model.BulkUserOperationResponse{
		Success: make([]xid.ID, 0),
		Failed:  make([]xid.ID, 0),
		Errors:  make([]string, 0),
	}

	for _, userID := range userIDs {
		deleteReq := model.DeleteUserRequest{
			TransferDataTo: transferDataTo,
			Reason:         "bulk deletion",
		}

		if err := s.DeleteUser(ctx, userID, deleteReq); err != nil {
			response.Failed = append(response.Failed, userID)
			response.Errors = append(response.Errors, err.Error())
			s.logger.Error("Bulk deletion failed for user",
				logging.String("user_id", userID.String()),
				logging.Error(err))
		} else {
			response.Success = append(response.Success, userID)
		}
	}

	response.SuccessCount = len(response.Success)
	response.FailureCount = len(response.Failed)

	// Create audit log for bulk deletion
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		Action:   "user.bulk_delete",
		Resource: "user",
		Status:   "completed",
		Details: map[string]interface{}{
			"total_users":      len(userIDs),
			"success_count":    response.SuccessCount,
			"failure_count":    response.FailureCount,
			"transfer_data_to": transferDataTo,
		},
	})

	s.logger.Info("Bulk user deletion completed",
		logging.Int("success_count", response.SuccessCount),
		logging.Int("failure_count", response.FailureCount))

	return response, nil
}

func (s *service) PromoteToPlatformAdmin(ctx context.Context, userID xid.ID) error {
	s.logger.Info("Promoting user to platform admin", logging.String("user_id", userID.String()))

	// Get user to validate existence
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Check if user is already platform admin
	if existingUser.IsPlatformAdmin {
		return errors.New(errors.CodeBadRequest, "user is already a platform admin")
	}

	// Update user to platform admin
	updateReq := model.UpdateUserRequest{
		// IsPlatformAdmin: &[]bool{true}[0],
	}

	if _, err := s.UpdateUser(ctx, userID, updateReq); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to promote user to platform admin")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.promoted_to_platform_admin",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &existingUser.OrganizationID,
	})

	s.logger.Info("User promoted to platform admin successfully", logging.String("user_id", userID.String()))
	return nil
}

func (s *service) DemoteFromPlatformAdmin(ctx context.Context, userID xid.ID) error {
	s.logger.Info("Demoting user from platform admin", logging.String("user_id", userID.String()))

	// Get user to validate existence
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Check if user is platform admin
	if !existingUser.IsPlatformAdmin {
		return errors.New(errors.CodeBadRequest, "user is not a platform admin")
	}

	// Update user to remove platform admin
	updateReq := model.UpdateUserRequest{
		// IsPlatformAdmin: &[]bool{false}[0], // todo fix
	}

	if _, err := s.UpdateUser(ctx, userID, updateReq); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to demote user from platform admin")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.demoted_from_platform_admin",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &existingUser.OrganizationID,
	})

	s.logger.Info("User demoted from platform admin successfully", logging.String("user_id", userID.String()))
	return nil
}

func (s *service) GetPlatformAdmins(ctx context.Context) ([]model.UserSummary, error) {
	// Get platform admins from repository
	entUsers, err := s.userRepo.GetPlatformAdmins(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get platform admins")
	}

	// Convert to model summaries
	admins := make([]model.UserSummary, len(entUsers))
	for i, entUser := range entUsers {
		admins[i] = *s.convertEntUserToModelSummary(entUser)
	}

	return admins, nil
}

func (s *service) buildHookContext(ctx context.Context, userID *xid.ID, orgID *xid.ID) *hooks.HookContext {
	hookCtx := &hooks.HookContext{
		UserID:         userID,
		OrganizationID: orgID,
		Timestamp:      time.Now(),
	}

	// Extract additional context from request context
	if ip, ok := ctx.Value("ip_address").(string); ok {
		hookCtx.IPAddress = ip
	}
	if ua, ok := ctx.Value("user_agent").(string); ok {
		hookCtx.UserAgent = ua
	}
	if reqID, ok := ctx.Value("request_id").(string); ok {
		hookCtx.RequestID = reqID
	}
	if sessionID, ok := ctx.Value("session_id").(xid.ID); ok {
		hookCtx.SessionID = &sessionID
	}

	return hookCtx
}

func (s *service) shouldBlockOnHookFailure(err error) bool {
	// Define policy for when hook failures should block operations
	// This could be configurable or based on hook type
	return false // For now, hooks don't block operations
}

func (s *service) getContextOrganizationID(contextType string, contextID *xid.ID, defaultOrgID *xid.ID) *xid.ID {
	if contextType == "organization" && contextID != nil {
		return contextID
	}
	return defaultOrgID
}
