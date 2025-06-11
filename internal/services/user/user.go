package user

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
	"github.com/samber/lo"
	"golang.org/x/crypto/bcrypt"
)

// Service defines the user service interface
type Service interface {
	// User CRUD operations
	CreateUser(ctx context.Context, req model.CreateUserRequest) (*model.User, error)
	GetUser(ctx context.Context, id xid.ID) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string, userType user.UserType, organizationID *xid.ID) (*model.User, error)
	GetUserByIdentifier(ctx context.Context, identifier string, userType user.UserType) (*model.User, error)
	GetUserByUsername(ctx context.Context, username string, userType user.UserType, organizationID *xid.ID) (*model.User, error)
	GetUserByPhone(ctx context.Context, phone string, userType user.UserType, organizationID *xid.ID) (*model.User, error)
	UpdateUser(ctx context.Context, id xid.ID, req model.UpdateUserRequest) (*model.User, error)
	DeleteUser(ctx context.Context, id xid.ID, req model.DeleteUserRequest) error
	ListUsers(ctx context.Context, req model.UserListRequest) (*model.UserListResponse, error)
	ExistsByEmail(ctx context.Context, email string, userType user.UserType, organizationID *xid.ID) (bool, error)
	IncrementLoginCount(ctx context.Context, id xid.ID) error

	// Authentication operations
	AuthenticateUser(ctx context.Context, email, password string, userType user.UserType, organizationID *xid.ID) (*model.User, error)
	ValidatePassword(ctx context.Context, userID xid.ID, password string) error
	ChangePassword(ctx context.Context, userID xid.ID, req model.ChangePasswordRequest) error
	SetPassword(ctx context.Context, userID xid.ID, req model.SetPasswordRequest) error
	ResetPassword(ctx context.Context, email string, userType user.UserType, organizationID *xid.ID) (string, error)
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
	ValidateUserEmail(ctx context.Context, email string, userType user.UserType, organizationID *xid.ID, excludeUserID *xid.ID) error
	ValidateUsername(ctx context.Context, username string, userType user.UserType, organizationID *xid.ID, excludeUserID *xid.ID) error
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
	logger           logging.Logger
}

// NewService creates a new user service instance
func NewService(
	userRepo repository.UserRepository,
	verificationRepo repository.VerificationRepository,
	auditRepo repository.AuditRepository,
	logger logging.Logger,
) Service {
	return &service{
		userRepo:         userRepo,
		verificationRepo: verificationRepo,
		auditRepo:        auditRepo,
		logger:           logger,
	}
}

// CreateUser creates a new user
func (s *service) CreateUser(ctx context.Context, req model.CreateUserRequest) (*model.User, error) {
	s.logger.Info("Creating new user", logging.String("email", req.Email), logging.String("user_type", string(req.UserType)))

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

	// Create user
	entUser, err := s.userRepo.Create(ctx, input)
	if err != nil {
		s.logger.Error("Failed to create user", logging.Error(err))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create user")
	}

	// Convert to model
	modelUser := s.convertEntUserToModel(entUser)

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
func (s *service) GetUserByIdentifier(ctx context.Context, id string, userType user.UserType) (*model.User, error) {
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
func (s *service) GetUserByEmail(ctx context.Context, email string, userType user.UserType, organizationID *xid.ID) (*model.User, error) {
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
func (s *service) GetUserByPhone(ctx context.Context, phone string, userType user.UserType, organizationID *xid.ID) (*model.User, error) {
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
func (s *service) GetUserByUsername(ctx context.Context, username string, userType user.UserType, organizationID *xid.ID) (*model.User, error) {
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
	// Get existing user
	existingUser, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
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

	// Update user
	updatedUser, err := s.userRepo.Update(ctx, id, repository.UpdateUserInput{
		UpdateUserRequest: req,
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update user")
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

	return s.convertEntUserToModel(updatedUser), nil
}

// DeleteUser deletes a user
func (s *service) DeleteUser(ctx context.Context, id xid.ID, req model.DeleteUserRequest) error {
	// Get user to validate existence
	existingUser, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
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

	return nil
}

// AuthenticateUser authenticates a user with email/password
func (s *service) AuthenticateUser(ctx context.Context, email, password string, userType user.UserType, organizationID *xid.ID) (*model.User, error) {
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

	// Update last login
	if err := s.userRepo.UpdateLastLogin(ctx, entUser.ID, ""); err != nil {
		s.logger.Warn("Failed to update last login", logging.Error(err))
	}

	// Increment login count
	if err := s.userRepo.IncrementLoginCount(ctx, entUser.ID); err != nil {
		s.logger.Warn("Failed to increment login count", logging.Error(err))
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

	return s.convertEntUserToModel(entUser), nil
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
func (s *service) ValidateUserEmail(ctx context.Context, email string, userType user.UserType, organizationID *xid.ID, excludeUserID *xid.ID) error {
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
func (s *service) ValidateUsername(ctx context.Context, username string, userType user.UserType, organizationID *xid.ID, excludeUserID *xid.ID) error {
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

func (s *service) parseUserType(userTypeStr string) (user.UserType, error) {
	switch strings.ToLower(userTypeStr) {
	case "internal":
		return user.UserTypeInternal, nil
	case "external":
		return user.UserTypeExternal, nil
	case "end_user":
		return user.UserTypeEndUser, nil
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
		UserType:              entUser.UserType.String(),
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
		UserType:        entUser.UserType.String(),
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
		UserType:         nil,
		OrganizationID:   nil,
		Active:           nil,
		Blocked:          nil,
		EmailVerified:    nil,
		AuthProvider:     nil,
	}
	list, err := s.userRepo.List(ctx, params)
	if err != nil {
		return nil, err
	}

	users := lo.Map(list.Data, func(item *ent.User, index int) model.UserSummary {
		return *s.convertEntUserToModelSummary(item)
	})

	return &model.UserListResponse{
		Data: users,
	}, nil
}

func (s *service) ExistsByEmail(ctx context.Context, email string, userType user.UserType, organizationID *xid.ID) (bool, error) {
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

func (s *service) ResetPassword(ctx context.Context, email string, userType user.UserType, organizationID *xid.ID) (string, error) {
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
	// TODO: Implement user blocking
	return nil
}

func (s *service) UnblockUser(ctx context.Context, userID xid.ID, reason string) error {
	// TODO: Implement user unblocking
	return nil
}

func (s *service) ActivateUser(ctx context.Context, userID xid.ID, reason string) error {
	// TODO: Implement user activation
	return nil
}

func (s *service) DeactivateUser(ctx context.Context, userID xid.ID, reason string) error {
	// TODO: Implement user deactivation
	return nil
}

func (s *service) AssignRole(ctx context.Context, userID xid.ID, req model.AssignRoleRequest) error {
	// TODO: Implement role assignment
	return nil
}

func (s *service) RemoveRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType string, contextID *xid.ID) error {
	// TODO: Implement role removal
	return nil
}

func (s *service) AssignPermission(ctx context.Context, userID xid.ID, req model.AssignPermissionRequest) error {
	// TODO: Implement permission assignment
	return nil
}

func (s *service) RemovePermission(ctx context.Context, userID xid.ID, permissionID xid.ID, contextType string, contextID *xid.ID) error {
	// TODO: Implement permission removal
	return nil
}

func (s *service) GetUserPermissions(ctx context.Context, userID xid.ID, contextType string, contextID *xid.ID) ([]model.UserPermissionAssignment, error) {
	// TODO: Implement get user permissions
	return nil, nil
}

func (s *service) GetUserRoles(ctx context.Context, userID xid.ID, contextType string, contextID *xid.ID) ([]model.UserRoleAssignment, error) {
	// TODO: Implement get user roles
	return nil, nil
}

func (s *service) GetUserActivity(ctx context.Context, userID xid.ID, req model.UserActivityRequest) (*model.UserActivityResponse, error) {
	// TODO: Implement get user activity
	return nil, nil
}

func (s *service) GetUserStats(ctx context.Context, organizationID *xid.ID) (*model.UserStats, error) {
	// TODO: Implement get user stats
	return nil, nil
}

func (s *service) GetRecentLogins(ctx context.Context, userID xid.ID, limit int) ([]model.UserActivity, error) {
	// TODO: Implement get recent logins
	return nil, nil
}

func (s *service) BulkUpdateUsers(ctx context.Context, req model.BulkUserOperation) (*model.BulkUserOperationResponse, error) {
	// TODO: Implement bulk user update
	return nil, nil
}

func (s *service) BulkDeleteUsers(ctx context.Context, userIDs []xid.ID, transferDataTo *xid.ID) (*model.BulkUserOperationResponse, error) {
	// TODO: Implement bulk user deletion
	return nil, nil
}

func (s *service) PromoteToPlatformAdmin(ctx context.Context, userID xid.ID) error {
	// TODO: Implement promote to platform admin
	return nil
}

func (s *service) DemoteFromPlatformAdmin(ctx context.Context, userID xid.ID) error {
	// TODO: Implement demote from platform admin
	return nil
}

func (s *service) GetPlatformAdmins(ctx context.Context) ([]model.UserSummary, error) {
	// TODO: Implement get platform admins
	return nil, nil
}
