package user

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/organization"
	"github.com/juicycleff/frank/pkg/validator"
	"github.com/rs/xid"
	"go.uber.org/zap"
)

// Service provides user management operations
type Service interface {
	// Create creates a new user
	Create(ctx context.Context, input CreateUserInput) (*model.User, error)

	// Get retrieves a user by ID
	Get(ctx context.Context, id xid.ID) (*model.User, error)

	// GetByEmail retrieves a user by email
	GetByEmail(ctx context.Context, email string) (*model.User, error)

	// List retrieves users with pagination
	List(ctx context.Context, params ListUsersParams) (*model.PaginatedOutput[*model.User], error)

	// Update updates a user
	Update(ctx context.Context, id xid.ID, input UpdateUserInput) (*model.User, error)

	// Delete deletes a user
	Delete(ctx context.Context, id xid.ID) error

	// GetOrganizations retrieves organizations a user belongs to
	GetOrganizations(ctx context.Context, userID xid.ID) ([]*model.Organization, error)

	// UpdatePassword updates a user's password
	UpdatePassword(ctx context.Context, userID xid.ID, currentPassword, newPassword string) error

	// VerifyEmail marks a user's email as verified
	VerifyEmail(ctx context.Context, userID xid.ID) error

	// VerifyPhone marks a user's phone as verified
	VerifyPhone(ctx context.Context, userID xid.ID) error

	// CreateVerification creates a verification token for email/phone verification
	CreateVerification(ctx context.Context, input CreateVerificationInput) (*Verification, error)

	// VerifyToken verifies a verification token
	VerifyToken(ctx context.Context, token string) (*Verification, error)

	// VerifyEmailOTP validates the provided OTP for a given email and returns the corresponding verification record or an error.
	VerifyEmailOTP(ctx context.Context, email string, otp string) (*Verification, error)

	// Authenticate authenticates a user with email and password
	Authenticate(ctx context.Context, email, password string, orgID *xid.ID) (*LoginResult, error)
}

type service struct {
	repo          Repository
	pwdManager    PasswordManager
	orgService    organization.Service
	verifyManager VerificationManager
	cfg           *config.Config
	logger        logging.Logger
}

// NewService creates a new user service
func NewService(
	repo Repository,
	pwdManager PasswordManager,
	verifyManager VerificationManager,
	orgService organization.Service,
	cfg *config.Config,
	logger logging.Logger,
) Service {
	return &service{
		repo:          repo,
		pwdManager:    pwdManager,
		orgService:    orgService,
		verifyManager: verifyManager,
		cfg:           cfg,
		logger:        logger,
	}
}

// Create creates a new user
func (s *service) Create(ctx context.Context, input CreateUserInput) (*model.User, error) {
	// Normalize email
	input.Email = normalizeEmail(input.Email)

	err := validator.Validate(&input)
	if err != nil {
		return nil, err
	}

	// Check if user with this email already exists
	existingUser, err := s.repo.GetByEmail(ctx, input.Email)
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}

	if existingUser != nil {
		return nil, errors.New(errors.CodeConflict, "user with this email already exists")
	}

	// Hash password if provided
	var passwordHash string
	if input.Password != "" {
		hash, err := s.pwdManager.HashPassword(input.Password)
		if err != nil {
			return nil, err
		}
		passwordHash = hash
	}

	// Create ent.UserCreate
	userCreate := s.repo.Client().User.Create().
		SetID(xid.New()).
		SetEmail(input.Email)

	// Set optional fields
	if passwordHash != "" {
		userCreate = userCreate.SetPasswordHash(passwordHash)
	}

	if input.PhoneNumber != "" {
		userCreate = userCreate.SetPhoneNumber(input.PhoneNumber)
	}

	if input.FirstName != "" {
		userCreate = userCreate.SetFirstName(input.FirstName)
	}

	if input.LastName != "" {
		userCreate = userCreate.SetLastName(input.LastName)
	}

	if input.ProfileImageURL != "" {
		userCreate = userCreate.SetProfileImageURL(input.ProfileImageURL)
	}

	if input.Locale != "" {
		userCreate = userCreate.SetLocale(input.Locale)
	} else {
		userCreate = userCreate.SetLocale("en") // Default locale
	}

	if input.Metadata != nil {
		userCreate = userCreate.SetMetadata(input.Metadata)
	}

	// Create user in repository
	entUser, err := s.repo.Create(ctx, userCreate)
	if err != nil {
		return nil, err
	}

	// Check if this is the first user ever created
	// If so, create a default organization and make this user the root user
	count, err := s.repo.GetUserCount(ctx)
	if err != nil {
		s.logger.Error("Failed to get user count", logging.Error(err))
	}

	orgID := input.OrgID
	if orgID.IsNil() && count > 1 {
		return nil, errors.New(errors.CodeConflict, "cannot create a new user without an organization")
	}

	if count == 1 {
		defaultName := s.cfg.Organization.DefaultName
		if defaultName == "" {
			defaultName = "Default"
		}

		newOrg, err := s.orgService.Create(ctx, organization.CreateOrganizationInput{
			Name:    defaultName,
			OwnerID: entUser.ID,
		})
		if err != nil {
			return nil, err
		}

		orgID = newOrg.ID

		// This is the first user, make them root and create default org
		err = s.makeFirstUserRoot(ctx, entUser, newOrg.ID)
		if err != nil {
			s.logger.Error("Failed to set up first user as root", logging.Error(err))
		}
	} else if !orgID.IsNil() {
		// For non-first users, add to specified organization if provided
		err = s.orgService.AddMember(ctx, orgID, entUser.ID, []string{"member"})
		if err != nil {
			s.logger.Error("Failed to add user to organization",
				logging.String("user_id", entUser.ID.String()),
				logging.String("org_id", orgID.String()),
				logging.Error(err))
		}
	} else {
		s.logger.Warn("User created without an organization",
			logging.String("user_id", entUser.ID.String()))
	}

	return model.ConvertUserToDTO(entUser), nil
}

// makeFirstUserRoot sets up the first user as a root user and creates a default organization
func (s *service) makeFirstUserRoot(ctx context.Context, user *ent.User, orgID xid.ID) error {
	// Add "root" role to user metadata
	metadata := user.Metadata
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["is_root"] = true
	metadata["is_admin"] = true

	// Update user metadata and primary organization
	userUpdate := s.repo.Client().User.UpdateOneID(user.ID).
		SetMetadata(metadata).
		SetPrimaryOrganizationID(orgID)

	_, err := s.repo.Update(ctx, userUpdate)
	if err != nil {
		return fmt.Errorf("failed to update first user as root: %w", err)
	}

	// Add user as owner of the organization with all privileges
	err = s.orgService.AddMember(ctx, orgID, user.ID, []string{"owner", "admin"})
	if err != nil {
		return fmt.Errorf("failed to add first user as owner of default organization: %w", err)
	}

	s.logger.Info("Set up first user as root with default organization",
		logging.String("user_id", user.ID.String()),
		logging.String("org_id", orgID.String()))

	return nil
}

// Get retrieves a user by ID
func (s *service) Get(ctx context.Context, id xid.ID) (*model.User, error) {
	entUser, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return model.ConvertUserToDTO(entUser), nil
}

// GetByEmail retrieves a user by email
func (s *service) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	entUser, err := s.repo.GetByEmail(ctx, normalizeEmail(email))
	if err != nil {
		return nil, err
	}

	return model.ConvertUserToDTO(entUser), nil
}

// List retrieves users with pagination
func (s *service) List(ctx context.Context, params ListUsersParams) (*model.PaginatedOutput[*model.User], error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	entResult, err := s.repo.List(ctx, params)
	if err != nil {
		return nil, err
	}

	// Convert the paginated result
	users := model.ConvertUsersToDTO(entResult.Data)

	return &model.PaginatedOutput[*model.User]{
		Data:       users,
		Pagination: entResult.Pagination,
	}, nil
}

// Update updates a user
func (s *service) Update(ctx context.Context, id xid.ID, input UpdateUserInput) (*model.User, error) {
	// Create ent.UserUpdateOne
	userUpdate := s.repo.Client().User.UpdateOneID(id)

	// Apply updates conditionally
	if input.PhoneNumber != nil {
		if *input.PhoneNumber != "" {
			userUpdate = userUpdate.SetPhoneNumber(*input.PhoneNumber)
		} else {
			userUpdate = userUpdate.ClearPhoneNumber()
		}
	}

	if input.FirstName != nil {
		if *input.FirstName != "" {
			userUpdate = userUpdate.SetFirstName(*input.FirstName)
		} else {
			userUpdate = userUpdate.ClearFirstName()
		}
	}

	if input.LastName != nil {
		if *input.LastName != "" {
			userUpdate = userUpdate.SetLastName(*input.LastName)
		} else {
			userUpdate = userUpdate.ClearLastName()
		}
	}

	if input.Metadata != nil {
		userUpdate = userUpdate.SetMetadata(input.Metadata)
	}

	if input.ProfileImageURL != nil {
		if *input.ProfileImageURL != "" {
			userUpdate = userUpdate.SetProfileImageURL(*input.ProfileImageURL)
		} else {
			userUpdate = userUpdate.ClearProfileImageURL()
		}
	}

	if input.Locale != nil {
		userUpdate = userUpdate.SetLocale(*input.Locale)
	}

	if input.Active != nil {
		userUpdate = userUpdate.SetActive(*input.Active)
	}

	if input.PrimaryOrgID != nil {
		// Check if user is a member of this organization
		if !input.PrimaryOrgID.IsNil() {
			isMember, err := s.repo.IsUserMemberOfOrganization(ctx, id, *input.PrimaryOrgID)
			if err != nil {
				return nil, err
			}

			if !isMember {
				return nil, errors.New(errors.CodeForbidden, "user is not a member of this organization")
			}

			userUpdate = userUpdate.SetPrimaryOrganizationID(*input.PrimaryOrgID)
		} else {
			userUpdate = userUpdate.ClearPrimaryOrganizationID()
		}
	}

	entUser, err := s.repo.Update(ctx, userUpdate)
	if err != nil {
		return nil, err
	}

	return model.ConvertUserToDTO(entUser), nil
}

// Delete deletes a user
func (s *service) Delete(ctx context.Context, id xid.ID) error {
	return s.repo.Delete(ctx, id)
}

// GetOrganizations retrieves organizations a user belongs to
func (s *service) GetOrganizations(ctx context.Context, userID xid.ID) ([]*model.Organization, error) {
	organizations, err := s.repo.GetUserOrganizations(ctx, userID)
	if err != nil {
		return nil, err
	}

	return model.ConvertOrganizationsToDTO(organizations), nil
}

// UpdatePassword updates a user's password
func (s *service) UpdatePassword(ctx context.Context, userID xid.ID, currentPassword, newPassword string) error {
	// Get user to check current password
	entUser, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Check if user has a password set
	if entUser.PasswordHash == "" {
		return errors.New(errors.CodeInvalidCredentials, "user has no password set")
	}

	// Verify current password
	err = s.pwdManager.VerifyPassword(entUser.PasswordHash, currentPassword)
	if err != nil {
		return errors.New(errors.CodeInvalidCredentials, "current password is incorrect")
	}

	// Hash new password
	newHash, err := s.pwdManager.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update password hash
	now := time.Now()
	userUpdate := s.repo.Client().User.UpdateOneID(userID).
		SetPasswordHash(newHash).
		SetLastPasswordChange(now)

	_, err = s.repo.Update(ctx, userUpdate)
	return err
}

// VerifyEmail marks a user's email as verified
func (s *service) VerifyEmail(ctx context.Context, userID xid.ID) error {
	userUpdate := s.repo.Client().User.UpdateOneID(userID).
		SetEmailVerified(true)

	_, err := s.repo.Update(ctx, userUpdate)
	return err
}

// VerifyPhone marks a user's phone as verified
func (s *service) VerifyPhone(ctx context.Context, userID xid.ID) error {
	userUpdate := s.repo.Client().User.UpdateOneID(userID).
		SetPhoneVerified(true)

	_, err := s.repo.Update(ctx, userUpdate)
	return err
}

// CreateVerification creates a verification token for email/phone verification
func (s *service) CreateVerification(ctx context.Context, input CreateVerificationInput) (*Verification, error) {
	// Get user to verify they exist and to check email/phone
	entUser, err := s.repo.GetByID(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	// Validate verification type
	switch input.Type {
	case "email":
		if input.Email == "" {
			input.Email = entUser.Email
		}
	case "phone":
		if input.PhoneNumber == "" {
			if entUser.PhoneNumber == "" {
				return nil, errors.New(errors.CodeInvalidInput, "user has no phone number")
			}
			input.PhoneNumber = entUser.PhoneNumber
		}
	case "password_reset":
		if input.Email == "" {
			input.Email = entUser.Email
		}
	case "magic_link":
		if input.Email == "" {
			input.Email = entUser.Email
		}
		if input.RedirectURL == "" {
			return nil, errors.New(errors.CodeInvalidInput, "redirect URL is required for magic links")
		}
	default:
		return nil, errors.New(errors.CodeInvalidInput, "invalid verification type")
	}

	// Create verification
	ver, err := s.verifyManager.CreateVerification(ctx, input)
	if err != nil {
		return nil, err
	}

	return convertVerificationToDTO(ver), nil
}

// VerifyToken verifies a verification token
func (s *service) VerifyToken(ctx context.Context, token string) (*Verification, error) {
	verification, err := s.verifyManager.VerifyToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Mark verification as used
	verification, err = s.verifyManager.MarkAsUsed(ctx, verification.ID)
	if err != nil {
		return nil, err
	}

	// Update user verification status based on verification type
	switch verification.Type {
	case "email":
		err = s.VerifyEmail(ctx, verification.UserID)
	case "phone":
		err = s.VerifyPhone(ctx, verification.UserID)
	}

	if err != nil {
		// Log error but don't fail verification
		s.logger.Error("Failed to update user verification status",
			logging.String("user_id", verification.UserID.String()),
			logging.Error(err),
		)
	}

	return convertVerificationToDTO(verification), nil
}

func (s *service) VerifyEmailOTP(ctx context.Context, email string, otp string) (*Verification, error) {
	// Verify OTP
	verification, err := s.verifyManager.VerifyEmailOTP(ctx, email, otp)
	if err != nil {
		return nil, err
	}

	// Update user verification status
	err = s.VerifyEmail(ctx, verification.UserID)
	if err != nil {
		// Log error but don't fail verification
		s.logger.Error("Failed to update email verification status",
			logging.String("user_id", verification.UserID.String()),
			logging.Error(err),
		)
	}

	return convertVerificationToDTO(verification), nil
}

// Authenticate authenticates a user with email and password
func (s *service) Authenticate(ctx context.Context, email, password string, orgID *xid.ID) (*LoginResult, error) {
	// Get user by email
	entUser, err := s.repo.GetByEmail(ctx, normalizeEmail(email))
	if err != nil {
		s.logger.Error("Failed to get user by email", zap.Error(err), zap.String("email", email))
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeInvalidCredentials, "invalid email or password")
		}
		return nil, err
	}

	if orgID != nil {
		// Convert orgID to xid.ID
		oid := *orgID

		isMember, err := s.repo.IsUserMemberOfOrganization(ctx, entUser.ID, oid)
		if err != nil {
			return nil, err
		}
		if !isMember {
			return nil, errors.New(errors.CodeForbidden, "user is not a member of this organization")
		}
	}

	// Check if user is active
	if !entUser.Active {
		return nil, errors.New(errors.CodeUnauthorized, "account is inactive")
	}

	// Check if user has a password set
	if entUser.PasswordHash == "" {
		return nil, errors.New(errors.CodeInvalidCredentials, "account has no password set")
	}

	// Verify password
	err = s.pwdManager.VerifyPassword(entUser.PasswordHash, password)
	if err != nil {
		s.logger.Error("Failed to verify password", zap.Error(err), zap.String("email", email))
		return nil, errors.New(errors.CodeInvalidCredentials, "invalid email or password")
	}

	// Update last login time
	now := time.Now()
	userUpdate := s.repo.Client().User.UpdateOneID(entUser.ID).
		SetLastLogin(now)

	_, err = s.repo.Update(ctx, userUpdate)
	if err != nil {
		// Log error but don't fail authentication
		s.logger.Error("Failed to update last login time",
			logging.String("user_id", entUser.ID.String()),
			logging.Error(err),
		)
	}

	result := &LoginResult{
		User:          model.ConvertUserToDTO(entUser),
		EmailVerified: entUser.EmailVerified,
	}

	// If email is not verified and verification is required, create a verification
	if !entUser.EmailVerified && s.cfg.Auth.RequireEmailVerification {
		// Create verification for email
		expiresAt := time.Now().Add(time.Hour * 24) // 24 hour expiry
		verification, err := s.CreateVerification(ctx, CreateVerificationInput{
			UserID:    entUser.ID,
			Type:      "email",
			Email:     entUser.Email,
			ExpiresAt: expiresAt,
			IPAddress: "",
			UserAgent: "",
			Method:    VerificationMethodOTP,
		})

		if err != nil {
			s.logger.Error("Failed to create verification",
				logging.String("user_id", entUser.ID.String()),
				logging.Error(err),
			)
		} else {
			result.VerificationID = verification.ID
		}

		// Return result without tokens
		return result, nil
	}

	return result, nil
}

// Helper function to normalize email addresses for consistent lookup
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// convertVerificationToDTO converts an ent.Verification to Verification DTO
func convertVerificationToDTO(entVerification *ent.Verification) *Verification {
	return &Verification{
		Base: model.Base{
			ID:        entVerification.ID,
			CreatedAt: entVerification.CreatedAt,
			UpdatedAt: entVerification.UpdatedAt,
		},
		UserID:      entVerification.UserID,
		Type:        entVerification.Type,
		Token:       entVerification.Token,
		Email:       entVerification.Email,
		PhoneNumber: entVerification.PhoneNumber,
		RedirectURL: entVerification.RedirectURL,
		ExpiresAt:   entVerification.ExpiresAt,
		Used:        entVerification.Used,
		UsedAt:      entVerification.UsedAt,
		Attempts:    entVerification.Attempts,
		IPAddress:   entVerification.IPAddress,
		UserAgent:   entVerification.UserAgent,
		Attestation: entVerification.Attestation,
	}
}
