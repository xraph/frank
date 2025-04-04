package user

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/organization"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/validator"
)

// Service provides user management operations
type Service interface {
	// Create creates a new user
	Create(ctx context.Context, input CreateUserInput) (*ent.User, error)

	// Get retrieves a user by ID
	Get(ctx context.Context, id string) (*ent.User, error)

	// GetByEmail retrieves a user by email
	GetByEmail(ctx context.Context, email string) (*ent.User, error)

	// List retrieves users with pagination
	List(ctx context.Context, params ListParams) ([]*ent.User, int, error)

	// Update updates a user
	Update(ctx context.Context, id string, input UpdateUserInput) (*ent.User, error)

	// Delete deletes a user
	Delete(ctx context.Context, id string) error

	// GetOrganizations retrieves organizations a user belongs to
	GetOrganizations(ctx context.Context, userID string) ([]*ent.Organization, error)

	// UpdatePassword updates a user's password
	UpdatePassword(ctx context.Context, userID string, currentPassword, newPassword string) error

	// VerifyEmail marks a user's email as verified
	VerifyEmail(ctx context.Context, userID string) error

	// VerifyPhone marks a user's phone as verified
	VerifyPhone(ctx context.Context, userID string) error

	// CreateVerification creates a verification token for email/phone verification
	CreateVerification(ctx context.Context, input CreateVerificationInput) (*ent.Verification, error)

	// VerifyToken verifies a verification token
	VerifyToken(ctx context.Context, token string) (*ent.Verification, error)

	// VerifyEmailOTP validates the provided OTP for a given email and returns the corresponding verification record or an error.
	VerifyEmailOTP(ctx context.Context, email string, otp string) (*ent.Verification, error)

	// Authenticate authenticates a user with email and password
	Authenticate(ctx context.Context, email, password string) (*LoginResult, error)
}

// VerificationMethod represents the method used for verification
type VerificationMethod string

const (
	// VerificationMethodLink uses a magic link for verification
	VerificationMethodLink VerificationMethod = "link"

	// VerificationMethodOTP uses a one-time password for verification
	VerificationMethodOTP VerificationMethod = "otp"
)

// CreateUserInput represents input for creating a user
type CreateUserInput struct {
	Email           string                 `json:"email" validate:"required,email"`
	Password        string                 `json:"password,omitempty"`
	PhoneNumber     string                 `json:"phone_number,omitempty"`
	FirstName       string                 `json:"first_name,omitempty"`
	LastName        string                 `json:"last_name,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	ProfileImageURL string                 `json:"profile_image_url,omitempty"`
	Locale          string                 `json:"locale,omitempty"`
	OrganizationID  string                 `json:"organization_id,omitempty"`
}

// UpdateUserInput represents input for updating a user
type UpdateUserInput struct {
	PhoneNumber           *string                `json:"phone_number,omitempty"`
	FirstName             *string                `json:"first_name,omitempty"`
	LastName              *string                `json:"last_name,omitempty"`
	Metadata              map[string]interface{} `json:"metadata,omitempty"`
	ProfileImageURL       *string                `json:"profile_image_url,omitempty"`
	Locale                *string                `json:"locale,omitempty"`
	Active                *bool                  `json:"active,omitempty"`
	PrimaryOrganizationID *string                `json:"primary_organization_id,omitempty"`
}

// CreateVerificationInput represents input for creating a verification
type CreateVerificationInput struct {
	UserID      string             `json:"user_id" validate:"required"`
	Type        string             `json:"type" validate:"required"` // email, phone, password_reset, magic_link
	Email       string             `json:"email,omitempty"`
	PhoneNumber string             `json:"phone_number,omitempty"`
	RedirectURL string             `json:"redirect_url,omitempty"`
	ExpiresAt   time.Time          `json:"expires_at"`
	IPAddress   string             `json:"ip_address,omitempty"`
	UserAgent   string             `json:"user_agent,omitempty"`
	Method      VerificationMethod `json:"method,omitempty"`
}

// LoginResult represents the result of an authentication attempt
type LoginResult struct {
	User           *ent.User // The authenticated user
	EmailVerified  bool      `json:"email_verified"`
	VerificationID string    `json:"verification_id"`
}

// ListParams represents pagination and filtering parameters
type ListParams struct {
	Offset         int    `json:"offset" query:"offset"`
	Limit          int    `json:"limit" query:"limit"`
	Search         string `json:"search" query:"search"`
	OrganizationID string `json:"organization_id" query:"organization_id"`
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
func (s *service) Create(ctx context.Context, input CreateUserInput) (*ent.User, error) {
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
	var passwordHash *string
	if input.Password != "" {
		hash, err := s.pwdManager.HashPassword(input.Password)
		if err != nil {
			return nil, err
		}
		passwordHash = &hash
	}

	// Create user in repository
	user, err := s.repo.Create(ctx, RepositoryCreateInput{
		Email:           input.Email,
		PasswordHash:    passwordHash,
		PhoneNumber:     input.PhoneNumber,
		FirstName:       input.FirstName,
		LastName:        input.LastName,
		Metadata:        input.Metadata,
		ProfileImageURL: input.ProfileImageURL,
		Locale:          input.Locale,
	})
	if err != nil {
		return nil, err
	}

	// Check if this is the first user ever created
	// If so, create a default organization and make this user the root user
	count, err := s.repo.GetUserCount(ctx)
	if err != nil {
		s.logger.Error("Failed to get user count", logging.Error(err))
	} else if count == 1 {
		// This is the first user, make them root and create default org
		err = s.makeFirstUserRoot(ctx, user)
		if err != nil {
			s.logger.Error("Failed to set up first user as root", logging.Error(err))
		}
	} else if input.OrganizationID != "" {
		// For non-first users, add to specified organization if provided
		err = s.orgService.AddMember(ctx, input.OrganizationID, user.ID, []string{"member"})
		if err != nil {
			s.logger.Error("Failed to add user to organization",
				logging.String("user_id", user.ID),
				logging.String("org_id", input.OrganizationID),
				logging.Error(err))
		}
	} else {
		// For non-first users without an organization, you might want to
		// require an organization or add them to a default one
		s.logger.Warn("User created without an organization",
			logging.String("user_id", user.ID))
	}

	// Add user to organization if provided
	if input.OrganizationID != "" {
		err = s.orgService.AddMember(ctx, input.OrganizationID, user.ID, []string{"member"})
		if err != nil {
			// Log error but don't fail user creation
			// TODO: Add proper logging
		}
	}

	return user, nil
}

// makeFirstUserRoot sets up the first user as a root user and creates a default organization
func (s *service) makeFirstUserRoot(ctx context.Context, user *ent.User) error {
	// Add "root" role to user metadata
	metadata := user.Metadata
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["is_root"] = true
	metadata["is_admin"] = true

	// Update user metadata
	_, err := s.repo.Update(ctx, user.ID, RepositoryUpdateInput{
		Metadata: metadata,
	})
	if err != nil {
		return fmt.Errorf("failed to update first user as root: %w", err)
	}

	// Create default organization
	orgInput := organization.CreateOrganizationInput{
		Name:      s.cfg.Organization.DefaultName,
		Slug:      "default",
		Plan:      "enterprise",
		OwnerID:   user.ID,
		TrialDays: 0, // No trial for default org
		Features:  s.cfg.Organization.DefaultFeatures,
		Metadata: map[string]interface{}{
			"default": true,
			"system":  true,
		},
	}

	org, err := s.orgService.Create(ctx, orgInput)
	if err != nil {
		return fmt.Errorf("failed to create default organization: %w", err)
	}

	// Add user as owner of the organization with all privileges
	err = s.orgService.AddMember(ctx, org.ID, user.ID, []string{"owner", "admin"})
	if err != nil {
		return fmt.Errorf("failed to add first user as owner of default organization: %w", err)
	}

	// Set organization as user's primary organization
	primaryOrgID := org.ID
	_, err = s.repo.Update(ctx, user.ID, RepositoryUpdateInput{
		PrimaryOrganizationID: &primaryOrgID,
	})
	if err != nil {
		return fmt.Errorf("failed to set default organization as primary for first user: %w", err)
	}

	s.logger.Info("Set up first user as root with default organization",
		logging.String("user_id", user.ID),
		logging.String("org_id", org.ID))

	return nil
}

// Get retrieves a user by ID
func (s *service) Get(ctx context.Context, id string) (*ent.User, error) {
	return s.repo.GetByID(ctx, id)
}

// GetByEmail retrieves a user by email
func (s *service) GetByEmail(ctx context.Context, email string) (*ent.User, error) {
	return s.repo.GetByEmail(ctx, normalizeEmail(email))
}

// List retrieves users with pagination
func (s *service) List(ctx context.Context, params ListParams) ([]*ent.User, int, error) {
	// Set default limit if not provided
	if params.Limit <= 0 {
		params.Limit = 10
	}

	// Map service input to repository input
	repoInput := RepositoryListInput{
		Offset:         params.Offset,
		Limit:          params.Limit,
		Search:         params.Search,
		OrganizationID: params.OrganizationID,
	}

	return s.repo.List(ctx, repoInput)
}

// Update updates a user
func (s *service) Update(ctx context.Context, id string, input UpdateUserInput) (*ent.User, error) {
	// Map service input to repository input
	repoInput := RepositoryUpdateInput{}

	if input.PhoneNumber != nil {
		repoInput.PhoneNumber = input.PhoneNumber
	}

	if input.FirstName != nil {
		repoInput.FirstName = input.FirstName
	}

	if input.LastName != nil {
		repoInput.LastName = input.LastName
	}

	if input.Metadata != nil {
		repoInput.Metadata = input.Metadata
	}

	if input.ProfileImageURL != nil {
		repoInput.ProfileImageURL = input.ProfileImageURL
	}

	if input.Locale != nil {
		repoInput.Locale = input.Locale
	}

	if input.Active != nil {
		repoInput.Active = input.Active
	}

	if input.PrimaryOrganizationID != nil {
		// Check if user is a member of this organization
		if *input.PrimaryOrganizationID != "" {
			isMember, err := s.repo.IsUserMemberOfOrganization(ctx, id, *input.PrimaryOrganizationID)
			if err != nil {
				return nil, err
			}

			if !isMember {
				return nil, errors.New(errors.CodeForbidden, "user is not a member of this organization")
			}
		}

		repoInput.PrimaryOrganizationID = input.PrimaryOrganizationID
	}

	return s.repo.Update(ctx, id, repoInput)
}

// Delete deletes a user
func (s *service) Delete(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

// GetOrganizations retrieves organizations a user belongs to
func (s *service) GetOrganizations(ctx context.Context, userID string) ([]*ent.Organization, error) {
	return s.repo.GetUserOrganizations(ctx, userID)
}

// UpdatePassword updates a user's password
func (s *service) UpdatePassword(ctx context.Context, userID string, currentPassword, newPassword string) error {
	// Get user to check current password
	user, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Check if user has a password set
	if user.PasswordHash == "" {
		return errors.New(errors.CodeInvalidCredentials, "user has no password set")
	}

	// Verify current password
	err = s.pwdManager.VerifyPassword(user.PasswordHash, currentPassword)
	if err != nil {
		return errors.New(errors.CodeInvalidCredentials, "current password is incorrect")
	}

	// Hash new password
	newHash, err := s.pwdManager.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update password hash
	_, err = s.repo.Update(ctx, userID, RepositoryUpdateInput{
		PasswordHash: &newHash,
		LastPasswordChange: func() *time.Time {
			t := time.Now()
			return &t
		}(),
	})

	return err
}

// VerifyEmail marks a user's email as verified
func (s *service) VerifyEmail(ctx context.Context, userID string) error {
	_, err := s.repo.Update(ctx, userID, RepositoryUpdateInput{
		EmailVerified: func() *bool {
			b := true
			return &b
		}(),
	})

	return err
}

// VerifyPhone marks a user's phone as verified
func (s *service) VerifyPhone(ctx context.Context, userID string) error {
	_, err := s.repo.Update(ctx, userID, RepositoryUpdateInput{
		PhoneVerified: func() *bool {
			b := true
			return &b
		}(),
	})

	return err
}

// CreateVerification creates a verification token for email/phone verification
func (s *service) CreateVerification(ctx context.Context, input CreateVerificationInput) (*ent.Verification, error) {
	// Get user to verify they exist and to check email/phone
	user, err := s.repo.GetByID(ctx, input.UserID)
	if err != nil {
		return nil, err
	}

	// Validate verification type
	switch input.Type {
	case "email":
		if input.Email == "" {
			input.Email = user.Email
		}
	case "phone":
		if input.PhoneNumber == "" {
			if user.PhoneNumber == "" {
				return nil, errors.New(errors.CodeInvalidInput, "user has no phone number")
			}
			input.PhoneNumber = user.PhoneNumber
		}
	case "password_reset":
		if input.Email == "" {
			input.Email = user.Email
		}
	case "magic_link":
		if input.Email == "" {
			input.Email = user.Email
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

	return ver, nil
}

// VerifyToken verifies a verification token
func (s *service) VerifyToken(ctx context.Context, token string) (*ent.Verification, error) {
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
		s.logger.Error("Failed to update email verification status",
			logging.String("user_id", verification.UserID),
			logging.Error(err),
		)
	}

	return verification, nil
}

func (s *service) VerifyEmailOTP(ctx context.Context, email string, otp string) (*ent.Verification, error) {
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
			logging.String("user_id", verification.UserID),
			logging.Error(err),
		)
	}

	return verification, nil
}

// Authenticate authenticates a user with email and password
func (s *service) Authenticate(ctx context.Context, email, password string) (*LoginResult, error) {
	// Get user by email
	user, err := s.repo.GetByEmail(ctx, normalizeEmail(email))
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeInvalidCredentials, "invalid email or password")
		}
		return nil, err
	}

	// Check if user is active
	if !user.Active {
		return nil, errors.New(errors.CodeUnauthorized, "account is inactive")
	}

	// Check if user has a password set
	if user.PasswordHash == "" {
		return nil, errors.New(errors.CodeInvalidCredentials, "account has no password set")
	}

	// Verify password
	err = s.pwdManager.VerifyPassword(user.PasswordHash, password)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidCredentials, "invalid email or password")
	}

	// Update last login time
	now := time.Now()
	_, err = s.repo.Update(ctx, user.ID, RepositoryUpdateInput{
		LastLogin: &now,
	})

	if err != nil {
		// Log error but don't fail authentication
		s.logger.Error("Failed to update last login time",
			logging.String("user_id", user.ID),
			logging.Error(err),
		)
	}

	result := &LoginResult{
		User:          user,
		EmailVerified: user.EmailVerified,
	}

	// If email is not verified and verification is required, create a verification
	if !user.EmailVerified && s.cfg.Auth.RequireEmailVerification {
		// Create verification for email
		expiresAt := time.Now().Add(time.Hour * 24) // 24 hour expiry
		verification, err := s.CreateVerification(ctx, CreateVerificationInput{
			UserID:    user.ID,
			Type:      "email",
			Email:     user.Email,
			ExpiresAt: expiresAt,
			IPAddress: "",
			UserAgent: "",
			Method:    VerificationMethodOTP,
		})

		if err != nil {
			s.logger.Error("Failed to create verification",
				logging.String("user_id", user.ID),
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
