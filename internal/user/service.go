package user

import (
	"context"
	"strings"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/organization"
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

	// Authenticate authenticates a user with email and password
	Authenticate(ctx context.Context, email, password string) (*ent.User, error)
}

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
	UserID      string    `json:"user_id" validate:"required"`
	Type        string    `json:"type" validate:"required"` // email, phone, password_reset, magic_link
	Email       string    `json:"email,omitempty"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	RedirectURL string    `json:"redirect_url,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
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
	return s.verifyManager.CreateVerification(ctx, input)
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
		// TODO: Add proper logging
	}

	return verification, nil
}

// Authenticate authenticates a user with email and password
func (s *service) Authenticate(ctx context.Context, email, password string) (*ent.User, error) {
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
		// TODO: Add proper logging
	}

	return user, nil
}

// Helper function to normalize email addresses for consistent lookup
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
