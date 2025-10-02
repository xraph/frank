package repository

import (
	"context"
	"time"

	"github.com/uptrace/bun"
	"github.com/xraph/frank/internal/models"
	"github.com/xraph/frank/pkg/model"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateUserInput) (*models.User, error)
	GetByID(ctx context.Context, id string) (*models.User, error)
	GetByEmail(ctx context.Context, email string, userType model.UserType, organizationID *string) (*models.User, error)
	GetByUsername(ctx context.Context, username string, userType model.UserType, organizationID *string) (*models.User, error)
	GetUserByPhone(ctx context.Context, phone string, userType model.UserType, organizationID *string) (*models.User, error)
	GetByExternalID(ctx context.Context, externalID string, provider string, userType model.UserType, organizationID *string) (*models.User, error)
	Update(ctx context.Context, id string, input UpdateUserInput) (*models.User, error)
	Delete(ctx context.Context, id string) error

	// List and search operations
	List(ctx context.Context, params ListUsersParams) (*PaginatedOutput[*models.User], error)
	ListByOrganization(ctx context.Context, organizationID string, params ListUsersParams) (*PaginatedOutput[*models.User], error)
	Search(ctx context.Context, query string, params SearchUsersParams) (*PaginatedOutput[*models.User], error)

	// Authentication related
	GetByPasswordResetToken(ctx context.Context, token string) (*models.User, error)
	UpdatePassword(ctx context.Context, id string, passwordHash string) error
	UpdateLastLogin(ctx context.Context, id string, ip string) error
	IncrementLoginCount(ctx context.Context, id string) error

	// Verification
	MarkEmailVerified(ctx context.Context, id string) error
	MarkPhoneVerified(ctx context.Context, id string) error

	// User management
	Block(ctx context.Context, id string) error
	Unblock(ctx context.Context, id string) error
	Activate(ctx context.Context, id string) error
	Deactivate(ctx context.Context, id string) error

	// Organization context
	GetPlatformAdmins(ctx context.Context) ([]*models.User, error)
	GetOrganizationMembers(ctx context.Context, organizationID string, activeOnly bool) ([]*models.User, error)
	CountByOrganization(ctx context.Context, organizationID string, userType model.UserType) (int, error)

	// Existence checks
	ExistsByEmail(ctx context.Context, email string, userType model.UserType, organizationID *string) (bool, error)
	ExistsByUsername(ctx context.Context, username string, userType model.UserType, organizationID *string) (bool, error)
}

// Input types
type CreateUserInput struct {
	Email                 string
	PhoneNumber           *string
	FirstName             *string
	LastName              *string
	Username              *string
	PasswordHash          *string
	UserType              model.UserType
	OrganizationID        *string
	PrimaryOrganizationID *string
	IsPlatformAdmin       bool
	AuthProvider          string
	ExternalID            *string
	CustomerID            *string
	CustomAttributes      map[string]interface{}
	CreatedBy             *string
	ProfileImageURL       *string
	Locale                string
	Timezone              string
	Metadata              map[string]interface{}
	EmailVerified         bool
	PhoneVerified         bool
	Active                bool
	Blocked               bool
}

type UpdateUserInput struct {
	Email              *string
	PhoneNumber        *string
	FirstName          *string
	LastName           *string
	Username           *string
	EmailVerified      *bool
	PhoneVerified      *bool
	Active             *bool
	Blocked            *bool
	ProfileImageURL    *string
	Locale             *string
	Timezone           *string
	CustomAttributes   map[string]interface{}
	Metadata           map[string]interface{}
	PasswordResetToken *string
	ExternalID         *string
	AuthProvider       *string
}

type ListUsersParams struct {
	PaginationParams
	UserType       *model.UserType
	OrganizationID *string
	Active         *bool
	Blocked        *bool
	EmailVerified  *bool
	AuthProvider   *string
}

type SearchUsersParams struct {
	PaginationParams
	UserType       *model.UserType
	OrganizationID *string
	Fields         []string
	ExactMatch     bool
}

// userRepository implements UserRepository
type userRepository struct {
	db *bun.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *bun.DB) UserRepository {
	return &userRepository{db: db}
}

// Create creates a new user
func (r *userRepository) Create(ctx context.Context, input CreateUserInput) (*models.User, error) {
	user := &models.User{
		Email:                 input.Email,
		PhoneNumber:           input.PhoneNumber,
		FirstName:             input.FirstName,
		LastName:              input.LastName,
		Username:              input.Username,
		PasswordHash:          input.PasswordHash,
		UserType:              input.UserType,
		OrganizationID:        input.OrganizationID,
		PrimaryOrganizationID: input.PrimaryOrganizationID,
		IsPlatformAdmin:       input.IsPlatformAdmin,
		AuthProvider:          input.AuthProvider,
		ExternalID:            input.ExternalID,
		CustomerID:            input.CustomerID,
		CustomAttributes:      input.CustomAttributes,
		CreatedBy:             input.CreatedBy,
		ProfileImageURL:       input.ProfileImageURL,
		Locale:                input.Locale,
		Timezone:              &input.Timezone,
		Metadata:              input.Metadata,
		EmailVerified:         input.EmailVerified,
		PhoneVerified:         input.PhoneVerified,
		Active:                input.Active,
		Blocked:               input.Blocked,
	}

	_, err := r.db.NewInsert().
		Model(user).
		Exec(ctx)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return nil, NewError(CodeConflict, "User with this email already exists")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to create user")
	}

	return user, nil
}

// GetByID retrieves a user by ID
func (r *userRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	user := new(models.User)
	err := r.db.NewSelect().
		Model(user).
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "User not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get user by ID")
	}
	return user, nil
}

// GetByEmail retrieves a user by email
func (r *userRepository) GetByEmail(ctx context.Context, email string, userType model.UserType, organizationID *string) (*models.User, error) {
	user := new(models.User)
	query := r.db.NewSelect().
		Model(user).
		Where("email = ?", email).
		Where("user_type = ?", userType)

	if organizationID != nil {
		query = query.Where("organization_id = ?", *organizationID)
	}

	err := query.Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "User not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get user by email")
	}
	return user, nil
}

// GetByUsername retrieves a user by username
func (r *userRepository) GetByUsername(ctx context.Context, username string, userType model.UserType, organizationID *string) (*models.User, error) {
	user := new(models.User)
	query := r.db.NewSelect().
		Model(user).
		Where("username = ?", username).
		Where("user_type = ?", userType)

	if organizationID != nil {
		query = query.Where("organization_id = ?", *organizationID)
	}

	err := query.Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "User not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get user by username")
	}
	return user, nil
}

// GetUserByPhone retrieves a user by phone number
func (r *userRepository) GetUserByPhone(ctx context.Context, phone string, userType model.UserType, organizationID *string) (*models.User, error) {
	user := new(models.User)
	query := r.db.NewSelect().
		Model(user).
		Where("phone_number = ?", phone).
		Where("user_type = ?", userType)

	if organizationID != nil {
		query = query.Where("organization_id = ?", *organizationID)
	}

	err := query.Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "User not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get user by phone")
	}
	return user, nil
}

// GetByExternalID retrieves a user by external provider ID
func (r *userRepository) GetByExternalID(ctx context.Context, externalID string, provider string, userType model.UserType, organizationID *string) (*models.User, error) {
	user := new(models.User)
	query := r.db.NewSelect().
		Model(user).
		Where("external_id = ?", externalID).
		Where("auth_provider = ?", provider).
		Where("user_type = ?", userType)

	if organizationID != nil {
		query = query.Where("organization_id = ?", *organizationID)
	}

	err := query.Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "User not found")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get user by external ID")
	}
	return user, nil
}

// Update updates a user
func (r *userRepository) Update(ctx context.Context, id string, input UpdateUserInput) (*models.User, error) {
	user, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	query := r.db.NewUpdate().
		Model(user).
		Where("id = ?", id)

	if input.Email != nil {
		query = query.Set("email = ?", *input.Email)
		user.Email = *input.Email
	}
	if input.PhoneNumber != nil {
		query = query.Set("phone_number = ?", *input.PhoneNumber)
		user.PhoneNumber = input.PhoneNumber
	}
	if input.FirstName != nil {
		query = query.Set("first_name = ?", *input.FirstName)
		user.FirstName = input.FirstName
	}
	if input.LastName != nil {
		query = query.Set("last_name = ?", *input.LastName)
		user.LastName = input.LastName
	}
	if input.Username != nil {
		query = query.Set("username = ?", *input.Username)
		user.Username = input.Username
	}
	if input.EmailVerified != nil {
		query = query.Set("email_verified = ?", *input.EmailVerified)
		user.EmailVerified = *input.EmailVerified
	}
	if input.PhoneVerified != nil {
		query = query.Set("phone_verified = ?", *input.PhoneVerified)
		user.PhoneVerified = *input.PhoneVerified
	}
	if input.Active != nil {
		query = query.Set("active = ?", *input.Active)
		user.Active = *input.Active
	}
	if input.Blocked != nil {
		query = query.Set("blocked = ?", *input.Blocked)
		user.Blocked = *input.Blocked
	}
	if input.ProfileImageURL != nil {
		query = query.Set("profile_image_url = ?", *input.ProfileImageURL)
		user.ProfileImageURL = input.ProfileImageURL
	}
	if input.Locale != nil {
		query = query.Set("locale = ?", *input.Locale)
		user.Locale = *input.Locale
	}
	if input.Timezone != nil {
		query = query.Set("timezone = ?", *input.Timezone)
		user.Timezone = input.Timezone
	}
	if input.CustomAttributes != nil {
		query = query.Set("custom_attributes = ?", input.CustomAttributes)
		user.CustomAttributes = input.CustomAttributes
	}
	if input.Metadata != nil {
		query = query.Set("metadata = ?", input.Metadata)
		user.Metadata = input.Metadata
	}
	if input.PasswordResetToken != nil {
		query = query.Set("password_reset_token = ?", *input.PasswordResetToken)
		user.PasswordResetToken = input.PasswordResetToken
	}

	_, err = query.Exec(ctx)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return nil, NewError(CodeConflict, "User with this email already exists")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to update user")
	}

	return user, nil
}

// Delete deletes a user
func (r *userRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.NewDelete().
		Model((*models.User)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return WrapError(err, CodeDatabaseError, "failed to delete user")
	}
	return nil
}

// List retrieves users with pagination and filtering
func (r *userRepository) List(ctx context.Context, params ListUsersParams) (*PaginatedOutput[*models.User], error) {
	query := r.db.NewSelect().Model((*models.User)(nil))

	if params.UserType != nil {
		query = query.Where("user_type = ?", *params.UserType)
	}
	if params.OrganizationID != nil {
		query = query.Where("organization_id = ?", *params.OrganizationID)
	}
	if params.Active != nil {
		query = query.Where("active = ?", *params.Active)
	}
	if params.Blocked != nil {
		query = query.Where("blocked = ?", *params.Blocked)
	}
	if params.EmailVerified != nil {
		query = query.Where("email_verified = ?", *params.EmailVerified)
	}
	if params.AuthProvider != nil {
		query = query.Where("auth_provider = ?", *params.AuthProvider)
	}

	return Paginate[*models.User](ctx, query, params.PaginationParams)
}

// ListByOrganization retrieves users by organization
func (r *userRepository) ListByOrganization(ctx context.Context, organizationID string, params ListUsersParams) (*PaginatedOutput[*models.User], error) {
	params.OrganizationID = &organizationID
	return r.List(ctx, params)
}

// Search searches for users
func (r *userRepository) Search(ctx context.Context, query string, params SearchUsersParams) (*PaginatedOutput[*models.User], error) {
	q := r.db.NewSelect().Model((*models.User)(nil))

	if params.UserType != nil {
		q = q.Where("user_type = ?", *params.UserType)
	}
	if params.OrganizationID != nil {
		q = q.Where("organization_id = ?", *params.OrganizationID)
	}

	if params.ExactMatch {
		q = q.Where("email = ? OR username = ? OR first_name = ? OR last_name = ?",
			query, query, query, query)
	} else {
		searchPattern := "%" + query + "%"
		q = q.Where("email ILIKE ? OR username ILIKE ? OR first_name ILIKE ? OR last_name ILIKE ?",
			searchPattern, searchPattern, searchPattern, searchPattern)
	}

	return Paginate[*models.User](ctx, q, params.PaginationParams)
}

// GetByPasswordResetToken retrieves user by password reset token
func (r *userRepository) GetByPasswordResetToken(ctx context.Context, token string) (*models.User, error) {
	user := new(models.User)
	err := r.db.NewSelect().
		Model(user).
		Where("password_reset_token = ?", token).
		Scan(ctx)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, NewError(CodeNotFound, "Invalid password reset token")
		}
		return nil, WrapError(err, CodeDatabaseError, "failed to get user by password reset token")
	}
	return user, nil
}

// UpdatePassword updates user password
func (r *userRepository) UpdatePassword(ctx context.Context, id string, passwordHash string) error {
	_, err := r.db.NewUpdate().
		Model((*models.User)(nil)).
		Set("password_hash = ?", passwordHash).
		Set("active = ?", true).
		Set("last_password_change = ?", time.Now()).
		Set("password_reset_token = NULL").
		Set("password_reset_token_expires = NULL").
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// UpdateLastLogin updates last login timestamp
func (r *userRepository) UpdateLastLogin(ctx context.Context, id string, ip string) error {
	_, err := r.db.NewUpdate().
		Model((*models.User)(nil)).
		Set("last_login = ?", time.Now()).
		Set("last_login_ip = ?", ip).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// IncrementLoginCount increments login count
func (r *userRepository) IncrementLoginCount(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.User)(nil)).
		Set("login_count = login_count + 1").
		Set("last_login = ?", time.Now()).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// MarkEmailVerified marks email as verified
func (r *userRepository) MarkEmailVerified(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.User)(nil)).
		Set("email_verified = ?", true).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// MarkPhoneVerified marks phone as verified
func (r *userRepository) MarkPhoneVerified(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.User)(nil)).
		Set("phone_verified = ?", true).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// Block blocks a user
func (r *userRepository) Block(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.User)(nil)).
		Set("blocked = ?", true).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// Unblock unblocks a user
func (r *userRepository) Unblock(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.User)(nil)).
		Set("blocked = ?", false).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// Activate activates a user
func (r *userRepository) Activate(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.User)(nil)).
		Set("active = ?", true).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// Deactivate deactivates a user
func (r *userRepository) Deactivate(ctx context.Context, id string) error {
	_, err := r.db.NewUpdate().
		Model((*models.User)(nil)).
		Set("active = ?", false).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// GetPlatformAdmins retrieves platform admins
func (r *userRepository) GetPlatformAdmins(ctx context.Context) ([]*models.User, error) {
	var users []*models.User
	err := r.db.NewSelect().
		Model(&users).
		Where("is_platform_admin = ?", true).
		Where("active = ?", true).
		Scan(ctx)
	return users, err
}

// GetOrganizationMembers retrieves organization members
func (r *userRepository) GetOrganizationMembers(ctx context.Context, organizationID string, activeOnly bool) ([]*models.User, error) {
	var users []*models.User
	query := r.db.NewSelect().
		Model(&users).
		Where("organization_id = ?", organizationID)

	if activeOnly {
		query = query.Where("active = ?", true)
	}

	err := query.Scan(ctx)
	return users, err
}

// CountByOrganization counts users by organization
func (r *userRepository) CountByOrganization(ctx context.Context, organizationID string, userType model.UserType) (int, error) {
	count, err := r.db.NewSelect().
		Model((*models.User)(nil)).
		Where("organization_id = ?", organizationID).
		Where("user_type = ?", userType).
		Where("active = ?", true).
		Count(ctx)
	return count, err
}

// ExistsByEmail checks if user exists by email
func (r *userRepository) ExistsByEmail(ctx context.Context, email string, userType model.UserType, organizationID *string) (bool, error) {
	query := r.db.NewSelect().
		Model((*models.User)(nil)).
		Where("email = ?", email).
		Where("user_type = ?", userType)

	if organizationID != nil {
		query = query.Where("organization_id = ?", *organizationID)
	}

	count, err := query.Count(ctx)
	return count > 0, err
}

// ExistsByUsername checks if user exists by username
func (r *userRepository) ExistsByUsername(ctx context.Context, username string, userType model.UserType, organizationID *string) (bool, error) {
	query := r.db.NewSelect().
		Model((*models.User)(nil)).
		Where("username = ?", username).
		Where("user_type = ?", userType)

	if organizationID != nil {
		query = query.Where("organization_id = ?", *organizationID)
	}

	count, err := query.Count(ctx)
	return count > 0, err
}
