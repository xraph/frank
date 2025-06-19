package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/predicate"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateUserInput) (*ent.User, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.User, error)
	GetByEmail(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID) (*ent.User, error)
	GetByUsername(ctx context.Context, username string, userType model.UserType, organizationID *xid.ID) (*ent.User, error)
	GetUserByPhone(ctx context.Context, phone string, userType model.UserType, organizationID *xid.ID) (*ent.User, error)
	GetByExternalID(ctx context.Context, externalID string, provider string, userType model.UserType, organizationID *xid.ID) (*ent.User, error)
	Update(ctx context.Context, id xid.ID, input UpdateUserInput) (*ent.User, error)
	Delete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params ListUsersParams) (*model.PaginatedOutput[*ent.User], error)
	ListByOrganization(ctx context.Context, organizationID xid.ID, params ListUsersParams) (*model.PaginatedOutput[*ent.User], error)
	Search(ctx context.Context, query string, params SearchUsersParams) (*model.PaginatedOutput[*ent.User], error)

	// Authentication related
	GetByPasswordResetToken(ctx context.Context, token string) (*ent.User, error)
	UpdatePassword(ctx context.Context, id xid.ID, passwordHash string) error
	UpdateLastLogin(ctx context.Context, id xid.ID, ip string) error
	IncrementLoginCount(ctx context.Context, id xid.ID) error

	// Verification
	MarkEmailVerified(ctx context.Context, id xid.ID) error
	MarkPhoneVerified(ctx context.Context, id xid.ID) error

	// User management
	Block(ctx context.Context, id xid.ID) error
	Unblock(ctx context.Context, id xid.ID) error
	Activate(ctx context.Context, id xid.ID) error
	Deactivate(ctx context.Context, id xid.ID) error

	// Organization context
	GetPlatformAdmins(ctx context.Context) ([]*ent.User, error)
	GetOrganizationMembers(ctx context.Context, organizationID xid.ID, activeOnly bool) ([]*ent.User, error)
	CountByOrganization(ctx context.Context, organizationID xid.ID, userType model.UserType) (int, error)

	// Existence checks
	ExistsByEmail(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID) (bool, error)
	ExistsByUsername(ctx context.Context, username string, userType model.UserType, organizationID *xid.ID) (bool, error)
}

// CreateUserInput represents input for creating a user
type CreateUserInput struct {
	Email                 string                 `json:"email"`
	PhoneNumber           *string                `json:"phone_number,omitempty"`
	FirstName             *string                `json:"first_name,omitempty"`
	LastName              *string                `json:"last_name,omitempty"`
	Username              *string                `json:"username,omitempty"`
	PasswordHash          *string                `json:"password_hash,omitempty"`
	ProviderName          string                 `json:"provider_name,omitempty"`
	UserType              model.UserType         `json:"user_type"`
	OrganizationID        *xid.ID                `json:"organization_id,omitempty"`
	PrimaryOrganizationID *xid.ID                `json:"primary_organization_id,omitempty"`
	IsPlatformAdmin       bool                   `json:"is_platform_admin"`
	AuthProvider          string                 `json:"auth_provider"`
	ExternalID            *string                `json:"external_id,omitempty"`
	CustomerID            *string                `json:"customer_id,omitempty"`
	CustomAttributes      map[string]interface{} `json:"custom_attributes,omitempty"`
	CreatedBy             *string                `json:"created_by,omitempty"`
	ProfileImageURL       *string                `json:"profile_image_url,omitempty"`
	Locale                string                 `json:"locale"`
	Timezone              *string                `json:"timezone,omitempty"`
	Metadata              map[string]interface{} `json:"metadata,omitempty"`
	EmailVerified         bool                   `json:"email_verified,omitempty"`
	PhoneVerified         bool                   `json:"phone_verified,omitempty"`
	Active                bool                   `json:"active,omitempty"`
	Blocked               bool                   `json:"blocked,omitempty"`
}

// UpdateUserInput represents input for updating a user
type UpdateUserInput struct {
	model.UpdateUserRequest

	EmailVerified         *bool                  `json:"emailVerified,omitempty"`
	PhoneVerified         *bool                  `json:"phoneVerified,omitempty"`
	Metadata              map[string]interface{} `json:"metadata,omitempty"`
	PasswordResetToken    *string                `json:"passwordResetToken,omitempty"`
	PasswordResetTokenExp *int64                 `json:"passwordResetTokenExp,omitempty"`
	ExternalID            *string                `json:"external_id,omitempty"`
	AuthProvider          *string                `json:"auth_provider,omitempty"`
}

// ListUsersParams represents parameters for listing users
type ListUsersParams struct {
	model.PaginationParams
	UserType       *model.UserType `json:"user_type,omitempty"`
	OrganizationID *xid.ID         `json:"organization_id,omitempty"`
	Active         *bool           `json:"active,omitempty"`
	Blocked        *bool           `json:"blocked,omitempty"`
	EmailVerified  *bool           `json:"email_verified,omitempty"`
	AuthProvider   *string         `json:"auth_provider,omitempty"`
}

// SearchUsersParams represents parameters for searching users
type SearchUsersParams struct {
	model.PaginationParams
	UserType       *model.UserType `json:"user_type,omitempty"`
	OrganizationID *xid.ID         `json:"organization_id,omitempty"`
	Fields         []string        `json:"fields,omitempty"` // Fields to search in: email, first_name, last_name, username
	ExactMatch     bool            `json:"exact_match"`
}

// userRepository implements UserRepository
type userRepository struct {
	client *ent.Client
	logger logging.Logger
}

// NewUserRepository creates a new user repository
func NewUserRepository(client *ent.Client, logger logging.Logger) UserRepository {
	return &userRepository{
		client: client,
		logger: logger,
	}
}

// Create creates a new user
func (r *userRepository) Create(ctx context.Context, input CreateUserInput) (*ent.User, error) {
	create := r.client.User.Create().
		SetEmail(input.Email).
		SetUserType(input.UserType).
		SetAuthProvider(input.AuthProvider).
		SetLocale(input.Locale).
		SetIsPlatformAdmin(input.IsPlatformAdmin)

	// Set optional fields
	if input.PhoneNumber != nil {
		create.SetPhoneNumber(*input.PhoneNumber)
	}
	if input.FirstName != nil {
		create.SetFirstName(*input.FirstName)
	}
	if input.LastName != nil {
		create.SetLastName(*input.LastName)
	}
	if input.Username != nil {
		create.SetUsername(*input.Username)
	}
	if input.PasswordHash != nil {
		create.SetPasswordHash(*input.PasswordHash)
	}
	if input.OrganizationID != nil {
		create.SetOrganizationID(*input.OrganizationID)
	}
	if input.PrimaryOrganizationID != nil {
		create.SetPrimaryOrganizationID(*input.PrimaryOrganizationID)
	}
	if input.ExternalID != nil {
		create.SetExternalID(*input.ExternalID)
	}
	if input.CustomerID != nil {
		create.SetCustomerID(*input.CustomerID)
	}
	if input.CustomAttributes != nil {
		create.SetCustomAttributes(input.CustomAttributes)
	}
	if input.CreatedBy != nil {
		create.SetCreatedBy(*input.CreatedBy)
	}
	if input.ProfileImageURL != nil {
		create.SetProfileImageURL(*input.ProfileImageURL)
	}
	if input.Timezone != nil {
		create.SetTimezone(*input.Timezone)
	}
	if input.Metadata != nil {
		create.SetMetadata(input.Metadata)
	}

	u, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "User with this email already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create user")
	}

	return u, nil
}

// GetByID retrieves a user by ID
func (r *userRepository) GetByID(ctx context.Context, id xid.ID) (*ent.User, error) {
	u, err := r.client.User.
		Query().
		Where(user.ID(id)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "User not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get user by ID")
	}
	return u, nil
}

// GetByEmail retrieves a user by email with optional filters
func (r *userRepository) GetByEmail(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID) (*ent.User, error) {
	query := r.client.User.Query().
		Where(
			user.Email(email),
			user.UserTypeEQ(userType),
		)

	if organizationID != nil {
		query = query.Where(user.OrganizationID(*organizationID))
	}

	u, err := query.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "User not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get user by email")
	}
	return u, nil
}

// GetByUsername retrieves a user by username
func (r *userRepository) GetByUsername(ctx context.Context, username string, userType model.UserType, organizationID *xid.ID) (*ent.User, error) {
	query := r.client.User.Query().
		Where(
			user.Username(username),
			user.UserTypeEQ(userType),
		)

	if organizationID != nil {
		query = query.Where(user.OrganizationID(*organizationID))
	}

	u, err := query.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "User not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get user by username")
	}
	return u, nil
}

// GetUserByPhone retrieves a user by username
func (r *userRepository) GetUserByPhone(ctx context.Context, phone string, userType model.UserType, organizationID *xid.ID) (*ent.User, error) {
	query := r.client.User.Query().
		Where(
			user.PhoneNumber(phone),
			user.UserTypeEQ(userType),
		)

	if organizationID != nil {
		query = query.Where(user.OrganizationID(*organizationID))
	}

	u, err := query.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "User not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get user by username")
	}
	return u, nil
}

// GetByExternalID retrieves a user by external provider ID
func (r *userRepository) GetByExternalID(ctx context.Context, externalID string, provider string, userType model.UserType, organizationID *xid.ID) (*ent.User, error) {
	query := r.client.User.Query().
		Where(
			user.ExternalID(externalID),
			user.AuthProvider(provider),
			user.UserTypeEQ(userType),
		)

	if organizationID != nil {
		query = query.Where(user.OrganizationID(*organizationID))
	}

	u, err := query.Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "User not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get user by external ID")
	}
	return u, nil
}

// Update updates a user
func (r *userRepository) Update(ctx context.Context, id xid.ID, input UpdateUserInput) (*ent.User, error) {
	update := r.client.User.UpdateOneID(id)

	if input.Email != nil {
		update.SetEmail(*input.Email)
	}
	if input.PhoneNumber != nil {
		update.SetPhoneNumber(*input.PhoneNumber)
	}
	if input.FirstName != nil {
		update.SetFirstName(*input.FirstName)
	}
	if input.LastName != nil {
		update.SetLastName(*input.LastName)
	}
	if input.Username != nil {
		update.SetUsername(*input.Username)
	}
	if input.EmailVerified != nil {
		update.SetEmailVerified(*input.EmailVerified)
	}
	if input.PhoneVerified != nil {
		update.SetPhoneVerified(*input.PhoneVerified)
	}
	if input.Active != nil {
		update.SetActive(*input.Active)
	}
	if input.Blocked != nil {
		update.SetBlocked(*input.Blocked)
	}
	if input.ProfileImageURL != nil {
		update.SetProfileImageURL(*input.ProfileImageURL)
	}
	if input.Locale != nil {
		update.SetLocale(*input.Locale)
	}
	if input.Timezone != nil {
		update.SetTimezone(*input.Timezone)
	}
	if input.CustomAttributes != nil {
		update.SetCustomAttributes(input.CustomAttributes)
	}
	if input.Metadata != nil {
		update.SetMetadata(input.Metadata)
	}
	if input.PasswordResetToken != nil {
		update.SetPasswordResetToken(*input.PasswordResetToken)
	}

	u, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "User not found")
		}
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "User with this email already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update user")
	}
	return u, nil
}

// Delete deletes a user
func (r *userRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.User.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "User not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete user")
	}
	return nil
}

// List retrieves users with pagination and filtering
func (r *userRepository) List(ctx context.Context, params ListUsersParams) (*model.PaginatedOutput[*ent.User], error) {
	query := r.client.User.Query()

	// Apply filters
	if params.UserType != nil {
		query = query.Where(user.UserTypeEQ(*params.UserType))
	}
	if params.OrganizationID != nil {
		query = query.Where(user.OrganizationID(*params.OrganizationID))
	}
	if params.Active != nil {
		query = query.Where(user.Active(*params.Active))
	}
	if params.Blocked != nil {
		query = query.Where(user.Blocked(*params.Blocked))
	}
	if params.EmailVerified != nil {
		query = query.Where(user.EmailVerified(*params.EmailVerified))
	}
	if params.AuthProvider != nil {
		query = query.Where(user.AuthProvider(*params.AuthProvider))
	}

	// Apply pagination
	return model.WithPaginationAndOptions[*ent.User, *ent.UserQuery](ctx, query, params.PaginationParams)
}

// ListByOrganization retrieves users by organization
func (r *userRepository) ListByOrganization(ctx context.Context, organizationID xid.ID, params ListUsersParams) (*model.PaginatedOutput[*ent.User], error) {
	params.OrganizationID = &organizationID
	return r.List(ctx, params)
}

// Search searches for users
func (r *userRepository) Search(ctx context.Context, query string, params SearchUsersParams) (*model.PaginatedOutput[*ent.User], error) {
	q := r.client.User.Query()

	// Apply filters
	if params.UserType != nil {
		q = q.Where(user.UserTypeEQ(*params.UserType))
	}
	if params.OrganizationID != nil {
		q = q.Where(user.OrganizationID(*params.OrganizationID))
	}

	// Apply search conditions
	var searchConditions []predicate.User

	if params.ExactMatch {
		// Exact match search
		searchConditions = append(searchConditions,
			user.Email(query),
			user.Username(query),
			user.FirstName(query),
			user.LastName(query),
		)
	} else {
		// Partial match search
		searchConditions = append(searchConditions,
			user.EmailContains(query),
			user.UsernameContains(query),
			user.FirstNameContains(query),
			user.LastNameContains(query),
		)
	}

	// Apply OR conditions for search
	orConditions := make([]predicate.User, 0, len(searchConditions))
	for _, condition := range searchConditions {
		orConditions = append(orConditions, condition)
	}

	if len(orConditions) > 0 {
		q = q.Where(user.Or(orConditions...))
	}

	return model.WithPaginationAndOptions[*ent.User, *ent.UserQuery](ctx, q, params.PaginationParams)
}

// Authentication-related methods

func (r *userRepository) GetByPasswordResetToken(ctx context.Context, token string) (*ent.User, error) {
	u, err := r.client.User.Query().
		Where(user.PasswordResetToken(token)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Invalid password reset token")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get user by password reset token")
	}
	return u, nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, id xid.ID, passwordHash string) error {
	err := r.client.User.UpdateOneID(id).
		SetPasswordHash(passwordHash).
		SetActive(true).
		SetLastPasswordChange(time.Now()).
		ClearPasswordResetToken().
		ClearPasswordResetTokenExpires().
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "User not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update password")
	}
	return nil
}

func (r *userRepository) UpdateLastLogin(ctx context.Context, id xid.ID, ip string) error {
	update := r.client.User.UpdateOneID(id).
		SetLastLoginIP(ip)

	err := update.Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "User not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update last login")
	}
	return nil
}

func (r *userRepository) IncrementLoginCount(ctx context.Context, id xid.ID) error {
	// Get current login count
	u, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	err = r.client.User.UpdateOneID(id).
		SetLoginCount(u.LoginCount + 1).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to increment login count")
	}
	return nil
}

// Verification methods

func (r *userRepository) MarkEmailVerified(ctx context.Context, id xid.ID) error {
	err := r.client.User.UpdateOneID(id).
		SetEmailVerified(true).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "User not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to mark email as verified")
	}
	return nil
}

func (r *userRepository) MarkPhoneVerified(ctx context.Context, id xid.ID) error {
	err := r.client.User.UpdateOneID(id).
		SetPhoneVerified(true).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "User not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to mark phone as verified")
	}
	return nil
}

// User management methods

func (r *userRepository) Block(ctx context.Context, id xid.ID) error {
	err := r.client.User.UpdateOneID(id).
		SetBlocked(true).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "User not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to block user")
	}
	return nil
}

func (r *userRepository) Unblock(ctx context.Context, id xid.ID) error {
	err := r.client.User.UpdateOneID(id).
		SetBlocked(false).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "User not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to unblock user")
	}
	return nil
}

func (r *userRepository) Activate(ctx context.Context, id xid.ID) error {
	err := r.client.User.UpdateOneID(id).
		SetActive(true).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "User not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to activate user")
	}
	return nil
}

func (r *userRepository) Deactivate(ctx context.Context, id xid.ID) error {
	err := r.client.User.UpdateOneID(id).
		SetActive(false).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "User not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to deactivate user")
	}
	return nil
}

// Organization context methods

func (r *userRepository) GetPlatformAdmins(ctx context.Context) ([]*ent.User, error) {
	users, err := r.client.User.Query().
		Where(
			user.IsPlatformAdmin(true),
			user.Active(true),
		).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get platform admins")
	}
	return users, nil
}

func (r *userRepository) GetOrganizationMembers(ctx context.Context, organizationID xid.ID, activeOnly bool) ([]*ent.User, error) {
	query := r.client.User.Query().
		Where(user.OrganizationID(organizationID))

	if activeOnly {
		query = query.Where(user.Active(true))
	}

	users, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get organization members")
	}
	return users, nil
}

func (r *userRepository) CountByOrganization(ctx context.Context, organizationID xid.ID, userType model.UserType) (int, error) {
	count, err := r.client.User.Query().
		Where(
			user.OrganizationID(organizationID),
			user.UserTypeEQ(userType),
			user.Active(true),
		).
		Count(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count users by organization")
	}
	return count, nil
}

// Existence check methods

func (r *userRepository) ExistsByEmail(ctx context.Context, email string, userType model.UserType, organizationID *xid.ID) (bool, error) {
	query := r.client.User.Query().
		Where(
			user.Email(email),
			user.UserTypeEQ(userType),
		)

	if organizationID != nil {
		query = query.Where(user.OrganizationID(*organizationID))
	}

	exists, err := query.Exist(ctx)
	if err != nil {
		fmt.Println(err)
		return false, errors.Wrap(err, errors.CodeDatabaseError, "failed to check if user exists by email")
	}
	return exists, nil
}

func (r *userRepository) ExistsByUsername(ctx context.Context, username string, userType model.UserType, organizationID *xid.ID) (bool, error) {
	query := r.client.User.Query().
		Where(
			user.Username(username),
			user.UserTypeEQ(userType),
		)

	if organizationID != nil {
		query = query.Where(user.OrganizationID(*organizationID))
	}

	exists, err := query.Exist(ctx)
	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "failed to check if user exists by username")
	}
	return exists, nil
}

// Helper function to check if error is a constraint violation
func IsConflict(err error) bool {
	return ent.IsConstraintError(err)
}

// Helper function to check if error is not found
func IsNotFound(err error) bool {
	return ent.IsNotFound(err)
}
