package user

import (
	"context"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/ent/predicate"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/utils"
)

// Repository provides access to user storage
type Repository interface {
	// Create creates a new user
	Create(ctx context.Context, input RepositoryCreateInput) (*ent.User, error)

	// GetByID retrieves a user by ID
	GetByID(ctx context.Context, id string) (*ent.User, error)

	// GetByEmail retrieves a user by email
	GetByEmail(ctx context.Context, email string) (*ent.User, error)

	// List retrieves users with pagination
	List(ctx context.Context, input RepositoryListInput) ([]*ent.User, int, error)

	// Update updates a user
	Update(ctx context.Context, id string, input RepositoryUpdateInput) (*ent.User, error)

	// Delete deletes a user
	Delete(ctx context.Context, id string) error

	// GetUserOrganizations retrieves organizations a user belongs to
	GetUserOrganizations(ctx context.Context, userID string) ([]*ent.Organization, error)

	// IsUserMemberOfOrganization checks if a user is a member of an organization
	IsUserMemberOfOrganization(ctx context.Context, userID, orgID string) (bool, error)

	// GetUserCount returns the total number of users
	GetUserCount(ctx context.Context) (int, error)
}

// RepositoryCreateInput represents input for creating a user
type RepositoryCreateInput struct {
	Email           string
	PasswordHash    *string
	PhoneNumber     string
	FirstName       string
	LastName        string
	Metadata        map[string]interface{}
	ProfileImageURL string
	Locale          string
}

// RepositoryUpdateInput represents input for updating a user
type RepositoryUpdateInput struct {
	PasswordHash          *string
	PhoneNumber           *string
	FirstName             *string
	LastName              *string
	Metadata              map[string]interface{}
	ProfileImageURL       *string
	Locale                *string
	Active                *bool
	EmailVerified         *bool
	PhoneVerified         *bool
	LastLogin             *time.Time
	LastPasswordChange    *time.Time
	PrimaryOrganizationID *string
}

// RepositoryListInput represents input for listing users
type RepositoryListInput struct {
	Offset         int
	Limit          int
	Search         string
	OrganizationID string
}

type repository struct {
	client *ent.Client
}

// NewRepository creates a new user repository
func NewRepository(client *ent.Client) Repository {
	return &repository{
		client: client,
	}
}

// Create creates a new user
func (r *repository) Create(ctx context.Context, input RepositoryCreateInput) (*ent.User, error) {
	// Generate UUID
	id := utils.NewID()

	// Check if email is already taken
	exists, err := r.client.User.
		Query().
		Where(user.EmailEQ(input.Email)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check email uniqueness")
	}

	if exists {
		return nil, errors.New(errors.CodeConflict, "email is already in use")
	}

	// Check if phone number is already taken (if provided)
	if input.PhoneNumber != "" {
		exists, err = r.client.User.
			Query().
			Where(user.PhoneNumberEQ(input.PhoneNumber)).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check phone number uniqueness")
		}

		if exists {
			return nil, errors.New(errors.CodeConflict, "phone number is already in use")
		}
	}

	// Build user creation query
	create := r.client.User.
		Create().
		SetID(id.String()).
		SetEmail(input.Email).
		SetNillableFirstName(nilIfEmpty(input.FirstName)).
		SetNillableLastName(nilIfEmpty(input.LastName)).
		SetNillablePhoneNumber(nilIfEmpty(input.PhoneNumber))

	// Optional fields
	if input.PasswordHash != nil {
		create = create.SetPasswordHash(*input.PasswordHash)
	}

	if input.Metadata != nil {
		create = create.SetMetadata(input.Metadata)
	}

	if input.ProfileImageURL != "" {
		create = create.SetProfileImageURL(input.ProfileImageURL)
	}

	if input.Locale != "" {
		create = create.SetLocale(input.Locale)
	} else {
		create = create.SetLocale("en") // Default locale
	}

	// Create user
	user, err := create.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create user")
	}

	return user, nil
}

// GetByID retrieves a user by ID
func (r *repository) GetByID(ctx context.Context, id string) (*ent.User, error) {
	user, err := r.client.User.
		Query().
		Where(user.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get user")
	}

	return user, nil
}

// GetByEmail retrieves a user by email
func (r *repository) GetByEmail(ctx context.Context, email string) (*ent.User, error) {
	user, err := r.client.User.
		Query().
		Where(user.EmailEQ(email)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get user by email")
	}

	return user, nil
}

// List retrieves users with pagination
func (r *repository) List(ctx context.Context, input RepositoryListInput) ([]*ent.User, int, error) {
	// Build the query with predicates
	var predicates []predicate.User

	// Apply search filter if provided
	if input.Search != "" {
		predicates = append(predicates,
			user.Or(
				user.EmailContainsFold(input.Search),
				user.FirstNameContainsFold(input.Search),
				user.LastNameContainsFold(input.Search),
				user.PhoneNumberContainsFold(input.Search),
			),
		)
	}

	// Apply organization filter if provided
	if input.OrganizationID != "" {
		predicates = append(predicates,
			user.HasOrganizationsWith(organization.Or(organization.ID(input.OrganizationID), organization.Slug(input.OrganizationID))),
		)
	}

	// Create query with predicates
	query := r.client.User.Query()
	if len(predicates) > 0 {
		query = query.Where(user.And(predicates...))
	}

	// Count total results
	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to count users")
	}

	// Apply pagination
	users, err := query.
		Limit(input.Limit).
		Offset(input.Offset).
		Order(ent.Desc(user.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to list users")
	}

	return users, total, nil
}

// Update updates a user
func (r *repository) Update(ctx context.Context, id string, input RepositoryUpdateInput) (*ent.User, error) {
	// Check if user exists
	exists, err := r.client.User.
		Query().
		Where(user.ID(id)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !exists {
		return nil, errors.New(errors.CodeNotFound, "user not found")
	}

	// Build update query
	update := r.client.User.
		UpdateOneID(id)

	// Apply updates
	if input.PasswordHash != nil {
		update = update.SetPasswordHash(*input.PasswordHash)
	}

	if input.PhoneNumber != nil {
		// Check if phone number is already taken (if provided and not empty)
		if *input.PhoneNumber != "" {
			exists, err = r.client.User.
				Query().
				Where(
					user.PhoneNumberEQ(*input.PhoneNumber),
					user.IDNEQ(id),
				).
				Exist(ctx)

			if err != nil {
				return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check phone number uniqueness")
			}

			if exists {
				return nil, errors.New(errors.CodeConflict, "phone number is already in use")
			}

			update = update.SetPhoneNumber(*input.PhoneNumber)
		} else {
			// Clear phone number
			update = update.ClearPhoneNumber()
		}
	}

	if input.FirstName != nil {
		if *input.FirstName != "" {
			update = update.SetFirstName(*input.FirstName)
		} else {
			update = update.ClearFirstName()
		}
	}

	if input.LastName != nil {
		if *input.LastName != "" {
			update = update.SetLastName(*input.LastName)
		} else {
			update = update.ClearLastName()
		}
	}

	if input.Metadata != nil {
		update = update.SetMetadata(input.Metadata)
	}

	if input.ProfileImageURL != nil {
		if *input.ProfileImageURL != "" {
			update = update.SetProfileImageURL(*input.ProfileImageURL)
		} else {
			update = update.ClearProfileImageURL()
		}
	}

	if input.Locale != nil {
		update = update.SetLocale(*input.Locale)
	}

	if input.Active != nil {
		update = update.SetActive(*input.Active)
	}

	if input.EmailVerified != nil {
		update = update.SetEmailVerified(*input.EmailVerified)
	}

	if input.PhoneVerified != nil {
		update = update.SetPhoneVerified(*input.PhoneVerified)
	}

	if input.LastLogin != nil {
		update = update.SetLastLogin(*input.LastLogin)
	}

	if input.LastPasswordChange != nil {
		update = update.SetLastPasswordChange(*input.LastPasswordChange)
	}

	if input.PrimaryOrganizationID != nil {
		if *input.PrimaryOrganizationID != "" {
			update = update.SetPrimaryOrganizationID(*input.PrimaryOrganizationID)
		} else {
			update = update.ClearPrimaryOrganizationID()
		}
	}

	// Execute update
	user, err := update.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to update user")
	}

	return user, nil
}

// Delete deletes a user
func (r *repository) Delete(ctx context.Context, id string) error {
	// Check if user exists
	exists, err := r.client.User.
		Query().
		Where(user.ID(id)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !exists {
		return errors.New(errors.CodeNotFound, "user not found")
	}

	// Delete user
	err = r.client.User.
		DeleteOneID(id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete user")
	}

	return nil
}

// GetUserOrganizations retrieves organizations a user belongs to
func (r *repository) GetUserOrganizations(ctx context.Context, userID string) ([]*ent.Organization, error) {
	// Check if user exists
	exists, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !exists {
		return nil, errors.New(errors.CodeNotFound, "user not found")
	}

	// Get organizations
	orgs, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		QueryOrganizations().
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get user organizations")
	}

	return orgs, nil
}

// IsUserMemberOfOrganization checks if a user is a member of an organization
func (r *repository) IsUserMemberOfOrganization(ctx context.Context, userID, orgID string) (bool, error) {
	return r.client.User.
		Query().
		Where(
			user.ID(userID),
			user.HasOrganizationsWith(organization.Or(organization.ID(orgID), organization.Slug(orgID))),
		).
		Exist(ctx)
}

// GetUserCount retrieves the total count of users from the database. Returns the count and any potential error.
func (r *repository) GetUserCount(ctx context.Context) (int, error) {
	return r.client.User.Query().Count(ctx)
}

// Helper function to return nil for empty strings
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
