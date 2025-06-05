package user

import (
	"context"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/ent/predicate"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

var (
	ErrUserNotFound            = errors.New(errors.CodeNotFound, "user not found")
	ErrEmailAlreadyInUse       = errors.New(errors.CodeConflict, "email is already in use")
	ErrPhoneNumberAlreadyInUse = errors.New(errors.CodeConflict, "phone number is already in use")
)

// Repository provides access to user storage
type Repository interface {
	// Create creates a new user
	Create(ctx context.Context, userCreate *ent.UserCreate) (*ent.User, error)

	// GetByID retrieves a user by ID
	GetByID(ctx context.Context, id xid.ID) (*ent.User, error)

	// GetByEmail retrieves a user by email
	GetByEmail(ctx context.Context, email string) (*ent.User, error)

	// List retrieves users with pagination
	List(ctx context.Context, params ListUsersParams) (*model.PaginatedOutput[*ent.User], error)

	// Update updates a user
	Update(ctx context.Context, userUpdate *ent.UserUpdateOne) (*ent.User, error)

	// Delete deletes a user
	Delete(ctx context.Context, id xid.ID) error

	// GetUserOrganizations retrieves organizations a user belongs to
	GetUserOrganizations(ctx context.Context, userID xid.ID) ([]*ent.Organization, error)

	// IsUserMemberOfOrganization checks if a user is a member of an organization
	IsUserMemberOfOrganization(ctx context.Context, userID, orgID xid.ID) (bool, error)

	// GetUserCount returns the total number of users
	GetUserCount(ctx context.Context) (int, error)

	// BulkCreate creates multiple users in a single operation
	BulkCreate(ctx context.Context, users []*ent.UserCreate) ([]*ent.User, error)

	// BulkUpdate updates multiple users in a single operation
	BulkUpdate(ctx context.Context, updates []*ent.UserUpdateOne) ([]*ent.User, error)

	// ExportAll exports all users
	ExportAll(ctx context.Context) ([]*ent.User, error)

	// Client returns the database client
	Client() *ent.Client
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
func (r *repository) Create(ctx context.Context, userCreate *ent.UserCreate) (*ent.User, error) {
	// Check if email is already taken
	email, emailExists := userCreate.Mutation().Email()
	if emailExists {
		exists, err := r.client.User.
			Query().
			Where(user.EmailEQ(email)).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check email uniqueness")
		}

		if exists {
			return nil, ErrEmailAlreadyInUse
		}
	}

	// Check if phone number is already taken (if provided)
	phoneNumber, phoneExists := userCreate.Mutation().PhoneNumber()
	if phoneExists && phoneNumber != "" {
		exists, err := r.client.User.
			Query().
			Where(user.PhoneNumberEQ(phoneNumber)).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check phone number uniqueness")
		}

		if exists {
			return nil, ErrPhoneNumberAlreadyInUse
		}
	}

	// Set default locale if not provided
	if _, localeExists := userCreate.Mutation().Locale(); !localeExists {
		userCreate = userCreate.SetLocale("en")
	}

	// Create user
	user, err := userCreate.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrEmailAlreadyInUse
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create user")
	}

	return user, nil
}

// GetByID retrieves a user by ID
func (r *repository) GetByID(ctx context.Context, id xid.ID) (*ent.User, error) {
	user, err := r.client.User.
		Query().
		Where(user.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrUserNotFound
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
			return nil, ErrUserNotFound
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get user by email")
	}

	return user, nil
}

// List retrieves users with pagination
func (r *repository) List(ctx context.Context, params ListUsersParams) (*model.PaginatedOutput[*ent.User], error) {
	// Build the query with predicates
	var predicates []predicate.User

	// Apply search filter if provided
	if params.Search != "" {
		predicates = append(predicates,
			user.Or(
				user.EmailContainsFold(params.Search),
				user.FirstNameContainsFold(params.Search),
				user.LastNameContainsFold(params.Search),
				user.PhoneNumberContainsFold(params.Search),
			),
		)
	}

	// Apply organization filter if provided
	if params.OrgID != "" {
		orgID, err := xid.FromString(params.OrgID)
		if err == nil {
			predicates = append(predicates,
				user.HasOrganizationsWith(organization.ID(orgID)),
			)
		} else {
			// Treat as slug if not a valid XID
			predicates = append(predicates,
				user.HasOrganizationsWith(organization.Slug(params.OrgID)),
			)
		}
	}

	// Apply active filter if provided
	if params.Active.IsSet {
		predicates = append(predicates, user.Active(params.Active.Value))
	}

	// Create query with predicates
	query := r.client.User.Query()
	if len(predicates) > 0 {
		query = query.Where(user.And(predicates...))
	}

	// Apply ordering
	for _, o := range model.GetOrdering(params.PaginationParams) {
		if o.Desc {
			query = query.Order(ent.Desc(o.Field))
			continue
		}
		query = query.Order(ent.Asc(o.Field))
	}

	return model.WithPaginationAndOptions[*ent.User, *ent.UserQuery](ctx, query, params.PaginationParams)
}

// Update updates a user
func (r *repository) Update(ctx context.Context, userUpdate *ent.UserUpdateOne) (*ent.User, error) {
	// Get the user ID from the update mutation
	userID, _ := userUpdate.Mutation().ID()

	// Check if user exists
	exists, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !exists {
		return nil, ErrUserNotFound
	}

	// Check phone number uniqueness if being updated
	phoneNumber, phoneUpdated := userUpdate.Mutation().PhoneNumber()
	if phoneUpdated && phoneNumber != "" {
		exists, err = r.client.User.
			Query().
			Where(
				user.PhoneNumberEQ(phoneNumber),
				user.IDNEQ(userID),
			).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check phone number uniqueness")
		}

		if exists {
			return nil, ErrPhoneNumberAlreadyInUse
		}
	}

	// Execute update
	user, err := userUpdate.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to update user")
	}

	return user, nil
}

// Delete deletes a user
func (r *repository) Delete(ctx context.Context, id xid.ID) error {
	// Check if user exists
	exists, err := r.client.User.
		Query().
		Where(user.ID(id)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !exists {
		return ErrUserNotFound
	}

	// Delete user
	err = r.client.User.
		DeleteOneID(id).
		Exec(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return ErrUserNotFound
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete user")
	}

	return nil
}

// GetUserOrganizations retrieves organizations a user belongs to
func (r *repository) GetUserOrganizations(ctx context.Context, userID xid.ID) ([]*ent.Organization, error) {
	// Check if user exists
	exists, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !exists {
		return nil, ErrUserNotFound
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
func (r *repository) IsUserMemberOfOrganization(ctx context.Context, userID, orgID xid.ID) (bool, error) {
	return r.client.User.
		Query().
		Where(
			user.ID(userID),
			user.HasOrganizationsWith(organization.ID(orgID)),
		).
		Exist(ctx)
}

// GetUserCount retrieves the total count of users from the database
func (r *repository) GetUserCount(ctx context.Context) (int, error) {
	count, err := r.client.User.Query().Count(ctx)
	if err != nil {
		return 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to count users")
	}
	return count, nil
}

// BulkCreate creates multiple users in a single operation
func (r *repository) BulkCreate(ctx context.Context, users []*ent.UserCreate) ([]*ent.User, error) {
	// Create users in a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]*ent.User, 0, len(users))

	for _, userCreate := range users {
		// Get email from mutation
		email, _ := userCreate.Mutation().Email()

		// Clone the create action for transaction
		creator := tx.User.Create().SetEmail(email)

		// Add other fields from the original create
		if firstName, exists := userCreate.Mutation().FirstName(); exists {
			creator.SetFirstName(firstName)
		}

		if lastName, exists := userCreate.Mutation().LastName(); exists {
			creator.SetLastName(lastName)
		}

		if phoneNumber, exists := userCreate.Mutation().PhoneNumber(); exists {
			creator.SetPhoneNumber(phoneNumber)
		}

		if passwordHash, exists := userCreate.Mutation().PasswordHash(); exists {
			creator.SetPasswordHash(passwordHash)
		}

		if profileImageURL, exists := userCreate.Mutation().ProfileImageURL(); exists {
			creator.SetProfileImageURL(profileImageURL)
		}

		if locale, exists := userCreate.Mutation().Locale(); exists {
			creator.SetLocale(locale)
		} else {
			creator.SetLocale("en") // Default locale
		}

		if metadata, exists := userCreate.Mutation().Metadata(); exists {
			creator.SetMetadata(metadata)
		}

		// Create user
		user, err := creator.Save(ctx)
		if err != nil {
			tx.Rollback()
			return nil, err
		}

		results = append(results, user)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return results, nil
}

// BulkUpdate updates multiple users in a single operation
func (r *repository) BulkUpdate(ctx context.Context, updates []*ent.UserUpdateOne) ([]*ent.User, error) {
	// Update users in a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]*ent.User, 0, len(updates))

	for _, update := range updates {
		// Get ID for the update
		p := update.Mutation()
		userID, _ := p.ID()

		// Create updater
		updater := tx.User.UpdateOneID(userID)

		// Apply all updates from the original update
		if firstName, exists := p.FirstName(); exists {
			updater.SetFirstName(firstName)
		}

		if lastName, exists := p.LastName(); exists {
			updater.SetLastName(lastName)
		}

		if phoneNumber, exists := p.PhoneNumber(); exists {
			updater.SetPhoneNumber(phoneNumber)
		}

		if passwordHash, exists := p.PasswordHash(); exists {
			updater.SetPasswordHash(passwordHash)
		}

		if profileImageURL, exists := p.ProfileImageURL(); exists {
			updater.SetProfileImageURL(profileImageURL)
		}

		if locale, exists := p.Locale(); exists {
			updater.SetLocale(locale)
		}

		if metadata, exists := p.Metadata(); exists {
			updater.SetMetadata(metadata)
		}

		if active, exists := p.Active(); exists {
			updater.SetActive(active)
		}

		if emailVerified, exists := p.EmailVerified(); exists {
			updater.SetEmailVerified(emailVerified)
		}

		if phoneVerified, exists := p.PhoneVerified(); exists {
			updater.SetPhoneVerified(phoneVerified)
		}

		if lastLogin, exists := p.LastLogin(); exists {
			updater.SetLastLogin(lastLogin)
		}

		if lastPasswordChange, exists := p.LastPasswordChange(); exists {
			updater.SetLastPasswordChange(lastPasswordChange)
		}

		if primaryOrgID, exists := p.PrimaryOrganizationID(); exists {
			updater.SetPrimaryOrganizationID(primaryOrgID)
		}

		// Update user
		user, err := updater.Save(ctx)
		if err != nil {
			tx.Rollback()
			return nil, err
		}

		results = append(results, user)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return results, nil
}

// ExportAll exports all users
func (r *repository) ExportAll(ctx context.Context) ([]*ent.User, error) {
	users, err := r.client.User.Query().All(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to export users")
	}
	return users, nil
}

// Client returns the database client
func (r *repository) Client() *ent.Client {
	return r.client
}
