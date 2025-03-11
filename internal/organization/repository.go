package organization

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/featureflag"
	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/ent/organizationfeature"
	"github.com/juicycleff/frank/ent/role"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/pkg/errors"
)

// Repository provides access to organization storage
type Repository interface {
	// Create creates a new organization
	Create(ctx context.Context, input RepositoryCreateInput) (*ent.Organization, error)

	// GetByID retrieves an organization by ID
	GetByID(ctx context.Context, id string) (*ent.Organization, error)

	// GetBySlug retrieves an organization by slug
	GetBySlug(ctx context.Context, slug string) (*ent.Organization, error)

	// GetByDomain retrieves an organization by domain
	GetByDomain(ctx context.Context, domain string) (*ent.Organization, error)

	// List retrieves organizations with pagination
	List(ctx context.Context, input RepositoryListInput) ([]*ent.Organization, int, error)

	// Update updates an organization
	Update(ctx context.Context, id string, input RepositoryUpdateInput) (*ent.Organization, error)

	// Delete deletes an organization
	Delete(ctx context.Context, id string) error

	// GetMembers retrieves members of an organization
	GetMembers(ctx context.Context, orgID string, input RepositoryListInput) ([]*ent.User, int, error)

	// AddMember adds a user to an organization
	AddMember(ctx context.Context, orgID, userID string, roles []string) error

	// RemoveMember removes a user from an organization
	RemoveMember(ctx context.Context, orgID, userID string) error

	// UpdateMember updates a member's roles in an organization
	UpdateMember(ctx context.Context, orgID, userID string, roles []string) error

	// IsFeatureEnabled checks if a feature is enabled for an organization
	IsFeatureEnabled(ctx context.Context, orgID string, featureKey string) (bool, error)

	// GetFeatures retrieves features of an organization
	GetFeatures(ctx context.Context, orgID string) ([]*ent.OrganizationFeature, error)

	// EnableFeature enables a feature for an organization
	EnableFeature(ctx context.Context, orgID string, featureKey string, settings map[string]interface{}) error

	// DisableFeature disables a feature for an organization
	DisableFeature(ctx context.Context, orgID string, featureKey string) error
}

// RepositoryCreateInput represents input for creating an organization
type RepositoryCreateInput struct {
	Name        string
	Slug        string
	Domain      string
	LogoURL     string
	Plan        string
	OwnerID     string
	Metadata    map[string]interface{}
	TrialEndsAt *time.Time
}

// RepositoryUpdateInput represents input for updating an organization
type RepositoryUpdateInput struct {
	Name     *string
	Domain   *string
	LogoURL  *string
	Plan     *string
	Active   *bool
	Metadata map[string]interface{}
}

// RepositoryListInput represents input for listing organizations
type RepositoryListInput struct {
	Offset int
	Limit  int
	Search string
}

type repository struct {
	client *ent.Client
}

// NewRepository creates a new organization repository
func NewRepository(client *ent.Client) Repository {
	return &repository{
		client: client,
	}
}

// Create creates a new organization
func (r *repository) Create(ctx context.Context, input RepositoryCreateInput) (*ent.Organization, error) {
	// Generate UUID if needed
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(errors.CodeInternalServer, err, "failed to generate uuid")
	}

	// Check if slug is already taken
	exists, err := r.client.Organization.
		Query().
		Where(organization.SlugEQ(input.Slug)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check slug uniqueness")
	}

	if exists {
		return nil, errors.New(errors.CodeConflict, "organization with this slug already exists")
	}

	// Start a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to start transaction")
	}

	// Create organization
	org, err := tx.Organization.
		Create().
		SetID(id.String()).
		SetName(input.Name).
		SetSlug(input.Slug).
		SetNillableDomain(nilIfEmpty(input.Domain)).
		SetNillableLogoURL(nilIfEmpty(input.LogoURL)).
		SetPlan(input.Plan).
		SetMetadata(input.Metadata).
		SetNillableTrialEndsAt(input.TrialEndsAt).
		Save(ctx)

	if err != nil {
		_ = tx.Rollback()
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create organization")
	}

	// Add owner to organization
	err = tx.Organization.
		UpdateOneID(org.ID).
		AddUserIDs(input.OwnerID).
		Exec(ctx)

	if err != nil {
		_ = tx.Rollback()
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to add owner to organization")
	}

	// Set primary organization for owner if not already set
	userHasPrimary, err := tx.User.Query().
		Where(
			user.ID(input.OwnerID),
			user.PrimaryOrganizationIDNotNil(),
		).
		Exist(ctx)

	if err != nil {
		_ = tx.Rollback()
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check user primary organization")
	}

	if !userHasPrimary {
		err = tx.User.
			UpdateOneID(input.OwnerID).
			SetPrimaryOrganizationID(org.ID).
			Exec(ctx)

		if err != nil {
			_ = tx.Rollback()
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to set primary organization")
		}
	}

	// Assign owner role
	ownerRole, err := tx.Role.
		Query().
		Where(
			role.Name("owner"),
			role.OrganizationIDEQ(org.ID),
		).
		First(ctx)

	if err != nil {
		// Create owner role if it doesn't exist
		ownerRole, err = tx.Role.
			Create().
			SetName("owner").
			SetDescription("Organization owner with full access").
			SetOrganizationID(org.ID).
			SetSystem(true).
			Save(ctx)

		if err != nil {
			_ = tx.Rollback()
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create owner role")
		}
	}

	// Assign owner role to user
	_, err = tx.User.
		UpdateOneID(input.OwnerID).
		AddRoles(ownerRole).
		Save(ctx)

	if err != nil {
		_ = tx.Rollback()
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to assign owner role")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to commit transaction")
	}

	return org, nil
}

// GetByID retrieves an organization by ID
func (r *repository) GetByID(ctx context.Context, id string) (*ent.Organization, error) {
	org, err := r.client.Organization.
		Query().
		Where(organization.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get organization")
	}

	return org, nil
}

// GetBySlug retrieves an organization by slug
func (r *repository) GetBySlug(ctx context.Context, slug string) (*ent.Organization, error) {
	org, err := r.client.Organization.
		Query().
		Where(organization.Slug(slug)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get organization")
	}

	return org, nil
}

// GetByDomain retrieves an organization by domain
func (r *repository) GetByDomain(ctx context.Context, domain string) (*ent.Organization, error) {
	org, err := r.client.Organization.
		Query().
		Where(organization.Domain(domain)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "organization not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get organization")
	}

	return org, nil
}

// List retrieves organizations with pagination
func (r *repository) List(ctx context.Context, input RepositoryListInput) ([]*ent.Organization, int, error) {
	query := r.client.Organization.Query()

	// Apply search filter if provided
	if input.Search != "" {
		query = query.Where(
			organization.Or(
				organization.NameContainsFold(input.Search),
				organization.SlugContainsFold(input.Search),
				organization.DomainContainsFold(input.Search),
			),
		)
	}

	// Count total results
	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to count organizations")
	}

	// Apply pagination
	orgs, err := query.
		Limit(input.Limit).
		Offset(input.Offset).
		Order(ent.Desc(organization.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to list organizations")
	}

	return orgs, total, nil
}

// Update updates an organization
func (r *repository) Update(ctx context.Context, id string, input RepositoryUpdateInput) (*ent.Organization, error) {
	// Check if organization exists
	exists, err := r.client.Organization.
		Query().
		Where(organization.ID(id)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !exists {
		return nil, errors.New(errors.CodeNotFound, "organization not found")
	}

	// Create update query
	update := r.client.Organization.
		UpdateOneID(id)

	// Apply updates
	if input.Name != nil {
		update = update.SetName(*input.Name)
	}

	if input.Domain != nil {
		if *input.Domain == "" {
			update = update.ClearDomain()
		} else {
			update = update.SetDomain(*input.Domain)
		}
	}

	if input.LogoURL != nil {
		if *input.LogoURL == "" {
			update = update.ClearLogoURL()
		} else {
			update = update.SetLogoURL(*input.LogoURL)
		}
	}

	if input.Plan != nil {
		update = update.SetPlan(*input.Plan)
	}

	if input.Active != nil {
		update = update.SetActive(*input.Active)
	}

	if input.Metadata != nil {
		update = update.SetMetadata(input.Metadata)
	}

	// Execute update
	org, err := update.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to update organization")
	}

	return org, nil
}

// Delete deletes an organization
func (r *repository) Delete(ctx context.Context, id string) error {
	// Check if organization exists
	exists, err := r.client.Organization.
		Query().
		Where(organization.ID(id)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !exists {
		return errors.New(errors.CodeNotFound, "organization not found")
	}

	// Delete organization
	err = r.client.Organization.
		DeleteOneID(id).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete organization")
	}

	return nil
}

// GetMembers retrieves members of an organization
func (r *repository) GetMembers(ctx context.Context, orgID string, input RepositoryListInput) ([]*ent.User, int, error) {
	// Check if organization exists
	exists, err := r.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !exists {
		return nil, 0, errors.New(errors.CodeNotFound, "organization not found")
	}

	// Build query
	query := r.client.User.
		Query().
		Where(
			user.HasOrganizationsWith(organization.ID(orgID)),
		)

	// Apply search filter if provided
	if input.Search != "" {
		query = query.Where(
			user.Or(
				user.EmailContainsFold(input.Search),
				user.FirstNameContainsFold(input.Search),
				user.LastNameContainsFold(input.Search),
			),
		)
	}

	// Count total results
	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to count organization members")
	}

	// Apply pagination
	members, err := query.
		Limit(input.Limit).
		Offset(input.Offset).
		Order(ent.Desc(user.FieldCreatedAt)).
		All(ctx)

	if err != nil {
		return nil, 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to list organization members")
	}

	return members, total, nil
}

// AddMember adds a user to an organization
func (r *repository) AddMember(ctx context.Context, orgID, userID string, roles []string) error {
	// Check if organization exists
	_, err := r.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization not found")
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to get organization")
	}

	// Check if user exists
	userExists, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !userExists {
		return errors.New(errors.CodeNotFound, "user not found")
	}

	// Check if user is already a member
	isMember, err := r.client.User.
		Query().
		Where(
			user.ID(userID),
			user.HasOrganizationsWith(organization.ID(orgID)),
		).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check membership")
	}

	if isMember {
		return errors.New(errors.CodeConflict, "user is already a member of this organization")
	}

	// Start a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to start transaction")
	}

	// Add user to organization
	err = tx.Organization.
		UpdateOneID(orgID).
		AddUserIDs(userID).
		Exec(ctx)

	if err != nil {
		_ = tx.Rollback()
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to add member to organization")
	}

	// Set primary organization for user if not already set
	userHasPrimary, err := tx.User.Query().
		Where(
			user.ID(userID),
			user.PrimaryOrganizationIDNotNil(),
		).
		Exist(ctx)

	if err != nil {
		_ = tx.Rollback()
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check user primary organization")
	}

	if !userHasPrimary {
		err = tx.User.
			UpdateOneID(userID).
			SetPrimaryOrganizationID(orgID).
			Exec(ctx)

		if err != nil {
			_ = tx.Rollback()
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to set primary organization")
		}
	}

	// Assign roles if provided
	if len(roles) > 0 {
		// Get or create roles
		for _, roleName := range roles {
			roleObj, err := tx.Role.
				Query().
				Where(
					role.Name(roleName),
					role.OrganizationIDEQ(orgID),
				).
				First(ctx)

			if err != nil {
				if !ent.IsNotFound(err) {
					_ = tx.Rollback()
					return errors.Wrap(errors.CodeDatabaseError, err, "failed to query role")
				}

				// Role doesn't exist, create a default one
				roleObj, err = tx.Role.
					Create().
					SetName(roleName).
					SetNillableDescription(nil).
					SetOrganizationID(orgID).
					Save(ctx)

				if err != nil {
					_ = tx.Rollback()
					return errors.Wrap(errors.CodeDatabaseError, err, "failed to create role")
				}
			}

			// Assign role to user
			err = tx.User.
				UpdateOneID(userID).
				AddRoles(roleObj).
				Exec(ctx)

			if err != nil {
				_ = tx.Rollback()
				return errors.Wrap(errors.CodeDatabaseError, err, "failed to assign role")
			}
		}
	} else {
		// Assign default member role
		memberRole, err := tx.Role.
			Query().
			Where(
				role.Name("member"),
				role.OrganizationIDEQ(orgID),
			).
			First(ctx)

		if err != nil {
			if !ent.IsNotFound(err) {
				_ = tx.Rollback()
				return errors.Wrap(errors.CodeDatabaseError, err, "failed to query member role")
			}

			// Create member role
			memberRole, err = tx.Role.
				Create().
				SetName("member").
				SetDescription("Regular organization member").
				SetOrganizationID(orgID).
				SetSystem(true).
				Save(ctx)

			if err != nil {
				_ = tx.Rollback()
				return errors.Wrap(errors.CodeDatabaseError, err, "failed to create member role")
			}
		}

		// Assign member role to user
		err = tx.User.
			UpdateOneID(userID).
			AddRoles(memberRole).
			Exec(ctx)

		if err != nil {
			_ = tx.Rollback()
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to assign member role")
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to commit transaction")
	}

	return nil
}

// RemoveMember removes a user from an organization
func (r *repository) RemoveMember(ctx context.Context, orgID, userID string) error {
	// Check if organization exists
	orgExists, err := r.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !orgExists {
		return errors.New(errors.CodeNotFound, "organization not found")
	}

	// Check if user exists
	userExists, err := r.client.User.
		Query().
		Where(user.ID(userID)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check user existence")
	}

	if !userExists {
		return errors.New(errors.CodeNotFound, "user not found")
	}

	// Check if user is a member
	isMember, err := r.client.User.
		Query().
		Where(
			user.ID(userID),
			user.HasOrganizationsWith(organization.ID(orgID)),
		).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check membership")
	}

	if !isMember {
		return errors.New(errors.CodeNotFound, "user is not a member of this organization")
	}

	// Start a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to start transaction")
	}

	// Check if user has this as their primary organization
	curUser, err := tx.User.
		Query().
		Where(user.ID(userID)).
		Only(ctx)

	if err != nil {
		_ = tx.Rollback()
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to get user")
	}

	// If this is the user's primary organization, set primary to null
	if curUser.PrimaryOrganizationID == orgID {
		// Find another organization to set as primary, or set to null
		orgs, err := tx.User.
			Query().
			Where(user.ID(userID)).
			QueryOrganizations().
			Where(organization.IDNEQ(orgID)).
			Order(ent.Asc(organization.FieldCreatedAt)).
			Limit(1).
			All(ctx)

		if err != nil {
			_ = tx.Rollback()
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to query user organizations")
		}

		if len(orgs) > 0 {
			// Set another organization as primary
			err = tx.User.
				UpdateOneID(userID).
				SetPrimaryOrganizationID(orgs[0].ID).
				Exec(ctx)
		} else {
			// Clear primary organization
			err = tx.User.
				UpdateOneID(userID).
				ClearPrimaryOrganizationID().
				Exec(ctx)
		}

		if err != nil {
			_ = tx.Rollback()
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to update primary organization")
		}
	}

	// Remove organization-specific roles from user
	orgRoles, err := tx.Role.
		Query().
		Where(role.OrganizationIDEQ(orgID)).
		All(ctx)

	if err != nil {
		_ = tx.Rollback()
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to query organization roles")
	}

	// Remove each role from user
	for _, role := range orgRoles {
		err = tx.User.
			UpdateOneID(userID).
			RemoveRoleIDs(role.ID).
			Exec(ctx)

		if err != nil {
			_ = tx.Rollback()
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to remove role from user")
		}
	}

	// Remove user from organization
	err = tx.Organization.
		UpdateOneID(orgID).
		RemoveUserIDs(userID).
		Exec(ctx)

	if err != nil {
		_ = tx.Rollback()
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to remove member from organization")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to commit transaction")
	}

	return nil
}

// UpdateMember updates a member's roles in an organization
func (r *repository) UpdateMember(ctx context.Context, orgID, userID string, roles []string) error {
	// Check if organization exists
	orgExists, err := r.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !orgExists {
		return errors.New(errors.CodeNotFound, "organization not found")
	}

	// Check if user exists and is a member
	isMember, err := r.client.User.
		Query().
		Where(
			user.ID(userID),
			user.HasOrganizationsWith(organization.ID(orgID)),
		).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check membership")
	}

	if !isMember {
		return errors.New(errors.CodeNotFound, "user is not a member of this organization")
	}

	// Start a transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to start transaction")
	}

	// Get all current organization roles
	orgRoles, err := tx.Role.
		Query().
		Where(role.OrganizationIDEQ(orgID)).
		All(ctx)

	if err != nil {
		_ = tx.Rollback()
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to query organization roles")
	}

	// Remove all current organization roles from user
	for _, role := range orgRoles {
		err = tx.User.
			UpdateOneID(userID).
			RemoveRoleIDs(role.ID).
			Exec(ctx)

		if err != nil {
			_ = tx.Rollback()
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to remove role from user")
		}
	}

	// Add new roles
	for _, roleName := range roles {
		roleObj, err := tx.Role.
			Query().
			Where(
				role.Name(roleName),
				role.OrganizationIDEQ(orgID),
			).
			First(ctx)

		if err != nil {
			if !ent.IsNotFound(err) {
				_ = tx.Rollback()
				return errors.Wrap(errors.CodeDatabaseError, err, "failed to query role")
			}

			// Role doesn't exist, create it
			roleObj, err = tx.Role.
				Create().
				SetName(roleName).
				SetNillableDescription(nil).
				SetOrganizationID(orgID).
				Save(ctx)

			if err != nil {
				_ = tx.Rollback()
				return errors.Wrap(errors.CodeDatabaseError, err, "failed to create role")
			}
		}

		// Assign role to user
		err = tx.User.
			UpdateOneID(userID).
			AddRoles(roleObj).
			Exec(ctx)

		if err != nil {
			_ = tx.Rollback()
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to assign role")
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to commit transaction")
	}

	return nil
}

// IsFeatureEnabled checks if a feature is enabled for an organization
func (r *repository) IsFeatureEnabled(ctx context.Context, orgID string, featureKey string) (bool, error) {
	// Check if organization exists
	orgExists, err := r.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return false, errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !orgExists {
		return false, errors.New(errors.CodeNotFound, "organization not found")
	}

	// Get feature flag by key
	featureFlag, err := r.client.FeatureFlag.
		Query().
		Where(featureflag.Key(featureKey)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return false, errors.New(errors.CodeNotFound, "feature flag not found")
		}
		return false, errors.Wrap(errors.CodeDatabaseError, err, "failed to get feature flag")
	}

	// Check if organization has this feature enabled
	orgFeature, err := r.client.OrganizationFeature.
		Query().
		Where(
			organizationfeature.OrganizationIDEQ(orgID),
			organizationfeature.FeatureIDEQ(featureFlag.ID),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			// Feature is not explicitly set for this organization
			// Check if the feature is enabled globally
			return featureFlag.Enabled, nil
		}
		return false, errors.Wrap(errors.CodeDatabaseError, err, "failed to query organization feature")
	}

	// Return organization-specific setting
	return orgFeature.Enabled, nil
}

// GetFeatures retrieves features of an organization
func (r *repository) GetFeatures(ctx context.Context, orgID string) ([]*ent.OrganizationFeature, error) {
	// Check if organization exists
	orgExists, err := r.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !orgExists {
		return nil, errors.New(errors.CodeNotFound, "organization not found")
	}

	// Get organization features
	features, err := r.client.OrganizationFeature.
		Query().
		Where(organizationfeature.OrganizationIDEQ(orgID)).
		WithFeature().
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query organization features")
	}

	return features, nil
}

// EnableFeature enables a feature for an organization
func (r *repository) EnableFeature(ctx context.Context, orgID string, featureKey string, settings map[string]interface{}) error {
	// Check if organization exists
	orgExists, err := r.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !orgExists {
		return errors.New(errors.CodeNotFound, "organization not found")
	}

	// Get feature flag by key
	featureFlag, err := r.client.FeatureFlag.
		Query().
		Where(featureflag.Key(featureKey)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "feature flag not found")
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to get feature flag")
	}

	// Check if organization already has this feature
	exists, err := r.client.OrganizationFeature.
		Query().
		Where(
			organizationfeature.OrganizationIDEQ(orgID),
			organizationfeature.FeatureIDEQ(featureFlag.ID),
		).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization feature")
	}

	// Start transaction
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to start transaction")
	}

	if exists {
		// Update existing feature
		_, err = tx.OrganizationFeature.
			Update().
			Where(
				organizationfeature.OrganizationIDEQ(orgID),
				organizationfeature.FeatureIDEQ(featureFlag.ID),
			).
			SetEnabled(true).
			SetSettings(settings).
			Save(ctx)
	} else {
		// Create new organization feature
		id, err := uuid.NewRandom()
		if err != nil {
			_ = tx.Rollback()
			return errors.Wrap(errors.CodeInternalServer, err, "failed to generate uuid")
		}

		_, err = tx.OrganizationFeature.
			Create().
			SetID(id.String()).
			SetOrganizationID(orgID).
			SetFeatureID(featureFlag.ID).
			SetEnabled(true).
			SetSettings(settings).
			Save(ctx)
	}

	if err != nil {
		_ = tx.Rollback()
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to enable feature")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to commit transaction")
	}

	return nil
}

// DisableFeature disables a feature for an organization
func (r *repository) DisableFeature(ctx context.Context, orgID string, featureKey string) error {
	// Check if organization exists
	orgExists, err := r.client.Organization.
		Query().
		Where(organization.ID(orgID)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization existence")
	}

	if !orgExists {
		return errors.New(errors.CodeNotFound, "organization not found")
	}

	// Get feature flag by key
	featureFlag, err := r.client.FeatureFlag.
		Query().
		Where(featureflag.Key(featureKey)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "feature flag not found")
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to get feature flag")
	}

	// Check if organization has this feature
	exists, err := r.client.OrganizationFeature.
		Query().
		Where(
			organizationfeature.OrganizationIDEQ(orgID),
			organizationfeature.FeatureIDEQ(featureFlag.ID),
		).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization feature")
	}

	if !exists {
		// Feature is not explicitly set for this organization
		// Create it with enabled=false
		id, err := uuid.NewRandom()
		if err != nil {
			return errors.Wrap(errors.CodeInternalServer, err, "failed to generate uuid")
		}

		_, err = r.client.OrganizationFeature.
			Create().
			SetID(id.String()).
			SetOrganizationID(orgID).
			SetFeatureID(featureFlag.ID).
			SetEnabled(false).
			Save(ctx)

		if err != nil {
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to create disabled feature")
		}

		return nil
	}

	// Update existing feature to disabled
	_, err = r.client.OrganizationFeature.
		Update().
		Where(
			organizationfeature.OrganizationIDEQ(orgID),
			organizationfeature.FeatureIDEQ(featureFlag.ID),
		).
		SetEnabled(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to disable feature")
	}

	return nil
}

// Helper function to return nil for empty strings
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
