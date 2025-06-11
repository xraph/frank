package authz

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	entMembership "github.com/juicycleff/frank/ent/membership"
	entOrganization "github.com/juicycleff/frank/ent/organization"
	entUser "github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

// UserManagementService handles both internal users and external end users
type UserManagementService struct {
	client *data.Clients
}

// NewUserManagementService creates a new user management service
func NewUserManagementService(client *data.Clients) *UserManagementService {
	return &UserManagementService{
		client: client,
	}
}

// UserType represents the type of user
type UserType = entUser.UserType

// CreateInternalUserRequest for creating internal platform users
type CreateInternalUserRequest struct {
	Email           string `json:"email"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	IsPlatformAdmin bool   `json:"is_platform_admin"`
	InitialPassword string `json:"initial_password"`
}

// CreateExternalUserRequest for creating customer organization users
type CreateExternalUserRequest struct {
	Email           string `json:"email"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	OrganizationID  xid.ID `json:"organization_id"`
	RoleName        string `json:"role_name"`
	InitialPassword string `json:"initial_password"`
}

// CreateEndUserRequest for creating end users in auth service
type CreateEndUserRequest struct {
	OrganizationID   xid.ID                 `json:"organization_id"`
	Email            string                 `json:"email"`
	Password         string                 `json:"password,omitempty"`
	FirstName        string                 `json:"first_name"`
	LastName         string                 `json:"last_name"`
	Username         string                 `json:"username,omitempty"`
	AuthProvider     string                 `json:"auth_provider"`
	ProviderID       string                 `json:"provider_id,omitempty"`
	CustomAttributes map[string]interface{} `json:"custom_attributes,omitempty"`
	ExternalID       string                 `json:"external_id,omitempty"`
	CreatedBy        string                 `json:"created_by,omitempty"`
}

// CreateInternalUser creates a new internal platform user
func (ums *UserManagementService) CreateInternalUser(ctx context.Context, req CreateInternalUserRequest) (*ent.User, error) {
	// Check if email already exists
	exists, err := ums.client.DB.User.Query().
		Where(entUser.Email(req.Email)).
		Exist(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New(errors.CodeConflict, "user with this email already exists")
	}

	// Hash password (implement your password hashing)
	passwordHash, err := hashPassword(req.InitialPassword)
	if err != nil {
		return nil, err
	}

	// Create internal user
	user, err := ums.client.DB.User.Create().
		SetEmail(req.Email).
		SetFirstName(req.FirstName).
		SetLastName(req.LastName).
		SetPasswordHash(passwordHash).
		SetUserType("internal").
		SetIsPlatformAdmin(req.IsPlatformAdmin).
		SetActive(true).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	// If platform admin, add to platform organization
	if req.IsPlatformAdmin {
		err = ums.addUserToPlatformOrganization(ctx, user.ID)
		if err != nil {
			// Log error but don't fail user creation
			// You might want to handle this differently
		}
	}

	return user, nil
}

// CreateExternalUser creates a new external customer organization user
func (ums *UserManagementService) CreateExternalUser(ctx context.Context, req CreateExternalUserRequest) (*ent.User, error) {
	// Verify organization exists and is a customer organization
	_, err := ums.client.DB.Organization.Query().
		Where(
			entOrganization.IDEQ(req.OrganizationID),
			entOrganization.OrgTypeEQ(entOrganization.OrgTypeCustomer),
			entOrganization.Active(true),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeResourceNotFound, "organization not found")
		}
		return nil, err
	}

	// Check if email already exists
	exists, err := ums.client.DB.User.Query().
		Where(entUser.Email(req.Email)).
		Exist(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New(errors.CodeConflict, "user with this email already exists")
	}

	// Hash password
	passwordHash, err := hashPassword(req.InitialPassword)
	if err != nil {
		return nil, err
	}

	// Create external user
	user, err := ums.client.DB.User.Create().
		SetEmail(req.Email).
		SetFirstName(req.FirstName).
		SetLastName(req.LastName).
		SetPasswordHash(passwordHash).
		SetUserType("external").
		SetPrimaryOrganizationID(req.OrganizationID).
		SetActive(true).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	// Create membership using the membership service
	membershipService := NewMembershipService(ums.client)
	_, err = membershipService.InviteUser(ctx, InviteUserRequest{
		Email:          req.Email,
		RoleName:       req.RoleName,
		InvitedByID:    xid.NilID(), // System created
		OrganizationID: req.OrganizationID,
	})
	if err != nil {
		// If membership creation fails, we should probably delete the user
		ums.client.DB.User.DeleteOne(user).Exec(ctx)
		return nil, err
	}

	// Auto-accept the membership since this is direct creation
	membership, err := ums.client.DB.Membership.Query().
		Where(
			entMembership.UserID(user.ID),
			entMembership.OrganizationID(req.OrganizationID),
		).
		Only(ctx)
	if err == nil {
		membership.Update().
			SetStatus("active").
			SetJoinedAt(time.Now()).
			Save(ctx)
	}

	return user, nil
}

// GetUserContext returns context about a user including their type and organizations
func (ums *UserManagementService) GetUserContext(ctx context.Context, userID xid.ID) (*UserContext, error) {
	user, err := ums.client.DB.User.Get(ctx, userID)
	if err != nil {
		return nil, err
	}

	userCtx := &UserContext{
		User:     user,
		UserType: UserType(user.UserType),
	}

	// Get memberships if external user
	if user.UserType == "external" {
		membershipQueries := NewMembershipQueries(ums.client)
		memberships, err := membershipQueries.GetUserMembershipsWithDetails(ctx, userID)
		if err != nil {
			return nil, err
		}
		userCtx.Memberships = memberships
	}

	return userCtx, nil
}

// UserContext provides comprehensive user information
type UserContext struct {
	User        *ent.User         `json:"user"`
	UserType    UserType          `json:"user_type"`
	Memberships []*ent.Membership `json:"memberships,omitempty"`
}

// Helper methods

// addUserToPlatformOrganization adds a user to the platform organization
func (ums *UserManagementService) addUserToPlatformOrganization(ctx context.Context, userID xid.ID) error {
	// Get or create platform organization
	platformOrg, err := ums.getOrCreatePlatformOrganization(ctx)
	if err != nil {
		return err
	}

	// Add user as admin to platform organization
	membershipService := NewMembershipService(ums.client)
	_, err = membershipService.InviteUser(ctx, InviteUserRequest{
		Email:          "", // Will be looked up
		RoleName:       "admin",
		InvitedByID:    xid.NilID(),
		OrganizationID: platformOrg.ID,
	})

	return err
}

// getOrCreatePlatformOrganization ensures platform organization exists
func (ums *UserManagementService) getOrCreatePlatformOrganization(ctx context.Context) (*ent.Organization, error) {
	// Try to find existing platform organization
	platformOrg, err := ums.client.DB.Organization.Query().
		Where(
			entOrganization.IsPlatformOrganization(true),
			entOrganization.OrgTypeEQ(entOrganization.OrgTypePlatform),
		).
		Only(ctx)

	if err == nil {
		return platformOrg, nil
	}

	if !ent.IsNotFound(err) {
		return nil, err
	}

	// Create platform organization
	platformOrg, err = ums.client.DB.Organization.Create().
		SetName("Platform Organization").
		SetSlug(string(entOrganization.OrgTypePlatform)).
		SetOrgType(entOrganization.OrgTypePlatform).
		SetIsPlatformOrganization(true).
		// SetMemberLimit(1000). // High limit for internal team
		SetActive(true).
		Save(ctx)

	return platformOrg, err
}

// IsInternalUser checks if a user is internal (platform staff)
func (ums *UserManagementService) IsInternalUser(ctx context.Context, userID xid.ID) (bool, error) {
	user, err := ums.client.DB.User.Get(ctx, userID)
	if err != nil {
		return false, err
	}
	return user.UserType == "internal", nil
}

// IsPlatformAdmin checks if a user is a platform administrator
func (ums *UserManagementService) IsPlatformAdmin(ctx context.Context, userID xid.ID) (bool, error) {
	user, err := ums.client.DB.User.Get(ctx, userID)
	if err != nil {
		return false, err
	}
	return user.IsPlatformAdmin, nil
}

// hashPassword is a placeholder - implement with your preferred hashing library
func hashPassword(password string) (string, error) {
	// TODO: Implement with bcrypt, argon2, or your preferred hashing
	return fmt.Sprintf("hashed_%s", password), nil
}
