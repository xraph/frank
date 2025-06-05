package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	entRole "github.com/juicycleff/frank/ent/role"
	entUserRole "github.com/juicycleff/frank/ent/userrole"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

// RoleService handles role assignments and management across all user types
type RoleService struct {
	client *data.Clients
}

// NewRoleService creates a new role service
func NewRoleService(client *data.Clients) *RoleService {
	return &RoleService{
		client: client,
	}
}

// ================================
// ROLE ASSIGNMENT METHODS
// ================================

// AssignSystemRole assigns a system-level role to a user (typically for internal users)
func (rs *RoleService) AssignSystemRole(ctx context.Context, userID xid.ID, roleName string) error {
	// Get system role
	role, err := rs.client.DB.Role.Query().
		Where(
			entRole.Name(roleName),
			entRole.RoleTypeEQ("system"),
			entRole.OrganizationIDIsNil(),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeResourceNotFound, "system role not found")
		}
		return err
	}

	// Check if assignment already exists
	exists, err := rs.client.DB.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.RoleID(role.ID),
			entUserRole.ContextTypeEQ(entUserRole.ContextTypeSystem),
			entUserRole.Active(true),
		).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil // Already assigned
	}

	// Create role assignment
	_, err = rs.client.DB.UserRole.Create().
		SetUserID(userID).
		SetRoleID(role.ID).
		SetContextType(entUserRole.ContextTypeSystem).
		SetActive(true).
		SetAssignedAt(time.Now()).
		Save(ctx)

	return err
}

// AssignOrganizationRole assigns an organization-scoped role to a user
func (rs *RoleService) AssignOrganizationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	// Get organization role
	role, err := rs.client.DB.Role.Query().
		Where(
			entRole.Name(roleName),
			entRole.RoleTypeEQ("organization"),
			entRole.OrganizationID(orgID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeResourceNotFound, "organization role not found")
		}
		return err
	}

	// Check if assignment already exists
	exists, err := rs.client.DB.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.RoleID(role.ID),
			entUserRole.ContextTypeEQ(entUserRole.ContextTypeOrganization),
			entUserRole.ContextID(orgID),
			entUserRole.Active(true),
		).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil // Already assigned
	}

	// Create role assignment
	_, err = rs.client.DB.UserRole.Create().
		SetUserID(userID).
		SetRoleID(role.ID).
		SetContextType(entUserRole.ContextTypeOrganization).
		SetContextID(orgID).
		SetActive(true).
		SetAssignedAt(time.Now()).
		Save(ctx)

	return err
}

// AssignApplicationRole assigns an application-scoped role to an end user
func (rs *RoleService) AssignApplicationRole(ctx context.Context, userID xid.ID, orgID xid.ID, roleName string) error {
	// Get application role
	role, err := rs.client.DB.Role.Query().
		Where(
			entRole.Name(roleName),
			entRole.RoleTypeEQ(entRole.RoleTypeApplication),
			entRole.OrganizationID(orgID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeResourceNotFound, "application role not found")
		}
		return err
	}

	// Check if assignment already exists
	exists, err := rs.client.DB.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.RoleID(role.ID),
			entUserRole.ContextTypeEQ(entUserRole.ContextTypeApplication),
			entUserRole.ContextID(orgID),
			entUserRole.Active(true),
		).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil // Already assigned
	}

	// Create role assignment
	_, err = rs.client.DB.UserRole.Create().
		SetUserID(userID).
		SetRoleID(role.ID).
		SetContextType(entUserRole.ContextTypeApplication).
		SetContextID(orgID).
		SetActive(true).
		SetAssignedAt(time.Now()).
		Save(ctx)

	return err
}

// ================================
// ROLE REMOVAL METHODS
// ================================

// RemoveUserRole removes a role assignment
func (rs *RoleService) RemoveUserRole(ctx context.Context, userID xid.ID, roleID xid.ID, contextType entUserRole.ContextType, contextID *xid.ID) error {
	query := rs.client.DB.UserRole.Update().
		Where(
			entUserRole.UserID(userID),
			entUserRole.RoleID(roleID),
			entUserRole.ContextTypeEQ(contextType),
		)

	if contextID != nil {
		query = query.Where(entUserRole.ContextID(*contextID))
	} else {
		query = query.Where(entUserRole.ContextIDIsNil())
	}

	_, err := query.SetActive(false).Save(ctx)
	return err
}

// ================================
// ROLE QUERY METHODS
// ================================

// GetUserSystemRoles returns all system roles for a user
func (rs *RoleService) GetUserSystemRoles(ctx context.Context, userID xid.ID) ([]*ent.Role, error) {
	userRoles, err := rs.client.DB.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.ContextTypeEQ(entUserRole.ContextTypeSystem),
			entUserRole.Active(true),
		).
		WithRole().
		All(ctx)
	if err != nil {
		return nil, err
	}

	roles := make([]*ent.Role, 0, len(userRoles))
	for _, ur := range userRoles {
		if ur.Edges.Role != nil {
			roles = append(roles, ur.Edges.Role)
		}
	}

	return roles, nil
}

// GetUserOrganizationRoles returns all organization roles for a user
func (rs *RoleService) GetUserOrganizationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error) {
	userRoles, err := rs.client.DB.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.ContextTypeEQ(entUserRole.ContextTypeOrganization),
			entUserRole.ContextID(orgID),
			entUserRole.Active(true),
		).
		WithRole().
		All(ctx)
	if err != nil {
		return nil, err
	}

	roles := make([]*ent.Role, 0, len(userRoles))
	for _, ur := range userRoles {
		if ur.Edges.Role != nil {
			roles = append(roles, ur.Edges.Role)
		}
	}

	return roles, nil
}

// GetUserApplicationRoles returns all application roles for a user
func (rs *RoleService) GetUserApplicationRoles(ctx context.Context, userID xid.ID, orgID xid.ID) ([]*ent.Role, error) {
	userRoles, err := rs.client.DB.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.ContextTypeEQ(entUserRole.ContextTypeApplication),
			entUserRole.ContextID(orgID),
			entUserRole.Active(true),
		).
		WithRole().
		All(ctx)
	if err != nil {
		return nil, err
	}

	roles := make([]*ent.Role, 0, len(userRoles))
	for _, ur := range userRoles {
		if ur.Edges.Role != nil {
			roles = append(roles, ur.Edges.Role)
		}
	}

	return roles, nil
}

// GetAllUserRoles returns all roles for a user across all contexts
func (rs *RoleService) GetAllUserRoles(ctx context.Context, userID xid.ID) ([]*ent.UserRole, error) {
	return rs.client.DB.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.Active(true),
		).
		WithRole().
		WithOrganizationContext().
		All(ctx)
}

// ================================
// ROLE MANAGEMENT METHODS
// ================================

// CreateRole creates a new role
func (rs *RoleService) CreateRole(ctx context.Context, req CreateRoleRequest) (*ent.Role, error) {
	// Check if role already exists in the same context
	query := rs.client.DB.Role.Query().
		Where(
			entRole.Name(req.Name),
			entRole.RoleTypeEQ(req.RoleType),
		)

	if req.OrganizationID != nil {
		query = query.Where(entRole.OrganizationID(*req.OrganizationID))
	} else {
		query = query.Where(entRole.OrganizationIDIsNil())
	}

	if req.ApplicationID != nil {
		query = query.Where(entRole.ApplicationID(*req.ApplicationID))
	}

	exists, err := query.Exist(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New(errors.CodeConflict, "role with this name already exists in this context")
	}

	// Create role
	roleBuilder := rs.client.DB.Role.Create().
		SetName(req.Name).
		SetDescription(req.Description).
		SetRoleType(req.RoleType).
		SetPriority(req.Priority).
		SetApplicableUserTypes(req.ApplicableUserTypes).
		SetActive(true)

	if req.DisplayName != "" {
		roleBuilder.SetDisplayName(req.DisplayName)
	}
	if req.OrganizationID != nil {
		roleBuilder.SetOrganizationID(*req.OrganizationID)
	}
	if req.ApplicationID != nil {
		roleBuilder.SetApplicationID(*req.ApplicationID)
	}
	if req.Color != "" {
		roleBuilder.SetColor(req.Color)
	}
	if req.CreatedBy != "" {
		roleBuilder.SetCreatedBy(req.CreatedBy)
	}

	role, err := roleBuilder.Save(ctx)
	if err != nil {
		return nil, err
	}

	// Assign permissions if provided
	if len(req.Permissions) > 0 {
		// Note: You'll need to implement PermissionService
		// or handle permission assignments directly here
		for _, permName := range req.Permissions {
			fmt.Println("permission name:", permName)
			// TODO: Implement permission assignment
			// err = permissionService.AssignPermissionToRole(ctx, role.ID, permName)
			// if err != nil {
			//     // Log error but continue
			// }
		}
	}

	return role, nil
}

// GetRolesByType returns roles of a specific type
func (rs *RoleService) GetRolesByType(ctx context.Context, roleType entRole.RoleType, orgID *xid.ID) ([]*ent.Role, error) {
	query := rs.client.DB.Role.Query().
		Where(
			entRole.RoleTypeEQ(roleType),
			entRole.Active(true),
		)

	if orgID != nil {
		query = query.Where(entRole.OrganizationID(*orgID))
	} else if roleType == "system" {
		query = query.Where(entRole.OrganizationIDIsNil())
	}

	return query.WithPermissions().All(ctx)
}

// UpdateRole updates a role
func (rs *RoleService) UpdateRole(ctx context.Context, roleID xid.ID, updates map[string]interface{}) (*ent.Role, error) {
	role, err := rs.client.DB.Role.Get(ctx, roleID)
	if err != nil {
		return nil, err
	}

	updateBuilder := role.Update()

	for field, value := range updates {
		switch field {
		case "display_name":
			if v, ok := value.(string); ok {
				updateBuilder.SetDisplayName(v)
			}
		case "description":
			if v, ok := value.(string); ok {
				updateBuilder.SetDescription(v)
			}
		case "priority":
			if v, ok := value.(int); ok {
				updateBuilder.SetPriority(v)
			}
		case "color":
			if v, ok := value.(string); ok {
				updateBuilder.SetColor(v)
			}
		case "active":
			if v, ok := value.(bool); ok {
				updateBuilder.SetActive(v)
			}
		case "is_default":
			if v, ok := value.(bool); ok {
				updateBuilder.SetIsDefault(v)
			}
		case "name":
			if v, ok := value.(string); ok {
				updateBuilder.SetName(v)
			}
		}
	}

	return updateBuilder.Save(ctx)
}

// ================================
// ROLE CHECKING METHODS
// ================================

// HasRole checks if a user has a specific role in a given context
func (rs *RoleService) HasRole(ctx context.Context, userID xid.ID, roleName string, contextType entUserRole.ContextType, contextID *xid.ID) (bool, error) {
	query := rs.client.DB.UserRole.Query().
		Where(
			entUserRole.UserID(userID),
			entUserRole.ContextTypeEQ(contextType),
			entUserRole.Active(true),
			entUserRole.HasRoleWith(entRole.Name(roleName)),
		)

	if contextID != nil {
		query = query.Where(entUserRole.ContextID(*contextID))
	} else {
		query = query.Where(entUserRole.ContextIDIsNil())
	}

	count, err := query.Count(ctx)
	return count > 0, err
}

// HasAnyRole checks if a user has any of the specified roles in a context
func (rs *RoleService) HasAnyRole(ctx context.Context, userID xid.ID, roleNames []string, contextType entUserRole.ContextType, contextID *xid.ID) (bool, error) {
	for _, roleName := range roleNames {
		hasRole, err := rs.HasRole(ctx, userID, roleName, contextType, contextID)
		if err != nil {
			return false, err
		}
		if hasRole {
			return true, nil
		}
	}
	return false, nil
}
