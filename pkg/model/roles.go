package model

import (
	"fmt"
	"strings"
)

// =============================================================================
// ROLE METADATA
// =============================================================================

// RoleMetadata contains metadata about a role
type RoleMetadata struct {
	Name        RoleName
	Description string
	Priority    int
	IsDefault   bool
	Parent      *RoleName // For hierarchical roles
	Category    RoleCategory
}

// RoleName represents the built-in role types in the system
type RoleName string

// =============================================================================
// SYSTEM ROLES (INTERNAL USERS)
// =============================================================================
const (
	// System roles for internal platform staff
	RolePlatformSuperAdmin RoleName = "platform_super_admin"
	RolePlatformAdmin      RoleName = "platform_admin"
	RolePlatformSupport    RoleName = "platform_support"
)

// =============================================================================
// ORGANIZATION ROLES (EXTERNAL USERS)
// =============================================================================
const (
	// Organization roles for customer organization members
	RoleOrganizationOwner  RoleName = "organization_owner"
	RoleOrganizationAdmin  RoleName = "organization_admin"
	RoleOrganizationMember RoleName = "organization_member"
	RoleOrganizationViewer RoleName = "organization_viewer"
)

// =============================================================================
// APPLICATION ROLES (END USERS)
// =============================================================================
const (
	// Application roles for end users of the auth service
	RoleEndUserAdmin    RoleName = "end_user_admin"
	RoleEndUser         RoleName = "end_user"
	RoleEndUserReadonly RoleName = "end_user_readonly"
)

func (r RoleName) Values() []string {
	return []string{
		string(RolePlatformSuperAdmin),
		string(RolePlatformAdmin),
		string(RolePlatformSupport),
		string(RoleOrganizationOwner),
		string(RoleOrganizationAdmin),
		string(RoleOrganizationMember),
		string(RoleOrganizationViewer),
		string(RoleEndUserAdmin),
		string(RoleEndUser),
		string(RoleEndUserReadonly),
	}
}

// =============================================================================
// ROLE UTILITY FUNCTIONS
// =============================================================================

// String returns the string representation of the role name
func (r RoleName) String() string {
	return string(r)
}

// IsValid checks if the role name is valid
func (r RoleName) IsValid() bool {
	_, exists := RoleDefinitions[r]
	return exists
}

// GetMetadata returns the metadata for the role
func (r RoleName) GetMetadata() (RoleMetadata, bool) {
	metadata, exists := RoleDefinitions[r]
	return metadata, exists
}

// GetDescription returns the description of the role
func (r RoleName) GetDescription() string {
	if metadata, exists := RoleDefinitions[r]; exists {
		return metadata.Description
	}
	return ""
}

// GetPriority returns the priority of the role
func (r RoleName) GetPriority() int {
	if metadata, exists := RoleDefinitions[r]; exists {
		return metadata.Priority
	}
	return 0
}

// IsDefault checks if the role is a default role
func (r RoleName) IsDefault() bool {
	if metadata, exists := RoleDefinitions[r]; exists {
		return metadata.IsDefault
	}
	return false
}

// GetParent returns the parent role if it exists
func (r RoleName) GetParent() *RoleName {
	if metadata, exists := RoleDefinitions[r]; exists {
		return metadata.Parent
	}
	return nil
}

// GetCategory returns the category of the role
func (r RoleName) GetCategory() RoleCategory {
	if metadata, exists := RoleDefinitions[r]; exists {
		return metadata.Category
	}
	return ""
}

// IsSystemRole checks if the role is a system role
func (r RoleName) IsSystemRole() bool {
	return r.GetCategory() == RoleCategorySystem
}

// IsOrganizationRole checks if the role is an organization role
func (r RoleName) IsOrganizationRole() bool {
	return r.GetCategory() == RoleCategoryOrganization
}

// IsApplicationRole checks if the role is an application role
func (r RoleName) IsApplicationRole() bool {
	return r.GetCategory() == RoleCategoryApplication
}

// HasHigherPriorityThan checks if this role has higher priority than another role
func (r RoleName) HasHigherPriorityThan(other RoleName) bool {
	return r.GetPriority() > other.GetPriority()
}

// =============================================================================
// ROLE HIERARCHY FUNCTIONS
// =============================================================================

// GetRoleHierarchy returns the hierarchy path from the given role to the root
func (r RoleName) GetRoleHierarchy() []RoleName {
	var hierarchy []RoleName
	current := r

	for {
		hierarchy = append(hierarchy, current)
		parent := current.GetParent()
		if parent == nil {
			break
		}
		current = *parent
	}

	return hierarchy
}

// InheritsFrom checks if this role inherits from another role
func (r RoleName) InheritsFrom(ancestorRole RoleName) bool {
	hierarchy := r.GetRoleHierarchy()
	for _, role := range hierarchy {
		if role == ancestorRole {
			return true
		}
	}
	return false
}

// GetChildRoles returns all roles that inherit from this role
func (r RoleName) GetChildRoles() []RoleName {
	var childRoles []RoleName
	for role, metadata := range RoleDefinitions {
		if metadata.Parent != nil && *metadata.Parent == r {
			childRoles = append(childRoles, role)
		}
	}
	return childRoles
}

// =============================================================================
// ROLE DISPLAY FUNCTIONS
// =============================================================================

// GetDisplayName returns a human-friendly display name for the role
func (r RoleName) GetDisplayName() string {
	// Convert snake_case to Title Case
	parts := strings.Split(string(r), "_")
	for i, part := range parts {
		parts[i] = strings.Title(part)
	}
	return strings.Join(parts, " ")
}

// GetRoleInfo returns formatted information about the role
func (r RoleName) GetRoleInfo() string {
	metadata, exists := RoleDefinitions[r]
	if !exists {
		return fmt.Sprintf("Unknown role: %s", r)
	}

	info := fmt.Sprintf("Role: %s\n", r.GetDisplayName())
	info += fmt.Sprintf("Description: %s\n", metadata.Description)
	info += fmt.Sprintf("Category: %s\n", metadata.Category)
	info += fmt.Sprintf("Priority: %d\n", metadata.Priority)
	info += fmt.Sprintf("Default: %t\n", metadata.IsDefault)

	if metadata.Parent != nil {
		info += fmt.Sprintf("Parent: %s\n", *metadata.Parent)
	}

	return info
}

var orgMem = RoleOrganizationMember
var orgViewer = RoleOrganizationViewer

// RoleDefinitions contains all role metadata
var RoleDefinitions = map[RoleName]RoleMetadata{
	// System Roles (Internal Users)
	RolePlatformSuperAdmin: {
		Name:        RolePlatformSuperAdmin,
		Description: "Full platform administrative access",
		Priority:    100,
		IsDefault:   false,
		Parent:      nil,
		Category:    RoleCategorySystem,
	},
	RolePlatformAdmin: {
		Name:        RolePlatformAdmin,
		Description: "Platform administration with limited destructive access",
		Priority:    90,
		IsDefault:   false,
		Parent:      nil,
		Category:    RoleCategorySystem,
	},
	RolePlatformSupport: {
		Name:        RolePlatformSupport,
		Description: "Support role for assisting customers",
		Priority:    50,
		IsDefault:   true,
		Parent:      nil,
		Category:    RoleCategorySystem,
	},

	// Organization Roles (External Users)
	RoleOrganizationOwner: {
		Name:        RoleOrganizationOwner,
		Description: "Full ownership and control of organization",
		Priority:    100,
		IsDefault:   false,
		Parent:      nil,
		Category:    RoleCategoryOrganization,
	},
	RoleOrganizationAdmin: {
		Name:        RoleOrganizationAdmin,
		Description: "Administrative access without destructive permissions",
		Priority:    90,
		IsDefault:   false,
		Parent:      &orgMem,
		Category:    RoleCategoryOrganization,
	},
	RoleOrganizationMember: {
		Name:        RoleOrganizationMember,
		Description: "Standard member access",
		Priority:    50,
		IsDefault:   true,
		Parent:      &orgViewer,
		Category:    RoleCategoryOrganization,
	},
	RoleOrganizationViewer: {
		Name:        RoleOrganizationViewer,
		Description: "Read-only access",
		Priority:    10,
		IsDefault:   false,
		Parent:      nil,
		Category:    RoleCategoryOrganization,
	},

	// Application Roles (End Users)
	RoleEndUserAdmin: {
		Name:        RoleEndUserAdmin,
		Description: "Administrative access for end user management",
		Priority:    90,
		IsDefault:   false,
		Parent:      nil,
		Category:    RoleCategoryApplication,
	},
	RoleEndUser: {
		Name:        RoleEndUser,
		Description: "Standard end user access",
		Priority:    50,
		IsDefault:   true,
		Parent:      nil,
		Category:    RoleCategoryApplication,
	},
	RoleEndUserReadonly: {
		Name:        RoleEndUserReadonly,
		Description: "Read-only access for end users",
		Priority:    10,
		IsDefault:   false,
		Parent:      nil,
		Category:    RoleCategoryApplication,
	},
}

// =============================================================================
// ROLE COLLECTION FUNCTIONS
// =============================================================================

// GetAllRoles returns all defined roles
func GetAllRoles() []RoleName {
	roles := make([]RoleName, 0, len(RoleDefinitions))
	for role := range RoleDefinitions {
		roles = append(roles, role)
	}
	return roles
}

// GetRolesByCategory returns roles filtered by category
func GetRolesByCategory(category RoleCategory) []RoleName {
	var roles []RoleName
	for role, metadata := range RoleDefinitions {
		if metadata.Category == category {
			roles = append(roles, role)
		}
	}
	return roles
}

// GetSystemRoles returns all system roles
func GetSystemRoles() []RoleName {
	return GetRolesByCategory(RoleCategorySystem)
}

// GetOrganizationRoles returns all organization roles
func GetOrganizationRoles() []RoleName {
	return GetRolesByCategory(RoleCategoryOrganization)
}

// GetApplicationRoles returns all application roles
func GetApplicationRoles() []RoleName {
	return GetRolesByCategory(RoleCategoryApplication)
}

// GetDefaultRoles returns all default roles
func GetDefaultRoles() []RoleName {
	var defaultRoles []RoleName
	for role, metadata := range RoleDefinitions {
		if metadata.IsDefault {
			defaultRoles = append(defaultRoles, role)
		}
	}
	return defaultRoles
}

// GetDefaultRoleForCategory returns the default role for a specific category
func GetDefaultRoleForCategory(category RoleCategory) *RoleName {
	for role, metadata := range RoleDefinitions {
		if metadata.Category == category && metadata.IsDefault {
			return &role
		}
	}
	return nil
}

// =============================================================================
// ROLE VALIDATION FUNCTIONS
// =============================================================================

// IsValidRoleName checks if a string is a valid role name
func IsValidRoleName(roleName string) bool {
	role := RoleName(roleName)
	return role.IsValid()
}

// ParseRoleName parses a string into a RoleName if valid
func ParseRoleName(roleName string) (RoleName, error) {
	role := RoleName(strings.ToLower(roleName))
	if !role.IsValid() {
		return "", fmt.Errorf("invalid role name: %s", roleName)
	}
	return role, nil
}

// MustParseRoleName parses a string into a RoleName, panics if invalid
func MustParseRoleName(roleName string) RoleName {
	role, err := ParseRoleName(roleName)
	if err != nil {
		panic(err)
	}
	return role
}

// =============================================================================
// ROLE CONSTANTS FOR EASY ACCESS
// =============================================================================

// DefaultRoles provides easy access to default roles by category
var DefaultRoles = struct {
	System       RoleName
	Organization RoleName
	Application  RoleName
}{
	System:       RolePlatformSupport,
	Organization: RoleOrganizationMember,
	Application:  RoleEndUser,
}

// HighestPrivilegeRoles provides easy access to highest privilege roles by category
var HighestPrivilegeRoles = struct {
	System       RoleName
	Organization RoleName
	Application  RoleName
}{
	System:       RolePlatformSuperAdmin,
	Organization: RoleOrganizationOwner,
	Application:  RoleEndUserAdmin,
}
