package rbac

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// ResourceDiscoveryService manages dynamic resource and action registration
type ResourceDiscoveryService struct {
	logger    logging.Logger
	repo      repository.RoleRepository
	resources map[string]*ResourceDefinition
	mu        sync.RWMutex
}

// ResourceDefinition represents a dynamic resource type
type ResourceDefinition struct {
	Name           string                   `json:"name"`
	DisplayName    string                   `json:"display_name"`
	Description    string                   `json:"description"`
	Category       string                   `json:"category"`
	Actions        map[string]*ActionDef    `json:"actions"`
	Attributes     map[string]*AttributeDef `json:"attributes"`
	Dependencies   []string                 `json:"dependencies"`
	CreatedAt      time.Time                `json:"created_at"`
	CreatedBy      string                   `json:"created_by"`
	OrganizationID *xid.ID                  `json:"organization_id,omitempty"`
}

// ActionDef represents an action that can be performed on a resource
type ActionDef struct {
	Name             string            `json:"name"`
	DisplayName      string            `json:"display_name"`
	Description      string            `json:"description"`
	RiskLevel        int               `json:"risk_level"` // 1-5
	RequiresApproval bool              `json:"requires_approval"`
	Conditions       map[string]string `json:"conditions,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
}

// AttributeDef represents resource attributes that can be used in conditions
type AttributeDef struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"` // string, number, boolean, array
	Description  string      `json:"description"`
	Required     bool        `json:"required"`
	DefaultValue interface{} `json:"default_value,omitempty"`
}

// ResourceRegistrationInput for registering new resources
type ResourceRegistrationInput struct {
	Name           string                  `json:"name" validate:"required"`
	DisplayName    string                  `json:"display_name" validate:"required"`
	Description    string                  `json:"description"`
	Category       string                  `json:"category" validate:"required"`
	Actions        []ActionRegistration    `json:"actions" validate:"required,min=1"`
	Attributes     []AttributeRegistration `json:"attributes,omitempty"`
	Dependencies   []string                `json:"dependencies,omitempty"`
	OrganizationID *xid.ID                 `json:"organization_id,omitempty"`
	CreatedBy      string                  `json:"created_by"`
}

type ActionRegistration struct {
	Name             string            `json:"name" validate:"required"`
	DisplayName      string            `json:"display_name" validate:"required"`
	Description      string            `json:"description"`
	RiskLevel        int               `json:"risk_level" validate:"min=1,max=5"`
	RequiresApproval bool              `json:"requires_approval"`
	Conditions       map[string]string `json:"conditions,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
}

type AttributeRegistration struct {
	Name         string      `json:"name" validate:"required"`
	Type         string      `json:"type" validate:"required,oneof=string number boolean array"`
	Description  string      `json:"description"`
	Required     bool        `json:"required"`
	DefaultValue interface{} `json:"default_value,omitempty"`
}

// PermissionTemplate represents pre-defined permission bundles
type PermissionTemplate struct {
	ID              xid.ID               `json:"id"`
	Name            string               `json:"name"`
	DisplayName     string               `json:"displayName"`
	Description     string               `json:"description"`
	Category        string               `json:"category"`
	Permissions     []TemplatePermission `json:"permissions"`
	TargetUserTypes []string             `json:"target_user_types"`
	Resource        string               `json:"resource"`
	Action          string               `json:"action"`
	Variables       []string             `json:"variables"`
	Metadata        map[string]string    `json:"metadata"`
	OrganizationID  *xid.ID              `json:"organization_id,omitempty"`
	IsSystem        bool                 `json:"is_system"`
	CreatedAt       time.Time            `json:"createdAt"`
	CreatedBy       string               `json:"createdBy"`
}

type TemplatePermission struct {
	Resource   string            `json:"resource"`
	Action     string            `json:"action"`
	Conditions map[string]string `json:"conditions,omitempty"`
}

// NewResourceDiscoveryService creates a new resource discovery service
func NewResourceDiscoveryService(repo repository.RoleRepository, logger logging.Logger) *ResourceDiscoveryService {
	service := &ResourceDiscoveryService{
		logger:    logger,
		repo:      repo,
		resources: make(map[string]*ResourceDefinition),
	}

	// Initialize with default resources
	service.initializeDefaultResources()

	return service
}

// RegisterResource registers a new resource type with its actions
func (rds *ResourceDiscoveryService) RegisterResource(ctx context.Context, input ResourceRegistrationInput) (*ResourceDefinition, error) {
	rds.mu.Lock()
	defer rds.mu.Unlock()

	// Validate resource doesn't already exist
	resourceKey := rds.getResourceKey(input.Name, input.OrganizationID)
	if _, exists := rds.resources[resourceKey]; exists {
		return nil, errors.New(errors.CodeConflict, "resource already registered")
	}

	// Validate dependencies exist
	for _, dep := range input.Dependencies {
		depKey := rds.getResourceKey(dep, input.OrganizationID)
		if _, exists := rds.resources[depKey]; !exists {
			return nil, errors.New(errors.CodeValidationError, fmt.Sprintf("dependency resource %s not found", dep))
		}
	}

	// Create resource definition
	resource := &ResourceDefinition{
		Name:           input.Name,
		DisplayName:    input.DisplayName,
		Description:    input.Description,
		Category:       input.Category,
		Actions:        make(map[string]*ActionDef),
		Attributes:     make(map[string]*AttributeDef),
		Dependencies:   input.Dependencies,
		CreatedAt:      time.Now(),
		CreatedBy:      input.CreatedBy,
		OrganizationID: input.OrganizationID,
	}

	// Add actions
	for _, action := range input.Actions {
		resource.Actions[action.Name] = &ActionDef{
			Name:             action.Name,
			DisplayName:      action.DisplayName,
			Description:      action.Description,
			RiskLevel:        action.RiskLevel,
			RequiresApproval: action.RequiresApproval,
			Conditions:       action.Conditions,
			Tags:             action.Tags,
		}
	}

	// Add attributes
	for _, attr := range input.Attributes {
		resource.Attributes[attr.Name] = &AttributeDef{
			Name:         attr.Name,
			Type:         attr.Type,
			Description:  attr.Description,
			Required:     attr.Required,
			DefaultValue: attr.DefaultValue,
		}
	}

	// Store in memory cache
	rds.resources[resourceKey] = resource

	// Auto-create permissions for each action
	err := rds.createPermissionsForResource(ctx, resource)
	if err != nil {
		rds.logger.Error("Failed to create permissions for resource",
			logging.String("resource", input.Name),
			logging.Error(err))
		// Don't fail registration, but log the error
	}

	rds.logger.Info("Resource registered successfully",
		logging.String("resource", input.Name),
		logging.String("category", input.Category))

	return resource, nil
}

// GetResource retrieves a resource definition
func (rds *ResourceDiscoveryService) GetResource(name string, orgID *xid.ID) (*ResourceDefinition, error) {
	rds.mu.RLock()
	defer rds.mu.RUnlock()

	resourceKey := rds.getResourceKey(name, orgID)
	resource, exists := rds.resources[resourceKey]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "resource not found")
	}

	return resource, nil
}

// ListResources returns all registered resources
func (rds *ResourceDiscoveryService) ListResources(orgID *xid.ID, category string) ([]*ResourceDefinition, error) {
	rds.mu.RLock()
	defer rds.mu.RUnlock()

	var resources []*ResourceDefinition

	for _, resource := range rds.resources {
		// Filter by organization
		if orgID != nil {
			if resource.OrganizationID == nil || *resource.OrganizationID != *orgID {
				continue
			}
		} else {
			// If no orgID specified, only return system resources
			if resource.OrganizationID != nil {
				continue
			}
		}

		// Filter by category
		if category != "" && resource.Category != category {
			continue
		}

		resources = append(resources, resource)
	}

	// Sort by category, then name
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Category != resources[j].Category {
			return resources[i].Category < resources[j].Category
		}
		return resources[i].Name < resources[j].Name
	})

	return resources, nil
}

// GetAvailableActions returns all actions for a resource
func (rds *ResourceDiscoveryService) GetAvailableActions(resourceName string, orgID *xid.ID) ([]*ActionDef, error) {
	resource, err := rds.GetResource(resourceName, orgID)
	if err != nil {
		return nil, err
	}

	var actions []*ActionDef
	for _, action := range resource.Actions {
		actions = append(actions, action)
	}

	// Sort by risk level, then name
	sort.Slice(actions, func(i, j int) bool {
		if actions[i].RiskLevel != actions[j].RiskLevel {
			return actions[i].RiskLevel < actions[j].RiskLevel
		}
		return actions[i].Name < actions[j].Name
	})

	return actions, nil
}

// ValidatePermission checks if a resource:action combination is valid
func (rds *ResourceDiscoveryService) ValidatePermission(resourceName, actionName string, orgID *xid.ID) error {
	resource, err := rds.GetResource(resourceName, orgID)
	if err != nil {
		return err
	}

	if _, exists := resource.Actions[actionName]; !exists {
		return errors.New(errors.CodeValidationError, fmt.Sprintf("action %s not available for resource %s", actionName, resourceName))
	}

	return nil
}

// GetResourceCategories returns all available categories
func (rds *ResourceDiscoveryService) GetResourceCategories(orgID *xid.ID) ([]string, error) {
	rds.mu.RLock()
	defer rds.mu.RUnlock()

	categorySet := make(map[string]struct{})

	for _, resource := range rds.resources {
		// Filter by organization
		if orgID != nil {
			if resource.OrganizationID == nil || *resource.OrganizationID != *orgID {
				continue
			}
		} else {
			if resource.OrganizationID != nil {
				continue
			}
		}

		categorySet[resource.Category] = struct{}{}
	}

	var categories []string
	for category := range categorySet {
		categories = append(categories, category)
	}

	sort.Strings(categories)
	return categories, nil
}

// Helper methods

func (rds *ResourceDiscoveryService) getResourceKey(name string, orgID *xid.ID) string {
	if orgID == nil {
		return fmt.Sprintf("system:%s", name)
	}
	return fmt.Sprintf("org:%s:%s", orgID.String(), name)
}

func (rds *ResourceDiscoveryService) createPermissionsForResource(ctx context.Context, resource *ResourceDefinition) error {
	for actionName, action := range resource.Actions {
		permissionName := fmt.Sprintf("%s:%s", resource.Name, actionName)

		// Check if permission already exists
		_, err := rds.repo.GetPermissionByName(ctx, permissionName)
		if err == nil {
			// Permission already exists, skip
			continue
		}
		if !errors.IsNotFound(err) {
			return err
		}

		// Create permission
		permissionCreate := &ent.PermissionCreate{}
		permissionCreate = permissionCreate.
			SetID(xid.New()).
			SetName(permissionName).
			SetDisplayName(fmt.Sprintf("%s - %s", resource.DisplayName, action.DisplayName)).
			SetDescription(action.Description).
			SetResource(resource.Name).
			SetAction(actionName).
			SetSystem(resource.OrganizationID == nil)

		if action.Conditions != nil {
			// Convert conditions map to JSON string
			// Implementation depends on your JSON handling
		}

		_, err = rds.repo.CreatePermission(ctx, permissionCreate)
		if err != nil {
			return err
		}
	}

	return nil
}

func (rds *ResourceDiscoveryService) initializeDefaultResources() {
	// System-level resources
	defaultResources := []ResourceRegistrationInput{
		{
			Name:        "user",
			DisplayName: "User Management",
			Description: "User accounts and profile management",
			Category:    "identity",
			Actions: []ActionRegistration{
				{Name: "create", DisplayName: "Create User", Description: "Create new user accounts", RiskLevel: 3},
				{Name: "read", DisplayName: "View User", Description: "View user information", RiskLevel: 1},
				{Name: "update", DisplayName: "Update User", Description: "Modify user information", RiskLevel: 2},
				{Name: "delete", DisplayName: "Delete User", Description: "Delete user accounts", RiskLevel: 5, RequiresApproval: true},
				{Name: "impersonate", DisplayName: "Impersonate User", Description: "Login as another user", RiskLevel: 5, RequiresApproval: true},
			},
		},
		{
			Name:        "organization",
			DisplayName: "Organization Management",
			Description: "Organization settings and configuration",
			Category:    "administration",
			Actions: []ActionRegistration{
				{Name: "create", DisplayName: "Create Organization", Description: "Create new organizations", RiskLevel: 4},
				{Name: "read", DisplayName: "View Organization", Description: "View organization details", RiskLevel: 1},
				{Name: "update", DisplayName: "Update Organization", Description: "Modify organization settings", RiskLevel: 3},
				{Name: "delete", DisplayName: "Delete Organization", Description: "Delete organizations", RiskLevel: 5, RequiresApproval: true},
				{Name: "billing", DisplayName: "Manage Billing", Description: "Access billing and subscription management", RiskLevel: 4},
			},
		},
		{
			Name:        "role",
			DisplayName: "Role Management",
			Description: "Role and permission management",
			Category:    "security",
			Actions: []ActionRegistration{
				{Name: "create", DisplayName: "Create Role", Description: "Create new roles", RiskLevel: 3},
				{Name: "read", DisplayName: "View Role", Description: "View role definitions", RiskLevel: 1},
				{Name: "update", DisplayName: "Update Role", Description: "Modify role permissions", RiskLevel: 4},
				{Name: "delete", DisplayName: "Delete Role", Description: "Delete roles", RiskLevel: 4, RequiresApproval: true},
				{Name: "assign", DisplayName: "Assign Role", Description: "Assign roles to users", RiskLevel: 3},
			},
		},
		{
			Name:        "permission",
			DisplayName: "Permission Management",
			Description: "Permission definitions and assignments",
			Category:    "security",
			Actions: []ActionRegistration{
				{Name: "create", DisplayName: "Create Permission", Description: "Create new permissions", RiskLevel: 4},
				{Name: "read", DisplayName: "View Permission", Description: "View permission definitions", RiskLevel: 1},
				{Name: "update", DisplayName: "Update Permission", Description: "Modify permissions", RiskLevel: 4},
				{Name: "delete", DisplayName: "Delete Permission", Description: "Delete permissions", RiskLevel: 5, RequiresApproval: true},
				{Name: "assign", DisplayName: "Assign Permission", Description: "Assign permissions directly to users", RiskLevel: 4},
			},
		},
	}

	for _, resource := range defaultResources {
		resource.CreatedBy = "system"
		resource.OrganizationID = nil // System resources

		def := &ResourceDefinition{
			Name:           resource.Name,
			DisplayName:    resource.DisplayName,
			Description:    resource.Description,
			Category:       resource.Category,
			Actions:        make(map[string]*ActionDef),
			Attributes:     make(map[string]*AttributeDef),
			Dependencies:   resource.Dependencies,
			CreatedAt:      time.Now(),
			CreatedBy:      resource.CreatedBy,
			OrganizationID: resource.OrganizationID,
		}

		for _, action := range resource.Actions {
			def.Actions[action.Name] = &ActionDef{
				Name:             action.Name,
				DisplayName:      action.DisplayName,
				Description:      action.Description,
				RiskLevel:        action.RiskLevel,
				RequiresApproval: action.RequiresApproval,
				Conditions:       action.Conditions,
				Tags:             action.Tags,
			}
		}

		resourceKey := rds.getResourceKey(resource.Name, resource.OrganizationID)
		rds.resources[resourceKey] = def
	}
}
