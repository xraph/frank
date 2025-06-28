package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// PermissionTemplateService manages permission templates and role suggestions
type PermissionTemplateService struct {
	logger    logging.Logger
	repo      repository.PermissionRepository
	roleRepo  repository.RoleRepository
	discovery *ResourceDiscoveryService
}

// CreateTemplateInput for creating permission templates
type CreateTemplateInput struct {
	Name            string               `json:"name" validate:"required"`
	DisplayName     string               `json:"display_name" validate:"required"`
	Description     string               `json:"description"`
	Category        string               `json:"category" validate:"required"`
	Permissions     []TemplatePermission `json:"permissions" validate:"required,min=1"`
	TargetUserTypes []string             `json:"target_user_types" validate:"required,min=1"`
	OrganizationID  *xid.ID              `json:"organization_id,omitempty"`
	CreatedBy       string               `json:"created_by"`
}

// ApplyTemplateInput for applying a template to create a role
type ApplyTemplateInput struct {
	TemplateID      xid.ID  `json:"template_id" validate:"required"`
	RoleName        string  `json:"role_name" validate:"required"`
	RoleDisplayName string  `json:"role_display_name"`
	RoleDescription string  `json:"role_description"`
	OrganizationID  *xid.ID `json:"organization_id,omitempty"`
	CreatedBy       string  `json:"created_by"`
}

// RoleSuggestion represents AI-generated role suggestions based on usage patterns
type RoleSuggestion struct {
	Name         string               `json:"name"`
	DisplayName  string               `json:"display_name"`
	Description  string               `json:"description"`
	Permissions  []TemplatePermission `json:"permissions"`
	Confidence   float64              `json:"confidence"` // 0-1 confidence score
	BasedOn      []string             `json:"based_on"`   // What this suggestion is based on
	UsagePattern *UsagePattern        `json:"usage_pattern"`
}

type UsagePattern struct {
	FrequentlyUsedTogether []string `json:"frequently_used_together"`
	CommonUserTypes        []string `json:"common_user_types"`
	TypicalDuration        string   `json:"typical_duration"`
	RiskAssessment         string   `json:"risk_assessment"`
}

// NewPermissionTemplateService creates a new permission template service
func NewPermissionTemplateService(repo repository.Repository, discovery *ResourceDiscoveryService, logger logging.Logger) *PermissionTemplateService {
	service := &PermissionTemplateService{
		logger:    logger,
		repo:      repo.Permission(),
		roleRepo:  repo.Role(),
		discovery: discovery,
	}

	return service
}

// CreateTemplate creates a new permission template
func (pts *PermissionTemplateService) CreateTemplate(ctx context.Context, input CreateTemplateInput) (*PermissionTemplate, error) {
	// Validate all permissions exist and are valid
	for _, perm := range input.Permissions {
		err := pts.discovery.ValidatePermission(perm.Resource, perm.Action, input.OrganizationID)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeValidationError,
				fmt.Sprintf("invalid permission %s:%s", perm.Resource, perm.Action))
		}
	}

	// Validate user types
	validUserTypes := map[string]bool{
		"internal": true,
		"external": true,
		"end_user": true,
	}
	for _, userType := range input.TargetUserTypes {
		if !validUserTypes[userType] {
			return nil, errors.New(errors.CodeValidationError,
				fmt.Sprintf("invalid user type: %s", userType))
		}
	}

	template := &PermissionTemplate{
		ID:              xid.New(),
		Name:            input.Name,
		DisplayName:     input.DisplayName,
		Description:     input.Description,
		Category:        input.Category,
		Permissions:     input.Permissions,
		TargetUserTypes: input.TargetUserTypes,
		OrganizationID:  input.OrganizationID,
		IsSystem:        input.OrganizationID == nil,
		CreatedAt:       time.Now(),
		CreatedBy:       input.CreatedBy,
	}

	// Store template (you'll need to add this to your schema/internalRepo)
	err := pts.storeTemplate(ctx, template)
	if err != nil {
		return nil, err
	}

	pts.logger.Info("Permission template created",
		logging.String("template", input.Name),
		logging.String("category", input.Category))

	return template, nil
}

// ApplyTemplate creates a role from a permission template
func (pts *PermissionTemplateService) ApplyTemplate(ctx context.Context, input ApplyTemplateInput) (*model.Role, error) {
	// Get template
	template, err := pts.getTemplate(ctx, input.TemplateID)
	if err != nil {
		return nil, err
	}

	// Verify template can be applied to this organization
	if template.OrganizationID != nil && input.OrganizationID != nil {
		if *template.OrganizationID != *input.OrganizationID {
			return nil, errors.New(errors.CodeForbidden, "template not available for this organization")
		}
	}

	// Create role
	roleInput := model.CreateRoleRequest{
		Name:           input.RoleName,
		DisplayName:    input.RoleDisplayName,
		Description:    input.RoleDescription,
		RoleType:       "organization", // Default to organization level
		OrganizationID: input.OrganizationID,
		CreatedBy:      input.CreatedBy,
	}

	if input.RoleDisplayName == "" {
		roleInput.DisplayName = template.DisplayName
	}
	if input.RoleDescription == "" {
		roleInput.Description = template.Description
	}

	// Create role using existing service
	role, err := pts.roleRepo.CreateRoleAdvanced(ctx, repository.CreateRoleRequest{
		Name:           roleInput.Name,
		DisplayName:    roleInput.DisplayName,
		Description:    roleInput.Description,
		RoleType:       roleInput.RoleType,
		OrganizationID: roleInput.OrganizationID,
		CreatedBy:      roleInput.CreatedBy,
	})
	if err != nil {
		return nil, err
	}

	// Add permissions from template
	for _, templatePerm := range template.Permissions {
		// Find or create permission
		permissionName := fmt.Sprintf("%s:%s", templatePerm.Resource, templatePerm.Action)
		permission, err := pts.repo.GetPermissionByName(ctx, permissionName)
		if err != nil {
			if errors.IsNotFound(err) {
				// Create permission if it doesn't exist
				permission, err = pts.createPermissionFromTemplate(ctx, templatePerm, input.OrganizationID)
				if err != nil {
					pts.logger.Warn("Failed to create permission from template",
						logging.String("permission", permissionName),
						logging.Error(err))
					continue
				}
			} else {
				return nil, err
			}
		}

		// Add permission to role
		err = pts.roleRepo.AddPermissionToRole(ctx, role.ID, permission.ID)
		if err != nil {
			pts.logger.Warn("Failed to add permission to role",
				logging.String("permission", permissionName),
				logging.String("role", role.Name),
				logging.Error(err))
		}
	}

	return convertEntRoleToModel(role), nil
}

// GetSuggestedRoles analyzes usage patterns and suggests roles
func (pts *PermissionTemplateService) GetSuggestedRoles(ctx context.Context, orgID *xid.ID, userType string) ([]*RoleSuggestion, error) {
	// Analyze current role assignments and permission usage
	patterns, err := pts.analyzeUsagePatterns(ctx, orgID, userType)
	if err != nil {
		return nil, err
	}

	var suggestions []*RoleSuggestion

	// Generate suggestions based on patterns
	for _, pattern := range patterns {
		suggestion := &RoleSuggestion{
			Name:         pts.generateRoleName(pattern),
			DisplayName:  pts.generateRoleDisplayName(pattern),
			Description:  pts.generateRoleDescription(pattern),
			Permissions:  pattern.Permissions,
			Confidence:   pattern.Confidence,
			BasedOn:      pattern.BasedOn,
			UsagePattern: pattern.UsagePattern,
		}
		suggestions = append(suggestions, suggestion)
	}

	// Add template-based suggestions
	templateSuggestions := pts.getTemplateSuggestions(ctx, orgID, userType)
	suggestions = append(suggestions, templateSuggestions...)

	return suggestions, nil
}

// GetTemplatesByCategory returns templates organized by category
func (pts *PermissionTemplateService) GetTemplatesByCategory(ctx context.Context, orgID *xid.ID) (map[string][]*PermissionTemplate, error) {
	templates, err := pts.listTemplates(ctx, orgID)
	if err != nil {
		return nil, err
	}

	categorized := make(map[string][]*PermissionTemplate)
	for _, template := range templates {
		categorized[template.Category] = append(categorized[template.Category], template)
	}

	return categorized, nil
}

// ValidateTemplate checks if a template is valid and safe to apply
func (pts *PermissionTemplateService) ValidateTemplate(ctx context.Context, templateID xid.ID, orgID *xid.ID) (*TemplateValidationResult, error) {
	template, err := pts.getTemplate(ctx, templateID)
	if err != nil {
		return nil, err
	}

	result := &TemplateValidationResult{
		TemplateID: templateID,
		IsValid:    true,
		Warnings:   []string{},
		Errors:     []string{},
		RiskLevel:  "low",
	}

	var totalRisk int
	var highRiskCount int

	// Validate each permission
	for _, perm := range template.Permissions {
		// Check if permission exists
		err := pts.discovery.ValidatePermission(perm.Resource, perm.Action, orgID)
		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Permission %s:%s is not valid: %s", perm.Resource, perm.Action, err.Error()))
			result.IsValid = false
			continue
		}

		// Get action definition for risk assessment
		resource, err := pts.discovery.GetResource(perm.Resource, orgID)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Cannot assess risk for %s:%s - resource definition not found", perm.Resource, perm.Action))
			continue
		}

		if action, exists := resource.Actions[perm.Action]; exists {
			totalRisk += action.RiskLevel
			if action.RiskLevel >= 4 {
				highRiskCount++
			}
			if action.RequiresApproval {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("Permission %s:%s requires approval workflow", perm.Resource, perm.Action))
			}
		}
	}

	// Calculate overall risk level
	if len(template.Permissions) > 0 {
		avgRisk := float64(totalRisk) / float64(len(template.Permissions))
		if avgRisk >= 4 || highRiskCount >= 3 {
			result.RiskLevel = "high"
		} else if avgRisk >= 3 || highRiskCount >= 1 {
			result.RiskLevel = "medium"
		}
	}

	return result, nil
}

// TemplateValidationResult represents the result of template validation
type TemplateValidationResult struct {
	TemplateID xid.ID   `json:"template_id"`
	IsValid    bool     `json:"is_valid"`
	Warnings   []string `json:"warnings"`
	Errors     []string `json:"errors"`
	RiskLevel  string   `json:"risk_level"` // low, medium, high
}

// Helper methods (these would need proper implementation)

func (pts *PermissionTemplateService) storeTemplate(ctx context.Context, template *PermissionTemplate) error {
	// Implementation depends on your storage strategy
	// You might want to add a PermissionTemplate entity to your schema
	return nil
}

func (pts *PermissionTemplateService) getTemplate(ctx context.Context, id xid.ID) (*PermissionTemplate, error) {
	// Implementation depends on your storage strategy
	return nil, errors.New(errors.CodeNotFound, "template not found")
}

func (pts *PermissionTemplateService) listTemplates(ctx context.Context, orgID *xid.ID) ([]*PermissionTemplate, error) {
	// Implementation depends on your storage strategy
	return []*PermissionTemplate{}, nil
}

func (pts *PermissionTemplateService) createPermissionFromTemplate(ctx context.Context, templatePerm TemplatePermission, orgID *xid.ID) (*ent.Permission, error) {
	// Get resource definition for better permission details
	resource, err := pts.discovery.GetResource(templatePerm.Resource, orgID)
	if err != nil {
		return nil, err
	}

	action, exists := resource.Actions[templatePerm.Action]
	if !exists {
		return nil, errors.New(errors.CodeValidationError, "action not found in resource definition")
	}

	permissionCreate := pts.repo.Client().Permission.Create().
		SetID(xid.New()).
		SetName(fmt.Sprintf("%s:%s", templatePerm.Resource, templatePerm.Action)).
		SetDisplayName(fmt.Sprintf("%s - %s", resource.DisplayName, action.DisplayName)).
		SetDescription(action.Description).
		SetResource(templatePerm.Resource).
		SetAction(templatePerm.Action).
		SetSystem(orgID == nil)

	if len(templatePerm.Conditions) > 0 {
		// Convert conditions to JSON string
		// Implementation depends on your JSON handling
	}

	return pts.repo.CreatePermission(ctx, permissionCreate)
}

// Pattern analysis methods (simplified implementations)

type AnalyzedPattern struct {
	Permissions  []TemplatePermission `json:"permissions"`
	Confidence   float64              `json:"confidence"`
	BasedOn      []string             `json:"based_on"`
	UsagePattern *UsagePattern        `json:"usage_pattern"`
}

func (pts *PermissionTemplateService) analyzeUsagePatterns(ctx context.Context, orgID *xid.ID, userType string) ([]*AnalyzedPattern, error) {
	// This would analyze actual usage data to find common permission patterns
	// Implementation would involve:
	// 1. Querying user roles and permissions
	// 2. Finding frequently co-occurring permissions
	// 3. Analyzing user behavior patterns
	// 4. Generating confidence scores based on data quality

	return []*AnalyzedPattern{}, nil
}

func (pts *PermissionTemplateService) getTemplateSuggestions(ctx context.Context, orgID *xid.ID, userType string) []*RoleSuggestion {
	// Get system templates that match the user type
	// This would query your stored templates and convert them to suggestions

	return []*RoleSuggestion{}
}

func (pts *PermissionTemplateService) generateRoleName(pattern *AnalyzedPattern) string {
	// Generate a role name based on the permission pattern
	// This could use NLP or simple heuristics
	return "suggested_role"
}

func (pts *PermissionTemplateService) generateRoleDisplayName(pattern *AnalyzedPattern) string {
	return "Suggested Role"
}

func (pts *PermissionTemplateService) generateRoleDescription(pattern *AnalyzedPattern) string {
	return "Role generated based on usage patterns"
}

// InitializeDefaultTemplates Initialize default templates
func (pts *PermissionTemplateService) InitializeDefaultTemplates(ctx context.Context) error {
	defaultTemplates := []CreateTemplateInput{
		{
			Name:        "admin",
			DisplayName: "Administrator",
			Description: "Full administrative access",
			Category:    "administrative",
			Permissions: []TemplatePermission{
				{Resource: "user", Action: "create"},
				{Resource: "user", Action: "read"},
				{Resource: "user", Action: "update"},
				{Resource: "user", Action: "delete"},
				{Resource: "role", Action: "create"},
				{Resource: "role", Action: "read"},
				{Resource: "role", Action: "update"},
				{Resource: "role", Action: "delete"},
				{Resource: "role", Action: "assign"},
				{Resource: "organization", Action: "read"},
				{Resource: "organization", Action: "update"},
			},
			TargetUserTypes: []string{"internal", "external"},
			CreatedBy:       "system",
		},
		{
			Name:        "viewer",
			DisplayName: "Viewer",
			Description: "Read-only access to most resources",
			Category:    "basic",
			Permissions: []TemplatePermission{
				{Resource: "user", Action: "read"},
				{Resource: "role", Action: "read"},
				{Resource: "permission", Action: "read"},
				{Resource: "organization", Action: "read"},
			},
			TargetUserTypes: []string{"internal", "external", "end_user"},
			CreatedBy:       "system",
		},
		{
			Name:        "user_manager",
			DisplayName: "User Manager",
			Description: "Manage users and basic role assignments",
			Category:    "user_management",
			Permissions: []TemplatePermission{
				{Resource: "user", Action: "create"},
				{Resource: "user", Action: "read"},
				{Resource: "user", Action: "update"},
				{Resource: "role", Action: "read"},
				{Resource: "role", Action: "assign"},
			},
			TargetUserTypes: []string{"internal", "external"},
			CreatedBy:       "system",
		},
	}

	for _, template := range defaultTemplates {
		_, err := pts.CreateTemplate(ctx, template)
		if err != nil {
			pts.logger.Error("Failed to create default template",
				logging.String("template", template.Name),
				logging.Error(err))
		}
	}

	return nil
}
