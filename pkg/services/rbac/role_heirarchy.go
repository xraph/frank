package rbac

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// RoleHierarchyService manages role hierarchies and permission inheritance
type RoleHierarchyService struct {
	logger logging.Logger
	repo   repository.RoleRepository
	cache  HierarchyCache
}

// RoleHierarchyNode represents a node in the role hierarchy tree
type RoleHierarchyNode struct {
	Role                 *model.Role          `json:"role"`
	Children             []*RoleHierarchyNode `json:"children,omitempty"`
	Parent               *RoleHierarchyNode   `json:"parent,omitempty"`
	Level                int                  `json:"level"`
	InheritedPermissions []*Permission        `json:"inherited_permissions,omitempty"`
	DirectPermissions    []*Permission        `json:"direct_permissions,omitempty"`
	EffectivePermissions []*Permission        `json:"effective_permissions,omitempty"`
	Path                 []string             `json:"path"` // Path from root to this node
}

// RoleHierarchy represents the complete hierarchy for an organization
type RoleHierarchy struct {
	OrganizationID *xid.ID                       `json:"organization_id,omitempty"`
	RootNodes      []*RoleHierarchyNode          `json:"root_nodes"`
	AllNodes       map[string]*RoleHierarchyNode `json:"all_nodes"`
	MaxDepth       int                           `json:"max_depth"`
	GeneratedAt    time.Time                     `json:"generated_at"`
}

// RoleInheritanceRule defines how permissions are inherited
type RoleInheritanceRule struct {
	ID               xid.ID                 `json:"id"`
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	ParentRoleID     xid.ID                 `json:"parent_role_id"`
	ChildRoleID      xid.ID                 `json:"child_role_id"`
	InheritanceType  InheritanceType        `json:"inheritance_type"`
	Conditions       map[string]interface{} `json:"conditions,omitempty"`
	PermissionFilter *PermissionFilter      `json:"permission_filter,omitempty"`
	Active           bool                   `json:"active"`
	CreatedAt        time.Time              `json:"created_at"`
	CreatedBy        string                 `json:"created_by"`
	OrganizationID   *xid.ID                `json:"organization_id,omitempty"`
}

type InheritanceType string

const (
	InheritanceTypeFull        InheritanceType = "full"        // Inherit all permissions
	InheritanceTypeConditional InheritanceType = "conditional" // Inherit based on conditions
	InheritanceTypeFiltered    InheritanceType = "filtered"    // Inherit specific permissions
	InheritanceTypeAdditive    InheritanceType = "additive"    // Add to existing permissions
	InheritanceTypeOverride    InheritanceType = "override"    // Override existing permissions
)

// HierarchyValidationResult represents validation results
type HierarchyValidationResult struct {
	IsValid      bool                   `json:"is_valid"`
	Errors       []string               `json:"errors,omitempty"`
	Warnings     []string               `json:"warnings,omitempty"`
	Cycles       [][]string             `json:"cycles,omitempty"`
	Conflicts    []*PermissionConflict  `json:"conflicts,omitempty"`
	Redundancies []*RedundantPermission `json:"redundancies,omitempty"`
}

type PermissionConflict struct {
	RoleID         xid.ID            `json:"role_id"`
	Permission     string            `json:"permission"`
	Source1        string            `json:"source1"` // direct, inherited
	Source2        string            `json:"source2"`
	Description    string            `json:"description"`
	Permission1    *model.Permission `json:"permission1"`
	Permission2    *model.Permission `json:"permission2"`
	ConflictType   string            `json:"conflictType"`
	Severity       string            `json:"severity"`
	Recommendation string            `json:"recommendation"`
}

type RedundantPermission struct {
	RoleID          xid.ID `json:"role_id"`
	Permission      string `json:"permission"`
	RedundantSource string `json:"redundant_source"`
	Description     string `json:"description"`
}

// HierarchyCache interface for caching hierarchy data
type HierarchyCache interface {
	GetHierarchy(orgID *xid.ID) (*RoleHierarchy, bool)
	SetHierarchy(orgID *xid.ID, hierarchy *RoleHierarchy)
	InvalidateHierarchy(orgID *xid.ID)
	InvalidateAll()
}

// NewRoleHierarchyService creates a new role hierarchy service
func NewRoleHierarchyService(repo repository.RoleRepository, cache HierarchyCache, logger logging.Logger) *RoleHierarchyService {
	return &RoleHierarchyService{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

// BuildHierarchy constructs the complete role hierarchy for an organization
func (rhs *RoleHierarchyService) BuildHierarchy(ctx context.Context, orgID *xid.ID) (*RoleHierarchy, error) {
	// Check cache first
	if hierarchy, found := rhs.cache.GetHierarchy(orgID); found {
		return hierarchy, nil
	}

	// Get all roles for the organization
	roles, err := rhs.getRolesForOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Build the hierarchy
	hierarchy := &RoleHierarchy{
		OrganizationID: orgID,
		AllNodes:       make(map[string]*RoleHierarchyNode),
		GeneratedAt:    time.Now(),
	}

	// Create nodes for all roles
	for _, role := range roles {
		node := &RoleHierarchyNode{
			Role:  role,
			Level: 0,
			Path:  []string{role.Name},
		}
		hierarchy.AllNodes[role.ID.String()] = node
	}

	// Build parent-child relationships
	err = rhs.buildRelationships(ctx, hierarchy, roles)
	if err != nil {
		return nil, err
	}

	// Calculate inheritance and effective permissions
	err = rhs.calculateInheritance(ctx, hierarchy)
	if err != nil {
		return nil, err
	}

	// Find root nodes and calculate levels
	rhs.findRootNodesAndLevels(hierarchy)

	// Cache the result
	rhs.cache.SetHierarchy(orgID, hierarchy)

	return hierarchy, nil
}

// CreateInheritanceRule creates a new inheritance rule
func (rhs *RoleHierarchyService) CreateInheritanceRule(ctx context.Context, rule *RoleInheritanceRule) (*RoleInheritanceRule, error) {
	// Validate the rule
	err := rhs.validateInheritanceRule(ctx, rule)
	if err != nil {
		return nil, err
	}

	// Check for cycles
	wouldCreateCycle, err := rhs.wouldCreateCycle(ctx, rule.ParentRoleID, rule.ChildRoleID)
	if err != nil {
		return nil, err
	}
	if wouldCreateCycle {
		return nil, errors.New(errors.CodeValidationError, "inheritance rule would create a cycle")
	}

	// Set defaults
	if rule.ID.IsNil() {
		rule.ID = xid.New()
	}
	rule.CreatedAt = time.Now()

	// Store the rule
	err = rhs.storeInheritanceRule(ctx, rule)
	if err != nil {
		return nil, err
	}

	// Invalidate cache
	rhs.cache.InvalidateHierarchy(rule.OrganizationID)

	rhs.logger.Info("Inheritance rule created",
		logging.String("rule_id", rule.ID.String()),
		logging.String("parent_role", rule.ParentRoleID.String()),
		logging.String("child_role", rule.ChildRoleID.String()))

	return rule, nil
}

// GetEffectivePermissions returns all effective permissions for a role (direct + inherited)
func (rhs *RoleHierarchyService) GetEffectivePermissions(ctx context.Context, roleID xid.ID, orgID *xid.ID) ([]*Permission, error) {
	hierarchy, err := rhs.BuildHierarchy(ctx, orgID)
	if err != nil {
		return nil, err
	}

	node, exists := hierarchy.AllNodes[roleID.String()]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "role not found in hierarchy")
	}

	return node.EffectivePermissions, nil
}

// GetRoleAncestors returns all ancestor roles in the hierarchy
func (rhs *RoleHierarchyService) GetRoleAncestors(ctx context.Context, roleID xid.ID, orgID *xid.ID) ([]*model.Role, error) {
	hierarchy, err := rhs.BuildHierarchy(ctx, orgID)
	if err != nil {
		return nil, err
	}

	node, exists := hierarchy.AllNodes[roleID.String()]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "role not found in hierarchy")
	}

	var ancestors []*model.Role
	current := node.Parent
	for current != nil {
		ancestors = append(ancestors, current.Role)
		current = current.Parent
	}

	return ancestors, nil
}

// GetRoleDescendants returns all descendant roles in the hierarchy
func (rhs *RoleHierarchyService) GetRoleDescendants(ctx context.Context, roleID xid.ID, orgID *xid.ID) ([]*model.Role, error) {
	hierarchy, err := rhs.BuildHierarchy(ctx, orgID)
	if err != nil {
		return nil, err
	}

	node, exists := hierarchy.AllNodes[roleID.String()]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "role not found in hierarchy")
	}

	var descendants []*model.Role
	rhs.collectDescendants(node, &descendants)

	return descendants, nil
}

// ValidateHierarchy validates the entire role hierarchy for consistency
func (rhs *RoleHierarchyService) ValidateHierarchy(ctx context.Context, orgID *xid.ID) (*HierarchyValidationResult, error) {
	result := &HierarchyValidationResult{
		IsValid: true,
	}

	// Build hierarchy
	hierarchy, err := rhs.BuildHierarchy(ctx, orgID)
	if err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to build hierarchy: %s", err.Error()))
		return result, nil
	}

	// Check for cycles
	cycles := rhs.detectCycles(hierarchy)
	if len(cycles) > 0 {
		result.IsValid = false
		result.Cycles = cycles
		result.Errors = append(result.Errors, "Cycles detected in role hierarchy")
	}

	// Check for permission conflicts
	conflicts := rhs.detectPermissionConflicts(hierarchy)
	if len(conflicts) > 0 {
		result.Conflicts = conflicts
		if rhs.hasHighSeverityConflicts(conflicts) {
			result.IsValid = false
			result.Errors = append(result.Errors, "High severity permission conflicts detected")
		} else {
			result.Warnings = append(result.Warnings, "Permission conflicts detected")
		}
	}

	// Check for redundant permissions
	redundancies := rhs.detectRedundantPermissions(hierarchy)
	if len(redundancies) > 0 {
		result.Redundancies = redundancies
		result.Warnings = append(result.Warnings, "Redundant permissions detected")
	}

	// Check hierarchy depth
	if hierarchy.MaxDepth > 10 { // Configurable threshold
		result.Warnings = append(result.Warnings, "Role hierarchy is very deep, consider flattening")
	}

	return result, nil
}

// Helper methods

func (rhs *RoleHierarchyService) getRolesForOrganization(ctx context.Context, orgID *xid.ID) ([]*model.Role, error) {
	params := repository.ListRolesParams{
		OrganizationID: orgID,
	}

	result, err := rhs.repo.ListRoles(ctx, params)
	if err != nil {
		return nil, err
	}

	return convertEntRolesToModel(result.Data), nil
}

func (rhs *RoleHierarchyService) buildRelationships(ctx context.Context, hierarchy *RoleHierarchy, roles []*model.Role) error {
	// Get inheritance rules
	rules, err := rhs.getInheritanceRules(ctx, hierarchy.OrganizationID)
	if err != nil {
		return err
	}

	// Apply inheritance rules
	for _, rule := range rules {
		if !rule.Active {
			continue
		}

		parentNode, parentExists := hierarchy.AllNodes[rule.ParentRoleID.String()]
		childNode, childExists := hierarchy.AllNodes[rule.ChildRoleID.String()]

		if !parentExists || !childExists {
			rhs.logger.Warn("Inheritance rule references non-existent role",
				logging.String("rule_id", rule.ID.String()),
				logging.String("parent_id", rule.ParentRoleID.String()),
				logging.String("child_id", rule.ChildRoleID.String()))
			continue
		}

		// Set parent-child relationship
		childNode.Parent = parentNode
		parentNode.Children = append(parentNode.Children, childNode)
	}

	// Also check for roles with parent_id field set directly
	for _, role := range roles {
		if role.ParentID != nil && !role.ParentID.IsNil() {
			parentNode, parentExists := hierarchy.AllNodes[role.ParentID.String()]
			childNode, childExists := hierarchy.AllNodes[role.ID.String()]

			if parentExists && childExists && childNode.Parent == nil {
				childNode.Parent = parentNode
				parentNode.Children = append(parentNode.Children, childNode)
			}
		}
	}

	return nil
}

func (rhs *RoleHierarchyService) calculateInheritance(ctx context.Context, hierarchy *RoleHierarchy) error {
	// Get inheritance rules
	rules, err := rhs.getInheritanceRules(ctx, hierarchy.OrganizationID)
	if err != nil {
		return err
	}

	// Build rules map for quick lookup
	rulesMap := make(map[string][]*RoleInheritanceRule)
	for _, rule := range rules {
		key := fmt.Sprintf("%s->%s", rule.ParentRoleID.String(), rule.ChildRoleID.String())
		rulesMap[key] = append(rulesMap[key], rule)
	}

	// Calculate permissions for each node
	for _, node := range hierarchy.AllNodes {
		err := rhs.calculateNodePermissions(ctx, node, rulesMap)
		if err != nil {
			return err
		}
	}

	return nil
}

func (rhs *RoleHierarchyService) calculateNodePermissions(ctx context.Context, node *RoleHierarchyNode, rulesMap map[string][]*RoleInheritanceRule) error {
	// Get direct permissions for this role
	directPermissions, err := rhs.repo.GetRolePermissions(ctx, node.Role.ID)
	if err != nil {
		return err
	}
	node.DirectPermissions = convertPermissionsToDTO(directPermissions)

	// Calculate inherited permissions
	var inheritedPermissions []*Permission

	if node.Parent != nil {
		// Get inheritance rules for this relationship
		key := fmt.Sprintf("%s->%s", node.Parent.Role.ID.String(), node.Role.ID.String())
		rules := rulesMap[key]

		if len(rules) > 0 {
			// Apply inheritance rules
			for _, rule := range rules {
				inherited := rhs.applyInheritanceRule(rule, node.Parent.EffectivePermissions)
				inheritedPermissions = append(inheritedPermissions, inherited...)
			}
		} else {
			// Default inheritance - inherit all parent permissions
			inheritedPermissions = append(inheritedPermissions, node.Parent.EffectivePermissions...)
		}
	}

	node.InheritedPermissions = inheritedPermissions

	// Combine direct and inherited permissions
	node.EffectivePermissions = rhs.combinePermissions(node.DirectPermissions, node.InheritedPermissions)

	return nil
}

func (rhs *RoleHierarchyService) applyInheritanceRule(rule *RoleInheritanceRule, parentPermissions []*Permission) []*Permission {
	var result []*Permission

	for _, permission := range parentPermissions {
		if rhs.permissionMatchesFilter(permission, rule.PermissionFilter) {
			switch rule.InheritanceType {
			case InheritanceTypeFull, InheritanceTypeAdditive:
				result = append(result, permission)
			case InheritanceTypeFiltered:
				if rhs.permissionPassesFilter(permission, rule.PermissionFilter) {
					result = append(result, permission)
				}
			case InheritanceTypeConditional:
				// Would need to evaluate conditions here
				result = append(result, permission)
			}
		}
	}

	return result
}

func (rhs *RoleHierarchyService) permissionMatchesFilter(permission *Permission, filter *PermissionFilter) bool {
	if filter == nil {
		return true
	}

	// Check include/exclude resources
	if len(filter.IncludeResources) > 0 && !contains(filter.IncludeResources, permission.Resource) {
		return false
	}
	if len(filter.ExcludeResources) > 0 && contains(filter.ExcludeResources, permission.Resource) {
		return false
	}

	// Check include/exclude actions
	if len(filter.IncludeActions) > 0 && !contains(filter.IncludeActions, permission.Action) {
		return false
	}
	if len(filter.ExcludeActions) > 0 && contains(filter.ExcludeActions, permission.Action) {
		return false
	}

	return true
}

func (rhs *RoleHierarchyService) permissionPassesFilter(permission *Permission, filter *PermissionFilter) bool {
	// Additional filtering logic for filtered inheritance
	return rhs.permissionMatchesFilter(permission, filter)
}

func (rhs *RoleHierarchyService) combinePermissions(direct, inherited []*Permission) []*Permission {
	// Create a map to deduplicate permissions
	permMap := make(map[string]*Permission)

	// Add direct permissions first (they take precedence)
	for _, perm := range direct {
		key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
		permMap[key] = perm
	}

	// Add inherited permissions if not already present
	for _, perm := range inherited {
		key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
		if _, exists := permMap[key]; !exists {
			permMap[key] = perm
		}
	}

	// Convert back to slice
	var result []*Permission
	for _, perm := range permMap {
		result = append(result, perm)
	}

	// Sort for consistency
	sort.Slice(result, func(i, j int) bool {
		if result[i].Resource != result[j].Resource {
			return result[i].Resource < result[j].Resource
		}
		return result[i].Action < result[j].Action
	})

	return result
}

func (rhs *RoleHierarchyService) findRootNodesAndLevels(hierarchy *RoleHierarchy) {
	// Find root nodes and calculate levels
	var roots []*RoleHierarchyNode
	maxDepth := 0

	for _, node := range hierarchy.AllNodes {
		if node.Parent == nil {
			roots = append(roots, node)
			depth := rhs.calculateNodeDepth(node, 0)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
	}

	hierarchy.RootNodes = roots
	hierarchy.MaxDepth = maxDepth
}

func (rhs *RoleHierarchyService) calculateNodeDepth(node *RoleHierarchyNode, currentLevel int) int {
	node.Level = currentLevel
	maxDepth := currentLevel

	for _, child := range node.Children {
		depth := rhs.calculateNodeDepth(child, currentLevel+1)
		if depth > maxDepth {
			maxDepth = depth
		}
	}

	return maxDepth
}

func (rhs *RoleHierarchyService) collectDescendants(node *RoleHierarchyNode, descendants *[]*model.Role) {
	for _, child := range node.Children {
		*descendants = append(*descendants, child.Role)
		rhs.collectDescendants(child, descendants)
	}
}

func (rhs *RoleHierarchyService) detectCycles(hierarchy *RoleHierarchy) [][]string {
	var cycles [][]string
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	for _, node := range hierarchy.AllNodes {
		if !visited[node.Role.ID.String()] {
			if cycle := rhs.dfsDetectCycle(node, visited, recStack, []string{}); len(cycle) > 0 {
				cycles = append(cycles, cycle)
			}
		}
	}

	return cycles
}

func (rhs *RoleHierarchyService) dfsDetectCycle(node *RoleHierarchyNode, visited, recStack map[string]bool, path []string) []string {
	nodeID := node.Role.ID.String()
	visited[nodeID] = true
	recStack[nodeID] = true
	path = append(path, node.Role.Name)

	for _, child := range node.Children {
		childID := child.Role.ID.String()
		if !visited[childID] {
			if cycle := rhs.dfsDetectCycle(child, visited, recStack, path); len(cycle) > 0 {
				return cycle
			}
		} else if recStack[childID] {
			// Found cycle
			return path
		}
	}

	recStack[nodeID] = false
	return []string{}
}

func (rhs *RoleHierarchyService) detectPermissionConflicts(hierarchy *RoleHierarchy) []*PermissionConflict {
	var conflicts []*PermissionConflict

	for _, node := range hierarchy.AllNodes {
		// Check for conflicts between direct and inherited permissions
		directPerms := make(map[string]*Permission)
		for _, perm := range node.DirectPermissions {
			key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
			directPerms[key] = perm
		}

		for _, perm := range node.InheritedPermissions {
			key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
			if directPerm, exists := directPerms[key]; exists {
				// Check if there are meaningful differences
				if rhs.permissionsConflict(directPerm, perm) {
					conflicts = append(conflicts, &PermissionConflict{
						RoleID:      node.Role.ID,
						Permission:  key,
						Source1:     "direct",
						Source2:     "inherited",
						Description: "Direct permission conflicts with inherited permission",
					})
				}
			}
		}
	}

	return conflicts
}

func (rhs *RoleHierarchyService) detectRedundantPermissions(hierarchy *RoleHierarchy) []*RedundantPermission {
	var redundancies []*RedundantPermission

	for _, node := range hierarchy.AllNodes {
		if node.Parent == nil {
			continue
		}

		// Check if any direct permissions are already inherited
		inheritedPerms := make(map[string]bool)
		for _, perm := range node.InheritedPermissions {
			key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
			inheritedPerms[key] = true
		}

		for _, perm := range node.DirectPermissions {
			key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
			if inheritedPerms[key] {
				redundancies = append(redundancies, &RedundantPermission{
					RoleID:          node.Role.ID,
					Permission:      key,
					RedundantSource: "direct",
					Description:     "Direct permission is redundant with inherited permission",
				})
			}
		}
	}

	return redundancies
}

func (rhs *RoleHierarchyService) permissionsConflict(perm1, perm2 *Permission) bool {
	// Define what constitutes a conflict
	// For now, just check if conditions are different
	return perm1.Conditions != perm2.Conditions
}

func (rhs *RoleHierarchyService) hasHighSeverityConflicts(conflicts []*PermissionConflict) bool {
	// Define criteria for high severity conflicts
	return len(conflicts) > 10 // Simple threshold
}

func (rhs *RoleHierarchyService) validateInheritanceRule(ctx context.Context, rule *RoleInheritanceRule) error {
	if rule.ParentRoleID.IsNil() {
		return errors.New(errors.CodeValidationError, "parent role ID is required")
	}

	if rule.ChildRoleID.IsNil() {
		return errors.New(errors.CodeValidationError, "child role ID is required")
	}

	if rule.ParentRoleID == rule.ChildRoleID {
		return errors.New(errors.CodeValidationError, "parent and child roles cannot be the same")
	}

	// Validate inheritance type
	validTypes := map[InheritanceType]bool{
		InheritanceTypeFull:        true,
		InheritanceTypeConditional: true,
		InheritanceTypeFiltered:    true,
		InheritanceTypeAdditive:    true,
		InheritanceTypeOverride:    true,
	}

	if !validTypes[rule.InheritanceType] {
		return errors.New(errors.CodeUnauthorized, fmt.Sprintf("invalid inheritance type: %s", rule.InheritanceType))
	}

	return nil
}

func (rhs *RoleHierarchyService) wouldCreateCycle(ctx context.Context, parentID, childID xid.ID) (bool, error) {
	// Simple cycle detection - check if parentID is a descendant of childID
	visited := make(map[string]bool)
	return rhs.isDescendant(ctx, childID, parentID, visited)
}

func (rhs *RoleHierarchyService) isDescendant(ctx context.Context, ancestorID, targetID xid.ID, visited map[string]bool) (bool, error) {
	if ancestorID == targetID {
		return true, nil
	}

	if visited[ancestorID.String()] {
		return false, nil // Already checked this path
	}
	visited[ancestorID.String()] = true

	// Get children of ancestorID
	children, err := rhs.getDirectChildren(ctx, ancestorID)
	if err != nil {
		return false, err
	}

	for _, child := range children {
		if child == targetID {
			return true, nil
		}

		isDesc, err := rhs.isDescendant(ctx, child, targetID, visited)
		if err != nil {
			return false, err
		}
		if isDesc {
			return true, nil
		}
	}

	return false, nil
}

func (rhs *RoleHierarchyService) getDirectChildren(ctx context.Context, roleID xid.ID) ([]xid.ID, error) {
	// Implementation would query inheritance rules or role parent_id fields
	// For now, return empty slice
	return []xid.ID{}, nil
}

func (rhs *RoleHierarchyService) getInheritanceRules(ctx context.Context, orgID *xid.ID) ([]*RoleInheritanceRule, error) {
	// Implementation would query your inheritance rules storage
	// For now, return empty slice
	return []*RoleInheritanceRule{}, nil
}

func (rhs *RoleHierarchyService) storeInheritanceRule(ctx context.Context, rule *RoleInheritanceRule) error {
	// Implementation would store the rule in your database
	// You might want to add a RoleInheritanceRule entity to your schema
	return nil
}

// Simple in-memory cache implementation
type MemoryHierarchyCache struct {
	cache map[string]*RoleHierarchy
}

func NewMemoryHierarchyCache() *MemoryHierarchyCache {
	return &MemoryHierarchyCache{
		cache: make(map[string]*RoleHierarchy),
	}
}

func (mhc *MemoryHierarchyCache) GetHierarchy(orgID *xid.ID) (*RoleHierarchy, bool) {
	key := "system"
	if orgID != nil {
		key = orgID.String()
	}

	hierarchy, found := mhc.cache[key]
	return hierarchy, found
}

func (mhc *MemoryHierarchyCache) SetHierarchy(orgID *xid.ID, hierarchy *RoleHierarchy) {
	key := "system"
	if orgID != nil {
		key = orgID.String()
	}

	mhc.cache[key] = hierarchy
}

func (mhc *MemoryHierarchyCache) InvalidateHierarchy(orgID *xid.ID) {
	key := "system"
	if orgID != nil {
		key = orgID.String()
	}

	delete(mhc.cache, key)
}

func (mhc *MemoryHierarchyCache) InvalidateAll() {
	mhc.cache = make(map[string]*RoleHierarchy)
}
